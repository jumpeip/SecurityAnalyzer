package securityanalyzer.analyzers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;
import securityanalyzer.findings.Finding;
import securityanalyzer.findings.FindingType;
import securityanalyzer.findings.Severity;
import securityanalyzer.util.PCodeHelper;

/**
 * De-obfuscation utilities that act as static analyzers (no execution).
 *
 * <h2>Stack strings</h2>
 * Many obfuscators (and some compiler optimizations) write a string to the
 * stack one byte/word at a time using immediate-store instructions, e.g.:
 * <pre>
 *     MOV [RBP-0x20], 0x68
 *     MOV [RBP-0x1F], 0x65
 *     MOV [RBP-0x1E], 0x6c
 *     ...
 * </pre>
 * We walk each function's instructions, group adjacent stack-relative
 * stores by offset, and reconstruct the strings.
 *
 * <h2>XOR decode</h2>
 * Given a memory range and a key (entered by the analyst via the UI), apply
 * a streaming XOR decode and return the printable result. This is a static,
 * deterministic transform — no execution involved.
 */
public class DeobfuscationAnalyzer {

    private final Program program;
    @SuppressWarnings("unused")
    private final PCodeHelper pcode;

    public DeobfuscationAnalyzer(Program program, PCodeHelper helper) {
        this.program = program;
        this.pcode = helper;
    }

    // ------------------------------------------------------------------
    // Stack string reconstruction
    // ------------------------------------------------------------------

    /**
     * Iterate every function and emit a Finding for each plausibly-real
     * stack string we can reconstruct.
     */
    public List<Finding> scanStackStrings(TaskMonitor monitor) {
        List<Finding> findings = new ArrayList<>();
        monitor.setMessage("Reconstructing stack strings...");
        for (Function fn : program.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) break;
            findings.addAll(reconstructForFunction(fn));
        }
        return findings;
    }

    /** Reconstruct stack strings for one function. */
    public List<Finding> reconstructForFunction(Function fn) {
        List<Finding> out = new ArrayList<>();
        if (fn == null) return out;
        AddressSetView body = fn.getBody();
        if (body == null) return out;

        // Map: stack offset -> (byte value, originating instruction address)
        TreeMap<Long, Long> bytes = new TreeMap<>();
        TreeMap<Long, Address> firstSeen = new TreeMap<>();

        InstructionIterator it = program.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            String mn = ins.getMnemonicString();
            if (!"MOV".equalsIgnoreCase(mn) && !"MOVB".equalsIgnoreCase(mn)
                    && !"STR".equalsIgnoreCase(mn) && !"STRB".equalsIgnoreCase(mn)
                    && !"STRH".equalsIgnoreCase(mn)) {
                continue;
            }
            // We're looking for: MOV [<stack-relative>], <imm>
            int numOps = ins.getNumOperands();
            if (numOps < 2) continue;

            // Operand 0 should reference a stack offset
            Long stackOff = stackOffsetOf(ins, 0);
            if (stackOff == null) continue;

            // Operand 1 should be a scalar immediate
            Object[] imms = ins.getOpObjects(1);
            Long imm = null;
            for (Object o : imms) {
                if (o instanceof Scalar) {
                    imm = ((Scalar) o).getUnsignedValue();
                    break;
                }
            }
            if (imm == null) continue;

            // Determine the size from the data type stored.
            // Default to 1 byte if we can't tell.
            int size = guessStoreSize(ins);
            if (size <= 0) size = 1;

            for (int i = 0; i < size; i++) {
                long b = (imm >> (8 * i)) & 0xFF;
                bytes.put(stackOff + i, b);
                firstSeen.putIfAbsent(stackOff + i, ins.getAddress());
            }
        }

        if (bytes.isEmpty()) return out;

        // Group contiguous offsets into runs and look for printable strings.
        List<long[]> runs = collectRuns(bytes);
        for (long[] run : runs) {
            long start = run[0], end = run[1];
            int len = (int) (end - start + 1);
            if (len < 4) continue;
            byte[] buf = new byte[len];
            for (int i = 0; i < len; i++) {
                Long b = bytes.get(start + i);
                buf[i] = (byte) (b == null ? 0 : (b & 0xFF));
            }
            String s = printableString(buf);
            if (s == null) continue;
            Address site = firstSeen.get(start);
            out.add(Finding.builder(FindingType.STACK_STRING, Severity.INFO)
                    .at(site).in(fn)
                    .title("Stack string: " + abbreviate(s, 64))
                    .describe("Reconstructed string built up via immediate stores to a " +
                            "stack frame inside " + fn.getName() + ". Length " +
                            len + " bytes.")
                    .evidence("\"" + s.replace("\n", "\\n").replace("\r", "\\r") + "\"")
                    .recommend("Add this as a comment at the function entry; " +
                            "consider whether it's a C2 URL, mutex name, or command " +
                            "string.")
                    .build());
        }
        return out;
    }

    // ------------------------------------------------------------------
    // XOR decode helpers (used by UI)
    // ------------------------------------------------------------------

    /**
     * Read {@code length} bytes from {@code start} and XOR them with a
     * repeating key. Return the decoded bytes.
     */
    public byte[] xorDecode(Address start, int length, byte[] key)
            throws MemoryAccessException {
        if (length <= 0 || key == null || key.length == 0) {
            return new byte[0];
        }
        Memory mem = program.getMemory();
        byte[] data = new byte[length];
        mem.getBytes(start, data);
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return data;
    }

    /**
     * Brute-force single-byte XOR over [start, start+length): try every key 1..255
     * and return a list of (key, decoded) for keys that produced a high
     * printable ratio. The result is sorted by descending printability.
     */
    public List<DecodedCandidate> bruteForceSingleByteXor(Address start, int length)
            throws MemoryAccessException {
        Memory mem = program.getMemory();
        byte[] data = new byte[length];
        mem.getBytes(start, data);
        List<DecodedCandidate> out = new ArrayList<>();
        for (int k = 1; k < 256; k++) {
            byte[] dec = new byte[length];
            int printable = 0;
            for (int i = 0; i < length; i++) {
                dec[i] = (byte) (data[i] ^ k);
                int b = dec[i] & 0xFF;
                if (isPrintable(b)) printable++;
            }
            double ratio = (double) printable / length;
            if (ratio >= 0.85) {
                out.add(new DecodedCandidate(k, dec, ratio,
                        new String(dec, java.nio.charset.StandardCharsets.ISO_8859_1)));
            }
        }
        out.sort((a, b) -> Double.compare(b.printableRatio, a.printableRatio));
        return out;
    }

    public static final class DecodedCandidate {
        public final int key;
        public final byte[] bytes;
        public final double printableRatio;
        public final String text;
        DecodedCandidate(int k, byte[] b, double r, String s) {
            this.key = k; this.bytes = b; this.printableRatio = r; this.text = s;
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Try to extract a stack-pointer-relative offset from an instruction
     * operand. Returns null if the operand isn't recognized as such.
     *
     * <p>The implementation is deliberately conservative: we look at the
     * default operand representation and parse common forms like
     * {@code [RBP - 0x20]}, {@code [ESP+0x10]}, {@code [BP-1]}.
     */
    private Long stackOffsetOf(Instruction ins, int operandIndex) {
        // First, check if any of the operand objects is a Scalar that we
        // believe is a stack-relative displacement.
        Object[] objs = ins.getOpObjects(operandIndex);
        Long off = null;
        boolean sawSp = false;
        for (Object o : objs) {
            String s = o.toString();
            String up = s.toUpperCase();
            if (up.equals("RBP") || up.equals("EBP") || up.equals("BP") ||
                up.equals("RSP") || up.equals("ESP") || up.equals("SP") ||
                up.equals("R11") || up.equals("FP") || up.equals("X29")) {
                sawSp = true;
            }
            if (o instanceof Scalar) {
                long v = ((Scalar) o).getSignedValue();
                if (Math.abs(v) < 0x10000) {
                    off = v;
                }
            }
        }
        if (sawSp && off != null) {
            return off;
        }
        return null;
    }

    private int guessStoreSize(Instruction ins) {
        // Many architectures encode size in the mnemonic or operand reps.
        String mn = ins.getMnemonicString().toUpperCase();
        if (mn.endsWith("B") || mn.equals("MOVB") || mn.equals("STRB")) return 1;
        if (mn.endsWith("W") || mn.equals("MOVW") || mn.equals("STRH")) return 2;
        // Look at default operand representation for MOV BYTE PTR / WORD PTR / etc.
        String def0 = ins.getDefaultOperandRepresentation(0).toUpperCase();
        if (def0.contains("BYTE")) return 1;
        if (def0.contains("WORD") && !def0.contains("DWORD") && !def0.contains("QWORD"))
            return 2;
        if (def0.contains("DWORD")) return 4;
        if (def0.contains("QWORD")) return 8;
        // Default to length of immediate
        return 4;
    }

    private static List<long[]> collectRuns(TreeMap<Long, Long> bytes) {
        List<long[]> runs = new ArrayList<>();
        long runStart = 0, runEnd = 0;
        boolean inRun = false;
        Long prev = null;
        for (Map.Entry<Long, Long> e : bytes.entrySet()) {
            long off = e.getKey();
            if (!inRun) {
                runStart = runEnd = off;
                inRun = true;
            } else if (prev != null && off == prev + 1) {
                runEnd = off;
            } else {
                runs.add(new long[]{runStart, runEnd});
                runStart = runEnd = off;
            }
            prev = off;
        }
        if (inRun) {
            runs.add(new long[]{runStart, runEnd});
        }
        return runs;
    }

    private static String printableString(byte[] buf) {
        // Trim any leading NULs from the start
        int s = 0;
        while (s < buf.length && buf[s] == 0) s++;
        // String ends at first NUL after start
        int e = s;
        while (e < buf.length && buf[e] != 0) e++;
        if (e - s < 4) return null;
        int printable = 0;
        for (int i = s; i < e; i++) {
            if (isPrintable(buf[i] & 0xFF)) printable++;
        }
        if (printable * 5 < (e - s) * 4) return null; // <80% printable -> reject
        return new String(buf, s, e - s, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static boolean isPrintable(int b) {
        return (b >= 0x20 && b < 0x7F) || b == '\n' || b == '\r' || b == '\t';
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...";
    }
}
