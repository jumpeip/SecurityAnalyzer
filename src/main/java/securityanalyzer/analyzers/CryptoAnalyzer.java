package securityanalyzer.analyzers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import securityanalyzer.findings.Finding;
import securityanalyzer.findings.FindingType;
import securityanalyzer.findings.Severity;
import securityanalyzer.util.PCodeHelper;

/**
 * Cryptography-relevant detectors:
 * <ul>
 *   <li>Search initialized memory for known crypto constants
 *       (AES S-box, SHA-256 round constants, MD5 T-table, etc.).</li>
 *   <li>Find tight loops dominated by XOR operations - candidate decode
 *       routines or stream cipher kernels.</li>
 *   <li>Compute Shannon entropy on each memory block; flag regions whose
 *       entropy is higher than typical compiled data (likely encrypted
 *       config, packed payload, etc.).</li>
 * </ul>
 */
public class CryptoAnalyzer {

    /** Named crypto constants we search for. */
    private static final Map<String, ConstantSignature> SIGNATURES = new HashMap<>();

    static {
        // AES forward S-box, first 16 bytes
        SIGNATURES.put("AES S-Box (forward)",
                new ConstantSignature(new byte[] {
                        (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b,
                        (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
                        (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b,
                        (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76 },
                        Severity.HIGH));

        // AES inverse S-box, first 16 bytes
        SIGNATURES.put("AES S-Box (inverse)",
                new ConstantSignature(new byte[] {
                        (byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5,
                        (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38,
                        (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e,
                        (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb },
                        Severity.HIGH));

        // AES Rcon (round constants), first eight bytes
        SIGNATURES.put("AES Rcon",
                new ConstantSignature(new byte[] {
                        (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08,
                        (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80 },
                        Severity.MEDIUM));

        // SHA-256 H0..H1 (initial hash values)
        SIGNATURES.put("SHA-256 IV",
                new ConstantSignature(new byte[] {
                        (byte)0x6a, (byte)0x09, (byte)0xe6, (byte)0x67,
                        (byte)0xbb, (byte)0x67, (byte)0xae, (byte)0x85 },
                        Severity.HIGH));

        // SHA-256 K[0..1] round constants
        SIGNATURES.put("SHA-256 K[0..1]",
                new ConstantSignature(new byte[] {
                        (byte)0x42, (byte)0x8a, (byte)0x2f, (byte)0x98,
                        (byte)0x71, (byte)0x37, (byte)0x44, (byte)0x91 },
                        Severity.HIGH));

        // SHA-1 IV
        SIGNATURES.put("SHA-1 IV",
                new ConstantSignature(new byte[] {
                        (byte)0x67, (byte)0x45, (byte)0x23, (byte)0x01,
                        (byte)0xef, (byte)0xcd, (byte)0xab, (byte)0x89 },
                        Severity.HIGH));

        // MD5 IV (A,B little-endian)
        SIGNATURES.put("MD5 IV",
                new ConstantSignature(new byte[] {
                        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
                        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef },
                        Severity.HIGH));

        // CRC-32 polynomial table - first table entries
        SIGNATURES.put("CRC-32 table (start)",
                new ConstantSignature(new byte[] {
                        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                        (byte)0x96, (byte)0x30, (byte)0x07, (byte)0x77 },
                        Severity.MEDIUM));

        // TEA / XTEA delta constant: 0x9E3779B9
        SIGNATURES.put("TEA/XTEA delta (LE)",
                new ConstantSignature(new byte[] {
                        (byte)0xb9, (byte)0x79, (byte)0x37, (byte)0x9e },
                        Severity.HIGH));
        SIGNATURES.put("TEA/XTEA delta (BE)",
                new ConstantSignature(new byte[] {
                        (byte)0x9e, (byte)0x37, (byte)0x79, (byte)0xb9 },
                        Severity.HIGH));

        // ChaCha20 / Salsa20 constants ("expand 32-byte k")
        SIGNATURES.put("ChaCha20 'expand 32-byte k'",
                new ConstantSignature("expand 32-byte k".getBytes(), Severity.HIGH));
        SIGNATURES.put("Salsa20 'expand 16-byte k'",
                new ConstantSignature("expand 16-byte k".getBytes(), Severity.HIGH));

        // DES SBox row 1
        SIGNATURES.put("DES Initial Permutation table (start)",
                new ConstantSignature(new byte[] {
                        (byte)0x3a, (byte)0x32, (byte)0x2a, (byte)0x22,
                        (byte)0x1a, (byte)0x12, (byte)0x0a, (byte)0x02 },
                        Severity.MEDIUM));

        // BLAKE2 IV (same as SHA-512 IV first 8 bytes)
        SIGNATURES.put("BLAKE2/SHA-512 IV",
                new ConstantSignature(new byte[] {
                        (byte)0x6a, (byte)0x09, (byte)0xe6, (byte)0x67,
                        (byte)0xf3, (byte)0xbc, (byte)0xc9, (byte)0x08 },
                        Severity.HIGH));
    }

    private static final class ConstantSignature {
        final byte[] bytes;
        final Severity severity;
        ConstantSignature(byte[] b, Severity s) {
            this.bytes = b;
            this.severity = s;
        }
    }

    private final Program program;
    private final PCodeHelper pcode;

    public CryptoAnalyzer(Program program, PCodeHelper helper) {
        this.program = program;
        this.pcode = helper;
    }

    // ------------------------------------------------------------------

    public List<Finding> scanAll(TaskMonitor monitor) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(scanCryptoConstants(monitor));
        findings.addAll(scanXorLoops(monitor));
        findings.addAll(scanEntropy(monitor));
        return findings;
    }

    /**
     * Search every initialized memory block for each known signature.
     */
    public List<Finding> scanCryptoConstants(TaskMonitor monitor) {
        List<Finding> findings = new ArrayList<>();
        Memory mem = program.getMemory();
        monitor.setMessage("Searching memory for crypto constants...");

        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || monitor.isCancelled()) {
                continue;
            }
            byte[] blockBytes;
            try {
                long size = block.getSize();
                if (size > 64 * 1024 * 1024) {
                    // Skip very large blocks; chunk-and-search is left as
                    // an enhancement.
                    continue;
                }
                blockBytes = new byte[(int) size];
                block.getBytes(block.getStart(), blockBytes);
            } catch (MemoryAccessException e) {
                continue;
            }

            for (Map.Entry<String, ConstantSignature> e : SIGNATURES.entrySet()) {
                int idx = indexOf(blockBytes, e.getValue().bytes, 0);
                while (idx != -1 && !monitor.isCancelled()) {
                    Address foundAddr = block.getStart().add(idx);
                    Function containing = program.getFunctionManager()
                            .getFunctionContaining(foundAddr);
                    findings.add(Finding.builder(FindingType.CRYPTO_CONSTANT,
                            e.getValue().severity)
                            .at(foundAddr).in(containing)
                            .title("Crypto constant: " + e.getKey())
                            .describe("Memory at " + foundAddr + " matches the start " +
                                    "of the " + e.getKey() + " table/IV/constant.")
                            .evidence("Block " + block.getName() + " offset 0x" +
                                    Integer.toHexString(idx))
                            .recommend("Inspect surrounding code and data for the full " +
                                    "implementation of " + e.getKey() + ". Mark the " +
                                    "table as data and look for xrefs.")
                            .build());
                    idx = indexOf(blockBytes, e.getValue().bytes, idx + 1);
                }
            }
        }
        return findings;
    }

    /**
     * Find functions whose body is dominated by XOR ops in a tight loop —
     * a classic sign of a custom XOR/stream-cipher decoder.
     *
     * <p>Heuristic: XOR p-code ops divided by total p-code ops, weighted
     * by whether the function contains a back-edge (loop).
     */
    public List<Finding> scanXorLoops(TaskMonitor monitor) {
        List<Finding> findings = new ArrayList<>();
        monitor.setMessage("Looking for XOR-dominated loops...");
        for (Function fn : program.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) {
                break;
            }
            if (fn.isThunk() || fn.isExternal()) {
                continue;
            }

            int xorCount = 0;
            int totalOps = 0;
            boolean hasBackEdge = hasBackEdge(fn);

            for (var op : pcode.getPcodeOps(fn, monitor)) {
                totalOps++;
                int o = op.getOpcode();
                if (o == ghidra.program.model.pcode.PcodeOp.INT_XOR) {
                    xorCount++;
                }
            }
            if (totalOps < 8) {
                continue;
            }
            double ratio = (double) xorCount / totalOps;
            if (ratio >= 0.10 && hasBackEdge) {
                Severity sev = ratio >= 0.20 ? Severity.HIGH : Severity.MEDIUM;
                findings.add(Finding.builder(FindingType.XOR_LOOP, sev)
                        .at(fn.getEntryPoint()).in(fn)
                        .title("XOR-heavy looped function")
                        .describe("Function contains a loop and " + xorCount +
                                " XOR p-code operations out of " + totalOps + " total " +
                                "(" + String.format("%.1f", ratio * 100) +
                                "%). Likely a custom decoder, stream cipher kernel, or " +
                                "checksum routine.")
                        .evidence("XOR ops: " + xorCount + " / " + totalOps +
                                ", back-edge present")
                        .recommend("Decompile and identify the key/IV. Consider running " +
                                "the De-Obfuscation > XOR Decode action over data buffers " +
                                "this function references.")
                        .build());
            }
        }
        return findings;
    }

    /**
     * Compute Shannon entropy of every memory block in 4KiB-aligned windows
     * and flag windows whose entropy exceeds a threshold.
     */
    public List<Finding> scanEntropy(TaskMonitor monitor) {
        return scanEntropy(monitor, 0x1000, 7.4);
    }

    public List<Finding> scanEntropy(TaskMonitor monitor, int windowSize, double threshold) {
        List<Finding> findings = new ArrayList<>();
        Memory mem = program.getMemory();
        monitor.setMessage("Computing block entropy...");
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || monitor.isCancelled()) {
                continue;
            }
            // Skip executable code blocks - high entropy there is normal-ish
            if (block.isExecute()) {
                continue;
            }
            long size = block.getSize();
            if (size < windowSize) {
                continue;
            }
            byte[] buf = new byte[windowSize];
            for (long off = 0; off + windowSize <= size; off += windowSize) {
                if (monitor.isCancelled()) {
                    break;
                }
                Address a = block.getStart().add(off);
                try {
                    block.getBytes(a, buf);
                } catch (MemoryAccessException e) {
                    continue;
                }
                double h = shannonEntropy(buf);
                if (h >= threshold) {
                    findings.add(Finding.builder(FindingType.HIGH_ENTROPY,
                            h >= 7.7 ? Severity.HIGH : Severity.MEDIUM)
                            .at(a).in(null)
                            .title(String.format("High-entropy region (H=%.2f)", h))
                            .describe("A " + windowSize + "-byte window starting at " +
                                    a + " has Shannon entropy " +
                                    String.format("%.3f", h) + ". Typical of encrypted " +
                                    "or compressed data.")
                            .evidence(String.format("entropy=%.3f, window=%d bytes",
                                    h, windowSize))
                            .recommend("If encrypted: locate the decryption routine. " +
                                    "If compressed: identify the algorithm header.")
                            .build());
                }
            }
        }
        return findings;
    }

    // ------------------------------------------------------------------

    private static double shannonEntropy(byte[] buf) {
        int[] hist = new int[256];
        for (byte b : buf) {
            hist[b & 0xFF]++;
        }
        double h = 0.0;
        double n = buf.length;
        for (int c : hist) {
            if (c == 0) continue;
            double p = c / n;
            h -= p * (Math.log(p) / Math.log(2));
        }
        return h;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer: for (int i = from; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private boolean hasBackEdge(Function fn) {
        AddressSetView body = fn.getBody();
        if (body == null) {
            return false;
        }
        InstructionIterator it = program.getListing().getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (ins.getFlowType().isJump()) {
                Address[] flows = ins.getFlows();
                for (Address f : flows) {
                    if (f != null && f.compareTo(ins.getAddress()) <= 0
                            && body.contains(f)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** For UI: returns the set of all addresses a function references. */
    public AddressSet referencedAddresses(Function fn) {
        AddressSet out = new AddressSet();
        if (fn == null) return out;
        AddressIterator it = fn.getBody().getAddresses(true);
        while (it.hasNext()) {
            Address a = it.next();
            for (var r : program.getReferenceManager().getReferencesFrom(a)) {
                out.addRange(r.getToAddress(), r.getToAddress());
            }
        }
        return out;
    }
}
