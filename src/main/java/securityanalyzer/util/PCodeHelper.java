package securityanalyzer.util;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

/**
 * Centralized utilities for P-code based analysis. Maintains a single
 * {@link DecompInterface} per session for performance.
 *
 * <p>P-code is preferred over instruction-level pattern matching because it
 * abstracts over architecture and gives stable arg/return modeling via
 * the high-level (decompiled) function representation.
 */
public class PCodeHelper implements AutoCloseable {

    public static final int DEFAULT_DECOMPILE_TIMEOUT_SEC = 30;

    private final Program program;
    private final DecompInterface decomp;

    public PCodeHelper(Program program) {
        this.program = program;
        this.decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        if (!decomp.openProgram(program)) {
            throw new RuntimeException("Failed to open program in DecompInterface: " +
                    decomp.getLastMessage());
        }
    }

    public Program getProgram() {
        return program;
    }

    public DecompInterface getDecompiler() {
        return decomp;
    }

    /**
     * Decompile a single function (with caching managed internally by the
     * DecompInterface) and return the {@link HighFunction}, or null on failure.
     */
    public HighFunction decompile(Function fn, TaskMonitor monitor) {
        if (fn == null || monitor.isCancelled()) {
            return null;
        }
        DecompileResults res = decomp.decompileFunction(fn, DEFAULT_DECOMPILE_TIMEOUT_SEC, monitor);
        if (res == null || !res.decompileCompleted()) {
            return null;
        }
        return res.getHighFunction();
    }

    /**
     * Iterate every {@link PcodeOpAST} in a function. Returns an empty list if
     * decompilation failed. The list is materialized to allow random-access.
     */
    public List<PcodeOpAST> getPcodeOps(Function fn, TaskMonitor monitor) {
        List<PcodeOpAST> ops = new ArrayList<>();
        HighFunction hf = decompile(fn, monitor);
        if (hf == null) {
            return ops;
        }
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext() && !monitor.isCancelled()) {
            ops.add(it.next());
        }
        return ops;
    }

    /**
     * Resolve a CALL pcode op to the called Function (when statically known).
     * Returns null for indirect calls that cannot be resolved.
     */
    public Function resolveCall(PcodeOp callOp) {
        if (callOp == null) {
            return null;
        }
        int op = callOp.getOpcode();
        if (op != PcodeOp.CALL && op != PcodeOp.CALLIND) {
            return null;
        }
        Varnode target = callOp.getInput(0);
        if (target == null || !target.isAddress() && !target.isConstant()) {
            // CALLIND with non-constant target - try via references
            Address callsite = callOp.getSeqnum().getTarget();
            return resolveByReference(callsite);
        }
        Address dest = target.getAddress();
        if (dest == null) {
            return null;
        }
        Function f = program.getFunctionManager().getFunctionAt(dest);
        if (f != null) {
            return f;
        }
        // Could be a thunk pointer in .got/.idata - resolve via references
        Address callsite = callOp.getSeqnum().getTarget();
        return resolveByReference(callsite);
    }

    /**
     * Fallback when the call target is computed/indirect: walk the
     * outgoing references at the call site and pick the first call ref
     * whose destination has an associated function.
     */
    private Function resolveByReference(Address callsite) {
        if (callsite == null) {
            return null;
        }
        Reference[] refs = program.getReferenceManager().getReferencesFrom(callsite);
        for (Reference r : refs) {
            RefType t = r.getReferenceType();
            if (t.isCall()) {
                Function f = program.getFunctionManager().getFunctionAt(r.getToAddress());
                if (f != null) {
                    return f;
                }
                // Possibly an external thunk
                f = program.getFunctionManager().getReferencedFunction(r.getToAddress());
                if (f != null) {
                    return f;
                }
            }
        }
        return null;
    }

    /**
     * For a CALL op, return the n'th argument varnode (1-based, matching
     * P-code convention where input 0 is the call target).
     */
    public Varnode getArg(PcodeOp callOp, int oneBasedIndex) {
        if (callOp == null) {
            return null;
        }
        if (oneBasedIndex < 1 || oneBasedIndex >= callOp.getNumInputs()) {
            return null;
        }
        return callOp.getInput(oneBasedIndex);
    }

    /**
     * If the varnode resolves to a constant (after walking through copies),
     * return its long value; otherwise null.
     */
    public Long getConstantValue(Varnode vn) {
        if (vn == null) {
            return null;
        }
        Varnode cur = vn;
        for (int i = 0; i < 8 && cur != null; i++) {
            if (cur.isConstant()) {
                return cur.getOffset();
            }
            // Walk through COPY / CAST / INT_ZEXT
            PcodeOp def = cur.getDef();
            if (def == null) {
                return null;
            }
            int op = def.getOpcode();
            if (op == PcodeOp.COPY || op == PcodeOp.CAST ||
                op == PcodeOp.INT_ZEXT || op == PcodeOp.INT_SEXT) {
                cur = def.getInput(0);
            } else {
                return null;
            }
        }
        return null;
    }

    /**
     * If the varnode is a constant pointer to a string (in any defined
     * memory block), return the string. Returns null otherwise.
     */
    public String getStringValue(Varnode vn) {
        Long c = getConstantValue(vn);
        if (c == null) {
            return null;
        }
        try {
            Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(c);
            return readNullTerminatedString(a, 4096);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Read a C-style string of up to maxLen bytes from {@code addr}.
     * Returns null on any read failure or if the address is undefined.
     */
    public String readNullTerminatedString(Address addr, int maxLen) {
        if (addr == null) {
            return null;
        }
        try {
            byte[] buf = new byte[maxLen];
            int n = program.getMemory().getBytes(addr, buf);
            int end = 0;
            while (end < n && buf[end] != 0) {
                end++;
            }
            if (end == 0) {
                return null;
            }
            // Quick printable check
            int printable = 0;
            for (int i = 0; i < end; i++) {
                int b = buf[i] & 0xFF;
                if (b >= 0x20 && b < 0x7F || b == '\n' || b == '\r' || b == '\t') {
                    printable++;
                }
            }
            if (printable * 4 < end * 3) {
                return null; // not predominantly printable
            }
            return new String(buf, 0, end, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns true if the varnode appears to be a "tainted" / non-constant
     * input to the current function — i.e. it ultimately derives from a
     * function parameter, an external read, or other unknown source.
     *
     * <p>Used as a conservative heuristic for taint-style detection: if the
     * argument to {@code printf}'s format slot is tainted, that's a finding.
     */
    public boolean isLikelyTainted(Varnode vn) {
        if (vn == null) {
            return false;
        }
        if (vn.isConstant()) {
            return false;
        }
        // Walk back through definitions; if any input is a parameter or
        // load from non-readonly memory, treat as tainted.
        return isLikelyTaintedRecursive(vn, 16);
    }

    private boolean isLikelyTaintedRecursive(Varnode vn, int depth) {
        if (vn == null || depth <= 0) {
            return true; // give up conservatively
        }
        if (vn.isConstant()) {
            return false;
        }
        if (vn.isInput()) {
            // Function input parameter - definitely tainted from the
            // current function's perspective.
            return true;
        }
        HighVariable hv = vn.getHigh();
        if (hv != null) {
            HighSymbol sym = hv.getSymbol();
            if (sym != null && sym.isParameter()) {
                return true;
            }
        }
        PcodeOp def = vn.getDef();
        if (def == null) {
            return true; // no definition visible -> conservative
        }
        int op = def.getOpcode();
        if (op == PcodeOp.LOAD || op == PcodeOp.CALL || op == PcodeOp.CALLIND) {
            // Loaded from memory or returned from a call - treat as tainted.
            return true;
        }
        // Recurse on inputs
        for (int i = 0; i < def.getNumInputs(); i++) {
            if (isLikelyTaintedRecursive(def.getInput(i), depth - 1)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolve the function name for a varnode that targets a CALL.
     * Tries direct address, then symbol-table lookup at that address.
     */
    public String getCalledName(PcodeOp callOp) {
        Function f = resolveCall(callOp);
        if (f != null) {
            return f.getName();
        }
        // Fall back to symbol at target address
        Varnode tgt = callOp.getInput(0);
        if (tgt != null && (tgt.isAddress() || tgt.isConstant())) {
            try {
                Address a = tgt.getAddress();
                if (a == null && tgt.isConstant()) {
                    a = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(tgt.getOffset());
                }
                if (a != null) {
                    SymbolTable st = program.getSymbolTable();
                    if (st.getPrimarySymbol(a) != null) {
                        return st.getPrimarySymbol(a).getName();
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }
        return null;
    }

    /**
     * Convenience: extract scalar from instruction operand (instruction-level
     * fallback for when full P-code analysis isn't needed).
     */
    public static Long scalarValue(Object opObj) {
        if (opObj instanceof Scalar) {
            return ((Scalar) opObj).getUnsignedValue();
        }
        return null;
    }

    @Override
    public void close() {
        try {
            decomp.dispose();
        } catch (Exception e) {
            // ignore
        }
    }
}
