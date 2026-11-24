package securityanalyzer.util;

import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import securityanalyzer.findings.Finding;
import securityanalyzer.findings.FindingType;
import securityanalyzer.findings.Severity;

/**
 * Renders findings in three forms:
 * <ul>
 *   <li>Markdown report (summary + per-finding sections)</li>
 *   <li>JSON export (machine-readable)</li>
 *   <li>Per-finding "writeup template" — a structured Markdown document the
 *       analyst fills in to document the issue for a vendor / bug report.
 *       This is documentation scaffolding, NOT exploit code.</li>
 * </ul>
 */
public class ReportGenerator {

    private final Program program;

    public ReportGenerator(Program program) {
        this.program = program;
    }

    // ------------------------------------------------------------------
    // Markdown
    // ------------------------------------------------------------------

    public void writeMarkdown(Path out, List<Finding> findings) throws IOException {
        try (Writer w = Files.newBufferedWriter(out)) {
            writeMarkdown(w, findings);
        }
    }

    public void writeMarkdown(Writer w, List<Finding> findings) throws IOException {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        w.write("# Security Analyzer Report\n\n");
        w.write("- **Program**: `" + program.getName() + "`\n");
        w.write("- **Executable path**: `" + program.getExecutablePath() + "`\n");
        w.write("- **Architecture**: " + program.getLanguage().getProcessor() + " / " +
                program.getLanguage().getLanguageDescription().getSize() + "-bit\n");
        w.write("- **Generated**: " + fmt.format(new Date()) + "\n\n");

        // Summary by severity
        Map<Severity, Integer> bySev = new LinkedHashMap<>();
        for (Severity s : Severity.values()) bySev.put(s, 0);
        for (Finding f : findings) bySev.merge(f.getSeverity(), 1, Integer::sum);

        w.write("## Summary\n\n");
        w.write("| Severity | Count |\n");
        w.write("|----------|-------|\n");
        for (Map.Entry<Severity, Integer> e : bySev.entrySet()) {
            w.write("| " + e.getKey().getLabel() + " | " + e.getValue() + " |\n");
        }
        w.write("| **Total** | **" + findings.size() + "** |\n\n");

        // Summary by category
        Map<FindingType.Category, Integer> byCat = new LinkedHashMap<>();
        for (FindingType.Category c : FindingType.Category.values()) byCat.put(c, 0);
        for (Finding f : findings) byCat.merge(f.getType().getCategory(), 1, Integer::sum);
        w.write("## By Category\n\n");
        w.write("| Category | Count |\n|----------|-------|\n");
        for (Map.Entry<FindingType.Category, Integer> e : byCat.entrySet()) {
            w.write("| " + e.getKey().name() + " | " + e.getValue() + " |\n");
        }
        w.write("\n");

        // Sort by severity (desc) then address
        List<Finding> sorted = new java.util.ArrayList<>(findings);
        sorted.sort(Comparator
                .comparingInt((Finding f) -> -f.getSeverity().ordinal())
                .thenComparing(f -> f.getAddress() == null ? "" : f.getAddress().toString()));

        w.write("## Findings\n\n");
        int idx = 1;
        for (Finding f : sorted) {
            w.write("### " + idx + ". [" + f.getSeverity().getLabel() + "] " +
                    escape(f.getTitle()) + "\n\n");
            w.write("- **Type**: " + f.getType().getDisplayName());
            if (f.getType().getCwe() != null) {
                w.write(" (" + f.getType().getCwe() + ")");
            }
            w.write("\n");
            if (f.getAddress() != null) {
                w.write("- **Address**: `" + f.getAddress() + "`\n");
            }
            if (f.getFunction() != null) {
                w.write("- **Function**: `" + f.getFunctionName() + "`");
                Address ep = f.getFunction().getEntryPoint();
                if (ep != null) w.write(" @ `" + ep + "`");
                w.write("\n");
            }
            if (!f.getRelated().isEmpty()) {
                w.write("- **Related addresses**: ");
                boolean first = true;
                for (Address a : f.getRelated()) {
                    if (!first) w.write(", ");
                    w.write("`" + a + "`");
                    first = false;
                }
                w.write("\n");
            }
            w.write("\n");
            if (f.getDescription() != null && !f.getDescription().isEmpty()) {
                w.write("**Description**\n\n" + escape(f.getDescription()) + "\n\n");
            }
            if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
                w.write("**Evidence**\n\n```\n" + f.getEvidence() + "\n```\n\n");
            }
            if (f.getRecommendation() != null && !f.getRecommendation().isEmpty()) {
                w.write("**Recommendation**\n\n" + escape(f.getRecommendation()) + "\n\n");
            }
            w.write("---\n\n");
            idx++;
        }
    }

    // ------------------------------------------------------------------
    // JSON (no external dep — minimal serializer)
    // ------------------------------------------------------------------

    public void writeJson(Path out, List<Finding> findings) throws IOException {
        try (Writer w = Files.newBufferedWriter(out)) {
            writeJson(w, findings);
        }
    }

    public void writeJson(Writer w, List<Finding> findings) throws IOException {
        w.write("{\n");
        w.write("  \"program\": " + jstr(program.getName()) + ",\n");
        w.write("  \"executable_path\": " + jstr(program.getExecutablePath()) + ",\n");
        w.write("  \"architecture\": " + jstr(program.getLanguage().getProcessor().toString()) + ",\n");
        w.write("  \"generated_at\": " + System.currentTimeMillis() + ",\n");
        w.write("  \"findings\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            w.write("    {\n");
            w.write("      \"type\": " + jstr(f.getType().getId()) + ",\n");
            w.write("      \"display_name\": " + jstr(f.getType().getDisplayName()) + ",\n");
            w.write("      \"category\": " + jstr(f.getType().getCategory().name()) + ",\n");
            if (f.getType().getCwe() != null) {
                w.write("      \"cwe\": " + jstr(f.getType().getCwe()) + ",\n");
            }
            w.write("      \"severity\": " + jstr(f.getSeverity().getLabel()) + ",\n");
            w.write("      \"address\": " + jstr(f.getAddress() == null ? null : f.getAddress().toString()) + ",\n");
            w.write("      \"function\": " + jstr(f.getFunction() == null ? null : f.getFunction().getName()) + ",\n");
            w.write("      \"title\": " + jstr(f.getTitle()) + ",\n");
            w.write("      \"description\": " + jstr(f.getDescription()) + ",\n");
            w.write("      \"evidence\": " + jstr(f.getEvidence()) + ",\n");
            w.write("      \"recommendation\": " + jstr(f.getRecommendation()) + ",\n");
            w.write("      \"related\": [");
            for (int j = 0; j < f.getRelated().size(); j++) {
                if (j > 0) w.write(", ");
                w.write(jstr(f.getRelated().get(j).toString()));
            }
            w.write("],\n");
            w.write("      \"timestamp\": " + f.getTimestamp() + "\n");
            w.write("    }" + (i + 1 < findings.size() ? "," : "") + "\n");
        }
        w.write("  ]\n");
        w.write("}\n");
    }

    // ------------------------------------------------------------------
    // PoC documentation template
    //
    // This generates a STRUCTURED MARKDOWN WRITE-UP TEMPLATE that the
    // analyst fills in. It produces no exploit code, no shellcode, no
    // payload generation — purely a writeup skeleton suitable for
    // attaching to a CVE request, vendor report, or internal tracker.
    // ------------------------------------------------------------------

    public String generateWriteupTemplate(Finding f) {
        StringBuilder sb = new StringBuilder();
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
        String today = fmt.format(new Date());

        sb.append("# Vulnerability Write-up: ").append(safe(f.getTitle())).append("\n\n");
        sb.append("> Fill in each section. Sections marked TODO should be completed by the analyst.\n\n");

        sb.append("## Metadata\n\n");
        sb.append("| Field | Value |\n|-------|-------|\n");
        sb.append("| Date | ").append(today).append(" |\n");
        sb.append("| Reporter | _TODO_ |\n");
        sb.append("| Product | ").append(safe(program.getName())).append(" |\n");
        sb.append("| Build / version analyzed | _TODO (file hash, version string)_ |\n");
        sb.append("| Architecture | ").append(program.getLanguage().getProcessor()).append(" |\n");
        sb.append("| Severity (analyst rating) | ").append(f.getSeverity().getLabel()).append(" |\n");
        sb.append("| Category | ").append(f.getType().getDisplayName());
        if (f.getType().getCwe() != null) sb.append(" (").append(f.getType().getCwe()).append(")");
        sb.append(" |\n\n");

        sb.append("## Summary\n\n");
        sb.append(safe(f.getDescription())).append("\n\n");

        sb.append("## Affected Code\n\n");
        if (f.getFunction() != null) {
            sb.append("- Function: `").append(f.getFunction().getName()).append("`\n");
            Address ep = f.getFunction().getEntryPoint();
            if (ep != null) sb.append("- Entry point: `").append(ep).append("`\n");
        }
        if (f.getAddress() != null) {
            sb.append("- Site: `").append(f.getAddress()).append("`\n");
        }
        sb.append("\n_TODO: paste the relevant decompiled snippet from Ghidra here._\n\n");
        sb.append("```c\n// paste decompiled function or excerpt here\n```\n\n");

        sb.append("## Detection Evidence\n\n");
        sb.append("```\n").append(safe(f.getEvidence())).append("\n```\n\n");

        sb.append("## Reachability\n\n");
        sb.append("_TODO: describe how an external input can reach this code path._\n\n");
        sb.append("- Input source (file format / network protocol / IPC channel): _TODO_\n");
        sb.append("- Required preconditions: _TODO_\n");
        sb.append("- Authentication required? _TODO_\n\n");

        sb.append("## Trigger Conditions\n\n");
        sb.append("_TODO: minimum set of conditions under which the bug fires._\n\n");
        sb.append("- Field/parameter that must be controlled: _TODO_\n");
        sb.append("- Boundary value that triggers the issue: _TODO_\n\n");

        sb.append("## Reproduction\n\n");
        sb.append("_TODO: describe how to reproduce the crash/misbehaviour in a controlled lab environment.\n");
        sb.append("Reference the test input by hash; do not embed live payloads in this document._\n\n");
        sb.append("1. Set up: _TODO (OS, compiler, sanitizer flags, debugger)_\n");
        sb.append("2. Input: _TODO (path to repro file, hash)_\n");
        sb.append("3. Observed behaviour: _TODO (crash address, register state, ASan/UBSan output)_\n\n");

        sb.append("## Impact\n\n");
        sb.append("_TODO: classify the impact (information disclosure, denial of service, ");
        sb.append("memory corruption, etc.) and any factors that constrain or amplify it._\n\n");

        sb.append("## Suggested Mitigation\n\n");
        sb.append(safe(f.getRecommendation())).append("\n\n");

        sb.append("## Disclosure Plan\n\n");
        sb.append("_TODO: vendor contact, disclosure timeline, embargo, CVE ID if assigned._\n\n");

        sb.append("## References\n\n");
        if (f.getType().getCwe() != null) {
            sb.append("- CWE: https://cwe.mitre.org/data/definitions/")
              .append(f.getType().getCwe().replace("CWE-", ""))
              .append(".html\n");
        }
        sb.append("- _TODO: vendor advisory, related CVEs, prior art._\n");

        return sb.toString();
    }

    /**
     * Generate a fuzzing-harness scaffolding stub for a function. The stub is
     * incomplete by design — the analyst supplies the actual input mutation
     * strategy and integration into a fuzzer (libFuzzer / AFL++). It is
     * intended to be used in the analyst's own controlled lab.
     */
    public String generateHarnessScaffolding(Function fn) {
        StringBuilder sb = new StringBuilder();
        String fname = fn.getName().replaceAll("[^A-Za-z0-9_]", "_");
        sb.append("// Fuzz harness scaffolding for ").append(fn.getName()).append("\n");
        sb.append("// Address: ").append(fn.getEntryPoint()).append("\n");
        sb.append("// Generated by Security Analyzer plugin.\n\n");
        sb.append("// ------------------------------------------------------------\n");
        sb.append("// IMPORTANT: This is scaffolding only. You must:\n");
        sb.append("//   1. Provide the correct function signature.\n");
        sb.append("//   2. Marshal data from fuzzer input into arguments.\n");
        sb.append("//   3. Compile with sanitizers (ASan/UBSan/MSan) in your lab.\n");
        sb.append("//   4. Run inside isolated infrastructure only.\n");
        sb.append("// ------------------------------------------------------------\n\n");
        sb.append("#include <stddef.h>\n");
        sb.append("#include <stdint.h>\n");
        sb.append("#include <string.h>\n\n");
        sb.append("/* TODO: replace with the real function signature. */\n");
        sb.append("extern int ").append(fname).append("(const void *data, size_t len);\n\n");
        sb.append("// libFuzzer entry point\n");
        sb.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n");
        sb.append("    if (size < 1 || size > (1 << 20)) return 0;\n");
        sb.append("    /* TODO: split `data` into the structured arguments expected\n");
        sb.append("       by the target function. The split shown is a placeholder. */\n");
        sb.append("    ").append(fname).append("(data, size);\n");
        sb.append("    return 0;\n");
        sb.append("}\n");
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("`", "\\`");
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String jstr(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
