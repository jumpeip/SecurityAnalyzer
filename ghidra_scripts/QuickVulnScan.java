/* SPDX-License-Identifier: Apache-2.0
 *
 * QuickVulnScan.java — standalone Ghidra script counterpart to the
 * SecurityAnalyzer plugin. Useful when you want a one-off scan without
 * loading the GUI panel, or in headless analysis pipelines.
 *
 * Headless invocation example:
 *
 *   $GHIDRA_INSTALL_DIR/support/analyzeHeadless \
 *       /tmp/projects MyProject \
 *       -import sample.exe \
 *       -postScript QuickVulnScan.java \
 *       -scriptPath /path/to/SecurityAnalyzer/ghidra_scripts
 *
 * Output: a Markdown report next to the program named
 *   <programName>-vulns.md
 */

//@author SecurityAnalyzer
//@category SecurityAnalyzer
//@menupath Tools.Security Analyzer.Quick Vulnerability Scan (script)

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import securityanalyzer.analyzers.MalwareAnalyzer;
import securityanalyzer.analyzers.VulnerabilityAnalyzer;
import securityanalyzer.findings.Finding;
import securityanalyzer.util.PCodeHelper;
import securityanalyzer.util.ReportGenerator;

public class QuickVulnScan extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("No program loaded.");
            return;
        }

        List<Finding> findings = new ArrayList<>();

        try (PCodeHelper helper = new PCodeHelper(currentProgram)) {
            println("[*] Running vulnerability scan...");
            VulnerabilityAnalyzer va = new VulnerabilityAnalyzer(currentProgram, helper);
            findings.addAll(va.scanAll(monitor));

            if (monitor.isCancelled()) {
                println("[!] Cancelled.");
                return;
            }

            println("[*] Running malware indicator scan...");
            MalwareAnalyzer ma = new MalwareAnalyzer(currentProgram, helper);
            findings.addAll(ma.scanAll(monitor));
        }

        println("[*] Total findings: " + findings.size());

        // Default report location: alongside the program executable path if we
        // have one, otherwise the user's home directory.
        Path outDir = resolveOutputDir();
        Path outFile = outDir.resolve(currentProgram.getName() + "-vulns.md");

        try (Writer w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            new ReportGenerator(currentProgram).writeMarkdown(w, findings);
        } catch (IOException ioe) {
            printerr("Failed to write report: " + ioe.getMessage());
            throw ioe;
        }

        println("[*] Report written: " + outFile);
    }

    private Path resolveOutputDir() {
        try {
            String exec = currentProgram.getExecutablePath();
            if (exec != null && !exec.isBlank()) {
                Path p = Paths.get(exec).getParent();
                if (p != null && Files.isWritable(p)) {
                    return p;
                }
            }
        } catch (Exception ignored) {
            // fall through to home dir
        }
        return Paths.get(System.getProperty("user.home", "."));
    }
}
