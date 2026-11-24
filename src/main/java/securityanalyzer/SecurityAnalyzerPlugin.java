/* ###
 * SecurityAnalyzerPlugin
 *
 * A Ghidra plugin providing combined malware-analysis, vulnerability-discovery,
 * crypto/obfuscation-detection, and finding-documentation features.
 *
 * Designed for Ghidra 12.0.x. All long-running work runs through TaskMonitor
 * so the UI stays responsive on large binaries.
 *
 * Author: Security Analyzer plugin
 * License: Apache 2.0
 */
package securityanalyzer;

import javax.swing.ImageIcon;

import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import securityanalyzer.ui.SecurityAnalyzerProvider;

/**
 * Top-level plugin entry point. Owns the {@link SecurityAnalyzerProvider}
 * (the dockable panel) and registers all menu actions under
 * <code>Tools &rarr; Security Analyzer</code>.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "SecurityAnalyzer",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Security Analysis Suite",
    description = "Combined malware, vulnerability, crypto and de-obfuscation " +
                  "analysis with annotation and reporting. Uses P-code for " +
                  "reliable parameter inspection."
)
//@formatter:on
public class SecurityAnalyzerPlugin extends ProgramPlugin {

    public static final String PLUGIN_NAME = "SecurityAnalyzer";
    public static final String MENU_GROUP = "SecurityAnalyzer";
    public static final String TOP_MENU = "&Security Analyzer";

    private SecurityAnalyzerProvider provider;

    public SecurityAnalyzerPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        provider = new SecurityAnalyzerProvider(this);
        provider.setHelpLocation(new HelpLocation(PLUGIN_NAME, "SecurityAnalyzer"));
        registerActions();
    }

    @Override
    protected void programActivated(Program program) {
        if (provider != null) {
            provider.setProgram(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        if (provider != null) {
            provider.setProgram(null);
        }
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
            provider = null;
        }
        super.dispose();
    }

    /** Returns the plugin's tool — exposed for the provider/actions. */
    public PluginTool getPluginTool() {
        return tool;
    }

    /** Returns the program currently in scope, or null. */
    public Program getActiveProgram() {
        return currentProgram;
    }

    /** Returns the UI provider. */
    public SecurityAnalyzerProvider getProvider() {
        return provider;
    }

    /** Public accessor for the current program location (cursor address). */
    public ghidra.program.util.ProgramLocation getCurrentLocation() {
        return getProgramLocation();
    }

    /** Public accessor for the current program selection. */
    public ghidra.program.util.ProgramSelection getCurrentSelection() {
        return getProgramSelection();
    }

    // ----------------------------------------------------------------
    // Menu actions
    // ----------------------------------------------------------------

    /**
     * Registers all top-level menu items. We use the {@link ActionBuilder}
     * fluent API rather than {@code DockingAction} subclasses to keep this
     * file readable. Heavy lifting is delegated to the provider.
     */
    private void registerActions() {
        ImageIcon icon = null; // could load from /images via Icons.get(...)

        new ActionBuilder("Show Security Analyzer", PLUGIN_NAME)
            .menuPath(TOP_MENU, "Show Panel")
            .menuGroup(MENU_GROUP, "0")
            .helpLocation(new HelpLocation(PLUGIN_NAME, "ShowPanel"))
            .onAction(c -> tool.showComponentProvider(provider, true))
            .buildAndInstall(tool);

        new ActionBuilder("Run All Analyzers", PLUGIN_NAME)
            .menuPath(TOP_MENU, "Run &All Analyzers")
            .menuGroup(MENU_GROUP, "1")
            .helpLocation(new HelpLocation(PLUGIN_NAME, "RunAll"))
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runAllAnalyzers())
            .buildAndInstall(tool);

        new ActionBuilder("Vulnerability Scan", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Vulnerabilities", "Full Scan")
            .menuGroup(MENU_GROUP, "2")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runVulnerabilityScan())
            .buildAndInstall(tool);

        new ActionBuilder("Dangerous Function Calls", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Vulnerabilities", "Dangerous Functions Only")
            .menuGroup(MENU_GROUP, "2")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runDangerousFunctionScan())
            .buildAndInstall(tool);

        new ActionBuilder("Format String Vulns", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Vulnerabilities", "Format Strings Only")
            .menuGroup(MENU_GROUP, "2")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runFormatStringScan())
            .buildAndInstall(tool);

        new ActionBuilder("Integer Overflow Patterns", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Vulnerabilities", "Integer Overflow Only")
            .menuGroup(MENU_GROUP, "2")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runIntegerOverflowScan())
            .buildAndInstall(tool);

        new ActionBuilder("Malware Indicators Scan", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Malware", "Full Scan")
            .menuGroup(MENU_GROUP, "3")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runMalwareScan())
            .buildAndInstall(tool);

        new ActionBuilder("Anti-Analysis Detection", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Malware", "Anti-Debug / Anti-VM")
            .menuGroup(MENU_GROUP, "3")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runAntiAnalysisScan())
            .buildAndInstall(tool);

        new ActionBuilder("Process Injection Patterns", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Malware", "Process Injection")
            .menuGroup(MENU_GROUP, "3")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runProcessInjectionScan())
            .buildAndInstall(tool);

        new ActionBuilder("Persistence Mechanisms", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Malware", "Persistence")
            .menuGroup(MENU_GROUP, "3")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runPersistenceScan())
            .buildAndInstall(tool);

        new ActionBuilder("Crypto Constant Hunt", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Encryption", "Crypto Constants")
            .menuGroup(MENU_GROUP, "4")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runCryptoConstantScan())
            .buildAndInstall(tool);

        new ActionBuilder("XOR Loop Detection", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Encryption", "XOR Loops")
            .menuGroup(MENU_GROUP, "4")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runXorLoopScan())
            .buildAndInstall(tool);

        new ActionBuilder("High Entropy Regions", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Encryption", "Entropy Map")
            .menuGroup(MENU_GROUP, "4")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runEntropyScan())
            .buildAndInstall(tool);

        new ActionBuilder("Stack String Reconstruction", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&De-Obfuscation", "Stack Strings")
            .menuGroup(MENU_GROUP, "5")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runStackStringScan())
            .buildAndInstall(tool);

        new ActionBuilder("Single-Byte XOR Decode (selection)", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&De-Obfuscation", "XOR Decode Selection")
            .menuGroup(MENU_GROUP, "5")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.runXorDecodeSelection())
            .buildAndInstall(tool);

        new ActionBuilder("Mark Finding at Cursor", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Annotation", "Tag Address as Finding")
            .menuGroup(MENU_GROUP, "6")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.tagCurrentAddress())
            .buildAndInstall(tool);

        new ActionBuilder("Clear All Findings", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Annotation", "Clear Findings")
            .menuGroup(MENU_GROUP, "6")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.clearFindings())
            .buildAndInstall(tool);

        new ActionBuilder("Export Markdown Report", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Reporting", "Export Markdown...")
            .menuGroup(MENU_GROUP, "7")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.exportMarkdown())
            .buildAndInstall(tool);

        new ActionBuilder("Export JSON Findings", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Reporting", "Export JSON...")
            .menuGroup(MENU_GROUP, "7")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.exportJson())
            .buildAndInstall(tool);

        new ActionBuilder("Generate PoC Documentation Template", PLUGIN_NAME)
            .menuPath(TOP_MENU, "&Reporting", "Generate PoC Template")
            .menuGroup(MENU_GROUP, "7")
            .enabledWhen(c -> currentProgram != null)
            .onAction(c -> provider.generatePocTemplate())
            .buildAndInstall(tool);
    }
}
