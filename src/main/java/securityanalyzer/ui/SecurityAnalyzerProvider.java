/* SPDX-License-Identifier: Apache-2.0
 *
 * SecurityAnalyzerProvider
 * ------------------------
 * The dockable UI for the Security Analyzer plugin. Responsibilities:
 *
 *   - Owns the findings table (Severity / Type / Address / Function / Title).
 *   - Bridges menu actions from {@link securityanalyzer.SecurityAnalyzerPlugin}
 *     to the analyzer classes; every long-running scan executes inside a
 *     {@link TaskLauncher}/{@link Task} so it has a real {@link TaskMonitor}
 *     and the user can cancel it.
 *   - Annotates the program when findings arrive (bookmark + pre-comment),
 *     and exposes "Tag Current Address" / "Clear Findings" actions.
 *   - Exports Markdown, JSON, and per-finding writeup templates via
 *     {@link ReportGenerator}.
 *
 * Design notes:
 *   - The provider creates one {@link PCodeHelper} per scan invocation and
 *     closes it via try-with-resources so the underlying DecompInterface is
 *     released promptly. Sharing a single helper across long-lived scans
 *     would keep decompiler resources pinned.
 *   - All Swing mutation happens on the EDT via {@code Swing.runLater}; the
 *     analyzer threads only touch the program through Ghidra's thread-safe
 *     read APIs and post results back when done.
 *   - When findings are added, we open a transaction and write a Bookmark
 *     and an EOL comment so the analyst sees them in the listing without
 *     having to look at our table.
 */
package securityanalyzer.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JToolBar;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;

import docking.WindowPosition;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

import securityanalyzer.SecurityAnalyzerPlugin;
import securityanalyzer.analyzers.CryptoAnalyzer;
import securityanalyzer.analyzers.DeobfuscationAnalyzer;
import securityanalyzer.analyzers.DeobfuscationAnalyzer.DecodedCandidate;
import securityanalyzer.analyzers.MalwareAnalyzer;
import securityanalyzer.analyzers.VulnerabilityAnalyzer;
import securityanalyzer.findings.Finding;
import securityanalyzer.findings.FindingType;
import securityanalyzer.findings.Severity;
import securityanalyzer.util.PCodeHelper;
import securityanalyzer.util.ReportGenerator;

public class SecurityAnalyzerProvider extends ComponentProviderAdapter {

    private static final String BOOKMARK_CATEGORY = "SecurityAnalyzer";
    private static final String COMMENT_PREFIX = "[SecAnalyzer] ";

    private final SecurityAnalyzerPlugin plugin;
    private final PluginTool tool;

    private JPanel mainPanel;
    private FindingsTableModel tableModel;
    private JTable table;
    private JLabel statusLabel;

    private Program currentProgram;
    private final List<Finding> findings = Collections.synchronizedList(new ArrayList<>());

    public SecurityAnalyzerProvider(SecurityAnalyzerPlugin plugin) {
        super(plugin.getTool(), "Security Analyzer", plugin.getName());
        this.plugin = plugin;
        this.tool = plugin.getTool();

        buildPanel();
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setTitle("Security Analyzer");
        setWindowMenuGroup("SecurityAnalyzer");
        setVisible(false);
    }

    /* ----------------------------------------------------------------- */
    /* UI construction                                                   */
    /* ----------------------------------------------------------------- */

    private void buildPanel() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setPreferredSize(new Dimension(900, 320));

        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);

        JButton btnRunAll = new JButton("Run All");
        btnRunAll.setToolTipText("Run every analyzer (vuln + malware + crypto + stack strings)");
        btnRunAll.addActionListener(e -> runAllAnalyzers());

        JButton btnClear = new JButton("Clear");
        btnClear.setToolTipText("Remove all findings (does not undo bookmarks/comments)");
        btnClear.addActionListener(e -> clearFindings());

        JButton btnMd = new JButton("Export MD");
        btnMd.addActionListener(e -> exportMarkdown());

        JButton btnJson = new JButton("Export JSON");
        btnJson.addActionListener(e -> exportJson());

        JButton btnPoc = new JButton("Writeup Template");
        btnPoc.setToolTipText("Generate a vulnerability writeup template for the selected finding");
        btnPoc.addActionListener(e -> generatePocTemplate());

        toolbar.add(btnRunAll);
        toolbar.add(btnClear);
        toolbar.addSeparator();
        toolbar.add(btnMd);
        toolbar.add(btnJson);
        toolbar.add(btnPoc);

        tableModel = new FindingsTableModel();
        table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);

        // Default sort: Severity descending so CRITICAL findings float to top.
        TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);
        sorter.setComparator(0, Comparator.comparingInt(o -> -((Severity) o).ordinal()));
        table.setRowSorter(sorter);

        ListSelectionListener nav = e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            Finding f = tableModel.get(modelRow);
            if (f != null && f.getAddress() != null) {
                GoToService gs = tool.getService(GoToService.class);
                if (gs != null) {
                    gs.goTo(f.getAddress());
                }
            }
        };
        table.getSelectionModel().addListSelectionListener(nav);

        statusLabel = new JLabel(" Ready. Open a program to begin.", SwingConstants.LEFT);

        mainPanel.add(toolbar, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(table), BorderLayout.CENTER);
        mainPanel.add(statusLabel, BorderLayout.SOUTH);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    /* ----------------------------------------------------------------- */
    /* Lifecycle                                                         */
    /* ----------------------------------------------------------------- */

    public void setProgram(Program program) {
        this.currentProgram = program;
        Swing.runLater(() -> {
            if (program == null) {
                statusLabel.setText(" No program loaded.");
            } else {
                statusLabel.setText(" Program: " + program.getName());
            }
        });
    }

    public void dispose() {
        super.removeFromTool();
    }

    private boolean requireProgram() {
        if (currentProgram == null) {
            Msg.showWarn(this, mainPanel, "Security Analyzer",
                "No program is currently open. Activate a program first.");
            return false;
        }
        return true;
    }

    /* ----------------------------------------------------------------- */
    /* Action: show the panel                                            */
    /* ----------------------------------------------------------------- */

    public void show() {
        setVisible(true);
        tool.toFront(this);
    }

    /* ----------------------------------------------------------------- */
    /* Vulnerability scans                                               */
    /* ----------------------------------------------------------------- */

    public void runAllAnalyzers() {
        if (!requireProgram()) {
            return;
        }
        runScan("Run All Analyzers", (program, monitor) -> {
            List<Finding> all = new ArrayList<>();
            try (PCodeHelper helper = new PCodeHelper(program)) {
                monitor.setMessage("Vulnerability scans...");
                all.addAll(new VulnerabilityAnalyzer(program, helper).scanAll(monitor));
                if (monitor.isCancelled()) return all;

                monitor.setMessage("Malware indicator scans...");
                all.addAll(new MalwareAnalyzer(program, helper).scanAll(monitor));
                if (monitor.isCancelled()) return all;

                monitor.setMessage("Crypto / entropy scans...");
                all.addAll(new CryptoAnalyzer(program, helper).scanAll(monitor));
                if (monitor.isCancelled()) return all;

                monitor.setMessage("Stack-string reconstruction...");
                all.addAll(new DeobfuscationAnalyzer(program, helper).scanStackStrings(monitor));
            }
            return all;
        });
    }

    public void runVulnerabilityScan() {
        runScan("Vulnerability Scan", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new VulnerabilityAnalyzer(program, helper).scanAll(monitor);
            }
        });
    }

    public void runDangerousFunctionScan() {
        runScan("Dangerous Function Calls", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new VulnerabilityAnalyzer(program, helper).scanDangerousFunctions(monitor);
            }
        });
    }

    public void runFormatStringScan() {
        runScan("Format String Vulnerabilities", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new VulnerabilityAnalyzer(program, helper).scanFormatStrings(monitor);
            }
        });
    }

    public void runIntegerOverflowScan() {
        runScan("Integer Overflow Patterns", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new VulnerabilityAnalyzer(program, helper).scanIntegerOverflow(monitor);
            }
        });
    }

    /* ----------------------------------------------------------------- */
    /* Malware scans                                                     */
    /* ----------------------------------------------------------------- */

    public void runMalwareScan() {
        runScan("Malware Indicator Scan", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new MalwareAnalyzer(program, helper).scanAll(monitor);
            }
        });
    }

    public void runAntiAnalysisScan() {
        runScan("Anti-Analysis Detection", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                MalwareAnalyzer ma = new MalwareAnalyzer(program, helper);
                List<Finding> out = new ArrayList<>(ma.scanAntiAnalysis(monitor));
                if (!monitor.isCancelled()) {
                    out.addAll(ma.scanCpuidAntiVm(monitor));
                }
                return out;
            }
        });
    }

    public void runProcessInjectionScan() {
        runScan("Process Injection Patterns", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                MalwareAnalyzer ma = new MalwareAnalyzer(program, helper);
                List<Finding> out = new ArrayList<>(ma.scanProcessInjection(monitor));
                if (!monitor.isCancelled()) {
                    out.addAll(ma.scanBehavioralCombinations(monitor));
                }
                return out;
            }
        });
    }

    public void runPersistenceScan() {
        runScan("Persistence Mechanisms", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                MalwareAnalyzer ma = new MalwareAnalyzer(program, helper);
                List<Finding> out = new ArrayList<>(ma.scanPersistence(monitor));
                if (!monitor.isCancelled()) {
                    out.addAll(ma.scanRegistryStrings(monitor));
                }
                return out;
            }
        });
    }

    /* ----------------------------------------------------------------- */
    /* Crypto / encryption                                               */
    /* ----------------------------------------------------------------- */

    public void runCryptoConstantScan() {
        runScan("Crypto Constant Hunt", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new CryptoAnalyzer(program, helper).scanCryptoConstants(monitor);
            }
        });
    }

    public void runXorLoopScan() {
        runScan("XOR Loop Detection", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new CryptoAnalyzer(program, helper).scanXorLoops(monitor);
            }
        });
    }

    public void runEntropyScan() {
        runScan("High Entropy Regions", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new CryptoAnalyzer(program, helper).scanEntropy(monitor);
            }
        });
    }

    /* ----------------------------------------------------------------- */
    /* De-obfuscation                                                    */
    /* ----------------------------------------------------------------- */

    public void runStackStringScan() {
        runScan("Stack String Reconstruction", (program, monitor) -> {
            try (PCodeHelper helper = new PCodeHelper(program)) {
                return new DeobfuscationAnalyzer(program, helper).scanStackStrings(monitor);
            }
        });
    }

    /**
     * Brute-force single-byte XOR over the current listing selection. Operates
     * inline (it's bounded to whatever the analyst highlighted) and pops the
     * top candidates in a dialog so they can pick one to apply as a comment.
     */
    public void runXorDecodeSelection() {
        if (!requireProgram()) {
            return;
        }
        ProgramSelection sel = getCurrentSelection();
        if (sel == null || sel.isEmpty()) {
            Msg.showWarn(this, mainPanel, "XOR Decode",
                "Select a range of bytes in the Listing first.");
            return;
        }
        AddressSetView ranges = sel;
        Address start = ranges.getMinAddress();
        long length = ranges.getNumAddresses();
        if (length <= 0 || length > 4096) {
            Msg.showWarn(this, mainPanel, "XOR Decode",
                "Selection must be between 1 and 4096 bytes.");
            return;
        }

        AtomicReference<List<DecodedCandidate>> ref = new AtomicReference<>();
        TaskLauncher.launchModal("XOR Brute Force", monitor -> {
            try (PCodeHelper helper = new PCodeHelper(currentProgram)) {
                DeobfuscationAnalyzer da = new DeobfuscationAnalyzer(currentProgram, helper);
                ref.set(da.bruteForceSingleByteXor(start, (int) length));
            } catch (Exception ex) {
                Msg.error(this, "XOR brute force failed", ex);
            }
        });

        List<DecodedCandidate> candidates = ref.get();
        if (candidates == null || candidates.isEmpty()) {
            Msg.showInfo(this, mainPanel, "XOR Decode",
                "No printable single-byte XOR keys produced a likely string.");
            return;
        }
        StringBuilder sb = new StringBuilder("Top candidates (printable ratio):\n\n");
        int show = Math.min(8, candidates.size());
        for (int i = 0; i < show; i++) {
            DecodedCandidate c = candidates.get(i);
            sb.append(String.format("key=0x%02X  %.0f%%  \"%s\"%n",
                c.key, c.printableRatio * 100.0, truncate(c.text, 60)));
        }
        DecodedCandidate top = candidates.get(0);
        sb.append("\nApply top result (key=0x")
          .append(String.format("%02X", top.key))
          .append(") as a pre-comment at ").append(start).append("?");
        int ans = JOptionPane.showConfirmDialog(mainPanel, sb.toString(),
            "XOR Decode Candidates", JOptionPane.YES_NO_OPTION);
        if (ans == JOptionPane.YES_OPTION) {
            applyDecodedComment(start, top);
        }
    }

    private void applyDecodedComment(Address at, DecodedCandidate c) {
        Program p = currentProgram;
        int tx = p.startTransaction("Apply XOR decode comment");
        try {
            String existing = p.getListing().getComment(CommentType.PRE, at);
            String line = String.format("%sXOR-decoded (key=0x%02X): \"%s\"",
                COMMENT_PREFIX, c.key, c.text);
            String combined = (existing == null || existing.isEmpty())
                ? line : existing + "\n" + line;
            p.getListing().setComment(at, CommentType.PRE, combined);
            // Bookmark too, so it shows up in the Bookmark Manager view.
            BookmarkManager bm = p.getBookmarkManager();
            bm.setBookmark(at, ghidra.program.model.listing.BookmarkType.NOTE,
                BOOKMARK_CATEGORY, line);
        } finally {
            p.endTransaction(tx, true);
        }
    }

    private ProgramSelection getCurrentSelection() {
        try {
            return plugin.getCurrentSelection();
        } catch (Throwable t) {
            return null;
        }
    }

    /* ----------------------------------------------------------------- */
    /* Annotation                                                        */
    /* ----------------------------------------------------------------- */

    /**
     * Tag the currently navigated address with a user-supplied note, as a
     * {@code FindingType.INFO} entry. This is the "manual finding" path so
     * analysts can drop pins during triage.
     */
    public void tagCurrentAddress() {
        if (!requireProgram()) {
            return;
        }
        Address addr = getCurrentAddress();
        if (addr == null) {
            Msg.showWarn(this, mainPanel, "Tag Address",
                "Place the cursor on an address in the Listing first.");
            return;
        }
        String note = JOptionPane.showInputDialog(mainPanel,
            "Note for " + addr + ":", "Tag Address", JOptionPane.QUESTION_MESSAGE);
        if (note == null || note.isBlank()) {
            return;
        }
        Function fn = currentProgram.getFunctionManager().getFunctionContaining(addr);
        Finding f = Finding.builder(FindingType.INFO, Severity.INFO)
            .at(addr)
            .in(fn)
            .title("Manual tag: " + truncate(note, 60))
            .describe(note)
            .evidence("Manually tagged by analyst.")
            .build();
        addFindings(Collections.singletonList(f));
    }

    private Address getCurrentAddress() {
        try {
            return plugin.getCurrentLocation() != null
                ? plugin.getCurrentLocation().getAddress() : null;
        } catch (Throwable t) {
            return null;
        }
    }

    public void clearFindings() {
        synchronized (findings) {
            findings.clear();
        }
        Swing.runLater(() -> {
            tableModel.fireTableDataChanged();
            statusLabel.setText(" Findings cleared (bookmarks/comments left in place).");
        });
    }

    /* ----------------------------------------------------------------- */
    /* Reporting                                                         */
    /* ----------------------------------------------------------------- */

    public void exportMarkdown() {
        if (!requireProgram() || requireFindings() == null) {
            return;
        }
        File f = chooseSaveFile("Save Markdown report",
            new FileNameExtensionFilter("Markdown (*.md)", "md"), ".md");
        if (f == null) return;
        try (Writer w = Files.newBufferedWriter(f.toPath(), StandardCharsets.UTF_8)) {
            new ReportGenerator(currentProgram).writeMarkdown(w, snapshot());
            Msg.showInfo(this, mainPanel, "Export Markdown", "Wrote: " + f.getAbsolutePath());
        } catch (IOException ioe) {
            Msg.showError(this, mainPanel, "Export Markdown", ioe.getMessage(), ioe);
        }
    }

    public void exportJson() {
        if (!requireProgram() || requireFindings() == null) {
            return;
        }
        File f = chooseSaveFile("Save JSON report",
            new FileNameExtensionFilter("JSON (*.json)", "json"), ".json");
        if (f == null) return;
        try (Writer w = Files.newBufferedWriter(f.toPath(), StandardCharsets.UTF_8)) {
            new ReportGenerator(currentProgram).writeJson(w, snapshot());
            Msg.showInfo(this, mainPanel, "Export JSON", "Wrote: " + f.getAbsolutePath());
        } catch (IOException ioe) {
            Msg.showError(this, mainPanel, "Export JSON", ioe.getMessage(), ioe);
        }
    }

    public void generatePocTemplate() {
        if (!requireProgram()) {
            return;
        }
        int row = table.getSelectedRow();
        if (row < 0) {
            Msg.showWarn(this, mainPanel, "Writeup Template",
                "Select a finding in the table first.");
            return;
        }
        Finding f = tableModel.get(table.convertRowIndexToModel(row));
        if (f == null) {
            return;
        }
        String md = new ReportGenerator(currentProgram).generateWriteupTemplate(f);
        File out = chooseSaveFile("Save vulnerability writeup template",
            new FileNameExtensionFilter("Markdown (*.md)", "md"), ".md");
        if (out == null) return;
        try {
            Files.writeString(out.toPath(), md, StandardCharsets.UTF_8);
            Msg.showInfo(this, mainPanel, "Writeup Template",
                "Wrote: " + out.getAbsolutePath()
                + "\n\nThis is a documentation scaffold (sections to fill in for vendor"
                + "\nreport / CVE filing). It contains no exploit payload.");
        } catch (IOException ioe) {
            Msg.showError(this, mainPanel, "Writeup Template", ioe.getMessage(), ioe);
        }
    }

    private List<Finding> requireFindings() {
        List<Finding> snap = snapshot();
        if (snap.isEmpty()) {
            Msg.showWarn(this, mainPanel, "Export",
                "There are no findings to export. Run a scan first.");
            return null;
        }
        return snap;
    }

    private List<Finding> snapshot() {
        synchronized (findings) {
            return new ArrayList<>(findings);
        }
    }

    private File chooseSaveFile(String title, FileNameExtensionFilter filter, String ext) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.setFileFilter(filter);
        int r = fc.showSaveDialog(mainPanel);
        if (r != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        File f = fc.getSelectedFile();
        if (!f.getName().toLowerCase().endsWith(ext)) {
            f = new File(f.getAbsolutePath() + ext);
        }
        return f;
    }

    /* ----------------------------------------------------------------- */
    /* Scan dispatcher                                                   */
    /* ----------------------------------------------------------------- */

    @FunctionalInterface
    private interface ScanFn {
        List<Finding> run(Program program, TaskMonitor monitor) throws Exception;
    }

    private void runScan(String title, ScanFn fn) {
        if (!requireProgram()) {
            return;
        }
        final Program program = currentProgram;
        Swing.runLater(() -> statusLabel.setText(" Running: " + title + "..."));

        Task task = new Task(title, true, true, false) {
            @Override
            public void run(TaskMonitor monitor) {
                List<Finding> result;
                try {
                    result = fn.run(program, monitor);
                } catch (CancelledException ce) {
                    Swing.runLater(() -> statusLabel.setText(" Cancelled: " + title));
                    return;
                } catch (Exception ex) {
                    Msg.error(SecurityAnalyzerProvider.this, title + " failed", ex);
                    Swing.runLater(() -> statusLabel.setText(" Failed: " + title
                        + " (" + ex.getClass().getSimpleName() + ")"));
                    return;
                }
                if (result == null) {
                    result = Collections.emptyList();
                }
                List<Finding> newOnes = result;
                addFindings(newOnes);
                Swing.runLater(() -> statusLabel.setText(" " + title + ": "
                    + newOnes.size() + " new finding(s). Total: " + findings.size() + "."));
            }
        };
        new TaskLauncher(task, mainPanel);
    }

    /* ----------------------------------------------------------------- */
    /* Adding findings + program annotation                              */
    /* ----------------------------------------------------------------- */

    private void addFindings(List<Finding> newOnes) {
        if (newOnes == null || newOnes.isEmpty()) {
            return;
        }
        synchronized (findings) {
            findings.addAll(newOnes);
        }
        annotateProgram(newOnes);
        Swing.runLater(() -> {
            tableModel.fireTableDataChanged();
            // Auto-show the panel the first time findings arrive.
            if (!isVisible()) {
                setVisible(true);
            }
        });
    }

    private void annotateProgram(List<Finding> newOnes) {
        if (currentProgram == null) {
            return;
        }
        Program p = currentProgram;
        int tx = p.startTransaction("SecurityAnalyzer annotations");
        try {
            BookmarkManager bm = p.getBookmarkManager();
            Listing listing = p.getListing();
            for (Finding f : newOnes) {
                if (f.getAddress() == null) continue;
                String label = f.getSeverity().getLabel() + " / "
                    + f.getType().getDisplayName() + ": " + f.getTitle();
                bm.setBookmark(f.getAddress(),
                    ghidra.program.model.listing.BookmarkType.WARNING,
                    BOOKMARK_CATEGORY, label);

                String existing = listing.getComment(CommentType.EOL, f.getAddress());
                String line = COMMENT_PREFIX + f.getSeverity().getLabel()
                    + " " + f.getType().getDisplayName() + ": " + truncate(f.getTitle(), 100);
                if (existing == null || !existing.contains(line)) {
                    String combined = (existing == null || existing.isEmpty())
                        ? line : existing + "\n" + line;
                    listing.setComment(f.getAddress(), CommentType.EOL, combined);
                }
            }
        } finally {
            p.endTransaction(tx, true);
        }
    }

    /* ----------------------------------------------------------------- */
    /* Misc                                                              */
    /* ----------------------------------------------------------------- */

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 1) + "\u2026";
    }

    /* ----------------------------------------------------------------- */
    /* Findings table model                                              */
    /* ----------------------------------------------------------------- */

    private final class FindingsTableModel extends AbstractTableModel {

        private final String[] columns = { "Severity", "Type", "Address", "Function", "Title" };

        @Override public int getRowCount()    { return findings.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int c) { return columns[c]; }

        @Override
        public Class<?> getColumnClass(int c) {
            if (c == 0) return Severity.class;
            return String.class;
        }

        Finding get(int row) {
            synchronized (findings) {
                return (row >= 0 && row < findings.size()) ? findings.get(row) : null;
            }
        }

        @Override
        public Object getValueAt(int row, int col) {
            Finding f = get(row);
            if (f == null) return "";
            switch (col) {
                case 0: return f.getSeverity();
                case 1: return f.getType().getDisplayName();
                case 2: return f.getAddress() == null ? "" : f.getAddress().toString();
                case 3: return f.getFunctionName();
                case 4: return f.getTitle();
                default: return "";
            }
        }
    }
}
