# SecurityAnalyzer — a Ghidra plugin for defensive security analysis

A complex, end-to-end Ghidra plugin that helps reverse engineers triage
binaries for vulnerabilities, identify malware behavior, recover obfuscated
strings and crypto, annotate findings in the program, and generate
documentation suitable for vendor disclosure or CVE filing.

The plugin is **scoped to defensive analysis**. It detects, annotates, and
documents — it does not generate working exploits or weaponized code. See
[Scope and limitations](#scope-and-limitations) at the bottom.

---

## Highlights

- **Five analyzer families**, all P-code based where parameter inspection is involved:
  - `VulnerabilityAnalyzer` — dangerous library calls, format strings, integer
    overflow → allocation patterns, command-injection sinks, double-free /
    use-after-free heuristics
  - `MalwareAnalyzer` — anti-debug / anti-VM API usage, CPUID hypervisor leaf
    detection, process-injection API combinations (e.g. `VirtualAllocEx` +
    `WriteProcessMemory` + `CreateRemoteThread`), persistence registry paths
  - `CryptoAnalyzer` — AES / SHA / MD5 / TEA / ChaCha / Salsa / DES / CRC
    constant signatures, XOR-loop density detection, Shannon-entropy windowed
    scan
  - `DeobfuscationAnalyzer` — stack-string reconstruction (immediate stores
    into stack slots), interactive single-byte XOR brute-force on the current
    selection
  - Manual tagging — drop a labeled finding at the cursor address while triaging
- **Annotation in-program**: every finding writes a Bookmark + EOL comment so
  results show up natively in the listing.
- **Report generation**: Markdown summary, JSON for tooling, and a per-finding
  vulnerability writeup template (sections for description, affected code,
  reproduction, mitigation, references — purely a documentation scaffold).
- **Background tasks with cancellation**: every long-running scan runs through
  Ghidra's `TaskLauncher` so the user gets a progress bar and cancel button.
- **Companion script** for headless use (`ghidra_scripts/QuickVulnScan.java`).

---

## Why P-code?

The plugin uses the decompiler's high-level P-code (via `HighFunction`) for
all argument and dataflow analysis. This is what makes parameter checking
reliable across architectures and calling conventions: instead of pattern
matching `mov rcx, ...` for x64 fastcall and `push ...` for x86 cdecl, the
analyzers ask the decompiler "what is argument N to this call?" and walk the
P-code def-use chain.

That same machinery powers:
- Constant resolution that looks through `COPY`, `CAST`, `INT_ZEXT`, `INT_SEXT`
- Taint heuristics that mark a varnode as analyst-controlled if it traces back
  to a parameter, a memory `LOAD`, or an `INDIRECT` call result
- String resolution from a constant pointer argument

The helper that wraps this is in `securityanalyzer.util.PCodeHelper` — it owns
the `DecompInterface`, is `AutoCloseable`, and is created fresh per scan so
decompiler resources aren't pinned across long sessions.

---

## Build

You need a Ghidra install (tested against 12.0.x and 12.1.x; builds for 12.2) and Gradle 7+ (or the
`gradle` shipped with your Ghidra install).

```bash
cd SecurityAnalyzer
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
```

Or set `GHIDRA_INSTALL_DIR` in your environment first. The build produces a
distributable zip in `dist/`:

```
dist/ghidra_12.2_PUBLIC_<date>_SecurityAnalyzer.zip
```

## Install

1. Open Ghidra (Project window).
2. **File → Install Extensions → "+"** and select the built zip.
3. Restart Ghidra.
4. Open a program in CodeBrowser.
5. **File → Configure → Miscellaneous** and tick `SecurityAnalyzer`.

The new top-level menu **Tools → Security Analyzer** is now available, and the
dockable findings panel can be opened from there.

---

## Menu reference

All actions are under `Tools → Security Analyzer`:

| Submenu | Action | What it does |
|---------|--------|--------------|
| — | Show Panel | Shows / focuses the findings panel |
| — | Run All Analyzers | Vuln + malware + crypto + stack-strings, in one task |
| Vulnerabilities | Vulnerability Scan | Every vuln detector |
| Vulnerabilities | Dangerous Function Calls | `gets`/`strcpy`/`sprintf`/etc + bounded-but-misused (`memcpy` with tainted size) |
| Vulnerabilities | Format String Vulns | `printf`-family with non-constant format argument |
| Vulnerabilities | Integer Overflow Patterns | Tainted arithmetic feeding `malloc`/`HeapAlloc`, plus `SUBPIECE` truncation |
| Malware | Malware Indicators Scan | Every malware detector |
| Malware | Anti-Analysis Detection | API calls + CPUID hypervisor leaf checks |
| Malware | Process Injection Patterns | Single-call indicators + behavioral combos |
| Malware | Persistence Mechanisms | Registry API calls + suspicious Run-key strings in data |
| Encryption | Crypto Constant Hunt | Byte signatures for AES/SHA/MD5/TEA/ChaCha/Salsa/DES/CRC |
| Encryption | XOR Loop Detection | High XOR density + back-edge → likely cipher loop |
| Encryption | High Entropy Regions | 4 KiB Shannon-entropy windowed scan |
| De-Obfuscation | Stack String Reconstruction | Immediate stores into stack slots reassembled into strings |
| De-Obfuscation | XOR Decode Selection | Brute-force single-byte XOR over the current Listing selection |
| Annotation | Tag Current Address | Drop a manual finding at the cursor with a note |
| Annotation | Clear Findings | Empty the findings table (does not undo bookmarks/comments) |
| Reporting | Export Markdown… | Save a Markdown report of all findings |
| Reporting | Export JSON… | Save a JSON report (for downstream tools / dashboards) |
| Reporting | Generate Vulnerability Writeup Template… | Per-finding writeup scaffold |

Findings drop into the panel as a sortable table (Severity / Type / Address
/ Function / Title) — clicking a row navigates the Listing to the address.
Each finding also writes a `WARNING` Bookmark and an EOL comment in the
program (under category `SecurityAnalyzer`), so results survive a reload.

---

## Headless usage

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    /tmp/ghidra-projects MyProject \
    -import sample.exe \
    -postScript QuickVulnScan.java \
    -scriptPath /path/to/SecurityAnalyzer/ghidra_scripts
```

This runs `VulnerabilityAnalyzer.scanAll` + `MalwareAnalyzer.scanAll` and
writes `<programName>-vulns.md` next to the executable (or `$HOME` if the
executable directory isn't writable).

---

## Project layout

```
SecurityAnalyzer/
├── build.gradle
├── extension.properties
├── Module.manifest
├── README.md
├── data/
├── ghidra_scripts/
│   └── QuickVulnScan.java
└── src/main/java/securityanalyzer/
    ├── SecurityAnalyzerPlugin.java
    ├── analyzers/
    │   ├── CryptoAnalyzer.java
    │   ├── DeobfuscationAnalyzer.java
    │   ├── MalwareAnalyzer.java
    │   └── VulnerabilityAnalyzer.java
    ├── findings/
    │   ├── Finding.java
    │   ├── FindingType.java
    │   └── Severity.java
    ├── ui/
    │   └── SecurityAnalyzerProvider.java
    └── util/
        ├── PCodeHelper.java
        └── ReportGenerator.java
```

---

## Scope and limitations

This plugin is for **defensive security work**: triaging samples, finding
bugs to report, and producing documentation. The following are deliberately
**out of scope**:

- No shellcode generation, no payload templates with embedded shellcode.
- No ROP/JOP gadget chain construction or exploit primitive automation.
- No working weaponized PoC code. The "Vulnerability Writeup Template"
  produces a Markdown scaffold (description, affected code, reproduction
  conditions, suggested mitigation, disclosure plan) — what a vendor or CVE
  Numbering Authority needs to triage a report. Reproduction is described in
  terms of "test input X causes condition Y", not a runnable exploit.
- The fuzzing-harness helper (`ReportGenerator.generateHarnessScaffolding`)
  produces an intentionally **incomplete** libFuzzer stub. It is a starting
  point you complete by hand, with the explicit expectation that you compile
  it with sanitizers and run it inside an isolated lab environment.

Detector caveats:

- All detectors are **conservative heuristics**, not proofs. Findings include
  evidence text so an analyst can triage false positives.
- Taint analysis is local (intra-procedural) and treats unknown definitions as
  tainted. This is the safe default for a vulnerability scanner — it
  over-reports rather than missing things — but means you should expect to
  dismiss some findings during review.
- The crypto constant scanner skips memory blocks larger than 64 MiB to keep
  scan time bounded; on huge firmware images you may want to scan blocks
  individually.
- The XOR-loop and entropy scanners are tuned to flag candidates worth
  looking at, not to identify specific algorithms.

---

## License

Apache License 2.0. See SPDX-License-Identifier headers in each source file.
