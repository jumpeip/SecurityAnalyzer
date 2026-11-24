package securityanalyzer.findings;

/**
 * Categories of findings the plugin can produce.
 * Each value carries a CWE identifier where applicable, plus a stable
 * machine-readable id used in reports and JSON exports.
 */
public enum FindingType {

    // --- Memory / vulnerability ---
    DANGEROUS_FUNCTION("vuln.dangerous_function", "Dangerous Function Call",
            "CWE-242", Category.VULNERABILITY),
    UNBOUNDED_COPY("vuln.unbounded_copy", "Unbounded Buffer Copy",
            "CWE-120", Category.VULNERABILITY),
    FORMAT_STRING("vuln.format_string", "Tainted Format String",
            "CWE-134", Category.VULNERABILITY),
    INTEGER_OVERFLOW("vuln.int_overflow", "Possible Integer Overflow",
            "CWE-190", Category.VULNERABILITY),
    INTEGER_TRUNCATION("vuln.int_trunc", "Possible Integer Truncation",
            "CWE-197", Category.VULNERABILITY),
    COMMAND_INJECTION("vuln.cmd_inj", "Command Injection Sink",
            "CWE-78", Category.VULNERABILITY),
    USE_AFTER_FREE("vuln.uaf", "Possible Use-After-Free",
            "CWE-416", Category.VULNERABILITY),
    DOUBLE_FREE("vuln.double_free", "Possible Double Free",
            "CWE-415", Category.VULNERABILITY),
    UNINITIALIZED_USE("vuln.uninit", "Uninitialized Variable Use",
            "CWE-457", Category.VULNERABILITY),
    OFF_BY_ONE("vuln.off_by_one", "Possible Off-By-One",
            "CWE-193", Category.VULNERABILITY),

    // --- Malware indicators ---
    ANTI_DEBUG("mw.anti_debug", "Anti-Debug Technique",
            null, Category.MALWARE),
    ANTI_VM("mw.anti_vm", "Anti-VM / Anti-Sandbox",
            null, Category.MALWARE),
    PROCESS_INJECTION("mw.injection", "Process Injection Pattern",
            null, Category.MALWARE),
    PERSISTENCE("mw.persistence", "Persistence Mechanism",
            null, Category.MALWARE),
    NETWORK_C2("mw.network", "Network / C2 Indicator",
            null, Category.MALWARE),
    CREDENTIAL_THEFT("mw.creds", "Credential Access",
            null, Category.MALWARE),
    DEFENSE_EVASION("mw.evasion", "Defense Evasion",
            null, Category.MALWARE),

    // --- Crypto / encoding ---
    CRYPTO_CONSTANT("crypto.constant", "Crypto Algorithm Constant",
            null, Category.CRYPTO),
    XOR_LOOP("crypto.xor_loop", "XOR Decryption Loop",
            null, Category.CRYPTO),
    HIGH_ENTROPY("crypto.entropy", "High-Entropy Region",
            null, Category.CRYPTO),
    CUSTOM_CRYPTO("crypto.custom", "Possible Custom Crypto",
            null, Category.CRYPTO),

    // --- De-obfuscation results ---
    STACK_STRING("deobf.stack_string", "Stack String",
            null, Category.DEOBFUSCATION),
    DECODED_STRING("deobf.decoded", "Decoded String",
            null, Category.DEOBFUSCATION),

    // --- Generic ---
    INFO("info", "Informational", null, Category.INFO);

    public enum Category {
        VULNERABILITY, MALWARE, CRYPTO, DEOBFUSCATION, INFO
    }

    private final String id;
    private final String displayName;
    private final String cwe;
    private final Category category;

    FindingType(String id, String displayName, String cwe, Category category) {
        this.id = id;
        this.displayName = displayName;
        this.cwe = cwe;
        this.category = category;
    }

    public String getId() { return id; }
    public String getDisplayName() { return displayName; }
    public String getCwe() { return cwe; }
    public Category getCategory() { return category; }

    @Override
    public String toString() { return displayName; }
}
