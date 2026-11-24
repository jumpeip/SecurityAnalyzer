package securityanalyzer.findings;

import java.awt.Color;

/**
 * Severity levels for findings. Colors are used for bookmarks and the
 * findings table. Severity is ordered: HIGHER ordinal = MORE severe.
 */
public enum Severity {
    INFO("Info", new Color(0x33, 0x66, 0xCC)),
    LOW("Low", new Color(0x33, 0x99, 0x33)),
    MEDIUM("Medium", new Color(0xCC, 0x99, 0x00)),
    HIGH("High", new Color(0xCC, 0x33, 0x00)),
    CRITICAL("Critical", new Color(0x99, 0x00, 0x00));

    private final String label;
    private final Color color;

    Severity(String label, Color color) {
        this.label = label;
        this.color = color;
    }

    public String getLabel() {
        return label;
    }

    public Color getColor() {
        return color;
    }

    @Override
    public String toString() {
        return label;
    }
}
