package securityanalyzer.findings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * One finding produced by an analyzer. Findings are immutable value objects.
 * Build them with {@link Builder}.
 */
public final class Finding {

    private final FindingType type;
    private final Severity severity;
    private final Address address;
    private final Function function;
    private final String title;
    private final String description;
    private final String evidence;
    private final String recommendation;
    private final List<Address> related;
    private final long timestamp;

    private Finding(Builder b) {
        this.type = b.type;
        this.severity = b.severity;
        this.address = b.address;
        this.function = b.function;
        this.title = b.title;
        this.description = b.description;
        this.evidence = b.evidence;
        this.recommendation = b.recommendation;
        this.related = Collections.unmodifiableList(new ArrayList<>(b.related));
        this.timestamp = System.currentTimeMillis();
    }

    public FindingType getType() { return type; }
    public Severity getSeverity() { return severity; }
    public Address getAddress() { return address; }
    public Function getFunction() { return function; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getRecommendation() { return recommendation; }
    public List<Address> getRelated() { return related; }
    public long getTimestamp() { return timestamp; }

    public String getFunctionName() {
        return function != null ? function.getName() : "<no function>";
    }

    @Override
    public String toString() {
        return String.format("[%s][%s] %s @ %s",
                severity.getLabel(), type.getDisplayName(), title,
                address != null ? address.toString() : "?");
    }

    public static Builder builder(FindingType type, Severity severity) {
        return new Builder(type, severity);
    }

    /** Mutable builder. */
    public static final class Builder {
        private final FindingType type;
        private final Severity severity;
        private Address address;
        private Function function;
        private String title = "";
        private String description = "";
        private String evidence = "";
        private String recommendation = "";
        private final List<Address> related = new ArrayList<>();

        private Builder(FindingType t, Severity s) {
            this.type = t;
            this.severity = s;
        }

        public Builder at(Address a) { this.address = a; return this; }
        public Builder in(Function f) { this.function = f; return this; }
        public Builder title(String t) { this.title = t; return this; }
        public Builder describe(String d) { this.description = d; return this; }
        public Builder evidence(String e) { this.evidence = e; return this; }
        public Builder recommend(String r) { this.recommendation = r; return this; }
        public Builder related(Address a) { if (a != null) related.add(a); return this; }
        public Builder related(List<Address> l) { if (l != null) related.addAll(l); return this; }

        public Finding build() {
            if (title == null || title.isEmpty()) {
                title = type.getDisplayName();
            }
            return new Finding(this);
        }
    }
}
