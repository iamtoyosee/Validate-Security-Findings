import { useState } from "react";
import type { Finding, ScanResponse } from "../types";

// Display labels only - Semgrep's own severity words (ERROR/WARNING/INFO), relabeled
// for a reader who isn't a Semgrep user. The underlying value and badge color are
// unchanged; this only touches what's printed on screen.
const SEVERITY_LABELS: Record<string, string> = {
  ERROR: "Critical",
  WARNING: "Medium",
  INFO: "Low",
};

const SEVERITY_ORDER = ["Critical", "Medium", "Low"];

function severityLabel(severity: string): string {
  return SEVERITY_LABELS[severity.toUpperCase()] ?? severity;
}

function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_ORDER.indexOf(severityLabel(a.severity)) - SEVERITY_ORDER.indexOf(severityLabel(b.severity));
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity.toLowerCase()}`}>{severityLabel(severity)}</span>;
}

function SeverityBreakdown({ findings }: { findings: Finding[] }) {
  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    const label = severityLabel(f.severity);
    acc[label] = (acc[label] ?? 0) + 1;
    return acc;
  }, {});
  return (
    <div className="severity-breakdown">
      {SEVERITY_ORDER.map((label) => (
        <span key={label} className={`severity-chip severity-chip-${label.toLowerCase()}`}>
          <strong>{counts[label] ?? 0}</strong> {label}
        </span>
      ))}
    </div>
  );
}

function FindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <div className="finding-detail">
      <button type="button" className="close-button" onClick={onClose}>
        ← Back to list
      </button>
      <h3>
        {finding.file_path}:{finding.line_start}
      </h3>
      <SeverityBadge severity={finding.severity} />
      <dl>
        <dt>Finding ID</dt>
        <dd>{finding.finding_id}</dd>
        <dt>Scanner</dt>
        <dd>{finding.source_scanner}</dd>
        <dt>Rule IDs</dt>
        <dd>{finding.rule_ids.join(", ")}</dd>
        <dt>Vulnerability type</dt>
        <dd>{finding.vulnerability_type}</dd>
        <dt>CWE</dt>
        <dd>{finding.cwe.join(", ") || "—"}</dd>
        <dt>Location</dt>
        <dd>
          {finding.file_path}:{finding.line_start}
          {finding.line_end && finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}
          {finding.column_start ? ` (col ${finding.column_start})` : ""}
        </dd>
        <dt>Message</dt>
        <dd>{finding.message}</dd>
      </dl>
      {finding.code_snippet && (
        <>
          <h4>Code snippet</h4>
          <pre>{finding.code_snippet}</pre>
        </>
      )}
    </div>
  );
}

export function FindingsView({ result }: { result: ScanResponse }) {
  const [selected, setSelected] = useState<Finding | null>(null);

  if (selected) {
    return <FindingDetail finding={selected} onClose={() => setSelected(null)} />;
  }

  return (
    <div className="findings-view">
      <p className="findings-summary">
        {result.raw_result_count} raw result{result.raw_result_count === 1 ? "" : "s"} grouped into{" "}
        {result.findings.length} distinct finding{result.findings.length === 1 ? "" : "s"}
      </p>
      {result.findings.length > 0 && <SeverityBreakdown findings={result.findings} />}
      {result.findings.length === 0 ? (
        <p>No findings.</p>
      ) : (
        <>
          <div className="finding-row finding-row-findings finding-row-header" aria-hidden="true">
            <span>Location</span>
            <span>Severity</span>
            <span>Message</span>
            <span>CWE</span>
            <span />
          </div>
          <ul className="findings-list">
            {[...result.findings].sort(bySeverity).map((f) => (
              <li key={f.finding_id}>
                <button type="button" className="finding-row finding-row-findings" onClick={() => setSelected(f)}>
                  <span className="finding-location">
                    {f.file_path}:{f.line_start}
                  </span>
                  <SeverityBadge severity={f.severity} />
                  <span className="finding-message">{f.message}</span>
                  <span className="finding-cwe">{f.cwe.join(", ")}</span>
                  <span className="finding-chevron" aria-hidden="true">›</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
