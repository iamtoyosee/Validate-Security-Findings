import { useState } from "react";
import type { Finding, ScanResponse } from "../types";

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>;
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
      {result.findings.length === 0 ? (
        <p>No findings.</p>
      ) : (
        <ul className="findings-list">
          {result.findings.map((f) => (
            <li key={f.finding_id}>
              <button type="button" className="finding-row" onClick={() => setSelected(f)}>
                <span className="finding-location">
                  {f.file_path}:{f.line_start}
                </span>
                <SeverityBadge severity={f.severity} />
                <span className="finding-message">{f.message}</span>
                <span className="finding-cwe">{f.cwe.join(", ")}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
