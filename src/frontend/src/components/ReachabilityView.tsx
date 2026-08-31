import { useState } from "react";
import type { Finding, ReachabilityVerdict, ScanResponse } from "../types";

function StatusBadge({ status }: { status: string }) {
  return <span className={`badge badge-status-${status}`}>{status}</span>;
}

function ReachabilityDetail({
  finding,
  verdict,
  onClose,
}: {
  finding: Finding;
  verdict: ReachabilityVerdict;
  onClose: () => void;
}) {
  return (
    <div className="finding-detail">
      <button type="button" className="close-button" onClick={onClose}>
        ← Back to list
      </button>
      <h3>
        {finding.file_path}:{finding.line_start}
      </h3>
      <StatusBadge status={verdict.status} />
      <dl>
        <dt>Confidence</dt>
        <dd>{verdict.confidence}</dd>
        <dt>Containing function</dt>
        <dd>{verdict.containing_function ?? "—"}</dd>
        <dt>Entry point</dt>
        <dd>{verdict.entry_point ?? "—"}</dd>
        <dt>Call path</dt>
        <dd>{verdict.call_path ? verdict.call_path.join(" → ") : "—"}</dd>
        <dt>Reason</dt>
        <dd>{verdict.reason}</dd>
      </dl>
      <h4>Underlying finding</h4>
      <dl>
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

export function ReachabilityView({ result }: { result: ScanResponse }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const findingsById = new Map(result.findings.map((f) => [f.finding_id, f]));

  if (selectedId) {
    const finding = findingsById.get(selectedId);
    const verdict = result.reachability.find((v) => v.finding_id === selectedId);
    if (finding && verdict) {
      return <ReachabilityDetail finding={finding} verdict={verdict} onClose={() => setSelectedId(null)} />;
    }
  }

  const total = result.reachability.length;
  const reachableCount = result.reachability.filter((v) => v.status === "reachable").length;
  const reachablePct = total === 0 ? 0 : Math.round((reachableCount / total) * 100);

  return (
    <div className="findings-view">
      {total > 0 && (
        <div className="stat-card">
          <span className="stat-value">{reachablePct}%</span>
          <span className="stat-label">
            of findings are actually reachable ({reachableCount} of {total}) — the rest can wait
          </span>
        </div>
      )}
      <p className="findings-summary">
        {total} finding{total === 1 ? "" : "s"} analyzed, {reachableCount} reachable
      </p>
      {result.reachability.length === 0 ? (
        <p>No findings to analyze.</p>
      ) : (
        <>
          <div className="finding-row finding-row-reachability finding-row-header" aria-hidden="true">
            <span>Location</span>
            <span>Status</span>
            <span>Reason</span>
            <span />
          </div>
          <ul className="findings-list">
            {result.reachability.map((v) => {
              const finding = findingsById.get(v.finding_id);
              if (!finding) return null;
              return (
                <li key={v.finding_id}>
                  <button
                    type="button"
                    className="finding-row finding-row-reachability"
                    onClick={() => setSelectedId(v.finding_id)}
                  >
                    <span className="finding-location">
                      {finding.file_path}:{finding.line_start}
                    </span>
                    <StatusBadge status={v.status} />
                    <span className="finding-message">{v.reason}</span>
                    <span className="finding-chevron" aria-hidden="true">›</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
