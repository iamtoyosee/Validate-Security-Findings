import type { Filters } from "../lib/filters";
import { EMPTY_FILTERS } from "../lib/filters";
import { cweName } from "../lib/remediation";
import type { ScanDiff, TriageState } from "../lib/storage";
import { RESOLVED_STATES } from "../lib/storage";
import type { ValidatedFinding } from "../lib/validated";
import { SEVERITIES, SEVERITY_LABEL, needsAttention } from "../lib/validated";
import type { ReachabilityStatus } from "../types";
import { Card, EmptyState, Icon, PriorityBadge, ReachBadge, SeverityBadge } from "./ui";

interface Props {
  rows: ValidatedFinding[];
  stateOf: (id: string) => TriageState;
  diff?: ScanDiff;
  onFilter: (f: Filters) => void;
  onOpen: (id: string) => void;
}

const REACH_COLS: ReachabilityStatus[] = ["reachable", "unknown", "unreachable"];

export function OverviewView({ rows, stateOf, diff, onFilter, onOpen }: Props) {
  if (rows.length === 0) {
    return (
      <EmptyState icon="shieldCheck" title="No findings">
        <p>The scanner reported nothing for this codebase. Nothing to validate.</p>
      </EmptyState>
    );
  }

  const open = rows.filter((r) => !RESOLVED_STATES.includes(stateOf(r.id)));
  const focus = open.filter(needsAttention).slice(0, 5);
  const reviewed = rows.filter((r) => stateOf(r.id) !== "open").length;
  const tiers = (["P1", "P2", "P3", "P4"] as const).map((t) => ({ t, n: open.filter((r) => r.priority.tier === t).length }));

  const cweCounts = countBy(rows.flatMap((r) => (r.finding.cwe.length ? r.finding.cwe : ["Uncategorized"])));
  const fileCounts = countBy(rows.map((r) => r.finding.file_path));
  const maxCwe = Math.max(...cweCounts.map(([, n]) => n));
  const maxFile = Math.max(...fileCounts.map(([, n]) => n));

  return (
    <div className="overview">
      <div className="overview-main">
        <Card
          title="Fix these first"
          aside={
            <button type="button" className="link" onClick={() => onFilter({ ...EMPTY_FILTERS, priority: ["P1", "P2"] })}>
              All P1–P2 <Icon name="chevronRight" size={12} />
            </button>
          }
        >
          {focus.length === 0 ? (
            <p className="muted pad">Nothing open needs attention — every remaining finding is unreachable or resolved.</p>
          ) : (
            <ul className="focus">
              {focus.map((r) => (
                <li key={r.id}>
                  <button type="button" className="focus-row" onClick={() => onOpen(r.id)}>
                    <PriorityBadge tier={r.priority.tier} />
                    <span className="focus-text">
                      <span className="focus-title">
                        {r.finding.cwe[0] ? cweName(r.finding.cwe[0]) : r.finding.message}
                        {diff?.newIds.has(r.id) && <span className="new-tag">New</span>}
                      </span>
                      <span className="focus-sub mono">
                        {r.finding.file_path}:{r.finding.line_start}
                        {r.reachability?.entry_point && <span className="focus-entry"> ← {r.reachability.entry_point}</span>}
                      </span>
                    </span>
                    <SeverityBadge severity={r.severity} />
                    <ReachBadge status={r.reachability?.status} />
                    <Icon name="chevronRight" className="muted" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Severity × reachability" aside={<span className="muted small">Click a cell to filter</span>}>
          <table className="matrix">
            <thead>
              <tr>
                <th />
                {REACH_COLS.map((c) => (
                  <th key={c}>
                    <ReachBadge status={c} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SEVERITIES.map((s) => (
                <tr key={s}>
                  <th>
                    <SeverityBadge severity={s} />
                  </th>
                  {REACH_COLS.map((c) => {
                    const n = rows.filter((r) => r.severity === s && r.reachability?.status === c).length;
                    const heat = n === 0 ? 0 : c === "unreachable" ? 1 : s === "critical" && c === "reachable" ? 4 : c === "reachable" || s === "critical" ? 3 : 2;
                    return (
                      <td key={c}>
                        <button
                          type="button"
                          className={`cell heat-${heat}`}
                          disabled={n === 0}
                          onClick={() => onFilter({ ...EMPTY_FILTERS, severity: [s], reach: [c], triage: "all" })}
                          aria-label={`${n} ${SEVERITY_LABEL[s]} ${c} findings`}
                        >
                          {n}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>

      <div className="overview-side">
        <Card title="Open by priority">
          <div className="tiers">
            {tiers.map(({ t, n }) => (
              <button key={t} type="button" className="tier" onClick={() => onFilter({ ...EMPTY_FILTERS, priority: [t] })}>
                <PriorityBadge tier={t} showHint />
                <strong>{n}</strong>
              </button>
            ))}
          </div>
          <div className="progress-line">
            <div className="progress-bar">
              <span style={{ width: `${(reviewed / rows.length) * 100}%` }} />
            </div>
            <span className="muted small">
              {reviewed} of {rows.length} triaged
            </span>
          </div>
          {diff && (diff.newIds.size > 0 || diff.resolvedCount > 0) && (
            <button type="button" className="diff-card" onClick={() => onFilter({ ...EMPTY_FILTERS, onlyNew: true, triage: "all" })} disabled={diff.newIds.size === 0}>
              <span>
                <strong className="diff-new">+{diff.newIds.size}</strong> new
              </span>
              <span>
                <strong className="diff-resolved">−{diff.resolvedCount}</strong> resolved
              </span>
              <span className="muted small">vs. previous scan</span>
            </button>
          )}
        </Card>

        <Card title="Weakness types">
          <ul className="bars">
            {cweCounts.slice(0, 6).map(([cwe, n]) => (
              <li key={cwe}>
                <button type="button" disabled={cwe === "Uncategorized"} onClick={() => onFilter({ ...EMPTY_FILTERS, cwe, triage: "all" })}>
                  <span className="bar-label">
                    <span>{cwe === "Uncategorized" ? cwe : cweName(cwe)}</span>
                    {cwe !== "Uncategorized" && <span className="muted mono small">{cwe}</span>}
                  </span>
                  <span className="bar">
                    <span style={{ width: `${(n / maxCwe) * 100}%` }} />
                  </span>
                  <span className="bar-n">{n}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Hotspot files">
          <ul className="bars">
            {fileCounts.slice(0, 5).map(([file, n]) => (
              <li key={file}>
                <button type="button" onClick={() => onFilter({ ...EMPTY_FILTERS, file, triage: "all" })}>
                  <span className="bar-label mono small">{file}</span>
                  <span className="bar">
                    <span style={{ width: `${(n / maxFile) * 100}%` }} />
                  </span>
                  <span className="bar-n">{n}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}

function countBy(items: string[]): [string, number][] {
  const m = new Map<string, number>();
  for (const i of items) m.set(i, (m.get(i) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

