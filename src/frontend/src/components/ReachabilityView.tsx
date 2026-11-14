import { useState } from "react";
import type { ValidatedFinding } from "../lib/validated";
import { pathHops, plural } from "../lib/validated";
import { cweName } from "../lib/remediation";
import type { ReachabilityStatus, ReachabilityVerdict } from "../types";
import { Card, ConfidenceMeter, EmptyState, Icon, PriorityBadge, SeverityBadge } from "./ui";

const GROUPS: { status: ReachabilityStatus; title: string; blurb: string }[] = [
  {
    status: "reachable",
    title: "Reachable",
    blurb: "A confirmed call path connects an entry point to the vulnerable code. Review these first.",
  },
  {
    status: "unknown",
    title: "Unknown",
    blurb: "An ambiguous call blocked the trace. The tool says “can't tell” rather than guessing — worth a quick manual look.",
  },
  {
    status: "unreachable",
    title: "Unreachable",
    blurb: "No caller chain leads to a known entry point (HTTP routes, Django URLs, Celery tasks). Safe to deprioritize, not to ignore.",
  },
];

export function ReachabilityView({ rows, onOpen }: { rows: ValidatedFinding[]; onOpen: (id: string) => void }) {
  const [collapsed, setCollapsed] = useState<Set<ReachabilityStatus>>(new Set(["unreachable"]));
  const analyzed = rows.filter((r) => r.reachability);

  if (analyzed.length === 0) {
    return (
      <EmptyState icon="route" title="No reachability results">
        <p>There are no findings to trace for this scan.</p>
      </EmptyState>
    );
  }

  const count = (s: ReachabilityStatus) => analyzed.filter((r) => r.reachability!.status === s).length;
  const pct = (s: ReachabilityStatus) => (count(s) / analyzed.length) * 100;

  // Attack surface: which entry points actually lead somewhere dangerous.
  const surface = new Map<string, ValidatedFinding[]>();
  for (const r of analyzed) {
    const ep = r.reachability!.status === "reachable" ? r.reachability!.entry_point : null;
    if (ep) surface.set(ep, [...(surface.get(ep) ?? []), r]);
  }
  const surfaceList = [...surface.entries()].sort((a, b) => b[1].length - a[1].length);

  return (
    <div className="reach">
      <div className="reach-top">
        <Card className="reach-summary">
          <div className="big-stat">
            <span className="big-num">{Math.round(pct("reachable"))}%</span>
            <span className="big-label">
              of findings are reachable ({count("reachable")} of {analyzed.length}) — the rest can wait.
            </span>
          </div>
          <div className="stacked" role="img" aria-label="Share of findings by reachability">
            {GROUPS.map((g) => (
              <span key={g.status} className={`stacked-${g.status}`} style={{ width: `${pct(g.status)}%` }} />
            ))}
          </div>
          <div className="legend">
            {GROUPS.map((g) => (
              <span key={g.status}>
                <span className={`legend-dot stacked-${g.status}`} />
                {g.title} <strong>{count(g.status)}</strong>
              </span>
            ))}
          </div>
        </Card>

        <Card title="Attack surface" aside={<span className="muted small">Entry points that lead to a finding</span>} className="surface">
          {surfaceList.length === 0 ? (
            <p className="muted pad">No entry point reaches any finding.</p>
          ) : (
            <ul className="surface-list">
              {surfaceList.map(([ep, list]) => (
                <li key={ep}>
                  <code className="surface-ep">{ep}</code>
                  <span className="surface-n">{plural(list.length, "finding")}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {GROUPS.map((g) => {
        const list = analyzed.filter((r) => r.reachability!.status === g.status);
        if (list.length === 0) return null;
        const isCollapsed = collapsed.has(g.status);
        return (
          <section key={g.status} className={`reach-group reach-group-${g.status}`}>
            <button
              type="button"
              className="reach-group-head"
              aria-expanded={!isCollapsed}
              onClick={() => {
                const next = new Set(collapsed);
                if (isCollapsed) next.delete(g.status);
                else next.add(g.status);
                setCollapsed(next);
              }}
            >
              <Icon name={isCollapsed ? "chevronRight" : "chevronDown"} />
              <span className={`legend-dot stacked-${g.status}`} />
              <span className="reach-group-title">{g.title}</span>
              <span className="tab-count">{list.length}</span>
              <span className="reach-group-blurb">{g.blurb}</span>
            </button>
            {!isCollapsed && (
              <ul className="reach-list">
                {list.map((r) => (
                  <li key={r.id}>
                    <button type="button" className="reach-row" onClick={() => onOpen(r.id)}>
                      <span className="reach-row-main">
                        <span className="reach-row-title">
                          <PriorityBadge tier={r.priority.tier} />
                          {r.finding.cwe[0] ? cweName(r.finding.cwe[0]) : r.finding.message}
                          <SeverityBadge severity={r.severity} />
                        </span>
                        <span className="mono small muted">
                          {r.finding.file_path}:{r.finding.line_start}
                        </span>
                        {r.reachability!.call_path && r.reachability!.call_path.length > 0 ? (
                          <Crumbs reach={r.reachability!} />
                        ) : (
                          <span className="small reach-reason">{r.reachability!.reason}</span>
                        )}
                      </span>
                      <ConfidenceMeter confidence={r.reachability!.confidence} />
                      <Icon name="chevronRight" className="muted" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        );
      })}
    </div>
  );
}

function Crumbs({ reach }: { reach: ReachabilityVerdict }) {
  const { entry, hops } = pathHops(reach);
  return (
    <span className="crumbs">
      {entry && <code className="crumb crumb-entry">{entry}</code>}
      {hops.map((fn, i) => (
        <span key={`${fn}-${i}`} className="crumb-wrap">
          <Icon name="chevronRight" size={11} className="muted" />
          <code className="crumb">{fn}</code>
        </span>
      ))}
    </span>
  );
}
