import { useEffect, useMemo, useRef, useState } from "react";
import type { Filters, TriageView } from "../lib/filters";
import { EMPTY_FILTERS, activeFilterCount, applyFilters, toggle } from "../lib/filters";
import { cweName } from "../lib/remediation";
import type { TriageDecision, TriageState } from "../lib/storage";
import { TRIAGE_LABEL } from "../lib/storage";
import type { Exploitability, PriorityTier, Severity, ValidatedFinding } from "../lib/validated";
import { EXPLOITABILITY_LABEL, SEVERITIES, SEVERITY_LABEL, byPriority, shortRule } from "../lib/validated";
import type { ReachabilityStatus } from "../types";
import { EmptyState, ExploitBadge, Icon, PriorityBadge, ReachBadge, SeverityBadge, TriageBadge } from "./ui";

type SortKey = "priority" | "severity" | "location";

interface Props {
  rows: ValidatedFinding[];
  filters: Filters;
  onFilters: (f: Filters) => void;
  stateOf: (id: string) => TriageState;
  decisions: Record<string, TriageDecision>;
  onBulkTriage: (ids: string[], state: TriageState) => void;
  onOpen: (id: string) => void;
  selectedId: string | null;
  newIds?: Set<string>;
  showExploit: boolean;
}

const SEV_RANK: Record<Severity, number> = { critical: 0, medium: 1, low: 2 };

export function FindingsTable({ rows, filters, onFilters, stateOf, decisions, onBulkTriage, onOpen, selectedId, newIds, showExploit }: Props) {
  const [sort, setSort] = useState<SortKey>("priority");
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const searchRef = useRef<HTMLInputElement>(null);

  // "/" focuses search, like most dev tools.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement;
      if (e.key === "/" && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const visible = useMemo(() => {
    const out = applyFilters(rows, filters, stateOf, newIds);
    if (sort === "severity") return [...out].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || byPriority(a, b));
    if (sort === "location")
      return [...out].sort((a, b) => a.finding.file_path.localeCompare(b.finding.file_path) || a.finding.line_start - b.finding.line_start);
    return out;
  }, [rows, filters, stateOf, newIds, sort]);

  const counts = useMemo(() => {
    const all = applyFilters(rows, { ...filters, triage: "all" }, stateOf, newIds);
    const resolved = all.filter((r) => ["false_positive", "accepted_risk", "fixed"].includes(stateOf(r.id))).length;
    return { active: all.length - resolved, resolved, all: all.length };
  }, [rows, filters, stateOf, newIds]);

  const cwes = useMemo(() => [...new Set(rows.flatMap((r) => r.finding.cwe))].sort(), [rows]);
  const set = (patch: Partial<Filters>) => onFilters({ ...filters, ...patch });
  const visibleIds = visible.map((r) => r.id);
  const allChecked = visibleIds.length > 0 && visibleIds.every((id) => checked.has(id));
  const checkedIds = [...checked].filter((id) => visibleIds.includes(id));

  return (
    <div className="findings">
      <div className="toolbar">
        <div className="search">
          <Icon name="search" size={14} />
          <input
            ref={searchRef}
            type="search"
            aria-label="Search findings"
            placeholder="Search file, rule, CWE, function…"
            value={filters.query}
            onChange={(e) => set({ query: e.target.value })}
          />
          <kbd>/</kbd>
        </div>
        <FilterMenu<Severity>
          label="Severity"
          options={SEVERITIES.map((s) => [s, SEVERITY_LABEL[s]])}
          selected={filters.severity}
          onToggle={(v) => set({ severity: toggle(filters.severity, v) })}
        />
        <FilterMenu<ReachabilityStatus>
          label="Reachability"
          options={[
            ["reachable", "Reachable"],
            ["unknown", "Unknown"],
            ["unreachable", "Unreachable"],
          ]}
          selected={filters.reach}
          onToggle={(v) => set({ reach: toggle(filters.reach, v) })}
        />
        {showExploit && (
          <FilterMenu<Exploitability>
            label="Exploitability"
            options={(["exploitable", "inconclusive", "not_exploitable", "not_analyzed"] as const).map((e) => [e, EXPLOITABILITY_LABEL[e]])}
            selected={filters.exploit}
            onToggle={(v) => set({ exploit: toggle(filters.exploit, v) })}
          />
        )}
        <FilterMenu<PriorityTier>
          label="Priority"
          options={(["P1", "P2", "P3", "P4"] as const).map((p) => [p, p])}
          selected={filters.priority}
          onToggle={(v) => set({ priority: toggle(filters.priority, v) })}
        />
        {cwes.length > 1 && (
          <select className="select select-sm" aria-label="Filter by CWE" value={filters.cwe ?? ""} onChange={(e) => set({ cwe: e.target.value || null })}>
            <option value="">All CWEs</option>
            {cwes.map((c) => (
              <option key={c} value={c}>
                {c} · {cweName(c)}
              </option>
            ))}
          </select>
        )}
        <div className="segmented segmented-sm toolbar-right">
          {(["active", "resolved", "all"] as TriageView[]).map((v) => (
            <button key={v} type="button" className={filters.triage === v ? "active" : ""} onClick={() => set({ triage: v })}>
              {v === "active" ? "Open" : v === "resolved" ? "Resolved" : "All"}
              <span className="seg-count">{counts[v]}</span>
            </button>
          ))}
        </div>
      </div>

      {(activeFilterCount(filters) > 0 || filters.file) && (
        <div className="chips">
          {filters.file && <Chip onRemove={() => set({ file: null })}>File: {filters.file}</Chip>}
          {filters.cwe && <Chip onRemove={() => set({ cwe: null })}>{filters.cwe}</Chip>}
          {filters.onlyNew && <Chip onRemove={() => set({ onlyNew: false })}>New since last scan</Chip>}
          {filters.severity.map((s) => (
            <Chip key={s} onRemove={() => set({ severity: toggle(filters.severity, s) })}>{SEVERITY_LABEL[s]}</Chip>
          ))}
          {filters.reach.map((s) => (
            <Chip key={s} onRemove={() => set({ reach: toggle(filters.reach, s) })}>{s}</Chip>
          ))}
          {filters.exploit.map((s) => (
            <Chip key={s} onRemove={() => set({ exploit: toggle(filters.exploit, s) })}>{EXPLOITABILITY_LABEL[s]}</Chip>
          ))}
          {filters.priority.map((s) => (
            <Chip key={s} onRemove={() => set({ priority: toggle(filters.priority, s) })}>{s}</Chip>
          ))}
          <button type="button" className="link" onClick={() => onFilters({ ...EMPTY_FILTERS, triage: filters.triage })}>
            Clear all
          </button>
        </div>
      )}

      {checkedIds.length > 0 && (
        <div className="bulkbar">
          <span>{checkedIds.length} selected</span>
          {(["confirmed", "false_positive", "accepted_risk", "fixed", "open"] as TriageState[]).map((s) => (
            <button
              key={s}
              type="button"
              className="btn btn-sm"
              onClick={() => {
                onBulkTriage(checkedIds, s);
                setChecked(new Set());
              }}
            >
              {s === "open" ? "Reopen" : TRIAGE_LABEL[s]}
            </button>
          ))}
          <button type="button" className="link" onClick={() => setChecked(new Set())}>
            Cancel
          </button>
        </div>
      )}

      {visible.length === 0 ? (
        <EmptyState icon="search" title={rows.length === 0 ? "No findings" : "Nothing matches"}>
          {rows.length === 0 ? (
            <p>The scanner didn't report anything for this codebase.</p>
          ) : filters.triage === "active" && counts.resolved > 0 && counts.active === 0 ? (
            <p>Every matching finding has been triaged. Switch to “Resolved” to review decisions.</p>
          ) : (
            <p>Try removing a filter.</p>
          )}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th className="col-check">
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    checked={allChecked}
                    onChange={() => setChecked(allChecked ? new Set() : new Set(visibleIds))}
                  />
                </th>
                <SortTh label="Priority" k="priority" sort={sort} onSort={setSort} className="col-pri" />
                <SortTh label="Finding" k="location" sort={sort} onSort={setSort} />
                <SortTh label="Severity" k="severity" sort={sort} onSort={setSort} className="col-sev" />
                <th className="col-reach">Reachability</th>
                {showExploit && <th className="col-exploit">Exploitability</th>}
                <th className="col-triage">Triage</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((r) => (
                <tr
                  key={r.id}
                  className={selectedId === r.id ? "selected" : ""}
                  onClick={() => onOpen(r.id)}
                  tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && onOpen(r.id)}
                >
                  <td className="col-check" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${r.finding.file_path}:${r.finding.line_start}`}
                      checked={checked.has(r.id)}
                      onChange={() => {
                        const next = new Set(checked);
                        if (next.has(r.id)) next.delete(r.id);
                        else next.add(r.id);
                        setChecked(next);
                      }}
                    />
                  </td>
                  <td className="col-pri">
                    <PriorityBadge tier={r.priority.tier} />
                  </td>
                  <td>
                    <div className="cell-finding">
                      <span className="cell-title">
                        {r.finding.cwe[0] ? cweName(r.finding.cwe[0]) : shortRule(r.finding.vulnerability_type)}
                        {newIds?.has(r.id) && <span className="new-tag">New</span>}
                        {decisions[r.id]?.note && <span className="note-tag" title={decisions[r.id].note}>Note</span>}
                      </span>
                      <span className="cell-loc">
                        {r.finding.file_path}
                        <span className="muted">:{r.finding.line_start}</span>
                        {r.reachability?.containing_function && (
                          <span className="cell-fn"> in {r.reachability.containing_function}</span>
                        )}
                      </span>
                    </div>
                  </td>
                  <td className="col-sev">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="col-reach">
                    <ReachBadge status={r.reachability?.status} confidence={r.reachability?.confidence} />
                  </td>
                  {showExploit && (
                    <td className="col-exploit">
                      <ExploitBadge status={r.exploit} />
                    </td>
                  )}
                  <td className="col-triage">
                    <TriageBadge state={stateOf(r.id)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SortTh({ label, k, sort, onSort, className }: { label: string; k: SortKey; sort: SortKey; onSort: (k: SortKey) => void; className?: string }) {
  return (
    <th className={className} aria-sort={sort === k ? "ascending" : undefined}>
      <button type="button" className={`th-sort${sort === k ? " on" : ""}`} onClick={() => onSort(k)}>
        {label}
        {sort === k && <Icon name="chevronDown" size={11} />}
      </button>
    </th>
  );
}

function Chip({ children, onRemove }: { children: React.ReactNode; onRemove: () => void }) {
  return (
    <span className="chip">
      {children}
      <button type="button" aria-label="Remove filter" onClick={onRemove}>
        <Icon name="x" size={11} />
      </button>
    </span>
  );
}

function FilterMenu<T extends string>({
  label,
  options,
  selected,
  onToggle,
}: {
  label: string;
  options: (readonly [T, string])[];
  selected: T[];
  onToggle: (v: T) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  return (
    <div className="menu" ref={ref}>
      <button type="button" className={`btn btn-sm${selected.length ? " btn-active" : ""}`} onClick={() => setOpen(!open)} aria-expanded={open}>
        {label}
        {selected.length > 0 && <span className="btn-count">{selected.length}</span>}
        <Icon name="chevronDown" size={11} />
      </button>
      {open && (
        <div className="menu-pop menu-pop-sm">
          {options.map(([value, text]) => (
            <label key={value} className="menu-check">
              <input type="checkbox" checked={selected.includes(value)} onChange={() => onToggle(value)} />
              {text}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
