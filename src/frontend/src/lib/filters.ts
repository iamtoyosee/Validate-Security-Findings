import type { ReachabilityStatus } from "../types";
import type { TriageState } from "./storage";
import { RESOLVED_STATES } from "./storage";
import type { Exploitability, PriorityTier, Severity, ValidatedFinding } from "./validated";

export type TriageView = "active" | "resolved" | "all";

export interface Filters {
  query: string;
  severity: Severity[];
  reach: ReachabilityStatus[];
  exploit: Exploitability[];
  priority: PriorityTier[];
  cwe: string | null;
  file: string | null;
  triage: TriageView;
  onlyNew: boolean;
}

export const EMPTY_FILTERS: Filters = {
  query: "",
  severity: [],
  reach: [],
  exploit: [],
  priority: [],
  cwe: null,
  file: null,
  triage: "active",
  onlyNew: false,
};

export function activeFilterCount(f: Filters): number {
  return (
    (f.query ? 1 : 0) +
    f.severity.length +
    f.reach.length +
    f.exploit.length +
    f.priority.length +
    (f.cwe ? 1 : 0) +
    (f.file ? 1 : 0) +
    (f.onlyNew ? 1 : 0)
  );
}

export function applyFilters(
  rows: ValidatedFinding[],
  f: Filters,
  stateOf: (id: string) => TriageState,
  newIds?: Set<string>,
): ValidatedFinding[] {
  const q = f.query.trim().toLowerCase();
  return rows.filter((r) => {
    const state = stateOf(r.id);
    const resolved = RESOLVED_STATES.includes(state);
    if (f.triage === "active" && resolved) return false;
    if (f.triage === "resolved" && !resolved) return false;
    if (f.severity.length && !f.severity.includes(r.severity)) return false;
    if (f.reach.length && !(r.reachability && f.reach.includes(r.reachability.status))) return false;
    if (f.exploit.length && !f.exploit.includes(r.exploit)) return false;
    if (f.priority.length && !f.priority.includes(r.priority.tier)) return false;
    if (f.cwe && !r.finding.cwe.includes(f.cwe)) return false;
    if (f.file && r.finding.file_path !== f.file) return false;
    if (f.onlyNew && !newIds?.has(r.id)) return false;
    if (q) {
      const hay = [
        r.finding.file_path,
        r.finding.message,
        r.finding.rule_ids.join(" "),
        r.finding.cwe.join(" "),
        r.reachability?.containing_function ?? "",
        r.reachability?.entry_point ?? "",
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

export function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}
