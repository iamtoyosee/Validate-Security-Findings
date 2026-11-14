import { useCallback, useEffect, useMemo, useState } from "react";
import type { ScanOptions, ScanResponse } from "../types";

// Browser storage is a convenience here, not a database: it can be cleared, it's
// per-browser, and some contexts throw on access. Every read/write is guarded and
// failure just means "nothing saved".

function read<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // quota exceeded / storage disabled - drop silently
  }
}

// ---------------------------------------------------------------------------
// Triage decisions
// ---------------------------------------------------------------------------

export type TriageState = "open" | "confirmed" | "false_positive" | "accepted_risk" | "fixed";

export const TRIAGE_LABEL: Record<TriageState, string> = {
  open: "Needs review",
  confirmed: "Confirmed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed",
};

export const TRIAGE_STATES: TriageState[] = ["open", "confirmed", "false_positive", "accepted_risk", "fixed"];

/** States that mean "an engineer doesn't need to look at this again". */
export const RESOLVED_STATES: TriageState[] = ["false_positive", "accepted_risk", "fixed"];

export interface TriageDecision {
  state: TriageState;
  note: string;
  updatedAt: string;
}

const TRIAGE_KEY = "vsf.triage.v2";

/**
 * Triage decisions, scoped to one scan target. finding_id is hash(scanner, path,
 * line) with no project in it, so two codebases that both have app.py:12 would
 * otherwise share a decision. Stored keys are `${scope}::${finding_id}`; callers
 * only ever see plain finding ids.
 */
export function useTriage(scope: string) {
  const [all, setAll] = useState<Record<string, TriageDecision>>(() => read(TRIAGE_KEY, {}));

  useEffect(() => write(TRIAGE_KEY, all), [all]);

  const prefix = `${scope}::`;
  const decisions = useMemo(() => {
    const out: Record<string, TriageDecision> = {};
    for (const [k, v] of Object.entries(all)) if (k.startsWith(prefix)) out[k.slice(prefix.length)] = v;
    return out;
  }, [all, prefix]);

  const setDecision = useCallback(
    (id: string, patch: Partial<Omit<TriageDecision, "updatedAt">>) => {
      const key = prefix + id;
      setAll((prev) => {
        const current = prev[key] ?? { state: "open" as TriageState, note: "" };
        const next = { ...current, ...patch, updatedAt: new Date().toISOString() };
        const copy = { ...prev };
        if (next.state === "open" && !next.note) delete copy[key];
        else copy[key] = next;
        return copy;
      });
    },
    [prefix],
  );

  const stateOf = useCallback((id: string): TriageState => decisions[id]?.state ?? "open", [decisions]);

  return { decisions, setDecision, stateOf };
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

export interface ScanTarget {
  kind: "sample" | "upload";
  /** Stable key used to compare scans of the same codebase. */
  key: string;
  label: string;
}

export interface HistoryEntry {
  id: string;
  target: ScanTarget;
  startedAt: string;
  durationMs: number;
  options: ScanOptions;
  result: ScanResponse;
}

const HISTORY_KEY = "vsf.history.v1";
const HISTORY_LIMIT = 10;

export function loadHistory(): HistoryEntry[] {
  return read<HistoryEntry[]>(HISTORY_KEY, []);
}

export function saveToHistory(entry: HistoryEntry): HistoryEntry[] {
  const next = [entry, ...loadHistory().filter((e) => e.id !== entry.id)].slice(0, HISTORY_LIMIT);
  write(HISTORY_KEY, next);
  return next;
}

export function clearHistory(): void {
  write(HISTORY_KEY, []);
}

/** The most recent earlier scan of the same target, for new/resolved diffs. */
export function previousScanOf(history: HistoryEntry[], current: HistoryEntry): HistoryEntry | undefined {
  return history.find((e) => e.id !== current.id && e.target.key === current.target.key && e.startedAt < current.startedAt);
}

export interface ScanDiff {
  newIds: Set<string>;
  resolvedCount: number;
  previousAt: string;
}

export function diffScans(current: ScanResponse, previous: HistoryEntry | undefined): ScanDiff | undefined {
  if (!previous) return undefined;
  const before = new Set(previous.result.findings.map((f) => f.finding_id));
  const now = new Set(current.findings.map((f) => f.finding_id));
  return {
    newIds: new Set([...now].filter((id) => !before.has(id))),
    resolvedCount: [...before].filter((id) => !now.has(id)).length,
    previousAt: previous.startedAt,
  };
}
