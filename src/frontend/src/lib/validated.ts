import type {
  ExploitabilityStatus,
  ExploitabilityVerdict,
  Finding,
  ReachabilityVerdict,
  ScanResponse,
  TaintSignal,
} from "../types";

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export type Severity = "critical" | "medium" | "low";

// Semgrep's own words (ERROR/WARNING/INFO) plus the common words other scanners
// use, so Bandit/SARIF findings land in the same three buckets later.
const SEVERITY_MAP: Record<string, Severity> = {
  ERROR: "critical",
  CRITICAL: "critical",
  HIGH: "critical",
  WARNING: "medium",
  MEDIUM: "medium",
  INFO: "low",
  LOW: "low",
  NOTE: "low",
};

export const SEVERITIES: Severity[] = ["critical", "medium", "low"];
export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", medium: "Medium", low: "Low" };

export function normalizeSeverity(raw: string): Severity {
  return SEVERITY_MAP[raw.toUpperCase()] ?? "low";
}

// ---------------------------------------------------------------------------
// Exploitability - collapse legacy + proposed literals into three answers
// ---------------------------------------------------------------------------

export type Exploitability = "exploitable" | "not_exploitable" | "inconclusive" | "not_analyzed";

export const EXPLOITABILITY_LABEL: Record<Exploitability, string> = {
  exploitable: "Exploitable",
  not_exploitable: "Not exploitable",
  inconclusive: "Can't tell",
  not_analyzed: "Not analyzed",
};

export function normalizeExploitability(status: ExploitabilityStatus | undefined): Exploitability {
  switch (status) {
    case "exploitable":
    case "confirmed_exploitable":
      return "exploitable";
    case "not_exploitable":
    case "not_confirmed":
      return "not_exploitable";
    case "inconclusive":
    case "attempted_inconclusive":
      return "inconclusive";
    default:
      return "not_analyzed";
  }
}

// ---------------------------------------------------------------------------
// Priority - interim, client-side. Phase 7 should move this server-side.
// ---------------------------------------------------------------------------

export type PriorityTier = "P1" | "P2" | "P3" | "P4";

export interface PriorityFactor {
  label: string;
  points: number;
}

export interface Priority {
  score: number;
  tier: PriorityTier;
  factors: PriorityFactor[];
}

const SEVERITY_POINTS: Record<Severity, number> = { critical: 35, medium: 20, low: 5 };
const REACH_POINTS: Record<ReachabilityVerdict["status"], number> = { reachable: 40, unknown: 18, unreachable: 0 };
const EXPLOIT_POINTS: Record<Exploitability, number> = {
  exploitable: 25,
  inconclusive: 8,
  not_analyzed: 0,
  not_exploitable: -30,
};
const CONFIDENCE_POINTS = { high: 0, medium: -3, low: -6 } as const;

export function scorePriority(
  severity: Severity,
  reach: ReachabilityVerdict | undefined,
  exploit: Exploitability,
): Priority {
  const factors: PriorityFactor[] = [{ label: `${SEVERITY_LABEL[severity]} severity`, points: SEVERITY_POINTS[severity] }];
  if (reach) {
    factors.push({ label: `Reachability: ${reach.status}`, points: REACH_POINTS[reach.status] });
    // Only discount confidence on a positive claim - a low-confidence "unreachable"
    // shouldn't be rewarded with fewer points than a high-confidence one.
    if (reach.status === "reachable" && CONFIDENCE_POINTS[reach.confidence] !== 0) {
      factors.push({ label: `Reachability confidence: ${reach.confidence}`, points: CONFIDENCE_POINTS[reach.confidence] });
    }
  } else {
    factors.push({ label: "Reachability: not analyzed", points: 18 });
  }
  if (exploit !== "not_analyzed") {
    factors.push({ label: `Exploitability: ${EXPLOITABILITY_LABEL[exploit].toLowerCase()}`, points: EXPLOIT_POINTS[exploit] });
  }
  const score = Math.max(0, Math.min(100, factors.reduce((s, f) => s + f.points, 0)));
  const tier: PriorityTier = score >= 70 ? "P1" : score >= 50 ? "P2" : score >= 25 ? "P3" : "P4";
  return { score, tier, factors };
}

export const PRIORITY_HINT: Record<PriorityTier, string> = {
  P1: "Fix now",
  P2: "Fix soon",
  P3: "Review",
  P4: "Backlog",
};

// ---------------------------------------------------------------------------
// The joined row every view works from
// ---------------------------------------------------------------------------

export interface ValidatedFinding {
  id: string;
  finding: Finding;
  severity: Severity;
  reachability?: ReachabilityVerdict;
  exploitability?: ExploitabilityVerdict;
  exploit: Exploitability;
  taint?: TaintSignal;
  priority: Priority;
  /** Short file-name-only label for dense tables. */
  fileName: string;
}

export function buildValidated(result: ScanResponse): ValidatedFinding[] {
  const reachById = new Map(result.reachability.map((v) => [v.finding_id, v]));
  const exploitById = new Map((result.exploitability ?? []).map((v) => [v.finding_id, v]));
  const taintById = new Map((result.taint ?? []).map((t) => [t.finding_id, t]));

  return result.findings
    .map((finding) => {
      const severity = normalizeSeverity(finding.severity);
      const reachability = reachById.get(finding.finding_id);
      const exploitability = exploitById.get(finding.finding_id);
      const exploit = normalizeExploitability(exploitability?.status);
      return {
        id: finding.finding_id,
        finding,
        severity,
        reachability,
        exploitability,
        exploit,
        taint: taintById.get(finding.finding_id),
        priority: scorePriority(severity, reachability, exploit),
        fileName: finding.file_path.split("/").pop() ?? finding.file_path,
      };
    })
    .sort(byPriority);
}

export function byPriority(a: ValidatedFinding, b: ValidatedFinding): number {
  return (
    b.priority.score - a.priority.score ||
    a.finding.file_path.localeCompare(b.finding.file_path) ||
    a.finding.line_start - b.finding.line_start
  );
}

/** Findings an engineer should actually look at: not ruled out by analysis. */
export function needsAttention(v: ValidatedFinding): boolean {
  if (v.exploit === "not_exploitable") return false;
  return v.reachability?.status !== "unreachable";
}

export function location(f: Finding): string {
  return `${f.file_path}:${f.line_start}`;
}

/** Turn a semgrep rule id like python.lang.security.audit.formatted-sql-query.formatted-sql-query
 *  into "formatted-sql-query" for display. */
export function shortRule(ruleId: string): string {
  const parts = ruleId.split(".");
  return parts[parts.length - 1] ?? ruleId;
}

export function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return `${n} ${n === 1 ? word : pluralWord}`;
}

/**
 * Split a reachability path into (entry label, hops after it). The backend's
 * call_path starts at the entry-point function itself, and entry_point is often
 * that same name (or "GET /x -> fn"), so rendering both would show it twice.
 */
export function pathHops(reach: ReachabilityVerdict): { entry: string | null; hops: string[] } {
  const path = reach.call_path ?? [];
  const first = path[0];
  const entry = reach.entry_point ?? first ?? null;
  const entryIsFirstHop = !!first && (!reach.entry_point || reach.entry_point === first || reach.entry_point.endsWith(first));
  return { entry, hops: entryIsFirstHop ? path.slice(1) : path };
}
