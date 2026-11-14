// ---------------------------------------------------------------------------
// API contract types.
//
// Everything marked LIVE mirrors what src/api.py returns today. Everything marked
// PROPOSED is optional: the frontend already renders it when present and degrades
// gracefully when absent, so the backend can start returning these fields one at a
// time without a coordinated frontend change. Full contract notes live in
// docs/frontend-feature-roadmap.md.
// ---------------------------------------------------------------------------

/** LIVE - mirrors NormalizedFinding in src/schemas.py, minus `raw`. */
export interface Finding {
  finding_id: string;
  source_scanner: string;
  rule_ids: string[];
  vulnerability_type: string;
  cwe: string[];
  severity: string;
  file_path: string;
  line_start: number;
  line_end: number | null;
  column_start: number | null;
  message: string;
  code_snippet: string | null;
}

export type ReachabilityStatus = "reachable" | "unreachable" | "unknown";
export type Confidence = "high" | "medium" | "low";

/** LIVE - mirrors ReachabilityVerdict in src/schemas.py. */
export interface ReachabilityVerdict {
  finding_id: string;
  status: ReachabilityStatus;
  confidence: Confidence;
  containing_function: string | null;
  entry_point: string | null;
  call_path: string[] | null;
  reason: string;
}

/**
 * PROPOSED - Phase 4/5. Accepts both the placeholder literals already in
 * src/schemas.py and the clearer three-way split the UI is designed around
 * ("is this exploitable? yes / no / can't tell").
 */
export type ExploitabilityStatus =
  | "exploitable"
  | "not_exploitable"
  | "inconclusive"
  // legacy literals from schemas.py, mapped onto the three above for display
  | "confirmed_exploitable"
  | "not_confirmed"
  | "attempted_inconclusive";

export interface CodeLocation {
  file_path: string;
  line: number | null;
  description: string;
}

export interface ExploitabilityVerdict {
  finding_id: string;
  status: ExploitabilityStatus;
  confidence: Confidence;
  reason: string;
  /** "A" = static/LLM reasoning, "B" = sandboxed dynamic confirmation. */
  tier?: "A" | "B";
  /** Ordered reasoning steps the agent took - the inspectable trail. */
  reasoning_steps?: string[];
  /** Where attacker input enters, if the agent found one. */
  source?: CodeLocation | null;
  /** The dangerous call the finding points at. */
  sink?: CodeLocation | null;
  /** Sanitizers / parameterization observed on the path. Empty = none seen. */
  sanitizers?: CodeLocation[];
  attacker_controlled?: boolean | null;
  /** Tier B only: the payload that confirmed it. */
  proof_of_concept?: string | null;
  suggested_fix?: string | null;
  model?: string | null;
  duration_ms?: number | null;
}

/** PROPOSED - Phase 3 taint signal, per finding. */
export interface TaintSignal {
  finding_id: string;
  tainted: boolean | null;
  source_description: string | null;
}

/** PROPOSED - metadata about the run itself. */
export interface ScanMeta {
  scan_id?: string;
  scanners?: { name: string; version?: string; ruleset?: string }[];
  duration_ms?: number;
  file_count?: number;
  line_count?: number;
  /** Stage timings for real (not simulated) progress reporting. */
  stages?: { name: string; duration_ms: number }[];
}

export interface ScanResponse {
  raw_result_count: number;
  findings: Finding[];
  reachability: ReachabilityVerdict[];
  // PROPOSED - all optional
  exploitability?: ExploitabilityVerdict[];
  taint?: TaintSignal[];
  meta?: ScanMeta;
}

export interface SampleApp {
  id: string;
  name: string;
  description: string;
}

/** Sent with every scan. The backend currently ignores it (FastAPI drops unknown
 *  form fields / pydantic drops unknown JSON keys), so this is safe to send now
 *  and becomes meaningful as each option gets wired up server-side. */
export interface ScanOptions {
  scanners: ScannerId[];
  semgrep_ruleset: string;
  analyses: {
    reachability: boolean;
    taint: boolean;
    exploitability_static: boolean;
    exploitability_dynamic: boolean;
  };
  exclude_globs: string[];
}

export type ScannerId = "semgrep" | "bandit" | "codeql" | "import";

/** A file headed for upload, with the relative path kept separately because
 *  drag-and-dropped files don't carry webkitRelativePath. */
export interface UploadEntry {
  path: string;
  file: File;
}
