// Single source of truth for "what's real vs. what's designed but waiting on the
// backend". Every Planned badge in the UI links back to an entry here, and the
// Roadmap panel renders this list, so the frontend never quietly pretends a
// feature works.

export type CapabilityStatus = "live" | "client" | "planned";

export interface Capability {
  id: string;
  name: string;
  area: "Ingest" | "Analysis" | "Triage" | "Reporting";
  status: CapabilityStatus;
  summary: string;
  /** What the backend needs to add for this to be real. Empty for live features. */
  backendWork?: string;
  phase?: string;
}

export const CAPABILITIES: Capability[] = [
  // ---- Ingest ----
  {
    id: "semgrep",
    name: "Semgrep scanning",
    area: "Ingest",
    status: "live",
    summary: "Runs Semgrep (--config=auto) and groups duplicate rule hits per location.",
  },
  {
    id: "upload-preflight",
    name: "Safe upload preflight",
    area: "Ingest",
    status: "client",
    summary:
      "Filters out dependency/VCS folders and non-scannable files, blocks secret-bearing files (.env, keys), " +
      "redacts likely hardcoded credentials, and checks the line limit before anything leaves the browser.",
    backendWork:
      "Mirror the same allowlist + size caps server-side (never trust the client), and reject archives/symlinks.",
  },
  {
    id: "rulesets",
    name: "Ruleset selection",
    area: "Ingest",
    status: "planned",
    summary: "Choose Semgrep rule packs (p/python, p/owasp-top-ten, p/security-audit, p/secrets).",
    backendWork: "Read options.semgrep_ruleset and pass it as --config to run_semgrep().",
    phase: "8",
  },
  {
    id: "bandit",
    name: "Bandit scanner",
    area: "Ingest",
    status: "planned",
    summary: "Second Python scanner; findings at the same location merge with Semgrep's.",
    backendWork:
      "Add a bandit_adapter.from_bandit() producing NormalizedFinding; group across scanners by (path, line).",
    phase: "8",
  },
  {
    id: "codeql",
    name: "CodeQL scanner",
    area: "Ingest",
    status: "planned",
    summary: "Deeper dataflow-based scanning via CodeQL's Python queries.",
    backendWork: "CodeQL CLI database build + SARIF output, normalized through a SARIF adapter.",
    phase: "8",
  },
  {
    id: "import",
    name: "Import existing results",
    area: "Ingest",
    status: "planned",
    summary: "Bring your own SARIF or Semgrep JSON from CI instead of re-scanning.",
    backendWork:
      "POST /api/validate taking { results_file, codebase } - skips run_semgrep(), runs everything after it.",
    phase: "8",
  },
  {
    id: "exclude-globs",
    name: "Path exclusions",
    area: "Ingest",
    status: "client",
    summary: "Glob patterns (e.g. tests/**) dropped before upload.",
    backendWork: "Also honor options.exclude_globs for sample apps / server-side scans.",
  },

  // ---- Analysis ----
  {
    id: "dedup",
    name: "Deduplication",
    area: "Analysis",
    status: "live",
    summary: "Multiple rules at one location collapse into one finding.",
  },
  {
    id: "reachability",
    name: "Reachability",
    area: "Analysis",
    status: "live",
    summary: "Call graph + entry-point detection + backward traversal with call-path evidence.",
  },
  {
    id: "taint",
    name: "Taint signal",
    area: "Analysis",
    status: "planned",
    summary: "Is attacker input actually flowing into the sink, not just reachable by control flow?",
    backendWork: "Return taint: TaintSignal[] (see types.ts) from run_pipeline().",
    phase: "3",
  },
  {
    id: "exploitability-a",
    name: "Exploitability · Tier A (static agent)",
    area: "Analysis",
    status: "planned",
    summary:
      "An agent reads the code along the reachable path and answers: exploitable, not exploitable, or can't tell - with its reasoning shown.",
    backendWork:
      "Return exploitability: ExploitabilityVerdict[] (status, confidence, reason, reasoning_steps, source, sink, sanitizers).",
    phase: "4/5",
  },
  {
    id: "exploitability-b",
    name: "Exploitability · Tier B (sandbox)",
    area: "Analysis",
    status: "planned",
    summary: "Run a bundled fixture app in a sandbox and fire a real payload to confirm. Sample apps only.",
    backendWork: "Tier B verdicts with tier: \"B\" and proof_of_concept set. Never on uploaded code.",
    phase: "4/5",
  },
  {
    id: "real-progress",
    name: "Real scan progress",
    area: "Analysis",
    status: "planned",
    summary: "Stage-by-stage progress instead of elapsed-time estimates.",
    backendWork: "Stream stage events (SSE) or return meta.stages timings.",
  },

  // ---- Triage ----
  {
    id: "priority",
    name: "Priority scoring",
    area: "Triage",
    status: "client",
    summary:
      "P1-P4 from severity × reachability × exploitability, with the score breakdown shown on every finding.",
    backendWork: "Own the score server-side once exploitability lands, so CLI and web agree.",
    phase: "7",
  },
  {
    id: "triage",
    name: "Triage decisions",
    area: "Triage",
    status: "client",
    summary: "Mark findings confirmed / false positive / accepted risk, with notes. Saved in this browser.",
    backendWork: "Persist decisions keyed by finding_id so they follow the codebase, not the browser.",
    phase: "7",
  },
  {
    id: "remediation",
    name: "Remediation guidance",
    area: "Triage",
    status: "client",
    summary: "Fix guidance per CWE with links to MITRE and OWASP.",
  },
  {
    id: "scan-diff",
    name: "Compare with previous scan",
    area: "Triage",
    status: "client",
    summary: "New vs. resolved findings since the last scan of the same target.",
    backendWork: "Diff-aware re-validation on new commits.",
    phase: "9",
  },

  // ---- Reporting ----
  {
    id: "export",
    name: "Export",
    area: "Reporting",
    status: "client",
    summary: "SARIF 2.1.0 (for GitHub code scanning), CSV, JSON, and a Markdown report, triage included.",
  },
  {
    id: "history",
    name: "Scan history",
    area: "Reporting",
    status: "client",
    summary: "Recent scans kept in this browser so you can reopen results without re-scanning.",
  },
];

export const STATUS_LABEL: Record<CapabilityStatus, string> = {
  live: "Live",
  client: "In browser",
  planned: "Planned",
};

export function capability(id: string): Capability | undefined {
  return CAPABILITIES.find((c) => c.id === id);
}
