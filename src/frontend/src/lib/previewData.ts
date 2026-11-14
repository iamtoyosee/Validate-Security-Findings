import type { ExploitabilityVerdict, ScanResponse } from "../types";

// ---------------------------------------------------------------------------
// ILLUSTRATIVE ONLY.
//
// Phase 4/5 (exploitability) isn't built yet. This generates example verdicts so
// the Exploitability UI can be seen and iterated on before the backend exists.
// It's a crude string heuristic over the snippet - NOT analysis - and every screen
// that shows it carries a clear "example data" banner. Delete this file once
// /api/scan returns real `exploitability` verdicts.
// ---------------------------------------------------------------------------

const DYNAMIC_STRING = /(f["']|%\s*\(|%\s*\w|\.format\(|["']\s*\+|\+\s*["'])/;
const PARAMETERIZED = /execute\([^)]*,\s*[([]/;

export function buildPreviewExploitability(result: ScanResponse): ExploitabilityVerdict[] {
  const findings = new Map(result.findings.map((f) => [f.finding_id, f]));

  return result.reachability
    .filter((r) => r.status !== "unreachable")
    .map((r): ExploitabilityVerdict => {
      const f = findings.get(r.finding_id)!;
      const snippet = f.code_snippet ?? "";
      const entry = r.entry_point ?? "an entry point";
      const sink = { file_path: f.file_path, line: f.line_start, description: snippet.trim().slice(0, 90) || f.message };
      const firstHop = r.call_path?.[0];
      const source = firstHop ? { file_path: f.file_path, line: null, description: `Request data handled in ${firstHop}` } : null;

      if (r.status === "unknown") {
        return {
          finding_id: r.finding_id,
          tier: "A",
          status: "inconclusive",
          confidence: "low",
          reason: "Couldn't confirm a path from an entry point, so there's no input to trace to the sink.",
          reasoning_steps: [
            "Reachability returned unknown - an ambiguous call blocks the path.",
            "Without a confirmed entry point there's no attacker input to follow.",
            "Needs a human look at the unresolved call, or better call resolution.",
          ],
          source: null,
          sink,
          sanitizers: [],
          attacker_controlled: null,
        };
      }

      if (PARAMETERIZED.test(snippet)) {
        return {
          finding_id: r.finding_id,
          tier: "A",
          status: "not_exploitable",
          confidence: "medium",
          reason: "Input reaches the call, but it's passed as a bound parameter rather than interpolated.",
          reasoning_steps: [
            `Followed the path from ${entry}.`,
            "The dangerous call receives user data only through its parameters argument.",
            "Parameter binding keeps data out of the query structure.",
          ],
          source,
          sink,
          sanitizers: [{ file_path: f.file_path, line: f.line_start, description: "Parameterized execute()" }],
          attacker_controlled: true,
        };
      }

      if (DYNAMIC_STRING.test(snippet)) {
        return {
          finding_id: r.finding_id,
          tier: "A",
          status: "exploitable",
          confidence: r.confidence === "high" ? "high" : "medium",
          reason: `Request data from ${entry} is interpolated straight into the sink with no sanitization on the path.`,
          reasoning_steps: [
            `Entry point ${entry} reads request input.`,
            `Followed ${r.call_path?.join(" → ") ?? "the call path"} - the value is passed through unchanged.`,
            "The sink builds its argument with string formatting, so input changes its structure.",
            "No validation, escaping or allowlist observed on any hop.",
          ],
          source,
          sink,
          sanitizers: [],
          attacker_controlled: true,
          suggested_fix: "Pass the value as a bound parameter instead of formatting it into the string.",
        };
      }

      return {
        finding_id: r.finding_id,
        tier: "A",
        status: "inconclusive",
        confidence: "low",
        reason: "Reachable, but it isn't clear from the code whether the dangerous argument is attacker-influenced.",
        reasoning_steps: [
          `Followed the path from ${entry}.`,
          "The sink's argument comes from a value the agent couldn't trace back to request input.",
        ],
        source,
        sink,
        sanitizers: [],
        attacker_controlled: null,
      };
    });
}
