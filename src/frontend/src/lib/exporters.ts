import type { TriageDecision } from "./storage";
import { TRIAGE_LABEL } from "./storage";
import type { ValidatedFinding } from "./validated";
import { EXPLOITABILITY_LABEL, SEVERITY_LABEL, location, shortRule } from "./validated";
import type { HistoryEntry } from "./storage";

type Decisions = Record<string, TriageDecision>;

export type ExportFormat = "sarif" | "csv" | "json" | "markdown";

export const EXPORT_FORMATS: { id: ExportFormat; label: string; hint: string; ext: string; mime: string }[] = [
  { id: "sarif", label: "SARIF 2.1.0", hint: "GitHub code scanning, IDEs", ext: "sarif", mime: "application/sarif+json" },
  { id: "csv", label: "CSV", hint: "Spreadsheets, Jira import", ext: "csv", mime: "text/csv" },
  { id: "markdown", label: "Markdown report", hint: "PR comments, wikis", ext: "md", mime: "text/markdown" },
  { id: "json", label: "JSON", hint: "Raw results + triage", ext: "json", mime: "application/json" },
];

export function exportScan(format: ExportFormat, scan: HistoryEntry, rows: ValidatedFinding[], decisions: Decisions) {
  const spec = EXPORT_FORMATS.find((f) => f.id === format)!;
  const body =
    format === "sarif"
      ? toSarif(rows, decisions)
      : format === "csv"
        ? toCsv(rows, decisions)
        : format === "markdown"
          ? toMarkdown(scan, rows, decisions)
          : toJson(scan, rows, decisions);
  const stamp = scan.startedAt.slice(0, 19).replace(/[:T]/g, "-");
  download(`validated-findings-${slug(scan.target.label)}-${stamp}.${spec.ext}`, body, spec.mime);
}

function download(filename: string, text: string, mime: string) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function slug(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "scan";
}

const triageOf = (d: Decisions, id: string) => d[id]?.state ?? "open";

// ---------------------------------------------------------------------------

function toJson(scan: HistoryEntry, rows: ValidatedFinding[], decisions: Decisions): string {
  return JSON.stringify(
    {
      tool: "validate-security-findings",
      target: scan.target,
      scanned_at: scan.startedAt,
      options: scan.options,
      raw_result_count: scan.result.raw_result_count,
      findings: rows.map((r) => ({
        ...r.finding,
        priority: { tier: r.priority.tier, score: r.priority.score },
        reachability: r.reachability ?? null,
        exploitability: r.exploitability ?? null,
        triage: decisions[r.id] ?? { state: "open", note: "" },
      })),
    },
    null,
    2,
  );
}

function csvCell(v: unknown): string {
  const s = v == null ? "" : String(v);
  // Neutralize spreadsheet formula injection (CWE-1236) as well as quoting.
  const safe = /^\s*[=+\-@]/.test(s) || /^[\t\r]/.test(s) ? `'${s}` : s;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

function toCsv(rows: ValidatedFinding[], decisions: Decisions): string {
  const header = [
    "priority", "score", "severity", "file", "line", "cwe", "rule", "message",
    "reachability", "reachability_confidence", "entry_point", "exploitability", "triage", "triage_note", "finding_id",
  ];
  const lines = rows.map((r) =>
    [
      r.priority.tier,
      r.priority.score,
      SEVERITY_LABEL[r.severity],
      r.finding.file_path,
      r.finding.line_start,
      r.finding.cwe.join(" "),
      r.finding.rule_ids.map(shortRule).join(" "),
      r.finding.message,
      r.reachability?.status ?? "",
      r.reachability?.confidence ?? "",
      r.reachability?.entry_point ?? "",
      EXPLOITABILITY_LABEL[r.exploit],
      TRIAGE_LABEL[triageOf(decisions, r.id)],
      decisions[r.id]?.note ?? "",
      r.id,
    ]
      .map(csvCell)
      .join(","),
  );
  return [header.join(","), ...lines].join("\n");
}

const SARIF_LEVEL = { critical: "error", medium: "warning", low: "note" } as const;

function toSarif(rows: ValidatedFinding[], decisions: Decisions): string {
  const ruleIds = [...new Set(rows.map((r) => r.finding.rule_ids[0]))];
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "validate-security-findings",
            informationUri: "https://github.com/iamtoyosee/Validate-Security-Findings",
            rules: ruleIds.map((id) => {
              const sample = rows.find((r) => r.finding.rule_ids[0] === id)!;
              return {
                id,
                name: shortRule(id),
                shortDescription: { text: sample.finding.message },
                properties: { tags: ["security", ...sample.finding.cwe] },
              };
            }),
          },
        },
        results: rows.map((r) => {
          const state = triageOf(decisions, r.id);
          const suppressed = state === "false_positive" || state === "accepted_risk";
          return {
            ruleId: r.finding.rule_ids[0],
            level: SARIF_LEVEL[r.severity],
            message: { text: r.finding.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: r.finding.file_path },
                  region: {
                    startLine: r.finding.line_start,
                    ...(r.finding.line_end ? { endLine: r.finding.line_end } : {}),
                    ...(r.finding.column_start ? { startColumn: r.finding.column_start } : {}),
                  },
                },
              },
            ],
            // Reachability evidence as a code flow, so viewers can step through it.
            ...(r.reachability?.call_path?.length
              ? {
                  codeFlows: [
                    {
                      message: { text: r.reachability.reason },
                      threadFlows: [
                        {
                          locations: r.reachability.call_path.map((fn) => ({
                            location: { message: { text: fn } },
                          })),
                        },
                      ],
                    },
                  ],
                }
              : {}),
            partialFingerprints: { validatedFindingId: r.id },
            properties: {
              priority: r.priority.tier,
              priorityScore: r.priority.score,
              reachability: r.reachability?.status ?? "not_analyzed",
              exploitability: r.exploit,
              triage: state,
            },
            ...(suppressed
              ? {
                  suppressions: [
                    { kind: "external", status: "accepted", justification: decisions[r.id]?.note || TRIAGE_LABEL[state] },
                  ],
                }
              : {}),
          };
        }),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function toMarkdown(scan: HistoryEntry, rows: ValidatedFinding[], decisions: Decisions): string {
  const reachable = rows.filter((r) => r.reachability?.status === "reachable").length;
  const byTier = (t: string) => rows.filter((r) => r.priority.tier === t).length;
  const md: string[] = [
    `# Validated security findings — ${scan.target.label}`,
    "",
    `Scanned ${new Date(scan.startedAt).toLocaleString()} · ${scan.result.raw_result_count} raw results → ` +
      `${rows.length} distinct findings → ${reachable} reachable`,
    "",
    `| P1 | P2 | P3 | P4 |`,
    `|---|---|---|---|`,
    `| ${byTier("P1")} | ${byTier("P2")} | ${byTier("P3")} | ${byTier("P4")} |`,
    "",
    "## Findings",
    "",
    "| Priority | Severity | Location | Issue | Reachability | Exploitability | Triage |",
    "|---|---|---|---|---|---|---|",
    ...rows.map(
      (r) =>
        `| ${r.priority.tier} | ${SEVERITY_LABEL[r.severity]} | \`${location(r.finding)}\` | ${escapeMd(r.finding.message)} | ` +
        `${r.reachability?.status ?? "—"} | ${EXPLOITABILITY_LABEL[r.exploit]} | ${TRIAGE_LABEL[triageOf(decisions, r.id)]} |`,
    ),
    "",
  ];
  const withPaths = rows.filter((r) => r.reachability?.status === "reachable" && r.reachability.call_path?.length);
  if (withPaths.length) {
    md.push("## Reachability evidence", "");
    for (const r of withPaths) {
      md.push(`- \`${location(r.finding)}\` — ${r.reachability!.entry_point ?? "entry point"}: ${r.reachability!.call_path!.join(" → ")}`);
    }
    md.push("");
  }
  return md.join("\n");
}

function escapeMd(s: string) {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}
