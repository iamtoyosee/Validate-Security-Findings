# Frontend feature roadmap & backend contract

The frontend was redesigned so the whole product is visible, including the parts the
backend doesn't do yet. This doc lists every feature, where it runs today, and the exact
shape the backend needs to return to make each planned one real. Read it as a menu of
what to build next.

The same list ships in the app itself: **Roadmap** in the top bar opens it, and every
`PLANNED` tag in the UI links there. The source of truth is
[`src/frontend/src/lib/capabilities.ts`](../src/frontend/src/lib/capabilities.ts). Update
an entry's `status` there when its backend half lands.

## Status legend

| Tag | Meaning |
|---|---|
| **Live** | Backed by the server today. |
| **In browser** | Works today, computed or stored client-side. Fine for the demo, but some of these should move server-side eventually (noted below). |
| **Planned** | The UI is designed and wired, but the backend doesn't provide it yet. It's shown disabled or as an empty state, never faked. The one exception is exploitability's *"Preview with example verdicts"* button, which is clearly bannered as example data. |

## Feature inventory

### Ingest

| Feature | Status | Notes |
|---|---|---|
| Semgrep scan (`--config=auto`) | Live | Unchanged. |
| Bundled sample apps | Live | Now *select, then Run*, so scan settings are visible before scanning. |
| **Upload preflight** | In browser | See [Upload safety](#upload-safety). |
| Path exclusions (globs) | In browser | Applied before upload. Sent as `options.exclude_globs`. |
| Drag-and-drop folders | In browser | Uses the File System Entries API and doesn't descend into `node_modules` etc. |
| Ruleset picker | Planned | `options.semgrep_ruleset` |
| Bandit / CodeQL | Planned | `options.scanners` |
| Import existing SARIF / Semgrep JSON | Planned | New endpoint |

### Analysis

| Feature | Status | Notes |
|---|---|---|
| Dedup | Live | |
| Reachability | Live | Now has its own view: % reachable, **attack surface** (entry points → findings), grouped reachable / unknown / unreachable lists with call-path breadcrumbs. |
| Taint signal (Phase 3) | Planned | `taint: TaintSignal[]` |
| Exploitability Tier A (Phase 4/5) | Planned | `exploitability: ExploitabilityVerdict[]` — the full UI exists |
| Exploitability Tier B sandbox | Planned | Same field, `tier: "B"`, sample apps only |
| Real progress | Planned | Stage timings or SSE |

### Triage

| Feature | Status | Notes |
|---|---|---|
| Priority (P1–P4) | In browser | Severity × reachability × exploitability, score breakdown shown on every finding ("Why P1?"). Should move server-side in Phase 7 so the CLI and the web app agree. |
| Triage decisions + notes | In browser | Needs review / Confirmed / False positive / Accepted risk / Fixed. Bulk actions. Stored in `localStorage`, scoped per scan target, because `finding_id` doesn't include the project, so `app.py:12` in two codebases would otherwise share a decision. Worth folding a project id into `finding_id` server-side. |
| Remediation guidance | In browser | Static per-CWE guidance + OWASP/MITRE links (`lib/remediation.ts`). |
| New vs. resolved since last scan | In browser | Compares `finding_id`s with the previous scan of the same target in history. |
| Findings table | In browser | Search (`/`), filters (severity, reachability, exploitability, priority, CWE, file), Open/Resolved/All, sort, bulk triage, keyboard nav in the drawer (`j`/`k`, `Esc`). |

### Reporting

| Feature | Status | Notes |
|---|---|---|
| Export SARIF 2.1.0 | In browser | Reachability path → `codeFlows`; false positive / accepted risk → `suppressions`. Uploads cleanly to GitHub code scanning. |
| Export CSV / JSON / Markdown | In browser | CSV neutralizes spreadsheet formula injection. |
| Scan history | In browser | Last 10 scans, reopen without re-scanning. |

## Suggested backend order

Ranked by how much each unlocks in the UI for the effort.

1. **Exploitability Tier A** — the biggest gap; the whole tab, the funnel's last step, the drawer section, and priority scoring are waiting on it.
2. **Server-side upload checks** — mirror the preflight (see below). Small, and it closes a real hole, because the client checks can be bypassed with curl.
3. **Context lines in `code_snippet`** — return ±3 lines plus a `snippet_start_line`. The drawer's code view is ready for it, and it makes triage much faster.
4. **`options.semgrep_ruleset`** — about one line in `run_semgrep()`.
5. **Taint signal** — feeds Tier A and adds a column.
6. **Import results endpoint** — lets CI-run scans skip `run_semgrep()`.
7. **Bandit adapter** — exercises the multi-scanner grouping.
8. **Persist triage server-side** (Phase 7) and **move priority server-side**.

## Request contract

Both scan endpoints now receive an `options` object. The backend ignores it today
(FastAPI drops undeclared form fields, and pydantic drops unknown JSON keys), so nothing
breaks. Read it when you're ready:

```jsonc
// POST /api/scan          -> multipart: files[] + options (JSON string field)
// POST /api/scan-sample   -> { "sample_id": "...", "options": { ... } }
{
  "scanners": ["semgrep"],                 // "semgrep" | "bandit" | "codeql" | "import"
  "semgrep_ruleset": "auto",               // "auto" | "p/python" | "p/owasp-top-ten" | "p/security-audit" | "p/secrets"
  "analyses": {
    "reachability": true,
    "taint": false,
    "exploitability_static": false,
    "exploitability_dynamic": false
  },
  "exclude_globs": ["tests/**"]
}
```

FastAPI side, when you wire it up:

```python
@app.post("/api/scan")
async def scan(files: list[UploadFile], options: str = Form("{}")):
    opts = ScanOptions.model_validate_json(options)
```

## Response contract (all new fields optional)

The frontend renders each of these as soon as it appears. See
[`src/frontend/src/types.ts`](../src/frontend/src/types.ts).

```jsonc
{
  "raw_result_count": 6,
  "findings": [ /* unchanged */ ],
  "reachability": [ /* unchanged */ ],

  "exploitability": [{
    "finding_id": "a1b2…",
    "status": "exploitable",             // "exploitable" | "not_exploitable" | "inconclusive"
                                          // (legacy schemas.py literals also accepted)
    "confidence": "medium",
    "reason": "Request data from POST /todos is interpolated into the query unsanitized.",
    "tier": "A",                          // "A" static | "B" sandbox
    "reasoning_steps": ["Entry point reads request input.", "…"],
    "source":  { "file_path": "app.py", "line": 58, "description": "self.rfile body → title" },
    "sink":    { "file_path": "app.py", "line": 34, "description": "connection.execute(f\"…\")" },
    "sanitizers": [],                     // [] means none seen on the path
    "attacker_controlled": true,
    "proof_of_concept": null,             // Tier B: the payload that confirmed it
    "suggested_fix": "Use a bound parameter.",
    "model": "…", "duration_ms": 1830
  }],

  "taint": [{ "finding_id": "a1b2…", "tainted": true, "source_description": "request body" }],

  "meta": {
    "scanners": [{ "name": "semgrep", "version": "1.174.0", "ruleset": "auto" }],
    "duration_ms": 41200, "file_count": 12, "line_count": 840,
    "stages": [{ "name": "semgrep", "duration_ms": 30100 }]
  }
}
```

Tier A should only emit verdicts for `reachable` / `unknown` findings. The UI counts
`unreachable` ones as *skipped*.

**Suggestion:** collapse the three placeholder literals in `ExploitabilityVerdict.status`
(`confirmed_exploitable` / `not_confirmed` / `attempted_inconclusive`) into
`exploitable` / `not_exploitable` / `inconclusive`. "Not confirmed" reads as "can't tell"
rather than "no", which blurs the three answers the UI is built around. The frontend
accepts both sets in the meantime (`normalizeExploitability()` in `lib/validated.ts`).

## Upload safety

The preflight (`src/frontend/src/lib/uploadSafety.ts`) runs before anything is sent:

| Check | Behavior |
|---|---|
| Dependency / VCS / build dirs (`node_modules`, `.git`, `.venv`, `__pycache__`, `dist`, …) | Skipped. Drag-and-drop doesn't even walk into them. |
| Sensitive files (`.env*`, `*.pem`/`*.key`/`*.p12`, `id_rsa*`, `credentials*`, `.npmrc`/`.pypirc`/`.netrc`, `*.sqlite`/`*.db`) | **Blocked**, never uploaded, listed so the user can see it. |
| Not scannable (anything except `.py`, templates, `requirements*.txt`/`pyproject.toml`/`setup.*`/`Pipfile`) | Skipped. Less code leaves the machine. |
| Per-file > 1 MB, total > 10 MB | Skipped / blocks the scan. |
| Python lines > 5,000 | Blocks the scan *before* upload (mirrors `LocalPathSource`'s limit, so no wasted round trip). |
| Likely hardcoded secrets (AWS keys, GitHub/Slack/Stripe tokens, private-key blocks, `password = "…"`) | Flagged with file:line. **Redacted by default** — only the value is replaced, so line numbers and findings stay correct. |

**This is not a security boundary.** Anyone can POST to `/api/scan` directly.
Recommended server-side mirror, roughly in order of value:

- Same extension allowlist and sensitive-file denylist in `api.scan()`.
- Cap the number of files and the total bytes *while streaming*, before writing to disk (the current check runs only after everything is written).
- Reject symlinks and archives, and keep the existing `is_relative_to` path check.
- Rate-limit `/api/scan` per IP — it runs Semgrep, which is expensive.
- Paths: the frontend now sends paths relative to the project root (`app/server.py`, not `my-service/app/server.py`), so findings and SARIF exports line up with the repo. Keep the server tolerant of either.

## Files

```
src/frontend/src/
  App.tsx                  view state: new scan → scanning → results; drawer; panels
  types.ts                 API contract (live + proposed)
  api.ts                   fetch wrappers; sends options; AbortController support
  lib/
    capabilities.ts        feature registry → Roadmap panel + PLANNED tags
    validated.ts           joins findings+reachability+exploitability; priority score
    uploadSafety.ts        preflight, secret detection/redaction, glob excludes, DnD
    filters.ts             findings filter model
    storage.ts             triage decisions + scan history (localStorage, guarded)
    exporters.ts           SARIF / CSV / JSON / Markdown
    remediation.ts         per-CWE fix guidance
    previewData.ts         EXAMPLE exploitability verdicts — delete once Tier A ships
    format.ts              time formatting
  components/
    NewScan.tsx            source picker, dropzone, preflight review, scan settings
    ScanProgress.tsx       staged progress + cancel
    ResultsHeader.tsx      title, funnel, tabs, export menu
    OverviewView.tsx       fix-first list, severity×reachability matrix, CWE/file hotspots
    FindingsTable.tsx      search, filters, bulk triage, sortable table
    FindingDrawer.tsx      verdicts, priority breakdown, call path, exploitability, code, fix, triage
    ReachabilityView.tsx   % reachable, attack surface, grouped lists
    ExploitabilityView.tsx Tier A/B design, verdict cards, example-data mode
    Panels.tsx             top bar, roadmap panel, history panel
    ui.tsx                 icons, badges, cards, empty states
```
