# Phase 0 — Foundations: Finding Schema & Verdict Contracts

Status: **near complete.** Design is settled; remaining work is execution — see
`docs/phase-0-plan.md` for the task list and one open decision (Semgrep firing two
rules per code location in the real sample app).

## Out of scope

**Scanner accuracy.** This project trusts that a scanner's reported file/line for a
finding actually points at the relevant code. If the scanner itself misreports a
location (a scanner bug, not a reachability problem), our reachability/exploitability
conclusion inherits that error — detecting or correcting that is explicitly not this
project's job. We validate *what the scanner found*, not *whether the scanner found it
correctly*. This matters concretely for the file:line → function resolution rules below:
those rules assume the reported line is accurate and handle real structural ambiguity
(decorators, nesting); they are not trying to compensate for a wrong line number.

## Schema overview: three linked records, not one merged object

- **`NormalizedFinding`** — what every scanner's output gets normalized into on the way
  in. One per finding, from Phase 0.
- **`ReachabilityVerdict`** — Phase 1's output. One per finding, linked back by
  `finding_id`, not merged into the finding record.
- **`ExploitabilityVerdict`** — Phase 4/5's output. Linked the same way, and only exists
  for findings whose `ReachabilityVerdict.status == "reachable"` — a finding can have a
  `ReachabilityVerdict` with no `ExploitabilityVerdict` yet, and that's a normal state,
  not missing data.

These stay separate, linked-by-`finding_id` records rather than one flattened object,
because the actual consumption pattern is a web app with drill-down navigation (funnel
counts → click into a stage → click a finding → see why → click through to the raw
finding) — the UI performs the join by letting someone click a link, so the data doesn't
need to be pre-flattened. Full UI shape: `docs/project-design.md`.

Normalizing at the input boundary means Phase 5's exploit agent, Phase 6's reporting, and
any future second scanner all work against one stable shape — adding Bandit/CodeQL later
means writing one adapter function, not touching every downstream component.

## `NormalizedFinding` (input schema)

```python
@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str            # stable hash of (scanner, file_path, line_start) - see decision below
    source_scanner: str        # "semgrep" | "bandit" | "codeql" | "custom"
    rule_ids: list[str]         # ALL rules that matched this location - see "Same-location grouping" below
    vulnerability_type: str     # == rule_ids[0], permanently out of scope for this project - see decision below
    cwe: list[str]               # short codes e.g. ["CWE-89"], deduped across grouped rules - see decision below
    severity: str                # highest severity across grouped rules - NOT our final priority
    file_path: str               # relative to repo root, forward-slash normalized
    line_start: int
    line_end: Optional[int]
    column_start: Optional[int]
    message: str                  # first/primary rule's human-readable description
    code_snippet: Optional[str]   # DERIVED by us, not sourced from scanner - see decision below
    raw: list[dict]                # ALL original raw scanner records for this location, untouched
```

## Same-location grouping (decided)

Real Semgrep output against the sample app surfaced this: two different rules
(`python.lang.security.audit.formatted-sql-query` and
`python.sqlalchemy.security.sqlalchemy-execute-raw-query`) both fire on the same 3 code
locations, producing 6 raw results for 3 real bugs. Left ungrouped, the demo would show
"6 findings" for what's obviously 3 to anyone reading the code — undercutting the whole
"reduce noise" pitch.

**Decided:** group raw results by exact `(file_path, line_start)` before converting to
`NormalizedFinding` — one finding per code location, not one per rule match. This is
deliberately narrow: an exact match needs no fuzzy logic, unlike the full cross-scanner
semantic dedup problem deferred to Phase 7 (different rule-id namespaces, no shared
identity to match on). Combining rules within a group:

```python
def group_raw_results(raw_results: list[dict]) -> list[list[dict]]:
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for r in raw_results:
        key = (r["path"], r["start"]["line"])
        groups[key].append(r)
    return list(groups.values())
```

## Adapter pattern

One small function per scanner, converting one *group* of raw records (same location,
possibly multiple rules) into a single `NormalizedFinding`:

```python
SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}

def from_semgrep(raw_group: list[dict]) -> NormalizedFinding:
    primary = raw_group[0]   # representative record for display fields
    all_cwes = []
    for r in raw_group:
        for code in extract_cwes(r["extra"]["metadata"].get("cwe", [])):
            if code not in all_cwes:
                all_cwes.append(code)
    highest_severity = max(
        (r["extra"]["severity"] for r in raw_group),
        key=lambda s: SEVERITY_RANK.get(s, 0),
    )
    return NormalizedFinding(
        finding_id=hash_id("semgrep", primary["path"], primary["start"]["line"]),
        source_scanner="semgrep",
        rule_ids=[r["check_id"] for r in raw_group],
        vulnerability_type=raw_group[0]["check_id"],   # out of scope for this project, not deferred - see decision below
        cwe=all_cwes,
        severity=highest_severity,
        file_path=normalize_path(primary["path"]),
        line_start=primary["start"]["line"],
        line_end=primary["end"]["line"],
        column_start=primary["start"]["col"],
        message=primary["extra"]["message"],
        code_snippet=None,   # filled in later via read_snippet() against the materialized local codebase
        raw=raw_group,
    )
```

Severity picks the highest across the group (`ERROR` beats `WARNING`) — the
security-conservative choice, never silently downgrading. Known simplification: grouping
purely by exact line number would miss two genuinely different bugs that happen to start
on the same line — an accepted edge case for MVP, not something this narrow grouping
tries to handle.

Validated against real results (`python.lang.security.audit.formatted-sql-query` +
`python.sqlalchemy.security.sqlalchemy-execute-raw-query`, both at `app.py:34`) from
actual `semgrep scan --json` output against the sample app — not hand-guessed.

## `ReachabilityVerdict` (Phase 1 output schema)

```python
@dataclass(frozen=True)
class ReachabilityVerdict:
    finding_id: str                       # FK -> NormalizedFinding
    status: Literal["reachable", "unreachable", "unknown"]   # 3-valued, not boolean - see decision below
    confidence: Literal["high", "medium", "low"]
    containing_function: Optional[str]    # resolved qualified name, e.g. "app.upload.parse_archive"
    entry_point: Optional[str]            # e.g. "POST /upload -> handle_upload"
    call_path: Optional[list[str]]        # structured/technical - kept for Tier A input & debugging
    reason: str                           # one sentence, natural language, no jargon - see decision below
```

## `ExploitabilityVerdict` (Phase 4/5 output schema)

Sketched here for shape consistency; full design lives in
`docs/phase-4-5-exploitability-notes.md`, not yet settled in detail.

```python
@dataclass(frozen=True)
class ExploitabilityVerdict:
    finding_id: str                       # FK -> NormalizedFinding (only exists when reachable)
    status: Literal["confirmed_exploitable", "not_confirmed", "attempted_inconclusive"]  # refine in Phase 4/5
    confidence: Literal["high", "medium", "low"]
    reason: str
```

## File:line → function resolution (decided)

```python
def resolve_containing_function(functions: list[FunctionSpan], line: int) -> Optional[FunctionSpan]:
    # span_start = line of the FIRST decorator if any exist, else the `def` line
    # span_end   = last line of the function body
    candidates = [f for f in functions if f.span_start <= line <= f.span_end]
    if not candidates:
        return None   # module-level code - see "Open questions"
    return min(candidates, key=lambda f: f.span_end - f.span_start)  # smallest span = innermost
```

Concrete cases this handles: (1) a finding on a decorator line (`@app.route(...)`)
resolves correctly because `span_start` is defined at the decorator, not the `def` line
— `@app.route` is a *registration* decorator (registers the function into Flask's URL
map and hands back the same function unchanged, vs. a *wrapping* decorator like
`@login_required` that returns a new function calling the original) — either way,
nothing in the source code literally *calls* the decorated function, which is exactly why
entry-point detection has to be its own explicit pattern-matching step, not something a
generic call-graph walk would discover; (2) nested functions, where a line is technically
inside both the outer and inner function, resolve to the innermost because its span is
always the smallest; (3) multi-line expressions are not actually a resolution problem —
if the reported line falls anywhere inside a function's span it still resolves correctly
regardless of what's visually on that line; a scanner reporting a line genuinely outside
any span is a scanner-accuracy issue (see "Out of scope" above), not something this
algorithm needs to special-case.

The zero-candidates (module-level code) case is not yet decided — see "Open questions."

## Codebase input — MVP decision: local path / direct upload only

**Decided:** MVP supports local path / direct upload only. No GitHub URL, no cloning,
for now.

Why this isn't a cop-out: the entire SHA-pinning / clone-depth question (see "Future /
full-scale design" below) only exists because of a specific scenario — findings computed
by someone else, against a repo, at some point in the past, and this service
independently re-fetching the code *later*, with a real risk of landing on a different
state than what was scanned. Direct upload has no separate fetch step and no time gap:
the code received *is* the code scanned, in the same operation. The whole problem class
doesn't apply, not because it was solved, but because the scenario that creates it isn't
part of MVP.

**Bonus:** the ground-truth fixture codebases (`docs/project-design.md`, "Testing/
validation approach") do double duty here — they're both the internal correctness test
suite *and* a zero-setup "pick one of these" quick-start option in the actual demo, so a
time-pressed reviewer doesn't have to find or upload anything to try it immediately.

**Size limit:** cap uploads at roughly 5,000 lines of code, with a friendly rejection
message ("this codebase is too large to test right now — try one of our controlled
examples, or upload something smaller") rather than a silent timeout or crash. This
number is a starting knob, not a measured constant — reasoning is keeping parse/graph-
build time predictable for a live demo session, tune once Phase 1's actual build times
are known. **Full-scale note:** a production version would chunk/process large codebases
incrementally (per-module graphs, caching) rather than hard-capping input size — a known
scaling path, just not needed for MVP.

## Two producer modes for findings

See `docs/project-design.md` "Deployment modes" for the full picture. Schema-level
implications:

- **Self-scan mode** (demo path — **MVP: local path/upload, no GitHub URL/cloning**, see
  "Codebase input" above): the service runs `semgrep scan` itself, unauthenticated,
  against the uploaded/local codebase, and adapts the output via `from_semgrep()`. No SHA
  or drift concern at all here — there's no separate fetch step, the code received *is*
  the code scanned, in the same operation.
- **Findings-provided mode** (enterprise-style, mirrors a multi-scanner-plus-dedup setup
  upstream): assumes the future git-URL codebase source (SHA-pinning rules below), so
  this mode's practical use is deferred alongside that.

**Reversed: self-scan mode uses `--config=auto`, not a pinned local ruleset.** The
original reasoning (avoid registry drift, keep the demo's finding count stable) held for
a tool that only ever scanned the todo app. But once self-scan became a general
"upload any codebase" feature (see the FastAPI/React build), a pinned set of just the 2
rules the todo app happens to trigger meant *any other uploaded codebase* would be
checked against those same 2 narrow rules and nothing else — silently under-reporting,
not because the code was safe, but because we'd only kept rules for one specific bug
shape. Caught in practice: a real scan the user ran directly got 16 raw findings against
some codebase, while the app's pinned rules would have returned far fewer against the
same code. `raw_result_count` matching what a real, comprehensive Semgrep scan would
find is more important than perfect reproducibility once the tool needs to work
generically.

Real trade-off accepted, discovered while making this change: `--config=auto` requires
network access (to resolve rules from Semgrep's registry) **and does not support
`--metrics=off`** — Semgrep refuses to run auto config selection with metrics disabled,
so some anonymized scan telemetry is sent to Semgrep's servers. Full offline/telemetry-
free operation isn't compatible with `--config=auto`. Verified empirically that this
doesn't change the todo app's own ground truth: `--config=auto` runs ~1200 rules against
it but still converges on the exact same 6 raw results (2 rules × 3 locations) as the
old pinned set, so `ground_truth.md` and the existing tests didn't need updating. Also
confirmed `--no-rewrite-rule-ids` (added earlier to work around local-file config
rewriting `check_id`) is no longer needed — that rewriting only happens with local file
configs, not `auto`; removed for cleanliness. `src/adapters/rules/` (the pinned YAML
files) has been deleted — nothing to maintain now.

Findings-provided mode is kept, not as the demo's main experience, but because it
mirrors a common production pattern (scanners → dedup → downstream validation) seen in
real security tooling — worth having both, but self-scan is what gets featured.

## Future / full-scale design: git URL + cloning (NOT built for MVP)

Kept here deliberately, not deleted — this is the design for when git-URL support is
added later, with the reasoning already worked out so it doesn't need to be re-derived.
Applies only to findings-provided mode above, not to MVP self-scan.

- **Codebase `ref` must be a full commit SHA, not a branch name — enforced, not
  best-effort.** Findings carry `file_path:line_start` from one specific scan run; if the
  branch has moved since, every line number is silently wrong with no error surfaced.
  Reject non-SHA refs at the request boundary.
- **Clone full, not shallow.** `--depth 1` fetches the branch tip, not necessarily the
  target SHA. Full clone + explicit `checkout <sha>` is simple and correct; shallow-clone
  optimization is a later concern only if cloning is a measured bottleneck.

Three input scenarios (local path / git URL+ref / uploaded archive) all reduce to one
thing: a local directory on disk that the graph builder reads. The abstraction boundary
is "give me a materialized local path" — Phase 1 never knows or cares which source
produced it.

```python
class CodebaseSource(ABC):
    @abstractmethod
    def materialize(self) -> Path:
        """Returns a local filesystem path ready for graph building."""

class LocalPathSource(CodebaseSource):
    def __init__(self, path: Path):
        self.path = path
    def materialize(self) -> Path:
        return self.path

class GitRepoSource(CodebaseSource):
    def __init__(self, url: str, ref: str, auth_token: Optional[str] = None):
        self.url, self.ref, self.auth_token = url, ref, auth_token
    def materialize(self) -> Path:
        workdir = make_temp_dir()
        clone(self.url, workdir, auth_token=self.auth_token)   # full clone, see decision above
        checkout(workdir, self.ref)
        return workdir
```

Request shape:

```json
{
  "codebase": {
    "type": "git",
    "url": "https://github.com/org/repo",
    "ref": "a1b2c3d4e5f6...",
    "auth_token_ref": "secret:github-token"
  },
  "findings": [ /* NormalizedFinding[] */ ]
}
```

## Decisions made (Semgrep adapter & finding schema)

- **Ingest `semgrep --json` output, not CLI text output.** CLI text drops file path in
  isolated snippets, drops raw severity, drops CWE, and is fragile to parse (box-drawing
  chars, wrapping). JSON is a hard requirement for the adapter, not a convenience.
- **`finding_id` is our own hash, always — never a scanner-provided fingerprint, and not
  a cross-scanner dedup key.** `hash(source_scanner, file_path, line_start)` — note
  `rule_id` is deliberately **not** part of this hash (changed from an earlier version
  that included it), because same-location grouping (see above) needs multiple rules at
  one location to collapse to the *same* `finding_id`, not different ones. Reasons for
  the hash approach overall: (1) Semgrep OSS has no usable native per-finding ID —
  `fingerprint` returns `"requires login"` unauthenticated, and since this project
  deliberately stays unauthenticated/open, a fingerprint-fallback code path would almost
  never run, and worse, could silently assign the same finding two different IDs
  depending on who ran it; (2) `check_id` is a rule ID shared by every instance of that
  rule, not a per-finding ID; (3) even an authenticated fingerprint wouldn't be
  comparable across scanners (Bandit's `B608` vs Semgrep's `check_id` live in unrelated
  namespaces). The hash gives free idempotency (re-scan same code → same `finding_id`,
  no duplicate rows) but does **not** attempt cross-scanner deduplication — that's a
  separate, harder problem (different rule-id namespaces, genuinely needs fuzzy
  matching), see "Open questions."
- **`vulnerability_type` is explicitly out of scope for this project, not deferred.** In
  many real architectures, a separate upstream dedup/normalization service is
  responsible for turning multiple scanners' output into one consistent shape before it
  ever reaches a downstream validator like this one. For this project,
  Semgrep-only *is* that already-normalized input — `vulnerability_type == rule_ids[0]`
  (the primary/first rule in a grouped location), unmodified, permanently within this
  project's scope, not a placeholder waiting for a second scanner to be added here.
- **`code_snippet` is derived by us, not sourced from the scanner.** Semgrep's OSS engine
  returns `"lines": "requires login"` without a Semgrep account/token — but since we
  already have the codebase materialized locally by the time the adapter runs, we read
  `file_path:line_start` ourselves via a `read_snippet()` helper. Removes a dependency on
  Semgrep login entirely.
- **`cwe` is a list of short codes, not the full descriptive string(s).** Real
  `metadata.cwe` is a list of full sentences (e.g.
  `["CWE-89: Improper Neutralization of Special Elements..."]`); we extract just the
  short code from each entry via `re.match(r"(CWE-\d+)", ...)`, keeping the list
  structure — a finding legitimately can carry more than one CWE, and there's no real
  cost to keeping the list. With same-location grouping, this also naturally absorbs the
  union of CWEs across all grouped rules, deduped. (Reversed from an earlier "singular" proposal that had
  wrongly generalized from only two observed examples — dropping the descriptive prose,
  which duplicates `message`, is the part that actually holds up, not collapsing to one
  value.)
- **`ReachabilityVerdict.status` is 3-valued: `reachable` / `unreachable` / `unknown`.**
  "Unknown" (graph couldn't resolve a call — dynamic dispatch, `getattr`, etc.) is a
  real, common outcome; folding it into either boolean value would silently misrepresent
  confidence.
- **`reason` is required on every verdict, including `reachable` ones.** This is what
  lets an engineer trust the verdict instead of re-deriving it by hand.
- **`reason` must be one sentence, natural language, zero jargon — readable by someone
  who is not a security engineer.** E.g. "Reachable via `POST /upload` → `parse_archive`
  → this function", "Unreachable — only called from a function that's never invoked",
  "Unknown — the graph couldn't resolve this call." The structured `call_path` is kept
  *alongside* this, not replaced by it — the sentence is for a human reader, the path is
  for Tier A's exploitability reasoning and for debugging. Start with a simple format
  string for MVP (fast, free, deterministic); only reach for an LLM rewrite pass if
  templated output ever reads awkwardly.

## Fields noted for later phases (currently unused, sitting in `raw`)

- `metadata.likelihood` / `impact` / `confidence` — Semgrep's own risk scoring; possible
  Phase 6 prioritization tiebreaker.
- `extra.metavars.<VAR>.propagated_value` — **Correction, this was previously
  mis-described as a taint signal.** It's real, but it's basic intra-procedural constant
  propagation used for pattern-matching accuracy (e.g. confirming `connection` really is
  what `open_database()` returned) — not security-relevant taint tracking. Evidence: in
  every finding we captured, what's traced is the database connection object, never the
  actually-dangerous value (`title`, `query`) back to its HTTP-derived origin. Not
  usable as a taint signal. Superseded: Phase 3/Tier-A taint tracking will use Joern's
  dataflow queries instead — see `docs/phase-1-foundations.md`.
- `fingerprint` — real and stable when the scanner run is authenticated (confirmed via a
  logged-in Semgrep JSON sample); returns `"requires login"` under the OSS/unauthenticated
  engine. Since the public demo path must work unauthenticated, `finding_id`'s own hash
  remains the primary identity regardless — this field is a nice-to-have capture into
  `raw`, not a dependency.

## Open questions (not yet resolved)

- **Zero candidates in file:line resolution (module-level code).** Module-level
  statements run automatically the first time their file is imported, not when called —
  e.g. a hardcoded value sitting directly in `config.py` (not inside any `def`) executes
  the moment anything does `import config`. Likely direction, not yet decided:
  zero-candidate findings check module-import reachability (traced through `import`
  statements) instead of call reachability — revisit once Phase 1 is actually being
  built.
- **Cross-scanner deduplication is explicitly out of scope for MVP**, deferred to Phase 7
  (multi-scanner scale-out) alongside the `vulnerability_type` mapping table. Same
  underlying bug flagged by 2+ scanners (or 2+ rules within one scanner) is a semantic
  matching problem, not something `finding_id`'s hash solves. The user has previously
  built a dedup algorithm for exactly this — **reuse it when Phase 7 starts rather than
  rebuilding; locate/link it here once found.** Architecturally it would sit as its own
  step downstream of normalization: consumes a batch of `NormalizedFinding` records,
  emits `DedupGroup(group_id, member_finding_ids, canonical_finding_id)` — it does not
  change how `finding_id` itself is computed.
- Does `severity` need a sibling field for Semgrep AppSec Platform's policy action label
  (`"Blocking"` / `"Non-blocking"` / `"Monitor"`), separate from the raw
  `ERROR`/`WARNING`/`INFO` severity? Only relevant if findings come from the platform
  tier rather than plain `semgrep scan`.
- Monorepo scoping: assume single-package repo root for MVP. Revisit if the test app
  turns out to be nested in a larger repo.
- **(Future git-URL design only, not MVP-blocking)** Private repo auth: `auth_token_ref`
  in the request schema is a pointer to a secret (never a raw token in the request
  body), but where that resolves to (secrets manager, env var) is an infra decision, not
  yet made.
- **(Future git-URL design only, not MVP-blocking)** Clone caching: re-clone every time.
  Caching repeated commits is a Phase 7 scale concern.

## Pending next steps

Superseded by the task list in `docs/phase-0-plan.md`, which reflects the real sample
app (`src/sample-apps/todo-list-app/app.py` — one file, three functions, no separate
dead-code file, as originally mis-assumed here from stale `.pycache` remnants). See that
doc for the current task list and open decision (Semgrep firing two rules per location).
