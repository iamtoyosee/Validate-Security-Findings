# Phase 0 — Execution Plan

Converts the decisions in `docs/phase-0-foundations.md` into a concrete, ordered task
list with a definition of done. This is the "what to actually build, in what order"
document; `phase-0-foundations.md` remains the "what we decided and why" reference.

**Historical note:** this doc's Task 4 pseudocode and `demo.py` snippet below reference
a pinned local rules folder (`src/adapters/rules/`) that was later removed —
`run_semgrep()` now uses `--config=auto` instead. Also, `src/adapters/semgrep.py`
referenced throughout this doc has since moved to `src/semgrep_adapter.py` — the
`adapters/` folder was flattened once it was clear it would only ever hold one file
(no second scanner planned any time soon). `src/demo.py` (Task 7) has since been
**deleted entirely** — once `src/api.py` and the pytest suite existed, it was a
redundant second entry point into the same pipeline, less complete than either (no
`code_snippet`, no `raw` exclusion, hardcoded to one sample app). Left as-is here since
this is a record of what was actually built at the time; see
`docs/phase-0-foundations.md` ("Same-location grouping" section) for the ruleset
reversal.

**Revised** after actually inspecting the real project directory — earlier drafts of
this plan were based on a wrong mental model (a `dead_code.py` file that doesn't exist,
inferred from stale `.pycache` remnants of an older, different version of this sample
app). Corrected below.

## The controlled sample app — what it actually is

One folder, `src/sample-apps/todo-list-app/`, containing `app.py` (a plain Python
`http.server`-based todo list, no framework), `README.md`, and real Semgrep/Bandit
output already captured manually. No separate "dead code" file — all three
vulnerabilities live inside `app.py` itself.

Real ground truth, read directly from `app.py` and `semgrep_results.json`:

| Function | Lines | Called from | Verdict |
|---|---|---|---|
| `add_todo(title)` | 32-34 | `TodoHandler.do_POST`, path `/add` | **Reachable** |
| `search_todos(query)` | 37-41 | `TodoHandler.do_GET`, when `?q=` present | **Reachable** |
| `find_old_todos(connection, phrase)` | 93-96 | nowhere — no caller in the file | **Unreachable** |

Entry points are `do_GET`/`do_POST` on `TodoHandler` — called by Python's
`http.server` framework via naming convention, not a decorator. Nothing in the source
literally calls them, same underlying issue as the `@app.route` case discussed earlier,
different mechanism.

**Decided:** Semgrep's real output has 6 raw results, not 3 — two different rules
(`python.lang.security.audit.formatted-sql-query` and
`python.sqlalchemy.security.sqlalchemy-execute-raw-query`) both fire on each of the 3
locations above. Grouped by exact `(file_path, line_start)` into 3 `NormalizedFinding`
records, one per real bug — see "Same-location grouping" in
`docs/phase-0-foundations.md` for the full mechanism (`finding_id`'s hash no longer
includes `rule_id`, `rule_ids` is now a list, severity/CWE combine across the group).

There's also a `bandit-output.json` sitting in the same folder from earlier manual
testing — not part of this project's scope (Semgrep only, per `docs/project-design.md`)
and can be deleted whenever; not blocking anything.

## What's core vs. supporting

**Core:**
- The three schemas exist as real, importable code.
- `LocalPathSource` works — and comes *before* the adapter, not after, since the
  adapter's `read_snippet()` needs a materialized codebase path to read from.
- A function that actually runs `semgrep scan` as a subprocess against the sample app
  and captures its JSON output — this was missing from the original plan entirely. The
  existing `semgrep_results.json` in the sample app folder was captured manually; the
  real deliverable is the app doing this itself.
- The Semgrep adapter works correctly against all 3 real findings (grouped down from
  6 raw results, see "Same-location grouping" above) — and this needs to be *visible*,
  not just implemented (see Task 7 and the revised Definition of Done below).
- Ground truth for the sample app is documented, not just implied.

**Supporting (scoped into Phase 0 per your call, not blocking Phase 1):**
- The sample-data UI preview.

**Explicitly NOT Phase 0:**
- `resolve_containing_function()` needs actual AST parsing — that's Phase 1
  infrastructure (the start of the call graph), even though the algorithm was designed
  during Phase 0.
- A second, larger sample app — descoped, use the todo app only. UI gets inert
  placeholder slots suggesting more examples are coming.

## Directory structure (as it now exists)

```
Workload/
  CLAUDE.md
  docs/                              # design docs, this plan, etc. - unchanged
  src/                                # single folder for everything that isn't docs
    schemas.py                        # NormalizedFinding, ReachabilityVerdict, ExploitabilityVerdict
    codebase_source.py                # LocalPathSource
    adapters/
      semgrep.py                       # run_semgrep() + from_semgrep() + helpers
    reachability/                     # Phase 1+ call graph & traversal - empty for now
    exploitability/                   # Phase 4/5 Tier A/B logic - empty for now
    ui/                               # sample-data preview
    sample-apps/
      todo-list-app/                  # moved here from the repo root
        app.py
        semgrep_results.json          # manually captured - superseded by run_semgrep()
        bandit-output.json            # out of scope, deletable whenever
        README.md
        ground_truth.md               # NEW - to be written (Task 2)
```

## Task list

### Task 1 — Implement `LocalPathSource`

`src/codebase_source.py`. Comes first because the adapter's snippet-reading depends on
it having already materialized a path.

```python
class CodebaseTooLargeError(Exception):
    pass

class LocalPathSource:
    def __init__(self, path: Path, max_lines: int = 5000):
        self.path, self.max_lines = path, max_lines

    def materialize(self) -> Path:
        total_lines = sum(
            len(f.read_text().splitlines())
            for f in self.path.rglob("*.py")
        )
        if total_lines > self.max_lines:
            raise CodebaseTooLargeError(
                f"This codebase is too large to test right now ({total_lines} lines, "
                f"limit {self.max_lines}) — try one of our controlled examples, or "
                f"upload something smaller."
            )
        return self.path
```

DoD: returns the path for `src/sample-apps/todo-list-app/` (well under the cap); raises
the friendly error for something contrived to be oversized.

### Task 2 — Document the sample app's ground truth

`src/sample-apps/todo-list-app/ground_truth.md` — 3 entries, matching the 3 grouped
findings, not 6:

```markdown
## add_todo (line 34)
- Expected: REACHABLE
- Why: called from TodoHandler.do_POST when path == "/add"
- Semgrep rule_ids: [python.lang.security.audit.formatted-sql-query,
  python.sqlalchemy.security.sqlalchemy-execute-raw-query]

## search_todos (lines 39-41)
- Expected: REACHABLE
- Why: called from TodoHandler.do_GET when ?q= is present
- Semgrep rule_ids: (same two)

## find_old_todos (lines 94-96)
- Expected: UNREACHABLE
- Why: defined but never called anywhere in app.py
- Semgrep rule_ids: (same two)
```

Written independent of any tool output, as the answer key Phase 1 gets graded against
later.

### Task 3 — Implement the schemas

`src/schemas.py` — the three `@dataclass` definitions exactly as written in
`docs/phase-0-foundations.md`. DoD: importable, manual instantiation with fake values
doesn't error.

### Task 4 — Run Semgrep programmatically

`src/adapters/semgrep.py`. This was missing from the original plan — running the scan
is part of self-scan mode's core behavior, not something assumed to already exist as a
file on disk. The existing `semgrep_results.json` was captured by hand; this makes it
automatic.

```python
import subprocess
import json
from pathlib import Path

def run_semgrep(codebase_path: Path, rules_path: Path) -> list[dict]:
    result = subprocess.run(
        ["semgrep", "scan", f"--config={rules_path}", "--json"],
        cwd=codebase_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)["results"]
```

`rules_path` points at the locally pinned rule files (per the earlier "pinned ruleset,
not `--config=auto`" decision) — those rule files themselves still need to be fetched
once and committed somewhere; not yet done, small separate step.

DoD: running this against `src/sample-apps/todo-list-app/` produces the same 6 raw
results already captured in the existing `semgrep_results.json` (a good correctness
check — if it doesn't match, something's wrong with the rules path or invocation).

### Task 5 — Implement the Semgrep adapter and its helpers

`src/adapters/semgrep.py` (same file as Task 4). The adapter (`from_semgrep`) and the
grouping step (`group_raw_results`) are fully specified in `phase-0-foundations.md`
("Same-location grouping" and "Adapter pattern"); the smaller helper functions still
need writing:

```python
import hashlib
import re

def hash_id(*parts: str) -> str:
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]

def extract_cwes(cwe_entries: list[str]) -> list[str]:
    codes = []
    for entry in cwe_entries:
        match = re.match(r"(CWE-\d+)", entry)
        if match:
            codes.append(match.group(1))
    return codes

def normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")

def read_snippet(codebase_root: Path, file_path: str, line_start: int, line_end: int | None) -> str:
    end = line_end or line_start
    lines = (codebase_root / file_path).read_text().splitlines()
    return "\n".join(lines[line_start - 1 : end])   # line numbers are 1-indexed, list slicing isn't
```

Full path: `group_raw_results(raw_results)` → 3 groups → `from_semgrep(group)` for each
→ 3 `NormalizedFinding` records.

DoD: run the full path against the todo app's real 6 raw results, confirm it produces
exactly 3 `NormalizedFinding` records, and manually verify each one field-by-field
(`rule_ids` has 2 entries, `severity` picked the higher of `WARNING`/`ERROR`, etc.),
including `find_old_todos` — the case that's been pending validation since early in
Phase 0.

### Task 6 — Sample-data UI preview

Purpose: a visual anchor to look at while Phases 1-5 don't exist yet, and a cheap way to
validate the drill-down navigation design from `docs/project-design.md` before building
the real thing.

**Data:** the `NormalizedFinding` portion is **real**, not invented — pull it straight
from Task 7's script output (the actual 3 grouped findings from the actual sample app).
Only the verdict portions are hand-crafted, because Phase 1/4-5 don't exist yet to
compute them: illustrative `ReachabilityVerdict` and `ExploitabilityVerdict` entries for
the 2 reachable findings, and an illustrative unreachable verdict for `find_old_todos`,
written by hand to match the ground truth doc. Label the hand-crafted portions as
sample/illustrative somewhere visible, so they're never mistaken for real Phase 1/4-5
output later.

**Structure to render:**
1. Top-level funnel counts (using the sample data).
2. A findings list, each row showing its `reason` inline.
3. Click a finding → its `ReachabilityVerdict` detail (path, entry point, confidence).
4. From there, a link to the underlying `NormalizedFinding` detail (file, line, message,
   snippet).
5. Where applicable, a link to the `ExploitabilityVerdict` detail.
6. Two or three **inert placeholder cards** alongside the todo-app example, suggesting
   more controlled examples are coming — respond to a click, but nothing happens.

**Tech recommendation:** a single static HTML/JS page, no backend, no build step —
naturally shareable later the same way the real demo will eventually be distributed.
If it needs to become a real live app once Phases 1-5 exist, that's a separate build at
that point.

DoD: openable in a browser, all navigation works, placeholders are visibly present but
inert.

### Task 7 — End-to-end demo script (the visible proof)

`src/demo.py`. Ties Tasks 1, 3, 4, 5 together into one runnable script — this is what
turns "the code exists" into "you can see it work," which is the actual point being
made in this review: implementation claims aren't enough, Phase 0 needs a visible
result.

```python
from pathlib import Path
from schemas import NormalizedFinding
from codebase_source import LocalPathSource
from adapters.semgrep import run_semgrep, group_raw_results, from_semgrep

SAMPLE_APP = Path(__file__).parent / "sample-apps" / "todo-list-app"
RULES = Path(__file__).parent / "adapters" / "rules"   # pinned local ruleset

def main():
    codebase_path = LocalPathSource(SAMPLE_APP).materialize()

    raw_results = run_semgrep(codebase_path, RULES)
    print(f"Semgrep raw results: {len(raw_results)}")          # expect 6

    groups = group_raw_results(raw_results)
    findings = [from_semgrep(g) for g in groups]
    print(f"Normalized findings: {len(findings)}")               # expect 3, not 6

    for f in findings:
        print(f"- {f.file_path}:{f.line_start}  rules={f.rule_ids}  severity={f.severity}")

if __name__ == "__main__":
    main()
```

DoD: running `python src/demo.py` prints `Semgrep raw results: 6` then
`Normalized findings: 3`, followed by the 3 findings — the literal, visible "3, not 6"
confirmation, not just a claim that grouping was implemented. This script's output is
also what Task 6's UI pulls its real `NormalizedFinding` data from.

## Definition of Done — Phase 0

**Complete.** All verified for real (run and checked directly, not just implemented):

- [x] **Run `python src/demo.py`** → prints `Semgrep raw results: 6` and
      `Normalized findings: 3`, with the 3 findings listed
      (`add_todo`, `search_todos`, `find_old_todos`).
- [x] Each of the 3 findings matches `ground_truth.md` field-by-field, including
      `find_old_todos` — closes the long-pending dead-code validation item.
- [x] **UI preview** (`src/ui/index.html`) — 3 real findings (finding_ids independently
      recomputed and cross-checked against the hash formula), drill-down navigation
      verified (headless-browser click-through + manual trace), inert placeholder cards
      present, illustrative data clearly labeled.
- [x] `docs/phase-0-foundations.md` remains accurate.
- [x] 20/20 tests passing.

**Bug found and fixed during execution:** `adapters/semgrep.py` used `int | None`
(Python 3.10+ syntax) in `read_snippet`'s signature, which failed on the system's
default Python 3.9.6 — surfaced when a second agent hit it independently. Fixed to
`Optional[int]`, matching the style already used in `schemas.py`. Re-verified
`demo.py` and the full test suite pass on the system's default `/usr/bin/python3`
(3.9.6) with no special interpreter required.

**Also found and fixed:** Task 4's pseudocode subprocess call, run literally, does not
reproduce the real captured JSON — Semgrep rewrites `check_id` with a filesystem path
prefix when rules load from a local file/directory instead of registry shorthand. Fixed
by adding `--no-rewrite-rule-ids` (a real, documented Semgrep flag) to the `semgrep
scan` invocation; verified output now matches the originally captured
`semgrep_results.json` field-for-field.

## Open questions carried forward

Unchanged from `docs/phase-0-foundations.md`. The same-rule-duplicate-finding question
raised by this plan is now resolved (see "Same-location grouping" above).

## Suggested execution order

1. Task 1 (`LocalPathSource`) — no dependencies, needed by the adapter.
2. Task 4 (run Semgrep programmatically) — no dependencies, and gives something to
   correctness-check against the existing manual JSON.
3. Task 3 (schemas) — no dependencies, small.
4. Task 2 (ground truth doc) and Task 5 (grouping + adapter) together — the adapter's
   output is what the ground truth doc is checked against.
5. Task 7 (demo script) — the first point where you actually *see* "3, not 6."
6. Task 6 (UI preview) — uses Task 7's real findings as its `NormalizedFinding` data,
   hand-crafts only the verdict portions on top.
