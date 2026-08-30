# Phase 1 — Foundations: Call Graph & Reachability

Status: **built and verified.** Reached after hands-on trials of AppThreat/atom against
two real apps surfaced real correctness problems (documented below) — the decision
reversed from "adopt an external tool" to "build a small, deliberately narrow engine
ourselves," specifically because we don't need to solve the hard problem that broke
atom, only a simpler, more precise version of it. Implemented in `src/reachability/`
(`graph.py`, `entry_points.py`, `engine.py`); independently verified against all 12 real,
documented ground-truth findings across both apps (todo app + e-commerce app) — 12/12
match — plus a synthetic 4-hop chain proving multi-hop traversal genuinely walks the
full chain, not just one level. Not yet wired into `src/api.py` or the frontend — see
"Next step."

## What a call graph is and why we need it

Nodes are functions, edges are "this function calls that function." Reachability
becomes a graph-traversal question: "is there a path, following edges backward, from
the vulnerable function to some entry-point node?" Grounded in the real sample app:

```
TodoHandler.do_GET   → search_todos    [reachable]
TodoHandler.do_POST  → add_todo        [reachable]
find_old_todos                          [zero incoming edges — unreachable]
```

Two separable pieces of work:
1. **The graph itself** (who calls whom) — fully derivable from reading the code.
2. **Which nodes are entry points** — *not* derivable from edges alone. Nothing in
   `app.py` literally calls `do_GET`/`do_POST`; Python's `http.server` framework calls
   them by naming convention. Entry-point detection has to be its own explicit step.

Both feed `ReachabilityVerdict`'s `entry_point` and `call_path` fields (already defined
in `docs/phase-0-foundations.md`) — this phase is what actually computes them.

## Building the call graph, step by step

**Step 1 — find every function and its boundaries.** Python's `ast` module parses a
file's text into a structured tree reflecting its actual grammar (not just text) — walk
it once, and every time it's a function/method definition, record its name (qualified
with its class name if it's a method, e.g. `TodoHandler.do_POST`) and line span (start =
first decorator line or `def` line, end = last body line). One pass, produces a table:

| Name | Lines |
|---|---|
| `open_database` | 10-13 |
| `add_todo` | 32-34 |
| `search_todos` | 37-41 |
| `find_old_todos` | 93-96 |
| `TodoHandler.do_GET` | 122-129 |
| `TodoHandler.do_POST` | 131-149 |
| ... | ... |

**Step 2 — find every call inside each function's body, keep only calls to our own
code.** Walk each function's body for call expressions. For each one, check: **is this
name in our step-1 table?** If yes, it's ours — record an edge. If no, it's external
(standard library, a third-party import) — discard it, out of scope entirely. This
single check is also what correctly, automatically excludes inherited methods (e.g.
`self.send_response(...)`, inherited from `BaseHTTPRequestHandler`, never appears in our
table because we never parsed the parent class) — no special-casing needed.

**Resolving a call name — three cases, only one of them hard:**
- **Plain call by name** (`add_todo(title)`) — unambiguous. There's exactly one thing
  named `add_todo` to find; Python itself has to resolve it this way at runtime, no
  guessing required. Build a confident edge.
- **`self.method()`** — also unambiguous, for a specific reason: `self` always means
  "the current instance of the class this method is defined in." Since `do_POST` is
  defined inside `class TodoHandler`, `self` is always a `TodoHandler` — no exceptions.
  Same confidence as a plain name call.
- **A method call on a plain parameter/variable of unknown type**
  (`connection.execute(...)`, where `connection` is just a parameter with no declared
  type) — genuinely ambiguous. We cannot safely know which `execute` this refers to
  without real type inference. **We do not attempt to resolve this.** No edge gets
  built for it — not a wrong guess, just correctly out of scope. This is the exact case
  that broke atom (see "Why we're building this ourselves" below) — the fix is not
  attempting the hard, unreliable resolution at all, not doing it better.

## The reachability rule, in plain words

Start at the function in question. Ask: **is this an entry point?** If yes — stop,
reachable. If no — look up who calls it (using the edges from step 2). If nobody calls
it — stop, no path found. If someone does call it, move to *that* caller and ask the
exact same question again — is *this one* an entry point? Keep repeating that same
question, one caller at a time, moving backward, until either landing on an entry point
or genuinely running out of callers.

The critical part: the check happens **fresh, at every single link**, not once. A
function can be called by something that is itself never called by anything — in that
case the chain dead-ends without ever reaching a real entry point, and the correct
answer is still "no path found," even though the function technically *has* a caller.
"Is this name called anywhere" is not the same question as "is there an unbroken chain
back to an entry point" — the former is necessary but nowhere near sufficient.

**Traced on the real app:**

`add_todo`: is it an entry point? No. Who calls it? `TodoHandler.do_POST` (step-2 edge).
Is `do_POST` an entry point? Yes (tagged, see below). **Stop — reachable.**
Path: `TodoHandler.do_POST → add_todo`.

`find_old_todos`: is it an entry point? No. Who calls it? Nobody — zero edges point at
it. **Stop — no path found.**

## Entry-point detection

General problem: every framework has a different pattern (Flask/FastAPI decorators,
Django URLconf, Celery tasks, plain `http.server` naming convention). Design as a small
set of pluggable detector functions, not one hardcoded rule — start with only what the
real sample app needs (any method named `do_GET`/`do_POST`/etc. on a class subclassing
`BaseHTTPRequestHandler`), add more detectors later as real codebases demand them
(Phase 2 territory, not now — see "Confidence has two axes" for why this scoping matters
to how much we can trust an "unreachable" verdict, not just what it can detect).

## From trace to verdict

Every `ReachabilityVerdict` field maps directly off what the trace found:

```python
# add_todo — confident path to a tagged entry point
ReachabilityVerdict(
    status="reachable",
    confidence="high",
    containing_function="add_todo",
    entry_point="TodoHandler.do_POST",
    call_path=["TodoHandler.do_POST", "add_todo"],
    reason="Reachable via POST /add -> TodoHandler.do_POST -> add_todo.",
)

# find_old_todos — no path found, but see "Confidence has two axes" below for why
# this is NOT "high" confidence despite being a clean, unambiguous result
ReachabilityVerdict(
    status="unreachable",
    confidence="medium",
    containing_function="find_old_todos",
    entry_point=None,
    call_path=None,
    reason="Not reachable via any known HTTP entry point (do_GET, do_POST). Other "
           "entry-point types (CLI, RPC, message queues, scheduled jobs) were not "
           "checked.",
)
```

## Confidence has two axes, not one — this was a real correction, worth understanding why

Initially conflated into a single confidence value. There are actually two separate
questions:

1. **Within the paths checked, how certain is each connection?** Was every edge along
   the way a confident, name-based one, or did the trace have to stop short of an
   ambiguous call we chose not to resolve?
2. **Did the search check every entry-point category that's actually relevant, or only
   some?** "Unreachable" is a claim about the *whole* codebase and every possible way
   in — not just the one category (HTTP) we currently have a detector for.

**A clean, unambiguous "no path found" is not automatically `high` confidence** —
`find_old_todos` genuinely has zero incoming edges via HTTP, checked rigorously, but
since only HTTP entry points are detected today, we haven't ruled out a CLI script, an
RPC handler, or a scheduled job also calling it. Marking that `high` confidence would
overclaim certainty we haven't earned — exactly the mistake that made atom's output
untrustworthy, just in the opposite direction (silently underclaiming *uncertainty*
instead of correctness).

**`high` confidence on an `unreachable` verdict has to require both axes to check out**:
every edge unambiguous, *and* every relevant entry-point category actually checked. As
more entry-point detectors get built (Phase 2), the achievable confidence ceiling rises
correspondingly — for a codebase that genuinely has no other invocation paths at all,
thorough HTTP-only checking really would eventually earn `high` confidence; we're just
not there yet, and the verdict should say so rather than imply otherwise.

## When status is `unknown`

Comes up when a call was skipped as ambiguous (see step 2 above) *and* that skip is the
only thing standing between a function and a possible path to an entry point — i.e. we
can't confirm a path, but can't rule one out either, because part of the picture is
genuinely uncertain, not because we didn't look. **For our actual 3 findings, this never
triggers** — every relevant edge (`do_POST → add_todo`, `do_GET → search_todos`, and the
total absence of any caller for `find_old_todos`) is unambiguous. It's a safety net for
messier code, not something today's test cases exercise.

## Why we're building this ourselves, not using a tool

### Techniques atom/Joern use, and what specifically went wrong

1. **Parse to an AST** — same first step anyone takes.
2. **Attempt full type inference to resolve every call**, including ambiguous ones like
   `connection.execute(...)` — tracing backward to figure out what type `connection`
   actually is. Sophisticated, and exactly the part that broke: hands-on trial against
   our sample app produced a **confirmed false positive** — `algorithms --type paths`
   reported a path from `do_GET`/`do_POST` to `find_old_todos`, which is genuinely dead
   code (zero real callers, verified by direct grep). Root cause, confirmed by
   inspecting atom's own `usages` output: `"resolvedMethod": null` on the `.execute()`
   call inside `find_old_todos` — it couldn't resolve which `execute` this was (no type
   hints anywhere), and the path search treated it as connectible anyway rather than
   declining.
3. **Automatic, generic source/sink tagging** meant to cover many frameworks at once
   (`framework-input`, `framework-output`, etc.) — trialed against a real Flask
   e-commerce app with known ground truth (6 genuinely reachable vulnerable functions,
   3 genuinely dead). Correctly found `find_products`, `promotion_message`,
   `receipt_text` — but **missed `verify_account`, `stock_message`, and `review_text`
   entirely**, three confirmed-reachable vulnerabilities silently absent from the
   output. Correctly reported zero false positives on the 3 dead functions, but the
   false negatives are the more dangerous failure mode for a security tool — silence
   reads as "safe," not "we didn't check."
4. Also hit a real internal crash (`NoSuchElementException`) on `export`, and required
   reverse-engineering an undocumented full-name format (`app.py:<module>.ClassName.method`)
   to get `algorithms --type paths` working at all.

### What we're doing differently, mapped to each failure

1. **No attempt at full type inference, ever, for the reachability question.** We only
   build an edge for calls we can resolve with certainty (plain names, `self.method()`).
   Ambiguous calls get no edge at all, not a guessed one. This isn't a lesser version of
   what atom tried — it's a deliberate refusal to attempt the specific thing that broke
   it, because **we don't need to.** Resolving *which* `.execute()` a call refers to was
   never required to answer "is `find_old_todos` itself ever called" — that's a
   plain-name question, and plain-name questions aren't ambiguous in Python regardless
   of how dynamically typed the rest of the language is.
2. **No big automatic classifier.** A small, explicit, pluggable list of entry-point
   detectors, each written and hands-on verified against real code, same discipline
   used to confirm `do_GET`/`do_POST` work. Narrower today, but every piece is something
   we wrote, tested, and can debug — not a black box with unpredictable blind spots.
3. **A much simpler pipeline** — parse, build a table, walk bodies, walk backward. Fewer
   interacting parts, less surface for the kind of internal bug that crashed atom's
   `export`, and when something *is* wrong, it's in our own Python, not a Scala pass we
   can't inspect.
4. **When genuinely unsure, `unknown`, never a guess** — structural, covered above.

### Also considered and rejected, full trail

- **Pysa** (Meta, built on Pyre) — actively maintained, real inter-procedural taint
  tracking. Rejected as primary tool: purpose-built for detecting taint flows, not a
  general reachability-query platform — would mean two tools instead of one.
- **`pyt`** — confirmed dead (last updated 2020).
- **Joern** — real, valid CPG platform, same reachability+taint capability as atom in
  principle, but heavier (JVM, Scala query DSL) and never hands-on trialed once atom's
  failures made the underlying language-level problem (ambiguous dynamic-typed method
  resolution) visible — a different implementation of the same hard technique was
  judged likely to hit a similar wall, not confirmed to.
- **CodeQL** — ruled out outright on licensing: free only for open-source/academic
  analysis of public repos; this project scans arbitrary uploaded codebases, including
  private ones, in a context that may become professional.
- **PyCG** — confirmed archived.
- **Scalpel, pyan3** — alive, real call-graph construction, lighter than atom/Joern, but
  neither does taint/dataflow — same gap as building it ourselves, just with more
  pre-built plumbing we'd still need to trust.
- **Bearer** — alive, real dataflow reporting, but solves an adjacent, differently-
  shaped problem (a scanner with better dataflow, not a general graph platform).
- **koknat/callGraph** — regex-based line-by-line pattern matching, not real parsing at
  all. Rejected quickly: this is a step backward from precision we'd already secured
  with `ast`-based parsing — vulnerable to exactly the things a real parser handles for
  free (multi-line calls, text inside strings/comments that merely looks like code,
  no concept of `self` vs. an ambiguous method call). Also doesn't do entry-point
  detection or reachability queries at all — we'd still build both ourselves on a less
  reliable foundation.

## Two scope decisions made during implementation, beyond the original design

- **A Flask entry-point detector was added alongside the `http.server` one**, beyond the
  "only what the todo app needs" scoping above — because the e-commerce app's real,
  verified ground truth (6 reachable, 3 dead) gives a much stronger correctness test
  than the todo app's 3 findings alone, and a second small detector was cheap given the
  pluggable design. Both detectors live in `entry_points.py`, independently testable.
- **`unknown`-status detection (tracking skipped ambiguous calls to see if they could
  plausibly form a path) was explicitly NOT built.** The schema supports the status
  value, but nothing in this implementation produces it via that path — every edge that
  exists is confident by construction, so every `reachable` verdict is trivially `high`
  confidence (no partial-confidence tier to track). The one place `status="unknown"`
  *is* produced: `resolve_containing_function()` returning no match (module-level code)
  — mapped to `unknown`/`low` rather than silently dropping the finding. Neither test
  app has a module-level finding, so this path is implemented but not exercised by the
  ground-truth tests.

## Real gap this surfaced, not a Phase 1 bug

`receipt_text` (e-commerce app, line 100) has **no real scanner finding** — neither a
real `semgrep scan --config=auto` nor Bandit flags its `Path(...) / name` +
`.read_text()` path-traversal pattern; the only path-traversal rule that fires in that
file catches a different line (`checkout()`'s write, not this read). Per "Out of scope:
scanner accuracy" (`docs/phase-0-foundations.md`), this is a scanner-coverage gap, not
something this project is responsible for — a `NormalizedFinding` was hand-constructed
for this one case so the ground-truth ledger still fully exercises the reachability
engine, documented clearly in `Ecommerce-app/ground_truth.md`, not smoothed over.

## Wired into the running app

`/api/scan` now also builds a call graph from the uploaded codebase's `.py` files and
returns a `reachability` array alongside `findings` (linked by `finding_id`, per the
"three linked records, not one merged object" design from `docs/phase-0-foundations.md`
— not merged into the finding objects). The frontend's "Reachability Analysis" tab shows
real data (`ReachabilityView.tsx`) instead of the placeholder, joining findings and
verdicts by `finding_id`, same list-then-detail pattern as the Findings tab.

One robustness fix made during wiring, not part of the original design: `build_call_graph`
now skips files that fail to parse (`SyntaxError`) rather than crashing the whole scan —
necessary once real, arbitrary uploaded code is actually going through this path, not
just two known-good sample apps.

Verified end to end against a real running server (not just pytest): uploading the todo
app through a live `/api/scan` call returns the exact same 3 correct verdicts confirmed
earlier, and both the FastAPI and Vite dev servers run together with no errors.

## Open questions

- Multi-file codebases: the function table is codebase-wide with no file-scoping for
  name collisions — both real test apps are single-file, so this hasn't been exercised.
  A real gap if two files ever define same-named functions differently.
- Whether `unknown`-status detection (tracked ambiguous-call plausibility) is worth
  building before or after broadening entry-point coverage (Phase 2) — no current test
  case needs it, revisit when one does.
