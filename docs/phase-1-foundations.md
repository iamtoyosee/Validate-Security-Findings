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

**A generic "decorated + zero incoming edges = possible entry point, medium confidence"
heuristic was seriously considered for Phase 2, to cover unknown/future frameworks
without hand-writing a detector for each one — and rejected.** A pile of medium-
confidence "maybe reachable" findings doesn't actually reduce triage work; it still
needs manual review, and a noisy guess-tier risks eroding trust in the confident results
sitting next to it. Verified via real research (not assumed) that this rejection is
correct, not just a matter of taste: **CodeQL and Joern both handle entry/source
detection the exact same way we do — a curated, hand-maintained list of known framework
patterns, one model per framework** (CodeQL has a literal `Flask.qll` modeling file;
Joern calls the same concept "semantics"). Neither has a smarter generic mechanism.
"Curate a list, prioritized by real-world popularity" isn't a lesser, homegrown
approach — it's the actual industry standard, just with decades more entries than our
two. The path forward is the same: keep adding hand-written, high-confidence detectors
for real frameworks in order of actual usage, and lean on the existing "unreachable is
capped at medium confidence" caveat to honestly cover whatever we haven't gotten to yet
— not invent a new, noisier uncertainty tier.

**Also checked and ruled out**: Python's WSGI/ASGI (PEP 3333 and successor), the
standardized low-level interface Flask/Django/FastAPI/Starlette all implement
underneath their different high-level APIs. Real and detectable, but wrong granularity
— it tells you "this file exposes a web app," not which specific function handles which
specific URL, which sits on top of WSGI/ASGI and differs per framework. Not a shortcut
past per-framework route modeling.

**A genuinely interesting, honest trade-off surfaced by this research, worth naming
explicitly rather than treating as free**: Joern's own docs state that when it has no
model for a method, its default is to *assume* taint propagates through it anyway —
"sound, but imprecise... could result in `reachableBy` returning additional and
unrelated paths." That's the actual, documented mechanism behind the `find_old_todos`
false positive from our earlier atom trial — not a bug, but Joern/atom's lineage
choosing soundness over precision by design (when uncertain, assume connected, because
missing a real vulnerability is worse than flagging an extra one). Our engine makes the
opposite bet (no edge when uncertain, see "Resolving a call name" above) — precision
over soundness. Neither choice is free: Joern's approach optimizes against false
negatives, which is genuinely the thing we've said matters most for a security tool;
ours avoided the specific `find_old_todos` error only because that uncertainty (which
`.execute()` a call resolves to) was unrelated to the actual question being asked
(whether `find_old_todos` itself has any caller at all) — a different, more clearly
wrong kind of error than an honest "unsure, erring toward caution." This is a real,
deliberate trade-off this project is making, not a cost-free improvement over Joern.

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

## Post-launch update: rename + two more detectors (Phase 2 groundwork, done early)

`detect_flask_entry_points()` was renamed to `detect_decorator_route_entry_points()`
(constant: `DECORATOR_ROUTE_METHODS`). It matches on decorator *attribute name*
(`get`/`post`/etc.), never a specific framework object, so it already covered FastAPI
(and, untested but same decorator shape, Starlette/Sanic/bottle) with zero logic
changes — the old Flask-specific name was just inaccurate, not wrong.

Two more detectors were added, both following the same "curated, hand-written,
prioritized by real-world popularity" approach argued for above, not the rejected
generic heuristic:

- **`detect_django_entry_points()`** — Django's URLconf is structurally different from
  decorators: routes live in a separate module-level `urlpatterns` list
  (`path("admin/", views.admin_view)`), not attached to the view function itself. Finds
  `path`/`re_path`/`url` calls (by name, whether imported directly or via a module
  prefix like `django.urls.path`) and extracts the view reference's final name
  component — deliberately not general multi-file call resolution, just a name
  extraction that works because the function table is already codebase-wide.
- **`detect_celery_entry_points()`** — a genuinely different entry-point *category*
  (message queue, not HTTP). Handles two decorator shapes: bare `@shared_task`/`@task`
  (called or not) and attribute-style `@app.task`.

Both wired into `DEFAULT_ENTRY_POINT_DETECTORS`; `build_verdict`'s unreachable reason
text updated to mention Django/Celery alongside HTTP.

## Post-launch update: four real bugs found by a harder test app, plus the unreachable/unknown split

A second real, hand-built FastAPI app (`salary_reachability_lab`, 6 reachable + 6
unreachable ground-truth findings) exercised call shapes the todo/e-commerce apps never
happened to use — a router that's decorated but never mounted, calls made through a
module prefix (`services.find_employees(...)`), a locally-instantiated class
(`services.SalaryCalculator()` then `.calculate(...)`), and a function scheduled via
`BackgroundTasks.add_task(...)` rather than called outright. All four exposed real bugs:
2 false positives (dead code reported reachable) and 5 false negatives (real vulnerable
code reported unreachable), across the app's 12 findings.

**Shared groundwork: `build_import_table()`.** All three call-resolution fixes below
need the same fact: "what does this bare name refer to, given this file's imports."
Python's import statement already answers this statically and unambiguously — no
guessing, unlike resolving an arbitrary variable's type. One utility in `graph.py` parses
`import X [as Y]` and `from module import X [as Y]` at module level into `local name ->
canonical original name` (identity when there's no `as`), used by both `graph.py` and
`entry_points.py` instead of three separate ad-hoc parsers.

**Fix 1 — a decorated-but-unmounted router was wrongly counted as an entry point.**
`detect_decorator_route_entry_points()` matched `@X.method(...)` on decorator shape
alone, with no check on whether `X` was ever actually wired into the app. Now it also
collects every `X = APIRouter(...)` assignment (X is a *tracked router name*) and every
name ever passed to `.include_router(...)` anywhere in the codebase — resolved through
that call site's own import table first, since a mounted router is usually imported
under a local alias (`from app.routes.public import router as public_router`, then
`include_router(public_router)` — the import table maps `public_router` back to its
canonical `router`). A decorated function only loses entry-point status when its
decorator's object is a *tracked* router name that never shows up in any
`include_router(...)` call. Anything else decorating — the FastAPI/Flask `app` object
itself, which is never verified, or a router that *is* mounted — is unaffected. This is
exactly the shape of `orphan_routes.py`: an `APIRouter` decorated with real routes, never
imported or mounted anywhere in `main.py`.

**Fix 2 — module-qualified calls weren't resolved at all.** `build_call_edges()` only
matched a bare name or `self.method()`; `services.find_employees(name)` fell through to
"ambiguous, no edge," even though `services` is a plain module import — every bit as
unambiguous as a bare name, just spelled with a prefix. Extended: `name.attr(...)` is now
resolved with the same confidence as a bare call whenever `name` is a key in that file's
import table, looking up `attr` by bare name in the master function table exactly like an
existing bare call would. This is categorically different from `connection.execute(...)`
where `connection` is a local variable of untracked type (assigned from some function's
return value, not an import) — that case is *not* weakened; it still builds no edge. The
distinguishing question is simply: was this name imported, or merely assigned?

**Fix 3 — a local `ClassRef()` then `.method()` in the same function body wasn't
resolved.** `calculator = services.SalaryCalculator()` followed by
`calculator.calculate(...)` is neither a bare call nor `self.anything` — genuinely a new
shape. Within one function's body (assignment order only, no cross-function tracking),
track `name -> ClassName` whenever `name = ClassRef()` where `ClassRef` is a bare
imported class name or `module.ClassName`. A later `name.method(...)` in the *same*
function resolves to `ClassName.method` in the master table, the same qualification
`build_function_table()` already uses for methods. **The one non-obvious judgment call
here**: "class instantiation" is gated on `ClassName` being a class our own function
table actually knows about (i.e., some `ClassName.something` qualified name exists) —
not just any `module.attr()` call assigned to a variable. Without that gate, this fix
would also swallow `connection = sqlite3.connect(DATABASE)`, syntactically identical to a
real instantiation, and then silently "resolve" the deliberately-unresolved
`connection.execute(...)` pattern this whole project is built around refusing to guess
at. Reassignment to something else drops the tracked name outright rather than guessing
which assignment is "the real one," per the original scoping — no attempt at
conditionals or other control flow.

**Fix 4 — `BackgroundTasks.add_task(fn, ...)` doesn't call `fn`, it schedules it.**
`background_tasks.add_task(services.decode_payroll_import, payload)` passes
`decode_payroll_import` as a *value*, never as a call — `build_call_edges()` never saw
it at all. Added as its own case, independent of what object `add_task` is called on
(a `BackgroundTasks` parameter is neither self, an import, nor a fix-3 local): whenever a
call's method name is `add_task`, its first positional argument is resolved as a
callable reference (bare name, or `module.function` via the same import table as fix 2)
and an edge is added from the containing function to that reference — a call *edge*,
not an entry point, since nothing here changes who's reachable from outside, only what a
reachable function itself reaches.

### The unreachable/unknown split

"Unreachable" used to conflate two different situations: a function with genuinely zero
callers anywhere (`legacy_jobs.py` — strong signal), and a function whose only path in
runs through a call we deliberately declined to resolve (`connection.execute(...)`) — we
can *see* something calling toward it, we just can't verify who. Both used to come out as
a confident `"unreachable"`/`"medium"`.

Fixed by having `build_call_edges()` return a second value alongside `edges`:
`unresolved_call_targets`, the set of attribute names seen in every call that fell
through to the genuinely-ambiguous case (not self, not an import, not a fix-3 local
instantiation — the exact same gate that already decided "no edge gets built," just now
also recording what was being called). `CallGraph` carries this as a new field.
`build_verdict()`'s "no path found" branch now checks whether the containing function's
bare name (stripping any `ClassName.` prefix) appears in that set. If it does: status
`"unknown"`, confidence `"low"`, reason explaining that a call elsewhere targets a
same-named function through an unverifiable pattern, so reachability can't be
confidently ruled out. If it doesn't: unchanged `"unreachable"`/`"medium"` — the
genuinely-zero-callers-anywhere case stays exactly as it was.

**This is a name-based heuristic, not a type-based one — stated plainly, not hidden.**
An unrelated function that happens to share a name with something called ambiguously
elsewhere (two unrelated `execute` methods in a large codebase) also gets downgraded to
`"unknown"`, even though the ambiguous call was never actually going to reach it. This is
the same trade-off already accepted for the Celery bare-decorator match (`@task` matches
by name, not by verifying which `task` decorator it is) — a deliberate bet that a few
extra low-confidence "unknown" results are a better failure mode than a confidently wrong
"unreachable" on a real vulnerability. Verified this doesn't regress either real app's
ground truth: neither `find_old_todos` (todo app) nor `calculate_adjustment` /
`restore_preferences` / `fetch_partner_feed` (e-commerce app) happen to share a name with
anything called ambiguously in their own codebases, so all four stay `"unreachable"`/
`"medium"` exactly as before.

**A minor, harmless side effect surfaced during this work, worth naming rather than
smoothing over**: a route decorator itself (`@router.get("/employees")`) is a `Call`
node attached to the function it decorates, and the existing call-body walker already
treated decorator calls as part of "this function's own body" before this fix existed —
it just silently discarded them. Now that ambiguous attribute calls get recorded, a
decorator like `@router.get(...)` (where `router` isn't a tracked APIRouter variable
resolvable another way) adds `"get"`/`"post"` to `unresolved_call_targets` too. Harmless
for every real finding checked so far — no vulnerable function happens to be named `get`
or `post` — but a real, if narrow, source of future false "unknown" results worth keeping
in mind as more real apps get tried.

Verified against all 10 of `salary_reachability_lab`'s documented ground-truth
`file:line` findings (both apps' original 12 ground-truth findings unaffected) — 10/10
correct, reachable and unreachable alike, tracing the exact call chains through routers,
module-qualified calls, a locally-instantiated class, and a background task.

## Post-launch update: an orphan Celery app was wrongly trusted, same class of bug as Fix 1

A fourth real, hand-built app (`celery_reachability_lab`, 6 reachable + 6 unreachable
ground-truth findings) surfaced the Celery equivalent of Fix 1's unmounted-router bug.
`detect_celery_entry_points()` matched `@X.task(...)` on decorator shape alone, with no
check on whether `X`'s app is ever actually wired up to load the file the decorated
function lives in. The app has `celery_app.py` (`celery_app = Celery(..., include=
["tasks"])`, six real tasks in `tasks.py`) alongside `orphan_tasks.py` (`orphan_app =
Celery("retired_worker", broker="memory://")`, no `include=`, two tasks nothing ever
loads) — the detector trusted both, wrongly marking the orphan's two tasks reachable.

**The fix applies only to attribute-style decorators (`@X.task`).** Bare `@task`/
`@shared_task` stays unconditionally trusted, unchanged - Celery's own bare decorator is
intentionally app-agnostic, not a per-app registration.

For `@X.task`, `X` is resolved back to its `Celery(...)` instantiation the same way Fix
1 resolves a mounted router's alias - same file, or via `build_import_table()` if
imported. Then:

1. **If it's the only `Celery(...)` instance anywhere in the codebase**, trust
   unconditionally - the common single-app case, which often has no `include=` at all,
   must keep working exactly as before this fix.
2. **If `X` can't be resolved to any tracked instance at all**, also trust
   unconditionally - same default as an unrecognized `app`/`api` object in Fix 1: we
   never try to verify what we can't identify.
3. **Otherwise** (two or more tracked `Celery(...)` instances, and `X` is one of them), a
   decorated function counts as an entry point only if its own file is reachable through
   a real, verifiable loading channel:
   - named in `X`'s own `include=[...]` (a list of module name strings - `"tasks"` →
     `tasks.py`, `"app.tasks"` → `app/tasks.py`, the same module→file conversion Python's
     own import system uses), or
   - `X.autodiscover_tasks(...)` appears anywhere in the codebase - presence alone is
     treated as a real, explicit configuration signal, not something resolved further
     (attempting to reason about what it actually discovers would be a guess, the
     opposite of this project's whole approach), or
   - the file is plainly imported anywhere else in the codebase, checked across every
     file's own imports, not just one (same codebase-wide scope `build_import_table`
     already uses).

   If none hold, the function is confidently **not** an entry point - no `unknown`
   fallback here. Unlike an ambiguous `.execute()` call, whether a file is named in an
   `include=` list or plainly imported is a structural fact straight out of the AST, the
   same certainty class as every other confident edge this project builds.

**A fourth candidate channel was deliberately left out: "same file as `X`'s own
instantiation."** It reads like a real signal - plenty of small real Celery apps put the
app object and its tasks in one file - but it isn't independently verifiable, and
implementing it as an unconditional pass would have silently re-admitted the exact bug
being fixed: `orphan_app`'s two tasks live in the very file that instantiates it
(`orphan_tasks.py`), with no `include=`, no `autodiscover_tasks`, and no import from
anywhere else. A "same file" free pass would have called that reachable again. Worked
through by hand: whenever "same file" is legitimately true, it's already exactly the
plain-import check above the moment anything actually needs that file (as `tasks.py`
needing `celery_app.py`'s `celery_app` object already makes `celery_app.py` importable-
elsewhere in this very app) - and when nothing does, "same file" is indistinguishable
from guessing that this particular `Celery()` call happens to be the one some worker's
`-A` flag points at, which is exactly the ambiguity below, not a resolved fact.

**Documented, deliberately unsolved limitation**: even once a Celery app's file is
confirmed loaded through one of the three channels above, there is no source-level way
to tell whether that specific app is ever actually run as a worker versus only used as a
client to send tasks to some other worker - `-A <module>` is a deployment-time CLI
argument, not something any Python source file states. Not solved here, recorded as an
open question rather than guessed at.

Verified against all 12 of `celery_reachability_lab`'s documented ground-truth
`file:line` findings (all three earlier apps' 22 ground-truth findings unaffected) -
12/12 correct: the six real tasks' full call chains (task → service → repository, task →
locally-instantiated class, task → service) all reachable, `orphan_app`'s two tasks
correctly unreachable, and `legacy_jobs.py`'s four zero-caller functions (unrelated to
this fix) still correctly unreachable. 85/85 tests pass, zero regressions.
