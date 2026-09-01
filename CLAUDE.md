# Agentic Vulnerability Validation System

A service that validates scanner findings for reachability and exploitability, so
engineers focus on what matters instead of triaging noise by hand. Full goal, scope,
deployment modes, and constraints: [docs/project-design.md](docs/project-design.md).

## Controlled sample app

`src/sample-apps/todo-list-app/` — a small `http.server`-based todo app (no framework),
one file (`app.py`), 3 known SQL injection findings: `add_todo` and `search_todos` are
reachable (called from `TodoHandler.do_POST`/`do_GET`), `find_old_todos` is unreachable
(never called anywhere). Real Semgrep JSON already captured
(`semgrep_results.json`) — see `docs/phase-0-plan.md` for the full ground truth table
and an open question about Semgrep firing two rules per location (6 raw results for the
3 real bugs).

## Working style (how the user wants to collaborate on this)

- Go **phase by phase**, in detail, close to execution-ready — pseudocode expected, not
  just prose descriptions.
- The user asks a lot of follow-up questions and wants to build understanding
  incrementally — don't rush ahead to implementation before a phase's design is settled.
- Write a doc per phase in `docs/` capturing the design, decisions made, and open
  questions — **update it incrementally as decisions are settled, not just when a phase
  is "done."** Keep this file (`CLAUDE.md`) a lean index only — goal one-liner, fixture
  status, working style, phase table. Design rationale and detail belong in `docs/*.md`,
  written for a human reader trying to understand the project, not as agent context.
- When something is undecided, record it explicitly as an open question rather than
  silently picking an answer.

## Phase roadmap

| Phase | Description | Status | Doc |
|---|---|---|---|
| 0 | Contracts: finding schema + codebase input shape | **Done** — `src/` has the working pipeline (22/22 tests pass); `src/api.py` (FastAPI) and `src/frontend/` (React+TS, real upload/scan/findings UI) are the real product now — the old CLI proof script (`demo.py`) and static mockup have both been retired as redundant | [docs/phase-0-foundations.md](docs/phase-0-foundations.md), [docs/phase-0-plan.md](docs/phase-0-plan.md) |
| 1 | Reachability MVP: Python call graph, entry-point detection, backward traversal, path evidence | **Done** — `src/reachability/`, 34/34 real ground-truth findings correct across four apps (todo, e-commerce, salary_reachability_lab, celery_reachability_lab), 86/86 tests pass, wired into `/api/scan` and the frontend's Reachability Analysis tab, verified live; entry-point detectors cover HTTP handlers, decorator routes (Flask/FastAPI, with unmounted-router exclusion), Django URLconf, and Celery tasks (with unwired-Celery-app exclusion); call resolution also covers module-qualified calls, local class instantiation, and `BackgroundTasks.add_task`; "unreachable" is now split from a lower-confidence "unknown" when a call elsewhere is ambiguous rather than absent | [docs/phase-1-foundations.md](docs/phase-1-foundations.md) |
| 2 | Reachability hardening: confidence scoring, more entry-point types, benchmark suite | Not started | — |
| 3 | Taint/dataflow filter: is attacker input actually reaching the sink, not just control flow | Not started | — |
| 4/5 | Exploitability, split in two tiers — **Tier A**: static/LLM-reasoning judgment over the reachability path + code + taint signal, no sandbox, safe to run against any user-provided codebase, ships as part of MVP. **Tier B**: dynamic sandboxed confirmation (actually run + attack the target app) — scoped to controlled fixture apps only, never exposed on the arbitrary-URL path; a stretch goal, partial/imperfect is fine, purpose is to learn and document strategy/blockers, not to ship complete | Not started | [docs/phase-4-5-exploitability-notes.md](docs/phase-4-5-exploitability-notes.md) |
| 6 | Local CLI mode: package the engine as a standalone tool run on the user's own machine (scan runs client-side, only the results JSON — no source code — ever reaches the web viewer) | Not started, planned after Phase 4/5 progress | — |
| 7 | Prioritization & reporting: rank by evidence strength, inspectable trail, human override | Not started | — |
| 8 | Scale: more languages, scanners, frameworks | Not started | — |
| 9 | Continuous validation: diff-aware re-validation on new commits | Not started | — |

See [docs/project-design.md](docs/project-design.md) for goal/scope/constraints and
[docs/prior-art.md](docs/prior-art.md) for researched open-source and academic reference
projects gathered before committing to Phase 1's toolchain.
