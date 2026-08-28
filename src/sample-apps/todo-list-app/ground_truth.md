# Ground truth — todo-list-app

Written independent of any tool output, as the answer key Phase 1 gets graded against
later. 3 entries, matching the 3 grouped `NormalizedFinding` records (grouped down from
6 raw Semgrep results — see `docs/phase-0-foundations.md`, "Same-location grouping").

## add_todo (line 34)
- Expected: REACHABLE
- Why: called from `TodoHandler.do_POST` when path == "/add"
- Semgrep rule_ids: [python.lang.security.audit.formatted-sql-query.formatted-sql-query,
  python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query]

## search_todos (lines 39-41)
- Expected: REACHABLE
- Why: called from `TodoHandler.do_GET` when `?q=` is present
- Semgrep rule_ids: (same two)

## find_old_todos (lines 94-96)
- Expected: UNREACHABLE
- Why: defined but never called anywhere in app.py
- Semgrep rule_ids: (same two)
