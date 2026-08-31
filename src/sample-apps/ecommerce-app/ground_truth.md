# Ground truth — Ecommerce-app

Written independent of any tool output, as the answer key Phase 1 gets graded against.
Established by direct `grep`/manual reading of `app.py` during the earlier atom trial
(see `agentic-validation/docs/phase-1-foundations.md`, "Why we're building this
ourselves"), then re-confirmed here with a real `semgrep scan --config=auto --json` run
against this app (`semgrep_results.json`, 16 raw results, 12 of them in `app.py`).

9 findings total: 6 reachable, 3 unreachable.

## find_products (line 76)
- Expected: REACHABLE
- Why: called from `home()`, the `@app.route("/")` handler
- Semgrep rule_ids: [python.lang.security.audit.formatted-sql-query.formatted-sql-query,
  python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query]

## verify_account (line 84)
- Expected: REACHABLE
- Why: called from `login()`, the `@app.route("/login", methods=["GET", "POST"])`
  handler, on POST
- Semgrep rule_ids: (same two)

## stock_message (line 91)
- Expected: REACHABLE
- Why: called from `inventory()`, the `@app.route("/inventory")` handler
- Semgrep rule_ids: [python.lang.security.audit.subprocess-shell-true.subprocess-shell-true]

## promotion_message (line 95)
- Expected: REACHABLE
- Why: called from `promotion()`, the `@app.route("/promotion")` handler
- Semgrep rule_ids: [python.flask.security.audit.render-template-string.render-template-string]

## receipt_text (line 100)
- Expected: REACHABLE
- Why: called from `receipt()`, the `@app.route("/receipt")` handler
- Semgrep rule_ids: none — **gap, not a Phase 1 bug.** Neither a real `semgrep scan
  --config=auto` run nor Bandit (`bandit-output.json`) flags this line at all; the only
  path-traversal rule that fires in this file catches the *write* in `checkout()`
  (`app.py:183`, `python.flask.file.tainted-path-traversal-stdlib-flask`), not this
  `Path / name` then `.read_text()` read. Per `docs/phase-0-foundations.md` ("Out of
  scope: Scanner accuracy"), this project trusts a scanner's reported line and isn't
  responsible for a scanner's own coverage gaps — so the Phase 1 test suite constructs
  a `NormalizedFinding` by hand for this one, pointing at line 100, the same way it
  would look if a scanner had caught it.

## review_text (line 104)
- Expected: REACHABLE
- Why: called from `product()`, the `@app.route("/product/<int:product_id>", methods=[...])`
  handler, over each stored review row
- Semgrep rule_ids: [python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup]

## calculate_adjustment (line 115)
- Expected: UNREACHABLE
- Why: defined but never called anywhere in `app.py` (confirmed by grep)
- Semgrep rule_ids: [python.lang.security.audit.eval-detected.eval-detected]

## restore_preferences (line 119)
- Expected: UNREACHABLE
- Why: defined but never called anywhere in `app.py` (confirmed by grep)
- Semgrep rule_ids: [python.lang.security.deserialization.pickle.avoid-pickle]

## fetch_partner_feed (line 123)
- Expected: UNREACHABLE
- Why: defined but never called anywhere in `app.py` (confirmed by grep)
- Semgrep rule_ids: [python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected]
