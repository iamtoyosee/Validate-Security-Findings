import json
from pathlib import Path

from semgrep_adapter import from_semgrep, group_raw_results, hash_id

SEMGREP_RESULTS = (
    Path(__file__).parent.parent
    / "src" / "sample-apps" / "todo-list-app" / "semgrep_results.json"
)

FORMATTED_SQL_RULE = "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
SQLALCHEMY_RULE = "python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query"


def test_group_raw_results_groups_by_exact_file_and_line():
    raw = [
        {"path": "a.py", "start": {"line": 10}},
        {"path": "a.py", "start": {"line": 10}},
        {"path": "a.py", "start": {"line": 20}},
        {"path": "b.py", "start": {"line": 10}},
    ]

    groups = group_raw_results(raw)

    assert len(groups) == 3
    sizes = sorted(len(g) for g in groups)
    assert sizes == [1, 1, 2]
    doubled = next(g for g in groups if len(g) == 2)
    assert all(r["path"] == "a.py" and r["start"]["line"] == 10 for r in doubled)


def load_real_findings():
    raw_results = json.loads(SEMGREP_RESULTS.read_text())["results"]
    assert len(raw_results) == 6
    groups = group_raw_results(raw_results)
    assert len(groups) == 3
    findings = {f.line_start: f for f in (from_semgrep(g) for g in groups)}
    return findings


def test_from_semgrep_groups_six_raw_results_into_three_findings():
    findings = load_real_findings()
    assert set(findings.keys()) == {34, 39, 94}


def test_from_semgrep_add_todo():
    f = load_real_findings()[34]
    assert f.finding_id == hash_id("semgrep", "app.py", 34)
    assert f.source_scanner == "semgrep"
    assert f.rule_ids == [FORMATTED_SQL_RULE, SQLALCHEMY_RULE]
    assert f.vulnerability_type == FORMATTED_SQL_RULE
    assert f.cwe == ["CWE-89"]
    assert f.severity == "ERROR"  # higher of WARNING/ERROR across the group
    assert f.file_path == "app.py"
    assert f.line_start == 34
    assert f.line_end == 34
    assert f.column_start == 9
    assert f.message == "Detected possible formatted SQL query. Use parameterized queries instead."
    assert f.code_snippet is None
    assert len(f.raw) == 2


def test_from_semgrep_search_todos():
    f = load_real_findings()[39]
    assert f.rule_ids == [FORMATTED_SQL_RULE, SQLALCHEMY_RULE]
    assert f.cwe == ["CWE-89"]
    assert f.severity == "ERROR"
    assert f.file_path == "app.py"
    assert f.line_start == 39
    assert f.line_end == 41
    assert f.column_start == 16
    assert len(f.raw) == 2


def test_from_semgrep_find_old_todos_unreachable_bug_still_normalizes_correctly():
    f = load_real_findings()[94]
    assert f.rule_ids == [FORMATTED_SQL_RULE, SQLALCHEMY_RULE]
    assert f.cwe == ["CWE-89"]
    assert f.severity == "ERROR"
    assert f.file_path == "app.py"
    assert f.line_start == 94
    assert f.line_end == 96
    assert f.column_start == 12
    assert len(f.raw) == 2
