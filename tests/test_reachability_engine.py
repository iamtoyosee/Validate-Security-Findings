import ast
import json
from pathlib import Path

import pytest

from schemas import NormalizedFinding
from semgrep_adapter import from_semgrep, group_raw_results, hash_id

from reachability.engine import build_call_graph, build_verdict, trace_reachability

TODO_APP_DIR = Path(__file__).parent.parent / "src" / "sample-apps" / "todo-list-app"
ECOMMERCE_APP_DIR = Path("/Users/ausman/Workload/Ecommerce-app")


def load_todo_findings():
    raw = json.loads((TODO_APP_DIR / "semgrep_results.json").read_text())["results"]
    groups = group_raw_results(raw)
    findings = {f.line_start: f for f in (from_semgrep(g) for g in groups)}
    assert set(findings.keys()) == {34, 39, 94}
    return findings


def load_ecommerce_findings():
    raw = json.loads((ECOMMERCE_APP_DIR / "semgrep_results.json").read_text())["results"]
    target_lines = {76, 84, 91, 95, 104, 115, 119, 123}
    app_py_raw = [r for r in raw if r["path"] == "app.py" and r["start"]["line"] in target_lines]
    groups = group_raw_results(app_py_raw)
    findings = {f.line_start: f for f in (from_semgrep(g) for g in groups)}
    assert set(findings.keys()) == target_lines

    # receipt_text (line 100): a genuine scanner coverage gap, not a Phase 1 bug - see
    # ground_truth.md. Neither real Semgrep (`--config=auto`) nor Bandit flags this
    # `Path / name` then `.read_text()` read anywhere. Scanner accuracy is out of scope
    # for this project (docs/phase-0-foundations.md), so this finding is constructed by
    # hand, the same shape a scanner's output would take, to still exercise the pipeline
    # against this documented ground-truth function.
    findings[100] = NormalizedFinding(
        finding_id=hash_id("semgrep", "app.py", 100),
        source_scanner="semgrep",
        rule_ids=["constructed.path-traversal.receipt-read"],
        vulnerability_type="constructed.path-traversal.receipt-read",
        cwe=["CWE-22"],
        severity="WARNING",
        file_path="app.py",
        line_start=100,
        line_end=100,
        column_start=None,
        message="Hand-constructed finding - see ground_truth.md for why no real scanner flags this line.",
        code_snippet=None,
        raw=[],
    )
    return findings


def todo_graph():
    return build_call_graph({"app.py": (TODO_APP_DIR / "app.py").read_text()})


def ecommerce_graph():
    return build_call_graph({"app.py": (ECOMMERCE_APP_DIR / "app.py").read_text()})


def assert_verdict_matches(verdict, expected_function, expected_status, expected_entry):
    assert verdict.containing_function == expected_function
    assert verdict.status == expected_status
    if expected_status == "reachable":
        assert verdict.entry_point == expected_entry
        assert verdict.confidence == "high"
        assert verdict.call_path[0] == expected_entry
        assert verdict.call_path[-1] == expected_function
    else:
        assert verdict.entry_point is None
        assert verdict.call_path is None
        assert verdict.confidence == "medium"   # see phase-1-foundations.md, "two axes"
        assert "Other entry-point types" in verdict.reason


# ---- Todo app: 3 real findings (real semgrep_results.json), full pipeline ----

TODO_EXPECTED = {
    34: ("add_todo", "reachable", "TodoHandler.do_POST"),
    39: ("search_todos", "reachable", "TodoHandler.do_GET"),
    94: ("find_old_todos", "unreachable", None),
}


@pytest.mark.parametrize("line", [34, 39, 94])
def test_todo_app_verdicts_match_ground_truth(line):
    verdict = build_verdict(load_todo_findings()[line], todo_graph())
    assert_verdict_matches(verdict, *TODO_EXPECTED[line])


# ---- Ecommerce app: 9 real/documented findings, full pipeline ----

ECOMMERCE_EXPECTED = {
    76: ("find_products", "reachable", "home"),
    84: ("verify_account", "reachable", "login"),
    91: ("stock_message", "reachable", "inventory"),
    95: ("promotion_message", "reachable", "promotion"),
    100: ("receipt_text", "reachable", "receipt"),
    104: ("review_text", "reachable", "product"),
    115: ("calculate_adjustment", "unreachable", None),
    119: ("restore_preferences", "unreachable", None),
    123: ("fetch_partner_feed", "unreachable", None),
}


@pytest.mark.parametrize("line", [76, 84, 91, 95, 100, 104, 115, 119, 123])
def test_ecommerce_app_verdicts_match_ground_truth(line):
    verdict = build_verdict(load_ecommerce_findings()[line], ecommerce_graph())
    assert_verdict_matches(verdict, *ECOMMERCE_EXPECTED[line])


# ---- Synthetic multi-hop traversal - neither real app happens to need more than 1 hop ----

SYNTHETIC_MULTI_HOP_SOURCE = """
from http.server import BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        return self.layer_one("x")

    def layer_one(self, value):
        return layer_two(value)


def layer_two(value):
    return layer_three(value)


def layer_three(value):
    return vulnerable_sink(value)


def vulnerable_sink(value):
    return f"unsafe {value}"


def dead_function():
    return "never called by anything"
"""

EXPECTED_CHAIN = [
    "Handler.do_GET",
    "Handler.layer_one",
    "layer_two",
    "layer_three",
    "vulnerable_sink",
]


def test_multi_hop_traversal_walks_the_full_chain_not_just_one_level():
    graph = build_call_graph({"synthetic.py": SYNTHETIC_MULTI_HOP_SOURCE})
    assert trace_reachability(graph, "vulnerable_sink") == EXPECTED_CHAIN


def test_multi_hop_traversal_reports_no_path_for_genuinely_dead_code():
    graph = build_call_graph({"synthetic.py": SYNTHETIC_MULTI_HOP_SOURCE})
    assert trace_reachability(graph, "dead_function") is None


def test_multi_hop_traversal_verdict_end_to_end():
    sink_line = next(
        node.body[0].lineno
        for node in ast.walk(ast.parse(SYNTHETIC_MULTI_HOP_SOURCE))
        if isinstance(node, ast.FunctionDef) and node.name == "vulnerable_sink"
    )
    finding = NormalizedFinding(
        finding_id="synthetic-1",
        source_scanner="semgrep",
        rule_ids=["synthetic-rule"],
        vulnerability_type="synthetic-rule",
        cwe=["CWE-000"],
        severity="ERROR",
        file_path="synthetic.py",
        line_start=sink_line,
        line_end=None,
        column_start=None,
        message="synthetic",
        code_snippet=None,
        raw=[],
    )
    verdict = build_verdict(finding, build_call_graph({"synthetic.py": SYNTHETIC_MULTI_HOP_SOURCE}))

    assert verdict.status == "reachable"
    assert verdict.confidence == "high"
    assert verdict.containing_function == "vulnerable_sink"
    assert verdict.entry_point == "Handler.do_GET"
    assert verdict.call_path == EXPECTED_CHAIN


def test_unparseable_file_is_skipped_not_fatal():
    """Uploaded code can be anything - a syntax error in one file shouldn't crash the scan."""
    good = "def add_todo(title):\n    pass\n"
    broken = "def broken(:\n    this is not python\n"
    graph = build_call_graph({"good.py": good, "broken.py": broken})
    assert any(f.qualified_name == "add_todo" for f in graph.functions)
    assert not any(f.file_path == "broken.py" for f in graph.functions)
