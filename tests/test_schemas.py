from schemas import ExploitabilityVerdict, NormalizedFinding, ReachabilityVerdict


def test_normalized_finding_instantiates():
    f = NormalizedFinding(
        finding_id="abc123",
        source_scanner="semgrep",
        rule_ids=["rule.one"],
        vulnerability_type="rule.one",
        cwe=["CWE-89"],
        severity="ERROR",
        file_path="app.py",
        line_start=34,
        line_end=34,
        column_start=9,
        message="test message",
        code_snippet=None,
        raw=[{}],
    )
    assert f.finding_id == "abc123"


def test_reachability_verdict_instantiates():
    v = ReachabilityVerdict(
        finding_id="abc123",
        status="reachable",
        confidence="high",
        containing_function="app.add_todo",
        entry_point="POST /add -> add_todo",
        call_path=["do_POST", "add_todo"],
        reason="Reachable via POST /add.",
    )
    assert v.status == "reachable"


def test_exploitability_verdict_instantiates():
    v = ExploitabilityVerdict(
        finding_id="abc123",
        status="not_confirmed",
        confidence="low",
        reason="Not yet attempted.",
    )
    assert v.status == "not_confirmed"
