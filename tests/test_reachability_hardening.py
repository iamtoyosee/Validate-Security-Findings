import pytest

from reachability.engine import build_call_graph, build_verdict
from schemas import NormalizedFinding

from reachability_cases import CASES, finding_line


def run_case(case):
    path, line = finding_line(case)
    finding = NormalizedFinding(
        finding_id=case.name, source_scanner="synthetic", rule_ids=["r"], vulnerability_type="r",
        cwe=[], severity="ERROR", file_path=path, line_start=line, line_end=None,
        column_start=None, message="", code_snippet=None, raw=[],
    )
    return build_verdict(finding, build_call_graph(case.files))


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_hardening_case(case):
    verdict = run_case(case)
    assert verdict.status == case.status, verdict.reason
    if case.entry is not None:
        assert verdict.entry_point == case.entry
    if case.confidence is not None:
        assert verdict.confidence == case.confidence
    if case.kind is not None:
        assert verdict.entry_point_kind == case.kind


def test_route_label_includes_the_mount_prefix():
    case = next(c for c in CASES if c.name == "blueprint_registered_with_prefix")
    assert run_case(case).entry_point_label == "GET /admin/exec"


def test_every_hop_carries_its_file_and_line():
    case = next(c for c in CASES if c.name == "self_attribute_instantiated_in_init")
    verdict = run_case(case)
    assert [h["file_path"] for h in verdict.call_path_locations] == ["app.py", "service.py", "repo.py"]
    assert verdict.call_path == ["search", "Service.search", "Repo.find"]


def test_auth_looking_decorators_are_reported_as_guards():
    files = {
        "app.py": "from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n"
                  "@app.route('/admin/run')\n@login_required\ndef run():\n    return os.popen(request.args['c']).read()\n",
    }
    finding = NormalizedFinding("g", "s", ["r"], "r", [], "ERROR", "app.py", 8, None, None, "", None, [])
    verdict = build_verdict(finding, build_call_graph(files))
    assert verdict.status == "reachable"
    assert verdict.entry_guards == ["login_required"]


def test_network_entry_is_preferred_over_startup_when_both_reach_the_finding():
    files = {
        "app.py": "from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n"
                  "def warm(name):\n    return os.popen('cat ' + name).read()\n\n"
                  "warm('cache')\n\n@app.route('/w')\ndef w():\n    return warm(request.args['n'])\n",
    }
    finding = NormalizedFinding("p", "s", ["r"], "r", [], "ERROR", "app.py", 6, None, None, "", None, [])
    verdict = build_verdict(finding, build_call_graph(files))
    assert verdict.entry_point == "w"
    assert verdict.confidence == "high"
    assert verdict.other_entry_points == ["import of app.py"]
