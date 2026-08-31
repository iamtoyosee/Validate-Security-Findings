from pathlib import Path

from fastapi.testclient import TestClient

from api import app

SAMPLE_APP = Path(__file__).parent.parent / "src" / "sample-apps" / "todo-list-app"

client = TestClient(app)


def test_scan_todo_list_app_returns_three_findings_with_snippets():
    app_py = SAMPLE_APP / "app.py"
    with app_py.open("rb") as f:
        response = client.post(
            "/api/scan",
            files=[("files", ("todo-list-app/app.py", f, "text/x-python"))],
        )

    assert response.status_code == 200
    body = response.json()
    assert body["raw_result_count"] == 6

    findings = body["findings"]
    assert len(findings) == 3

    by_line = {f["line_start"]: f for f in findings}
    assert set(by_line.keys()) == {34, 39, 94}

    add_todo = by_line[34]
    assert add_todo["file_path"] == "todo-list-app/app.py"
    assert add_todo["severity"] == "ERROR"
    assert add_todo["cwe"] == ["CWE-89"]
    assert len(add_todo["rule_ids"]) == 2
    assert "raw" not in add_todo

    # every finding should have a real, non-empty snippet read from the uploaded file
    for f in findings:
        assert f["code_snippet"]
        assert isinstance(f["code_snippet"], str)


def test_scan_rejects_path_traversal_in_filename():
    # A crafted filename escaping the temp dir (e.g. via ../../..) must not be allowed
    # to write outside it - see api.py's containment check.
    response = client.post(
        "/api/scan",
        files=[("files", ("../../../tmp/evil.py", b"x = 1", "text/x-python"))],
    )
    assert response.status_code == 400
    assert "Invalid file path" in response.json()["detail"]


def test_scan_oversized_codebase_returns_413():
    big_content = "\n".join(f"x = {i}" for i in range(6000)).encode()

    response = client.post(
        "/api/scan",
        files=[("files", ("bigrepo/big.py", big_content, "text/x-python"))],
    )

    assert response.status_code == 413
    assert "too large to test right now" in response.json()["detail"]
