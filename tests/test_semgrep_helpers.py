import hashlib
from pathlib import Path

import pytest

from semgrep_adapter import extract_cwes, hash_id, normalize_path, read_snippet


def test_hash_id_matches_manual_sha256():
    expected = hashlib.sha256(b"semgrep|app.py|34").hexdigest()[:16]
    assert hash_id("semgrep", "app.py", 34) == expected


def test_hash_id_is_deterministic():
    assert hash_id("semgrep", "app.py", 34) == hash_id("semgrep", "app.py", 34)


def test_hash_id_differs_by_input():
    assert hash_id("semgrep", "app.py", 34) != hash_id("semgrep", "app.py", 39)


def test_extract_cwes_pulls_short_code_from_full_sentence():
    entries = ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
    assert extract_cwes(entries) == ["CWE-89"]


def test_extract_cwes_handles_multiple_entries():
    entries = ["CWE-89: SQL Injection", "CWE-79: Cross-site Scripting"]
    assert extract_cwes(entries) == ["CWE-89", "CWE-79"]


def test_extract_cwes_skips_entries_without_a_code():
    assert extract_cwes(["not a cwe entry"]) == []


def test_normalize_path_converts_backslashes():
    assert normalize_path("app\\utils\\db.py") == "app/utils/db.py"


def test_normalize_path_strips_leading_dot_slash():
    assert normalize_path("./app.py") == "app.py"


def test_read_snippet_single_line(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("line1\nline2\nline3\n")
    assert read_snippet(tmp_path, "sample.py", 2, None) == "line2"


def test_read_snippet_multi_line(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("line1\nline2\nline3\nline4\n")
    assert read_snippet(tmp_path, "sample.py", 2, 3) == "line2\nline3"
