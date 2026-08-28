import hashlib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Optional

from schemas import NormalizedFinding

SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def run_semgrep(codebase_path: Path) -> list[dict]:
    # --config=auto requires network access and does not support --metrics=off
    # (semgrep refuses to run auto config selection with metrics disabled)
    result = subprocess.run(
        ["semgrep", "scan", "--config=auto", "--json"],
        cwd=codebase_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)["results"]


def group_raw_results(raw_results: list[dict]) -> list[list[dict]]:
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for r in raw_results:
        key = (r["path"], r["start"]["line"])
        groups[key].append(r)
    return list(groups.values())


def hash_id(*parts: str) -> str:
    joined = "|".join(str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def extract_cwes(cwe_entries: list[str]) -> list[str]:
    codes = []
    for entry in cwe_entries:
        match = re.match(r"(CWE-\d+)", entry)
        if match:
            codes.append(match.group(1))
    return codes


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").removeprefix("./")


def read_snippet(codebase_root: Path, file_path: str, line_start: int, line_end: Optional[int]) -> str:
    end = line_end or line_start
    lines = (codebase_root / file_path).read_text().splitlines()
    return "\n".join(lines[line_start - 1 : end])   # line numbers are 1-indexed, list slicing isn't


def from_semgrep(raw_group: list[dict]) -> NormalizedFinding:
    primary = raw_group[0]   # representative record for display fields
    all_cwes = []
    for r in raw_group:
        for code in extract_cwes(r["extra"]["metadata"].get("cwe", [])):
            if code not in all_cwes:
                all_cwes.append(code)
    highest_severity = max(
        (r["extra"]["severity"] for r in raw_group),
        key=lambda s: SEVERITY_RANK.get(s, 0),
    )
    return NormalizedFinding(
        finding_id=hash_id("semgrep", primary["path"], primary["start"]["line"]),
        source_scanner="semgrep",
        rule_ids=[r["check_id"] for r in raw_group],
        vulnerability_type=raw_group[0]["check_id"],   # == rule_ids[0], see phase-0-foundations.md
        cwe=all_cwes,
        severity=highest_severity,
        file_path=normalize_path(primary["path"]),
        line_start=primary["start"]["line"],
        line_end=primary["end"]["line"],
        column_start=primary["start"]["col"],
        message=primary["extra"]["message"],
        code_snippet=None,   # filled in later via read_snippet() against the materialized local codebase
        raw=raw_group,
    )
