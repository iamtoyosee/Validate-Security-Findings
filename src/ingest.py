"""Findings-in: turn a scanner's output file into NormalizedFinding records.

This is the "findings-provided" deployment mode from docs/project-design.md: the caller
already ran their scanners (in CI, say) and hands us the results next to the code. Each
adapter does the same two things the Semgrep adapter always did - group a scanner's own
results that point at the same place, then normalize - and nothing else. Recognizing
the same bug across *different* scanners is dedupe.py's job.

Formats understood, detected from the document itself:
- Semgrep JSON (`semgrep scan --json`)
- Bandit JSON (`bandit -f json`)
- SARIF 2.1.0 (CodeQL, Semgrep `--sarif`, most commercial tools, and this app's own export)
- this app's own JSON export
- a plain JSON list of {file, line, ...} objects, for anything else
"""

import json
import re
from collections import defaultdict
from typing import Optional
from urllib.parse import unquote, urlparse

from schemas import NormalizedFinding
from semgrep_adapter import extract_cwes, from_semgrep, group_raw_results, hash_id, normalize_path

SEVERITY_RANK = {
    "CRITICAL": 4, "ERROR": 3, "HIGH": 3, "WARNING": 2, "MEDIUM": 2, "INFO": 1, "LOW": 1, "NOTE": 1, "NONE": 0,
}
# Bandit checks that describe a habit, not a location where something can go wrong:
# "you imported subprocess", "you used assert". They'd arrive as findings with nothing
# to trace, so they're dropped at the door and counted in the response instead.
BANDIT_INFORMATIONAL = re.compile(r"^(B4\d\d|B101)$")


class FindingsFormatError(ValueError):
    """The uploaded findings file isn't something we know how to read."""


def highest_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_RANK.get(str(s).upper(), 0)) if severities else "INFO"


def detect_format(doc) -> str:
    if isinstance(doc, dict):
        if isinstance(doc.get("runs"), list):
            return "sarif"
        if doc.get("tool") == "validate-security-findings" and isinstance(doc.get("findings"), list):
            return "validated-export"
        results = doc.get("results")
        if isinstance(results, list):
            if any(isinstance(r, dict) and "check_id" in r for r in results):
                return "semgrep"
            if any(isinstance(r, dict) and "test_id" in r for r in results):
                return "bandit"
            if not results:
                return "semgrep" if "paths" in doc or "version" in doc else "bandit" if "metrics" in doc else "empty"
        if isinstance(doc.get("findings"), list):
            return "generic"
    if isinstance(doc, list):
        return "generic"
    raise FindingsFormatError(
        "Unrecognized findings format. Supported: Semgrep JSON, Bandit JSON, SARIF 2.1.0, "
        "or a JSON list of objects with at least a file and a line."
    )


def parse_findings_document(name: str, data: bytes) -> tuple[str, list[NormalizedFinding], int]:
    """Returns (format, findings, raw_result_count). Raises FindingsFormatError."""
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FindingsFormatError(f"{name} is not valid JSON ({error}).") from error

    fmt = detect_format(doc)
    try:
        if fmt == "semgrep":
            raw = [r for r in doc["results"] if isinstance(r, dict)]
            return fmt, [from_semgrep(g) for g in group_raw_results(raw)], len(raw)
        if fmt == "bandit":
            return (fmt, *from_bandit(doc["results"]))
        if fmt == "sarif":
            return (fmt, *from_sarif(doc))
        if fmt == "validated-export":
            return (fmt, *from_generic(doc["findings"]))
        if fmt == "generic":
            return (fmt, *from_generic(doc["findings"] if isinstance(doc, dict) else doc))
    except (KeyError, TypeError, AttributeError) as error:
        raise FindingsFormatError(f"{name} looks like {fmt} output but is missing expected fields ({error!r}).") from error
    return fmt, [], 0


def _build(scanner: str, records: list[dict]) -> list[NormalizedFinding]:
    """Group one scanner's records by (file, line) and normalize each group.

    A record is our own small intermediate shape: rule_id, file, line, end_line, column,
    cwe (list), severity, message, raw.
    """
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for record in records:
        groups[(record["file"], record["line"])].append(record)

    findings = []
    for (file_path, line), group in groups.items():
        primary = group[0]
        cwes: list[str] = []
        for record in group:
            for code in record["cwe"]:
                if code not in cwes:
                    cwes.append(code)
        rule_ids = list(dict.fromkeys(r["rule_id"] for r in group))
        ends = [r["end_line"] for r in group if r["end_line"]]
        findings.append(NormalizedFinding(
            finding_id=hash_id(scanner, file_path, line),
            source_scanner=scanner,
            rule_ids=rule_ids,
            vulnerability_type=rule_ids[0],
            cwe=cwes,
            severity=highest_severity([r["severity"] for r in group]),
            file_path=file_path,
            line_start=line,
            line_end=max(ends) if ends else line,
            column_start=primary["column"],
            message=primary["message"],
            code_snippet=None,
            raw=[r["raw"] for r in group],
            scanners=[scanner],
        ))
    return findings


def from_bandit(results: list[dict]) -> tuple[list[NormalizedFinding], int]:
    records = []
    for r in results:
        if BANDIT_INFORMATIONAL.match(str(r.get("test_id", ""))):
            continue
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        line_range = r.get("line_range") or [r["line_number"]]
        records.append({
            "rule_id": f"bandit.{r['test_id']}.{r.get('test_name', '')}".rstrip("."),
            "file": normalize_path(r["filename"]),
            "line": r["line_number"],
            "end_line": max(line_range),
            "column": (r.get("col_offset") or 0) + 1 if r.get("col_offset") is not None else None,
            "cwe": [f"CWE-{cwe_id}"] if cwe_id else [],
            "severity": str(r.get("issue_severity", "LOW")).upper(),
            "message": r.get("issue_text", ""),
            "raw": r,
        })
    return _build("bandit", records), len(results)


def _sarif_uri_to_path(uri: str) -> str:
    parsed = urlparse(uri)
    path = unquote(parsed.path if parsed.scheme in ("file", "") else uri)
    return normalize_path(path)


def _sarif_scanner_name(run: dict) -> str:
    name = str(run.get("tool", {}).get("driver", {}).get("name", "sarif")).lower()
    for known in ("semgrep", "bandit", "codeql", "snyk", "sonar", "checkmarx", "trivy"):
        if known in name:
            return known
    return re.sub(r"[^a-z0-9]+", "-", name).strip("-") or "sarif"


def _sarif_severity(result: dict, rule: dict) -> str:
    score = (result.get("properties") or {}).get("security-severity") or (rule.get("properties") or {}).get("security-severity")
    try:
        score = float(score)
        return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    except (TypeError, ValueError):
        pass
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}.get(str(level).lower(), "WARNING")


def _sarif_cwes(result: dict, rule: dict) -> list[str]:
    texts = []
    for source in (result, rule):
        properties = source.get("properties") or {}
        texts.extend(str(t) for t in properties.get("tags") or [])
        texts.extend(str(c) for c in properties.get("cwe") or [] if isinstance(properties.get("cwe"), list))
        if isinstance(properties.get("cwe"), str):
            texts.append(properties["cwe"])
    for relationship in rule.get("relationships") or []:
        texts.append(str((relationship.get("target") or {}).get("id", "")))
    codes = []
    for text in texts:
        match = re.search(r"cwe[-/ _]?0*(\d+)", text, re.IGNORECASE)
        if match and f"CWE-{match.group(1)}" not in codes:
            codes.append(f"CWE-{match.group(1)}")
    return codes


def from_sarif(doc: dict) -> tuple[list[NormalizedFinding], int]:
    findings: list[NormalizedFinding] = []
    raw_count = 0
    for run in doc.get("runs") or []:
        scanner = _sarif_scanner_name(run)
        driver = run.get("tool", {}).get("driver", {})
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
        rule_list = driver.get("rules") or []
        records = []
        for result in run.get("results") or []:
            raw_count += 1
            if (result.get("kind") or "fail") not in ("fail", "open", "review"):
                continue   # "pass"/"notApplicable" entries are not findings
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
            index = result.get("ruleIndex", (result.get("rule") or {}).get("index"))
            rule = rules.get(rule_id) or (rule_list[index] if isinstance(index, int) and 0 <= index < len(rule_list) else {})
            rule_id = rule_id or rule.get("id") or "unknown-rule"
            locations = result.get("locations") or []
            physical = (locations[0].get("physicalLocation") if locations else None) or {}
            uri = (physical.get("artifactLocation") or {}).get("uri")
            region = physical.get("region") or {}
            if not uri or not region.get("startLine"):
                continue   # a finding with no file:line can't be validated against code
            records.append({
                "rule_id": rule_id,
                "file": _sarif_uri_to_path(uri),
                "line": int(region["startLine"]),
                "end_line": int(region.get("endLine") or region["startLine"]),
                "column": region.get("startColumn"),
                "cwe": _sarif_cwes(result, rule),
                "severity": _sarif_severity(result, rule),
                "message": (result.get("message") or {}).get("text")
                           or (rule.get("shortDescription") or {}).get("text") or rule_id,
                "raw": result,
            })
        findings.extend(_build(scanner, records))
    return findings, raw_count


def _first(record: dict, *keys, default=None):
    for key in keys:
        if record.get(key) not in (None, ""):
            return record[key]
    return default


def from_generic(items: list) -> tuple[list[NormalizedFinding], int]:
    """A plain list of findings: each needs a file and a line, everything else is optional."""
    by_scanner: dict[str, list[dict]] = defaultdict(list)
    count = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        count += 1
        file_path = _first(item, "file_path", "file", "path", "filename")
        line = _first(item, "line_start", "line", "start_line", "line_number")
        if not file_path or line is None:
            continue
        rule_ids = item.get("rule_ids") or [_first(item, "rule_id", "rule", "check_id", "id", default="custom-rule")]
        cwe = item.get("cwe") or []
        scanner = str(_first(item, "source_scanner", "scanner", "tool", default="custom")).lower()
        for rule_id in rule_ids:
            by_scanner[scanner].append({
                "rule_id": str(rule_id),
                "file": normalize_path(str(file_path)),
                "line": int(line),
                "end_line": _first(item, "line_end", "end_line"),
                "column": _first(item, "column_start", "column"),
                "cwe": extract_cwes(cwe) or [c for c in ([cwe] if isinstance(cwe, str) else cwe) if c],
                "severity": str(_first(item, "severity", "level", default="WARNING")).upper(),
                "message": str(_first(item, "message", "description", "title", default="")),
                "raw": item,
            })
    findings = []
    for scanner, records in by_scanner.items():
        findings.extend(_build(scanner, records))
    return findings, count


def reconcile_paths(findings: list[NormalizedFinding], known_files: set[str]) -> tuple[list[NormalizedFinding], list[str]]:
    """Line a findings file's paths up with the uploaded codebase's paths.

    A scan that ran in CI reports '/home/runner/work/shop/shop/app/views.py' or
    'shop/app/views.py'; the upload has 'app/views.py'. A path is rewritten when exactly
    one uploaded file is a suffix of it (or it is a suffix of exactly one uploaded
    file). Anything still unmatched is returned so the caller can say so instead of
    quietly reporting "unknown" for it later.
    """
    import dataclasses

    def match(path: str) -> Optional[str]:
        if path in known_files:
            return path
        parts = path.strip("/").split("/")
        for start in range(len(parts)):               # drop leading directories
            candidate = "/".join(parts[start:])
            if candidate in known_files:
                return candidate
        suffix_hits = [k for k in known_files if k.endswith("/" + path.strip("/"))]
        return suffix_hits[0] if len(suffix_hits) == 1 else None

    reconciled, unmatched = [], []
    for finding in findings:
        matched = match(finding.file_path)
        if matched is None:
            unmatched.append(finding.file_path)
            reconciled.append(finding)
        elif matched != finding.file_path:
            reconciled.append(dataclasses.replace(
                finding,
                file_path=matched,
                finding_id=hash_id(finding.source_scanner, matched, finding.line_start),
            ))
        else:
            reconciled.append(finding)
    return reconciled, sorted(set(unmatched))
