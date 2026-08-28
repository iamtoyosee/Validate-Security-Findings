from dataclasses import dataclass
from typing import Literal, Optional


@dataclass(frozen=True)
class NormalizedFinding:
    finding_id: str            # stable hash of (scanner, file_path, line_start) - see decision below
    source_scanner: str        # "semgrep" | "bandit" | "codeql" | "custom"
    rule_ids: list[str]         # ALL rules that matched this location - see "Same-location grouping" below
    vulnerability_type: str     # == rule_ids[0], permanently out of scope for this project - see decision below
    cwe: list[str]               # short codes e.g. ["CWE-89"], deduped across grouped rules - see decision below
    severity: str                # highest severity across grouped rules - NOT our final priority
    file_path: str               # relative to repo root, forward-slash normalized
    line_start: int
    line_end: Optional[int]
    column_start: Optional[int]
    message: str                  # first/primary rule's human-readable description
    code_snippet: Optional[str]   # DERIVED by us, not sourced from scanner - see decision below
    raw: list[dict]                # ALL original raw scanner records for this location, untouched


@dataclass(frozen=True)
class ReachabilityVerdict:
    finding_id: str                       # FK -> NormalizedFinding
    status: Literal["reachable", "unreachable", "unknown"]   # 3-valued, not boolean - see decision below
    confidence: Literal["high", "medium", "low"]
    containing_function: Optional[str]    # resolved qualified name, e.g. "app.upload.parse_archive"
    entry_point: Optional[str]            # e.g. "POST /upload -> handle_upload"
    call_path: Optional[list[str]]        # structured/technical - kept for Tier A input & debugging
    reason: str                           # one sentence, natural language, no jargon - see decision below


@dataclass(frozen=True)
class ExploitabilityVerdict:
    finding_id: str                       # FK -> NormalizedFinding (only exists when reachable)
    status: Literal["confirmed_exploitable", "not_confirmed", "attempted_inconclusive"]  # refine in Phase 4/5
    confidence: Literal["high", "medium", "low"]
    reason: str
