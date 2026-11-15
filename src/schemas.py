from dataclasses import dataclass, field
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
    # Every scanner that reported this bug. One entry (== source_scanner) straight out
    # of an adapter; more once cross-scanner deduplication has folded duplicates in.
    scanners: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DedupGroup:
    """Two or more findings, from different scanners, judged to be the same bug.

    Shape decided in docs/phase-0-foundations.md ("Open questions"): deduplication is its
    own step after normalization and never changes how finding_id is computed. The
    canonical finding is the one the rest of the pipeline analyzes; the members are kept
    so nothing a scanner said is lost.
    """
    group_id: str
    canonical_finding_id: str
    member_finding_ids: list[str]     # includes the canonical one
    scanners: list[str]
    reason: str                       # why they were matched, in plain words


@dataclass(frozen=True)
class ReachabilityVerdict:
    finding_id: str                       # FK -> NormalizedFinding
    status: Literal["reachable", "unreachable", "unknown"]   # 3-valued, not boolean - see decision below
    confidence: Literal["high", "medium", "low"]
    containing_function: Optional[str]    # resolved qualified name, e.g. "app.upload.parse_archive"
    entry_point: Optional[str]            # e.g. "POST /upload -> handle_upload"
    call_path: Optional[list[str]]        # structured/technical - kept for Tier A input & debugging
    reason: str                           # one sentence, natural language, no jargon - see decision below
    # Phase 2 additions - all optional, so Phase 1 callers and stored results still load.
    entry_point_kind: Optional[str] = None     # "http" | "task" | "cli" | "startup"
    entry_point_label: Optional[str] = None    # human form of the way in: "GET /salary/employees"
    entry_guards: list[str] = field(default_factory=list)   # auth-looking decorators on the entry point
    call_path_locations: list[dict] = field(default_factory=list)   # [{function, file_path, line}] per hop
    other_entry_points: list[str] = field(default_factory=list)     # labels of further ways in, if any


@dataclass(frozen=True)
class ExploitabilityVerdict:
    finding_id: str                       # FK -> NormalizedFinding (only exists when reachable)
    status: Literal["confirmed_exploitable", "not_confirmed", "attempted_inconclusive"]  # refine in Phase 4/5
    confidence: Literal["high", "medium", "low"]
    reason: str
