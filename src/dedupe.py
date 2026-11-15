"""Cross-scanner deduplication: recognize one bug reported by several scanners.

Sits exactly where docs/phase-0-foundations.md said it would: its own step after
normalization, taking a batch of NormalizedFinding records and emitting DedupGroups,
without changing how finding_id is computed. The whole matcher is the single function
`deduplicate()`, so a different algorithm can replace it without touching the pipeline.

Why line numbers alone aren't enough (real output, todo-list-app): Semgrep reports the
second SQL injection at lines 39-41 (the whole `connection.execute(...)` call) while
Bandit reports it at line 40 (the f-string inside it). In rest-api-lab the two scanners
don't even overlap: Bandit flags line 9, where the query string is built, and Semgrep
flags line 10, where it's executed.

Two findings from *different* scanners are the same bug when they describe the same
weakness and one of these holds:
  1. their line ranges overlap
  2. they sit in the same statement
  3. they sit in the same function and one statement assigns a variable the other uses
     (the query is built on one line and run on the next)
"Same weakness" means the same class (weakness.py) or a shared CWE number. When we
can't tell that two findings describe the same weakness they stay separate: a visible
duplicate costs a glance, a wrongly merged finding hides a bug.

Findings from the same scanner are never merged here - a scanner reporting two lines
means two things. (Same scanner, same line is already grouped by the adapters.)
"""

import ast
import dataclasses
from typing import Optional

from ingest import highest_severity
from schemas import DedupGroup, NormalizedFinding
from semgrep_adapter import hash_id
from weakness import classify_finding, cwe_numbers

# Whose record becomes the canonical one when scanners agree. Semgrep first keeps
# finding ids identical to a Semgrep-only run of the same code.
SCANNER_PRECEDENCE = ["semgrep", "codeql", "bandit"]


def _precedence(scanner: str) -> tuple[int, str]:
    return (SCANNER_PRECEDENCE.index(scanner) if scanner in SCANNER_PRECEDENCE else len(SCANNER_PRECEDENCE), scanner)


@dataclasses.dataclass(frozen=True)
class _Anchor:
    start: int
    end: int
    statement: Optional[ast.stmt]
    function: Optional[ast.AST]


def _statement_span(node: ast.stmt) -> tuple[int, int]:
    """Lines a statement itself occupies. For a compound statement (if/for/with/def)
    that's only its header - its body is made of other statements."""
    start = node.lineno
    decorators = getattr(node, "decorator_list", None)
    if decorators:
        start = min(start, decorators[0].lineno)
    body = getattr(node, "body", None)
    if isinstance(body, list) and body and isinstance(body[0], ast.AST):
        return start, max(node.lineno, body[0].lineno - 1)
    return start, node.end_lineno or node.lineno


def _anchor(tree: Optional[ast.Module], finding: NormalizedFinding) -> _Anchor:
    line = finding.line_start
    fallback = _Anchor(line, finding.line_end or line, None, None)
    if tree is None:
        return fallback
    best: Optional[tuple[int, int, ast.stmt]] = None
    function = None
    function_size = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= (node.end_lineno or node.lineno):
                size = (node.end_lineno or node.lineno) - node.lineno
                if function_size is None or size < function_size:
                    function, function_size = node, size
        if not isinstance(node, ast.stmt):
            continue
        start, end = _statement_span(node)
        if start <= line <= end and (best is None or end - start < best[1] - best[0]):
            best = (start, end, node)
    if best is None:
        return fallback
    return _Anchor(best[0], best[1], best[2], function)


def _assigned_names(statement: Optional[ast.stmt]) -> set[str]:
    if isinstance(statement, ast.Assign):
        targets = statement.targets
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets = [statement.target]
    else:
        return set()
    return {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}


def _used_names(statement: Optional[ast.stmt]) -> set[str]:
    if statement is None:
        return set()
    return {n.id for n in ast.walk(statement) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _same_weakness(a: NormalizedFinding, b: NormalizedFinding) -> bool:
    class_a, class_b = classify_finding(a), classify_finding(b)
    if class_a and class_b:
        return class_a == class_b
    return bool(cwe_numbers(a.cwe) & cwe_numbers(b.cwe))


def _match_reason(a: NormalizedFinding, anchor_a: _Anchor, b: NormalizedFinding, anchor_b: _Anchor) -> Optional[str]:
    if a.file_path != b.file_path or not _same_weakness(a, b):
        return None
    a_end, b_end = a.line_end or a.line_start, b.line_end or b.line_start
    if a.line_start <= b_end and b.line_start <= a_end:
        return "same lines"
    if anchor_a.statement is not None and anchor_a.statement is anchor_b.statement:
        return "same statement"
    if anchor_a.function is not None and anchor_a.function is anchor_b.function:
        first, second = (anchor_a, anchor_b) if anchor_a.start < anchor_b.start else (anchor_b, anchor_a)
        shared = _assigned_names(first.statement) & _used_names(second.statement)
        if shared:
            return f"same data flow (`{sorted(shared)[0]}` is built on one line and used on the other)"
    return None


def deduplicate(
    findings: list[NormalizedFinding], sources: dict[str, str]
) -> tuple[list[NormalizedFinding], list[DedupGroup]]:
    """Returns (canonical findings, groups).

    `sources` maps file_path -> source text, used to find statement boundaries. A file
    we can't parse falls back to plain line-range overlap.
    """
    trees: dict[str, Optional[ast.Module]] = {}

    def tree_for(path: str) -> Optional[ast.Module]:
        if path not in trees:
            try:
                trees[path] = ast.parse(sources[path]) if path in sources and path.endswith(".py") else None
            except (SyntaxError, ValueError):
                trees[path] = None
        return trees[path]

    ordered = sorted(enumerate(findings), key=lambda item: (_precedence(item[1].source_scanner), item[0]))
    anchors = {id(f): _anchor(tree_for(f.file_path), f) for f in findings}

    canonical: list[NormalizedFinding] = []
    members: dict[str, list[tuple[NormalizedFinding, str]]] = {}
    for _, finding in ordered:
        match = None
        for candidate in canonical:
            if candidate.source_scanner == finding.source_scanner:
                continue
            reason = _match_reason(candidate, anchors[id(candidate)], finding, anchors[id(finding)])
            if reason:
                match = (candidate, reason)
                break
        if match is None:
            canonical.append(finding)
        else:
            members.setdefault(match[0].finding_id, []).append((finding, match[1]))

    original_order = {f.finding_id: i for i, f in reversed(list(enumerate(findings)))}
    canonical.sort(key=lambda f: original_order[f.finding_id])

    merged: list[NormalizedFinding] = []
    groups: list[DedupGroup] = []
    for finding in canonical:
        absorbed = members.get(finding.finding_id, [])
        if not absorbed:
            merged.append(finding if finding.scanners else dataclasses.replace(finding, scanners=[finding.source_scanner]))
            continue
        everyone = [finding, *(m for m, _ in absorbed)]
        rule_ids, cwes, scanners = [], [], []
        for member in everyone:
            rule_ids.extend(r for r in member.rule_ids if r not in rule_ids)
            cwes.extend(c for c in member.cwe if c not in cwes)
            if member.source_scanner not in scanners:
                scanners.append(member.source_scanner)
        merged.append(dataclasses.replace(
            finding,
            rule_ids=rule_ids,
            cwe=cwes,
            severity=highest_severity([m.severity for m in everyone]),
            scanners=scanners,
        ))
        groups.append(DedupGroup(
            group_id=hash_id("dedup", finding.finding_id),
            canonical_finding_id=finding.finding_id,
            member_finding_ids=[m.finding_id for m in everyone],
            scanners=scanners,
            reason="; ".join(dict.fromkeys(reason for _, reason in absorbed)),
        ))
    return merged, groups

