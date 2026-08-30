"""Ties the graph, entry-point detectors, and backward traversal together into verdicts."""

import ast
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Optional

from schemas import NormalizedFinding, ReachabilityVerdict

from reachability.entry_points import DEFAULT_ENTRY_POINT_DETECTORS
from reachability.graph import FunctionSpan, build_call_edges, build_function_table, resolve_containing_function

EntryPointDetector = Callable[[dict[str, ast.Module]], set[str]]


@dataclass(frozen=True)
class CallGraph:
    functions: list[FunctionSpan]
    edges: dict[str, set[str]]   # caller qualified name -> confidently-called callee qualified names
    entry_points: set[str]        # qualified names tagged reachable-from-outside by some detector


def build_call_graph(
    files: dict[str, str],
    entry_point_detectors: list[EntryPointDetector] = DEFAULT_ENTRY_POINT_DETECTORS,
) -> CallGraph:
    """files: relative file_path (matching NormalizedFinding.file_path) -> source text.

    Codebase-wide function table, per docs/phase-1-foundations.md - both real test apps
    are single-file; resolving calls across multiple files with name collisions is a
    known, documented open question, not solved here.
    """
    trees = {}
    for path, source in files.items():
        try:
            trees[path] = ast.parse(source, filename=path)
        except SyntaxError:
            continue   # skip unparseable files rather than fail the whole scan

    functions: list[FunctionSpan] = []
    for path, tree in trees.items():
        functions.extend(build_function_table(path, tree))

    edges = build_call_edges(functions)

    entry_points: set[str] = set()
    for detector in entry_point_detectors:
        entry_points |= detector(trees)

    return CallGraph(functions=functions, edges=edges, entry_points=entry_points)


def trace_reachability(graph: CallGraph, start: str) -> Optional[list[str]]:
    """BFS backward from `start` through confident call edges to a tagged entry point.

    The entry-point check happens fresh at every hop, not just once at the start - a
    function having *a* caller doesn't mean the chain ever reaches an entry point.
    Returns the path as [entry_point, ..., start], or None if callers run out first.
    """
    callers_of: dict[str, set[str]] = defaultdict(set)
    for caller, callees in graph.edges.items():
        for callee in callees:
            callers_of[callee].add(caller)

    if start in graph.entry_points:
        return [start]

    visited = {start}
    queue = deque([(start, [start])])
    while queue:
        current, path_so_far = queue.popleft()
        for caller in callers_of.get(current, ()):
            if caller in graph.entry_points:
                return [caller] + path_so_far
            if caller not in visited:
                visited.add(caller)
                queue.append((caller, [caller] + path_so_far))
    return None


def build_verdict(finding: NormalizedFinding, graph: CallGraph) -> ReachabilityVerdict:
    containing = resolve_containing_function(graph.functions, finding.file_path, finding.line_start)

    if containing is None:
        # module-level code - zero-candidates case from docs/phase-0-foundations.md,
        # still an open question; treated here as unresolvable rather than guessed at.
        return ReachabilityVerdict(
            finding_id=finding.finding_id,
            status="unknown",
            confidence="low",
            containing_function=None,
            entry_point=None,
            call_path=None,
            reason="Could not resolve this finding to a containing function (likely "
                   "module-level code) - not yet supported.",
        )

    path = trace_reachability(graph, containing.qualified_name)

    if path is not None:
        return ReachabilityVerdict(
            finding_id=finding.finding_id,
            status="reachable",
            confidence="high",   # every edge we ever build is confident by construction (see graph.py)
            containing_function=containing.qualified_name,
            entry_point=path[0],
            call_path=path,
            reason=f"Reachable via {' -> '.join(path)}.",
        )

    return ReachabilityVerdict(
        finding_id=finding.finding_id,
        status="unreachable",
        # capped at medium: only 2 entry-point categories are detected today (HTTP
        # handlers, Flask routes) - "unreachable" is a claim about every possible way
        # in, and CLI/RPC/queues/scheduled jobs were never checked (see phase-1 doc,
        # "Confidence has two axes").
        confidence="medium",
        containing_function=containing.qualified_name,
        entry_point=None,
        call_path=None,
        reason="Not reachable via any known HTTP or Flask entry point. Other "
               "entry-point types (CLI, RPC, message queues, scheduled jobs) were not checked.",
    )
