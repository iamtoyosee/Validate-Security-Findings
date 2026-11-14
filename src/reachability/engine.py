"""Ties the graph, entry-point detectors, and backward traversal together into verdicts."""

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from schemas import NormalizedFinding, ReachabilityVerdict

from reachability.entry_points import DEFAULT_ENTRY_POINT_DETECTORS, EntryPoint, module_is_loaded
from reachability.graph import (
    WEAK_REFERENCE,
    FunctionSpan,
    Program,
    build_function_table,
    build_import_bindings,
    build_module_span,
    qualify_functions,
    resolve_containing_function,
    resolve_edges,
)

EntryPointDetector = Callable[[dict[str, ast.Module]], object]

# When a function can be reached several ways, report the way an outside attacker
# would care about most: a network request beats a queue message beats a local command
# beats "runs at import".
ENTRY_KIND_RANK = {"http": 0, "task": 1, "cli": 2, "startup": 3}
ENTRY_KIND_WORDS = {
    "http": "HTTP routes and request hooks",
    "task": "task-queue workers",
    "cli": "CLI commands and scripts",
    "startup": "module import",
}


@dataclass(frozen=True)
class CallGraph:
    functions: list[FunctionSpan]
    edges: dict[str, set[str]]   # caller qualified name -> confidently-called callee qualified names
    entry_points: set[str]        # qualified names tagged reachable-from-outside by some detector
    unresolved_call_targets: set[str]   # attribute names seen in calls we declined to resolve
    edge_kinds: dict = field(default_factory=dict)     # (caller, callee) -> "call" | "ref" | "weak-ref"
    entry_info: dict = field(default_factory=dict)     # qualified name -> EntryPoint
    modules: dict = field(default_factory=dict)        # file_path -> the module node's FunctionSpan
    program: Optional[Program] = None                  # resolver state, reused by the taint stage
    sources: dict = field(default_factory=dict)        # file_path -> source text

    def span(self, qualified_name: str) -> Optional[FunctionSpan]:
        for f in self.functions:
            if f.qualified_name == qualified_name:
                return f
        for m in self.modules.values():
            if m.qualified_name == qualified_name:
                return m
        return None


def build_call_graph(
    files: dict[str, str],
    entry_point_detectors: list[EntryPointDetector] = DEFAULT_ENTRY_POINT_DETECTORS,
) -> CallGraph:
    """files: relative file_path (matching NormalizedFinding.file_path) -> source text."""
    trees = {}
    for path, source in files.items():
        try:
            trees[path] = ast.parse(source, filename=path)
        except (SyntaxError, ValueError):
            continue   # skip unparseable files rather than fail the whole scan

    functions: list[FunctionSpan] = []
    for path, tree in trees.items():
        functions.extend(build_function_table(path, tree))
    functions = qualify_functions(functions)
    modules = {path: build_module_span(path, tree) for path, tree in trees.items()}

    imports = {path: build_import_bindings(tree, path) for path, tree in trees.items()}
    program = Program(functions, imports, trees, modules)
    resolved = resolve_edges(program)

    entry_info: dict[str, EntryPoint] = {}

    def tag(entry: EntryPoint) -> None:
        if entry.local_name == "":
            spans = [modules[entry.file_path]] if entry.file_path in modules else []
        else:
            hit = program.by_file_local.get((entry.file_path, entry.local_name)) if entry.file_path else None
            spans = [hit] if hit else program.by_local.get(entry.local_name, [])
        for span in spans:
            known = entry_info.get(span.qualified_name)
            if known is None or ENTRY_KIND_RANK.get(entry.kind, 9) < ENTRY_KIND_RANK.get(known.kind, 9):
                entry_info[span.qualified_name] = entry

    for detector in entry_point_detectors:
        for item in detector(trees):
            # a detector may still return bare names (the Phase 1 contract)
            tag(item if isinstance(item, EntryPoint) else EntryPoint(None, item, "http", item))

    # A file's top-level code runs when something loads the file. We count that when the
    # file holds an entry point of its own (it's the app module) or another file imports it.
    files_with_entries = {program_span.file_path for name in entry_info if (program_span := _span(functions, modules, name))}
    for path, module in modules.items():
        if module.qualified_name in entry_info:
            continue
        if path in files_with_entries or module_is_loaded(path, trees):
            entry_info[module.qualified_name] = EntryPoint(path, "", "startup", f"import of {path}")

    return CallGraph(
        functions=functions,
        edges=resolved.edges,
        entry_points=set(entry_info),
        unresolved_call_targets=resolved.unresolved_call_targets,
        edge_kinds=resolved.kinds,
        entry_info=entry_info,
        modules=modules,
        program=program,
        sources=dict(files),
    )


def _span(functions, modules, qualified_name):
    for f in functions:
        if f.qualified_name == qualified_name:
            return f
    for m in modules.values():
        if m.qualified_name == qualified_name:
            return m
    return None


def entry_paths(graph: CallGraph, start: str) -> list[list[str]]:
    """Every entry point that can reach `start`, each with its shortest path, best first.

    BFS backward through call edges. The entry-point check happens fresh at every hop,
    not just once at the start - a function having *a* caller doesn't mean the chain
    ever reaches an entry point. Paths read [entry_point, ..., start].
    """
    callers_of: dict[str, set[str]] = defaultdict(set)
    for caller, callees in graph.edges.items():
        for callee in callees:
            callers_of[callee].add(caller)

    paths: dict[str, list[str]] = {}
    if start in graph.entry_points:
        paths[start] = [start]
    visited = {start}
    queue = deque([(start, [start])])
    while queue:
        current, path_so_far = queue.popleft()
        for caller in sorted(callers_of.get(current, ())):
            if caller in visited:
                continue
            visited.add(caller)
            path = [caller] + path_so_far
            if caller in graph.entry_points:
                paths[caller] = path
            queue.append((caller, path))

    def rank(path: list[str]):
        entry = graph.entry_info.get(path[0])
        kind = ENTRY_KIND_RANK.get(entry.kind, 0) if entry else 0
        return (kind, _path_is_weak(graph, path), len(path), path[0])

    return sorted(paths.values(), key=rank)


def trace_reachability(graph: CallGraph, start: str) -> Optional[list[str]]:
    """The best path from an entry point to `start`, or None if callers run out first."""
    paths = entry_paths(graph, start)
    return paths[0] if paths else None


def _path_is_weak(graph: CallGraph, path: list[str]) -> bool:
    return any(graph.edge_kinds.get((a, b)) == WEAK_REFERENCE for a, b in zip(path, path[1:]))


def _locations(graph: CallGraph, path: list[str]) -> list[dict]:
    locations = []
    for name in path:
        span = graph.span(name)
        if span is not None:
            line = getattr(span.node, "lineno", span.span_start) if not span.is_module else 1
            locations.append({"function": name, "file_path": span.file_path, "line": line})
    return locations


def build_verdict(finding: NormalizedFinding, graph: CallGraph) -> ReachabilityVerdict:
    containing = resolve_containing_function(graph.functions, finding.file_path, finding.line_start)
    if containing is None:
        containing = graph.modules.get(finding.file_path)   # top-level code of a file we parsed

    if containing is None:
        return ReachabilityVerdict(
            finding_id=finding.finding_id,
            status="unknown",
            confidence="low",
            containing_function=None,
            entry_point=None,
            call_path=None,
            reason="This finding isn't in a Python file the call graph could parse, so "
                   "reachability wasn't analyzed for it.",
        )

    paths = entry_paths(graph, containing.qualified_name)

    if paths:
        path = paths[0]
        entry = graph.entry_info.get(path[0])
        weak = _path_is_weak(graph, path)
        startup = entry is not None and entry.kind == "startup"
        label = entry.label if entry else path[0]
        notes = []
        if weak:
            notes.append("one hop is a function passed or stored as a value rather than called directly")
        if startup:
            notes.append("it runs when the module is imported, not in response to a request")
        return ReachabilityVerdict(
            finding_id=finding.finding_id,
            status="reachable",
            # every call edge is confident by construction (see graph.py); the two softer
            # kinds of evidence are named in the reason and capped at medium
            confidence="medium" if (weak or startup) else "high",
            containing_function=containing.qualified_name,
            entry_point=path[0],
            call_path=path,
            reason=f"Reachable via {' -> '.join(path)}"
                   + (f" ({'; '.join(notes)})." if notes else "."),
            entry_point_kind=entry.kind if entry else None,
            entry_point_label=label,
            entry_guards=list(entry.guards) if entry else [],
            call_path_locations=_locations(graph, path),
            other_entry_points=[
                (graph.entry_info[p[0]].label if p[0] in graph.entry_info else p[0]) for p in paths[1:6]
            ],
        )

    # A same-named function was the target of a call somewhere that we couldn't verify
    # (e.g. connection.execute() on a local of untracked type) - that call might resolve
    # to THIS function, so "no path found" doesn't mean "no callers exist," just "we
    # can't confirm one." This is a name-based heuristic, not a type-based one, matching
    # the trade-off already accepted elsewhere in this project (e.g. the Celery bare-
    # decorator match): an unrelated function sharing a name with something called
    # ambiguously elsewhere (two unrelated `execute` methods in a large codebase) also
    # gets downgraded to "unknown" - a deliberate, accepted false-positive risk in
    # exchange for not silently overclaiming certainty on a real one.
    bare_name = (containing.local_name or containing.qualified_name).rsplit(".", 1)[-1]
    if not containing.is_module and bare_name in graph.unresolved_call_targets:
        return ReachabilityVerdict(
            finding_id=finding.finding_id,
            status="unknown",
            confidence="low",
            containing_function=containing.qualified_name,
            entry_point=None,
            call_path=None,
            reason="No confident call path to an entry point was found, but a call "
                   "elsewhere in the codebase targets a same-named function through a "
                   "pattern we don't resolve (e.g. a method call on a variable of "
                   "unverified type) - reachability can't be confidently ruled out.",
        )

    return ReachabilityVerdict(
        finding_id=finding.finding_id,
        status="unreachable",
        # capped at medium: "unreachable" is a claim about every possible way in, and
        # only the categories named below are detected (see phase-1 doc, "Confidence
        # has two axes").
        confidence="medium",
        containing_function=containing.qualified_name,
        entry_point=None,
        call_path=None,
        reason="No call path from any detected entry point (HTTP routes and hooks, Django "
               "URLs, task-queue workers, CLI commands, code run at import). Other "
               "entry-point types (RPC, plugin hooks, dynamic dispatch) were not checked.",
    )
