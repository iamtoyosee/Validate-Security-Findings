"""The call graph itself: which functions exist, and who confidently calls whom.

Deliberately does not know about entry points (see entry_points.py) or traversal
(see engine.py) - this module answers "what does the code literally do," nothing more.
"""

import ast
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class FunctionSpan:
    qualified_name: str   # "ClassName.method_name" if a method, else the bare function name
    file_path: str         # matches NormalizedFinding.file_path (e.g. "app.py")
    span_start: int        # first decorator's line if any, else the `def` line
    span_end: int           # last line of the function body
    node: ast.AST           # the FunctionDef/AsyncFunctionDef node, kept for edge-building


def build_function_table(file_path: str, tree: ast.Module) -> list[FunctionSpan]:
    """Walk a file's AST once, recording every function/method's qualified name and span."""
    functions: list[FunctionSpan] = []
    class_stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            class_stack.append(node.name)
            self.generic_visit(node)
            class_stack.pop()

        def _record(self, node) -> None:
            name = f"{class_stack[-1]}.{node.name}" if class_stack else node.name
            span_start = node.decorator_list[0].lineno if node.decorator_list else node.lineno
            functions.append(FunctionSpan(
                qualified_name=name,
                file_path=file_path,
                span_start=span_start,
                span_end=node.end_lineno,
                node=node,
            ))
            self.generic_visit(node)

        visit_FunctionDef = _record
        visit_AsyncFunctionDef = _record

    Visitor().visit(tree)
    return functions


def _calls_in_own_body(func_node: ast.AST):
    """Yield Call nodes belonging directly to this function, not to a nested def."""
    for child in ast.iter_child_nodes(func_node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue   # nested def's calls belong to itself, not the enclosing function
        if isinstance(child, ast.Call):
            yield child
        yield from _calls_in_own_body(child)


def build_call_edges(functions: list[FunctionSpan]) -> dict[str, set[str]]:
    """Map each function's qualified name -> the set of our-own-code functions it calls.

    Only three call shapes are resolved (see docs/phase-1-foundations.md):
    - bare name call, matched against the table
    - self.method(), matched as "<enclosing class>.method" against the table
    - anything else (a call on any other attribute/object) is ambiguous - no edge built.
    """
    table = {f.qualified_name for f in functions}
    edges: dict[str, set[str]] = {f.qualified_name: set() for f in functions}

    for f in functions:
        enclosing_class = f.qualified_name.rsplit(".", 1)[0] if "." in f.qualified_name else None
        for call in _calls_in_own_body(f.node):
            callee = call.func
            if isinstance(callee, ast.Name):
                if callee.id in table:
                    edges[f.qualified_name].add(callee.id)
            elif isinstance(callee, ast.Attribute):
                if (
                    enclosing_class
                    and isinstance(callee.value, ast.Name)
                    and callee.value.id == "self"
                ):
                    resolved = f"{enclosing_class}.{callee.attr}"
                    if resolved in table:
                        edges[f.qualified_name].add(resolved)
                # else: ambiguous attribute call on a non-self object - skip, no edge

    return edges


def resolve_containing_function(
    functions: list[FunctionSpan], file_path: str, line: int
) -> Optional[FunctionSpan]:
    """Given a finding's file:line, find which function contains it.

    Innermost (smallest span) match wins. Zero matches means module-level code -
    out of scope for now, caller should treat this as unresolvable.
    """
    candidates = [
        f for f in functions
        if f.file_path == file_path and f.span_start <= line <= f.span_end
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda f: f.span_end - f.span_start)
