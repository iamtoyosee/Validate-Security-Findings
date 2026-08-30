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


def _statements_in_own_body(func_node: ast.AST):
    """Yield statement nodes belonging directly to this function, not to a nested def.

    Same shape as _calls_in_own_body, but for the assignment-tracking fix 3 needs -
    ast.iter_child_nodes visits list fields (a function body, an if/for/with block) in
    source order, so straight-line code comes out in the order it actually executes.
    """
    for child in ast.iter_child_nodes(func_node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.Assign):
            yield child
        yield from _statements_in_own_body(child)


def build_import_table(tree: ast.Module) -> dict[str, str]:
    """Map each name this file's imports bind locally -> the canonical original name.

    Python's import statement is a complete, static answer to "what does this bare name
    refer to" - no guessing required, unlike resolving an arbitrary variable's type.
    Covers `import X [as Y]` and `from module import X [as Y]`, module-level only.
    Canonical name is the original (pre-`as`) name; identity when there's no `as`.
    """
    table: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                table[alias.asname or alias.name] = alias.name
    return table


def _class_ref(value: ast.AST, import_table: dict[str, str], known_classes: set[str]) -> Optional[str]:
    """If `value` is `ClassName()` or `module.ClassName()` for a class we parsed, return its name.

    Gating on "a class our own function table knows about" (rather than accepting any
    module.attr() call, e.g. sqlite3.connect(...)) is what keeps this from swallowing the
    exact ambiguous-object pattern (a connection-like local of untracked type) the project
    otherwise deliberately refuses to resolve.
    """
    if not isinstance(value, ast.Call):
        return None
    func = value.func
    if isinstance(func, ast.Name) and func.id in known_classes:
        return func.id
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in import_table
        and func.attr in known_classes
    ):
        return func.attr
    return None


def _local_class_instantiations(
    func_node: ast.AST, import_table: dict[str, str], known_classes: set[str]
) -> dict[str, str]:
    """Track `name = ClassRef()` locals within one function body, in assignment order.

    Deliberately narrow (see docs/phase-1-foundations.md, fix 3): only the literal
    single-assignment-then-call pattern. A later, different assignment to the same name
    drops it rather than guessing which assignment is "the real one" - no attempt to
    reason about conditionals or other control flow.
    """
    local_map: dict[str, str] = {}
    for stmt in _statements_in_own_body(func_node):
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            continue
        name = stmt.targets[0].id
        class_name = _class_ref(stmt.value, import_table, known_classes)
        if class_name:
            local_map[name] = class_name
        else:
            local_map.pop(name, None)
    return local_map


def _resolve_callable_reference(node: ast.AST, import_table: dict[str, str]) -> Optional[str]:
    """Resolve a value passed *as* a callable (e.g. BackgroundTasks.add_task's first arg)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in import_table:
        return node.attr
    return None


def build_call_edges(
    functions: list[FunctionSpan],
    import_tables: Optional[dict[str, dict[str, str]]] = None,
) -> tuple[dict[str, set[str]], set[str]]:
    """Map each function's qualified name -> the set of our-own-code functions it calls.

    Returns (edges, unresolved_call_targets) - the latter is every attribute name seen in
    a call we declined to resolve (see below), which build_verdict uses to tell a
    genuinely-zero-callers "unreachable" apart from a merely-unverifiable "unknown".

    Call shapes resolved with confidence (see docs/phase-1-foundations.md):
    - bare name call, matched against the table
    - self.method(), matched as "<enclosing class>.method" against the table
    - name.attr(), where `name` is a key in this file's import table (an imported module,
      not an arbitrary local variable) - same certainty as a bare call, since imports are
      static and unambiguous; attr is looked up by bare name, same as a plain call
    - name.method(), where `name` was assigned earlier in this same function body directly
      from a known local class's constructor (`name = ClassRef()`, see _local_class_instantiations)
    - BackgroundTasks.add_task(fn, ...) - `fn` isn't called syntactically, but it's passed
      to be invoked later; resolved the same way a normal call's target would be
    Anything else (a call on any other attribute/object, e.g. `connection.execute(...)`
    where `connection` is a local variable of untracked type) is genuinely ambiguous - no
    edge gets built, and the attribute name is recorded as unresolved instead.
    """
    import_tables = import_tables or {}
    table = {f.qualified_name for f in functions}
    known_classes = {qn.split(".", 1)[0] for qn in table if "." in qn}
    edges: dict[str, set[str]] = {f.qualified_name: set() for f in functions}
    unresolved_call_targets: set[str] = set()

    for f in functions:
        enclosing_class = f.qualified_name.rsplit(".", 1)[0] if "." in f.qualified_name else None
        import_table = import_tables.get(f.file_path, {})
        local_instantiations = _local_class_instantiations(f.node, import_table, known_classes)

        for call in _calls_in_own_body(f.node):
            callee = call.func
            if isinstance(callee, ast.Name):
                if callee.id in table:
                    edges[f.qualified_name].add(callee.id)
                continue
            if not isinstance(callee, ast.Attribute):
                continue

            obj = callee.value
            if enclosing_class and isinstance(obj, ast.Name) and obj.id == "self":
                resolved = f"{enclosing_class}.{callee.attr}"
                if resolved in table:
                    edges[f.qualified_name].add(resolved)
            elif isinstance(obj, ast.Name) and obj.id in import_table:
                if callee.attr in table:
                    edges[f.qualified_name].add(callee.attr)
            elif isinstance(obj, ast.Name) and obj.id in local_instantiations:
                resolved = f"{local_instantiations[obj.id]}.{callee.attr}"
                if resolved in table:
                    edges[f.qualified_name].add(resolved)
            elif callee.attr == "add_task":
                if call.args:
                    target = _resolve_callable_reference(call.args[0], import_table)
                    if target and target in table:
                        edges[f.qualified_name].add(target)
            else:
                unresolved_call_targets.add(callee.attr)

    return edges, unresolved_call_targets


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
