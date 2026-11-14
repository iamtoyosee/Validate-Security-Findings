"""The call graph itself: which functions exist, and who confidently calls whom.

Deliberately does not know about entry points (see entry_points.py) or traversal
(see engine.py) - this module answers "what does the code literally do," nothing more.

Phase 2 rewrote the resolution core (docs/phase-2-reachability-hardening.md). The rule
is unchanged - an edge is only built when the code says unambiguously what is being
called - but the set of things the resolver can prove grew:

- every function has a codebase-unique identity, so two files defining the same name
  no longer collapse into one node (the largest correctness gap in Phase 1)
- a bare name resolves the way Python resolves it: same file first, then this file's
  imports - never "any function anywhere with that name"
- methods resolve through base classes, `super()`, `self.attr` objects, annotated
  parameters, module-level instances and annotated return types
- a function passed or stored as a value (a callback, a dispatch table) produces a
  *reference* edge, kept distinct from a call edge so confidence can reflect it
- module-level code is a node of its own, so "this runs at import time" is expressible
"""

import ast
import dataclasses
from dataclasses import dataclass
from typing import Iterable, Optional, Union


@dataclass(frozen=True)
class FunctionSpan:
    qualified_name: str   # unique across the codebase; module-prefixed only when the bare name collides
    file_path: str         # matches NormalizedFinding.file_path (e.g. "app.py")
    span_start: int        # first decorator's line if any, else the `def` line
    span_end: int           # last line of the function body
    node: ast.AST           # the FunctionDef/AsyncFunctionDef node (ast.Module for a module node)
    local_name: str = ""    # name within its own file: "Class.method" or "function"
    class_name: Optional[str] = None
    is_module: bool = False  # the pseudo-function standing for a file's top-level code


@dataclass(frozen=True)
class ImportBinding:
    """What one imported local name refers to.

    `import a.b as c`        -> ImportBinding(module="a.b", name=None)   (c IS the module)
    `from a.b import x as y` -> ImportBinding(module="a.b", name="x")    (x may be a function,
                                 a class, a variable, or a submodule of a.b)
    """
    module: Optional[str]
    name: Optional[str]


ClassKey = tuple[str, str]   # (file_path, class name)

CALL = "call"            # literal call, or a method call whose receiver type is proven
REFERENCE = "ref"        # handed to an API that exists to invoke it later (add_task, Depends, Thread)
WEAK_REFERENCE = "weak-ref"   # stored or passed somewhere we can't see through (a dispatch table)

# Calls whose whole purpose is to run the function they are handed. A reference passed
# to one of these is as good as a call; anything else is only a "may be called".
INVOKER_NAMES = {
    "add_task", "submit", "map", "apply_async", "run_in_executor", "Thread", "Process",
    "Timer", "Depends", "Security", "add_job", "add_url_rule", "add_api_route",
    "add_route", "add_websocket_route", "add_done_callback", "call_soon", "call_later",
    "create_task", "ensure_future", "to_thread", "start_new_thread", "add_event_handler",
    "add_exception_handler", "register_error_handler", "before_request", "after_request",
    "connect", "partial", "starmap", "imap", "run_until_complete", "run",
}
# `task.delay(...)` and friends: the attribute call *is* an invocation of `task`.
TASK_INVOKE_ATTRS = {"delay", "apply_async", "s", "si", "signature", "apply", "send", "enqueue"}

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def module_node_name(file_path: str) -> str:
    return f"<module {file_path}>"


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
                local_name=name,
                class_name=class_stack[-1] if class_stack else None,
            ))
            self.generic_visit(node)

        visit_FunctionDef = _record
        visit_AsyncFunctionDef = _record

    Visitor().visit(tree)
    return functions


def build_module_span(file_path: str, tree: ast.Module) -> FunctionSpan:
    """The pseudo-function for a file's top-level code (runs when the module is loaded)."""
    last_line = max((getattr(n, "end_lineno", 0) or 0 for n in ast.walk(tree)), default=1)
    return FunctionSpan(
        qualified_name=module_node_name(file_path),
        file_path=file_path,
        span_start=1,
        span_end=max(last_line, 1),
        node=tree,
        local_name="",
        is_module=True,
    )


def qualify_functions(functions: list[FunctionSpan]) -> list[FunctionSpan]:
    """Make every qualified_name unique across the codebase.

    A name defined in exactly one file keeps its bare name, so single-file apps read
    exactly as before. A name defined in several files gets the shortest dotted module
    prefix that tells the copies apart: `services.run_diagnostic` vs `tasks.run_diagnostic`.
    """
    by_name: dict[str, list[FunctionSpan]] = {}
    for f in functions:
        by_name.setdefault(f.local_name or f.qualified_name, []).append(f)

    renamed: dict[int, str] = {}
    for name, group in by_name.items():
        files = sorted({f.file_path for f in group})
        if len(files) < 2:
            continue
        prefixes = _shortest_unique_module_labels(files)
        for f in group:
            renamed[id(f)] = f"{prefixes[f.file_path]}.{name}"
    return [
        dataclasses.replace(f, qualified_name=renamed[id(f)]) if id(f) in renamed else f
        for f in functions
    ]


def _shortest_unique_module_labels(files: list[str]) -> dict[str, str]:
    parts = {f: f.removesuffix(".py").split("/") for f in files}
    labels: dict[str, str] = {}
    for f, own in parts.items():
        for depth in range(1, len(own) + 1):
            label = own[-depth:]
            if not any(other[-depth:] == label for g, other in parts.items() if g != f):
                break
        labels[f] = ".".join(label)
    return labels


def _own_nodes(scope_node: ast.AST) -> Iterable[ast.AST]:
    """Every AST node that executes as part of this scope itself, in source order.

    A nested def's body belongs to the nested def, so it's skipped; a class body runs
    in the scope that defines the class, so it's included (minus its methods). A
    function's decorators are skipped here: they run once at definition time and are
    handled separately (they are how routes get registered, not calls the function makes).
    """
    if isinstance(scope_node, _SCOPE_NODES):
        roots: list[ast.AST] = [scope_node.args, *scope_node.body]
    elif isinstance(scope_node, ast.Module):
        roots = list(scope_node.body)
    else:
        roots = list(ast.iter_child_nodes(scope_node))

    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        if isinstance(node, _SCOPE_NODES):
            continue
        yield node
        children = list(ast.iter_child_nodes(node))
        if isinstance(node, ast.ClassDef):
            children = [c for c in node.body if not isinstance(c, _SCOPE_NODES)]
        stack.extend(reversed(children))


def _calls_in_own_body(func_node: ast.AST):
    """Yield Call nodes belonging directly to this function, not to a nested def."""
    for node in _own_nodes(func_node):
        if isinstance(node, ast.Call):
            yield node


def _local_bindings(scope_node: ast.AST) -> set[str]:
    """Names this scope binds itself: parameters, assignment targets, loop variables...

    A bare name that is locally bound is a local variable, whatever else in the
    codebase happens to share its name - `order = fetch(); return order` must never be
    read as a reference to a function called `order`.
    """
    names: set[str] = set()
    if isinstance(scope_node, _SCOPE_NODES):
        args = scope_node.args
        for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
            names.add(a.arg)
        if args.vararg:
            names.add(args.vararg.arg)
        if args.kwarg:
            names.add(args.kwarg.arg)
    for node in _own_nodes(scope_node):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)) and not isinstance(scope_node, ast.Module):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
    return names


def build_import_table(tree: ast.Module) -> dict[str, str]:
    """Map each name this file's imports bind locally -> the canonical original name.

    Python's import statement is a complete, static answer to "what does this bare name
    refer to" - no guessing required, unlike resolving an arbitrary variable's type.
    Covers `import X [as Y]` and `from module import X [as Y]`, module-level only.
    Canonical name is the original (pre-`as`) name; identity when there's no `as`.

    Kept for the entry-point detectors; call resolution uses build_import_bindings,
    which also remembers *which module* each name came from.
    """
    table: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                table[alias.asname or alias.name] = alias.name
    return table


def build_import_bindings(tree: ast.Module, file_path: str = "") -> dict[str, ImportBinding]:
    """Like build_import_table, but keeps the source module, resolves relative imports
    against this file's own package, and includes imports made inside functions (a
    common way to dodge circular imports in Flask/Django code)."""
    package_parts = file_path.removesuffix(".py").split("/")[:-1] if file_path else []
    bindings: dict[str, ImportBinding] = {}
    has_star = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = ImportBinding(module=alias.name, name=None)
                else:
                    root = alias.name.split(".")[0]
                    bindings[root] = ImportBinding(module=root, name=None)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                base = package_parts[: len(package_parts) - (node.level - 1)] if node.level > 1 else package_parts
                module = ".".join([*base, *([module] if module else [])])
            for alias in node.names:
                if alias.name == "*":
                    has_star = True
                    continue
                bindings[alias.asname or alias.name] = ImportBinding(module=module or None, name=alias.name)
    if has_star:
        bindings["*"] = ImportBinding(module=None, name="*")
    return bindings


def files_for_module(module: str, files: Iterable[str]) -> list[str]:
    """Which of our files a dotted module name would load.

    Tolerant in both directions, because the keys we hold are upload-relative paths and
    a module name is sys.path-relative: 'celery_lab/tasks.py' satisfies `tasks`, and
    'repository.py' satisfies `app.repository` (the project root itself was the package).
    """
    files = list(files)
    parts = module.split(".")
    for start in range(len(parts)):
        stem = "/".join(parts[start:])
        candidates = (stem + ".py", stem + "/__init__.py")
        matches = [f for f in files if any(f == c or f.endswith("/" + c) for c in candidates)]
        if matches:
            return matches
    return []


def _dotted_name(node: ast.AST) -> Optional[list[str]]:
    """`a.b.c` -> ["a", "b", "c"]; None for anything that isn't a plain dotted name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return None


@dataclass
class _ClassInfo:
    key: ClassKey
    bases: list[ast.expr]
    methods: dict[str, FunctionSpan]
    attr_types: dict[str, Optional[ClassKey]]   # self.x -> its class; None once it's ambiguous
    node: Optional[ast.ClassDef] = None


class Program:
    """Everything the resolver knows about a codebase, built once and queried per call."""

    def __init__(
        self,
        functions: list[FunctionSpan],
        import_tables: Optional[dict[str, dict[str, Union[str, ImportBinding]]]] = None,
        trees: Optional[dict[str, ast.Module]] = None,
        modules: Optional[dict[str, FunctionSpan]] = None,
    ):
        self.functions = functions
        self.trees = trees or {}
        self.modules = modules or {}
        self.files = sorted({f.file_path for f in functions} | set(self.trees))
        self.imports: dict[str, dict[str, ImportBinding]] = {}
        for path, table in (import_tables or {}).items():
            self.imports[path] = {
                local: value if isinstance(value, ImportBinding) else ImportBinding(module=None, name=value)
                for local, value in table.items()
            }
        self._legacy_imports = not self.trees

        self.by_file_local: dict[tuple[str, str], FunctionSpan] = {}
        self.by_local: dict[str, list[FunctionSpan]] = {}
        for f in functions:
            local = f.local_name or f.qualified_name
            self.by_file_local.setdefault((f.file_path, local), f)
            self.by_local.setdefault(local, []).append(f)

        self.classes: dict[ClassKey, _ClassInfo] = {}
        self.classes_by_name: dict[str, list[_ClassInfo]] = {}
        self._collect_classes()
        self.module_bound: dict[str, set[str]] = {
            path: _local_bindings(tree) for path, tree in self.trees.items()
        }
        self.module_instances: dict[str, dict[str, ClassKey]] = {}
        self._collect_module_instances()
        self._collect_attribute_types()

    # ---- construction -------------------------------------------------------------

    def _collect_classes(self) -> None:
        for f in self.functions:
            if not f.class_name:
                continue
            key = (f.file_path, f.class_name)
            info = self.classes.get(key)
            if info is None:
                info = self.classes[key] = _ClassInfo(key=key, bases=[], methods={}, attr_types={})
                self.classes_by_name.setdefault(f.class_name, []).append(info)
            method = (f.local_name or f.qualified_name).split(".", 1)[-1]
            info.methods.setdefault(method, f)
        for path, tree in self.trees.items():
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                key = (path, node.name)
                info = self.classes.get(key)
                if info is None:   # a class with no methods of its own still matters as a base
                    info = self.classes[key] = _ClassInfo(key=key, bases=[], methods={}, attr_types={})
                    self.classes_by_name.setdefault(node.name, []).append(info)
                info.bases = list(node.bases)
                info.node = node

    def _collect_module_instances(self) -> None:
        for path, tree in self.trees.items():
            instances: dict[str, Optional[ClassKey]] = {}
            for node in _own_nodes(tree):
                target, value, annotation = _simple_assignment(node)
                if target is None:
                    continue
                cls = self.annotation_class(annotation, path) if annotation is not None else None
                if cls is None and value is not None:
                    cls = self._instantiated_class(value, path)
                instances[target] = cls if target not in instances or instances[target] == cls else None
            self.module_instances[path] = {k: v for k, v in instances.items() if v}

    def _collect_attribute_types(self) -> None:
        for info in self.classes.values():
            if info.node is not None:
                for stmt in info.node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        cls = self.annotation_class(stmt.annotation, info.key[0])
                        if cls:
                            info.attr_types[stmt.target.id] = cls
            for method in info.methods.values():
                local_types = self.local_types(method)
                for node in _own_nodes(method.node):
                    targets, value = [], None
                    if isinstance(node, ast.Assign):
                        targets, value = node.targets, node.value
                    elif isinstance(node, ast.AnnAssign):
                        targets, value = [node.target], node.value
                    for target in targets:
                        if not (
                            isinstance(target, ast.Attribute)
                            and isinstance(target.value, ast.Name)
                            and target.value.id == "self"
                        ):
                            continue
                        cls = None
                        if isinstance(node, ast.AnnAssign):
                            cls = self.annotation_class(node.annotation, info.key[0])
                        if cls is None and value is not None:
                            cls = self.type_of(value, method, local_types, set())
                        known = info.attr_types.get(target.attr, cls)
                        info.attr_types[target.attr] = cls if known == cls else None

    # ---- name resolution ----------------------------------------------------------

    def _module_files(self, module: Optional[str]) -> list[str]:
        return files_for_module(module, self.files) if module else []

    def _binding_modules(self, binding: ImportBinding) -> list[str]:
        """Dotted module names an imported local name may stand for."""
        if binding.name is None:
            return [binding.module] if binding.module else []
        if binding.module:
            return [f"{binding.module}.{binding.name}"]
        return [binding.name]

    def resolve_function_name(self, name: str, file_path: str) -> tuple[Optional[FunctionSpan], bool]:
        """Resolve a bare name used as a function. Returns (span, ambiguous)."""
        same_file = self.by_file_local.get((file_path, name))
        if same_file:
            return same_file, False
        imports = self.imports.get(file_path, {})
        binding = imports.get(name)
        if binding is not None and binding.name is not None:
            for path in self._module_files(binding.module):
                hit = self.by_file_local.get((path, binding.name))
                if hit:
                    return hit, False
            if binding.module and self._module_files(binding.module):
                return None, False   # imported from one of our modules, but it's not a function there
            return self._unique(binding.name)
        if binding is not None:
            return None, False        # the name is a module, not a function
        # Not defined here and not imported: only a star import (or a caller that gave us
        # no import information at all) can legitimately bind it.
        if self._legacy_imports or "*" in imports:
            return self._unique(name)
        return None, False

    def _unique(self, name: str) -> tuple[Optional[FunctionSpan], bool]:
        candidates = self.by_local.get(name, [])
        if len(candidates) == 1:
            return candidates[0], False
        return None, len(candidates) > 1

    def resolve_module_attr(self, dotted: list[str], file_path: str) -> tuple[Optional[FunctionSpan], Optional[ClassKey], bool]:
        """Resolve `mod.name` / `pkg.mod.name`. Returns (function, class, is_import_rooted)."""
        root, attr = dotted[0], dotted[-1]
        binding = self.imports.get(file_path, {}).get(root)
        if binding is None:
            return None, None, False
        for base in self._binding_modules(binding):
            module = ".".join([base, *dotted[1:-1]])
            module_files = self._module_files(module)
            for path in module_files:
                fn = self.by_file_local.get((path, attr))
                if fn:
                    return fn, None, True
                if (path, attr) in self.classes:
                    return None, (path, attr), True
            if module_files:
                return None, None, True
        # We know the root is an import but can't map it to a file (legacy callers pass
        # no module info, and third-party modules never map): a unique name is still a
        # safe match, since nothing else in the codebase could be meant.
        fn, _ = self._unique(attr)
        if fn and not fn.class_name:
            return fn, None, True
        classes = self.classes_by_name.get(attr, [])
        if len(classes) == 1:
            return None, classes[0].key, True
        return None, None, True

    def resolve_class(self, node: ast.AST, file_path: str) -> Optional[ClassKey]:
        """If `node` names a class we parsed (`Cls` or `module.Cls`), return its key."""
        if isinstance(node, ast.Name):
            if (file_path, node.id) in self.classes:
                return (file_path, node.id)
            imports = self.imports.get(file_path, {})
            binding = imports.get(node.id)
            if binding is not None and binding.name is not None:
                for path in self._module_files(binding.module):
                    if (path, binding.name) in self.classes:
                        return (path, binding.name)
                if binding.module and self._module_files(binding.module):
                    return None
                name = binding.name
            elif binding is not None:
                return None
            elif self._legacy_imports or "*" in imports:
                name = node.id
            else:
                return None
            candidates = self.classes_by_name.get(name, [])
            return candidates[0].key if len(candidates) == 1 else None
        dotted = _dotted_name(node)
        if dotted and len(dotted) > 1:
            _, cls, _ = self.resolve_module_attr(dotted, file_path)
            return cls
        return None

    def annotation_class(self, annotation: Optional[ast.AST], file_path: str) -> Optional[ClassKey]:
        """`Repo`, `"Repo"`, `Optional[Repo]`, `Repo | None`, `Annotated[Repo, ...]` -> Repo."""
        if annotation is None:
            return None
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                annotation = ast.parse(annotation.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(annotation, ast.Subscript):
            wrapper = _dotted_name(annotation.value)
            if wrapper and wrapper[-1] in {"Optional", "Annotated", "Final", "ClassVar"}:
                inner = annotation.slice
                if isinstance(inner, ast.Tuple) and inner.elts:
                    inner = inner.elts[0]
                return self.annotation_class(inner, file_path)
            return None
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            return self.annotation_class(annotation.left, file_path) or self.annotation_class(annotation.right, file_path)
        return self.resolve_class(annotation, file_path)

    def _instantiated_class(self, value: ast.AST, file_path: str) -> Optional[ClassKey]:
        if isinstance(value, ast.Call):
            return self.resolve_class(value.func, file_path)
        return None

    def lookup_method(self, cls: ClassKey, name: str, _seen: Optional[set] = None) -> Optional[FunctionSpan]:
        """Find `name` on a class or, failing that, on the base classes we parsed."""
        seen = _seen if _seen is not None else set()
        if cls in seen or cls not in self.classes:
            return None
        seen.add(cls)
        info = self.classes[cls]
        if name in info.methods:
            return info.methods[name]
        for base in info.bases:
            base_key = self.resolve_class(base, cls[0])
            if base_key:
                found = self.lookup_method(base_key, name, seen)
                if found:
                    return found
        return None

    def _attr_type(self, cls: ClassKey, attr: str, _seen: Optional[set] = None) -> Optional[ClassKey]:
        seen = _seen if _seen is not None else set()
        if cls in seen or cls not in self.classes:
            return None
        seen.add(cls)
        info = self.classes[cls]
        if attr in info.attr_types:
            return info.attr_types[attr]
        for base in info.bases:
            base_key = self.resolve_class(base, cls[0])
            found = self._attr_type(base_key, attr, seen) if base_key else None
            if found:
                return found
        return None

    # ---- types of expressions -----------------------------------------------------

    def local_types(self, scope: FunctionSpan) -> dict[str, ClassKey]:
        """Variables in this scope whose class is stated outright by the code.

        Sources, all static: an annotated parameter, an annotated assignment, a direct
        `x = Cls(...)`, or `with Cls(...) as x`. A second, different assignment drops
        the name rather than guessing which one is live at a given call.
        """
        types: dict[str, Optional[ClassKey]] = {}
        node = scope.node
        if isinstance(node, _SCOPE_NODES):
            args = node.args
            for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
                cls = self.annotation_class(a.annotation, scope.file_path)
                if cls:
                    types[a.arg] = cls
        for stmt in _own_nodes(node):
            if isinstance(stmt, ast.With) or isinstance(stmt, ast.AsyncWith):
                for item in stmt.items:
                    if isinstance(item.optional_vars, ast.Name):
                        cls = self._instantiated_class(item.context_expr, scope.file_path)
                        types[item.optional_vars.id] = cls
                continue
            target, value, annotation = _simple_assignment(stmt)
            if target is None:
                continue
            cls = self.annotation_class(annotation, scope.file_path) if annotation is not None else None
            if cls is None and value is not None:
                cls = self.type_of(value, scope, {k: v for k, v in types.items() if v}, set())
            types[target] = cls
        return {k: v for k, v in types.items() if v}

    def type_of(
        self, node: ast.AST, scope: FunctionSpan, local_types: dict[str, ClassKey], local_bound: set[str]
    ) -> Optional[ClassKey]:
        """The class of the object `node` evaluates to, when the code states it."""
        file_path = scope.file_path
        if isinstance(node, ast.Name):
            if node.id in local_types:
                return local_types[node.id]
            if node.id in local_bound and not scope.is_module:
                return None
            if node.id in self.module_instances.get(file_path, {}):
                return self.module_instances[file_path][node.id]
            binding = self.imports.get(file_path, {}).get(node.id)
            if binding is not None and binding.name is not None:
                for path in self._module_files(binding.module):
                    cls = self.module_instances.get(path, {}).get(binding.name)
                    if cls:
                        return cls
            return None
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "self" and scope.class_name:
                return self._attr_type((file_path, scope.class_name), node.attr)
            owner = self.type_of(node.value, scope, local_types, local_bound)
            return self._attr_type(owner, node.attr) if owner else None
        if isinstance(node, ast.Call):
            cls = self.resolve_class(node.func, file_path)
            if cls:
                return cls
            fn = self._called_function(node, scope, local_types, local_bound)
            if fn is not None and isinstance(fn.node, _SCOPE_NODES):
                return self.annotation_class(fn.node.returns, fn.file_path)
            return None
        if isinstance(node, ast.Await):
            return self.type_of(node.value, scope, local_types, local_bound)
        return None

    def _called_function(self, call: ast.Call, scope, local_types, local_bound) -> Optional[FunctionSpan]:
        func = call.func
        if isinstance(func, ast.Name) and func.id not in local_bound:
            return self.resolve_function_name(func.id, scope.file_path)[0]
        dotted = _dotted_name(func)
        if dotted and len(dotted) > 1 and dotted[0] not in local_bound:
            return self.resolve_module_attr(dotted, scope.file_path)[0]
        return None

    def function_reference(self, node: ast.AST, scope: FunctionSpan, local_bound: set[str]) -> Optional[FunctionSpan]:
        """Resolve an expression used *as a value* that names one of our functions."""
        if isinstance(node, ast.Name):
            if node.id in local_bound and not scope.is_module:
                return None
            return self.resolve_function_name(node.id, scope.file_path)[0]
        dotted = _dotted_name(node)
        if not dotted or len(dotted) < 2 or (dotted[0] in local_bound and not scope.is_module):
            return None
        if dotted[0] in ("self", "cls") and scope.class_name and len(dotted) == 2:
            return self.lookup_method((scope.file_path, scope.class_name), dotted[1])
        fn, _, _ = self.resolve_module_attr(dotted, scope.file_path)
        if fn:
            return fn
        cls = self.resolve_class(node.value, scope.file_path)   # Cls.method handed around unbound
        return self.lookup_method(cls, dotted[-1]) if cls else None


def _simple_assignment(node: ast.AST) -> tuple[Optional[str], Optional[ast.AST], Optional[ast.AST]]:
    """(name, value, annotation) for `name = value` / `name: T = value`, else (None, None, None)."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id, node.value, None
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id, node.value, node.annotation
    return None, None, None


@dataclass
class CallEdges:
    edges: dict[str, set[str]]
    kinds: dict[tuple[str, str], str]
    unresolved_call_targets: set[str]


def resolve_edges(program: Program) -> CallEdges:
    """Build every edge the code states unambiguously, for functions and module nodes alike.

    Call shapes resolved with confidence (see docs/phase-2-reachability-hardening.md):
    - `name()` - a function in this file, or one this file imports (never "any function
      anywhere with that name"); `Cls()` reaches `Cls.__init__`
    - `self.m()` / `cls.m()` / `super().m()` - through the base classes we parsed
    - `module.name()` - `module` is an import of one of our files
    - `obj.m()` where obj's class is stated: `obj = Cls()`, an annotated parameter or
      variable, `self.attr` assigned from one of those, a module-level instance (also
      when imported), or the annotated return type of a function we can resolve
    - `Cls.m()` - a static/class method call
    - `task.delay(...)` - the Celery-style "call this function" attribute
    - a function passed to an invoker (`add_task`, `Depends`, `Thread(target=...)`, ...)
      is a REFERENCE edge; a function stored or passed anywhere else is a WEAK_REFERENCE
    Anything else (`connection.execute(...)` on a local of untracked type) is genuinely
    ambiguous: no edge, and the attribute name is recorded as unresolved instead.
    """
    scopes = [*program.functions, *program.modules.values()]
    edges: dict[str, set[str]] = {s.qualified_name: set() for s in scopes}
    kinds: dict[tuple[str, str], str] = {}
    unresolved: set[str] = set()

    def add(caller: FunctionSpan, callee: Optional[FunctionSpan], kind: str) -> None:
        if callee is None or callee.qualified_name == caller.qualified_name:
            return
        pair = (caller.qualified_name, callee.qualified_name)
        edges[caller.qualified_name].add(callee.qualified_name)
        rank = {CALL: 3, REFERENCE: 2, WEAK_REFERENCE: 1}
        if rank[kind] > rank.get(kinds.get(pair, ""), 0):
            kinds[pair] = kind

    for scope in scopes:
        local_bound = _local_bindings(scope.node)
        local_types = program.local_types(scope)
        enclosing = (scope.file_path, scope.class_name) if scope.class_name else None
        consumed: set[int] = set()   # value nodes already explained as part of a call

        nodes = list(_own_nodes(scope.node))
        if isinstance(scope.node, _SCOPE_NODES):
            # Depends(...) inside a route decorator's `dependencies=[...]` runs per request.
            for decorator in scope.node.decorator_list:
                nodes.extend(n for n in ast.walk(decorator) if _is_invoker_call(n))
                consumed.update(id(n) for n in ast.walk(decorator))

        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            for part in ast.walk(func):
                consumed.add(id(part))

            # Functions handed to this call as arguments.
            invoker = _is_invoker_call(node)
            for value in [*node.args, *(kw.value for kw in node.keywords)]:
                target = program.function_reference(value, scope, local_bound)
                if target is not None:
                    add(scope, target, REFERENCE if invoker else WEAK_REFERENCE)
                    consumed.update(id(n) for n in ast.walk(value))

            if isinstance(func, ast.Name):
                if func.id in local_bound and not scope.is_module:
                    continue   # calling a parameter or local variable - can't know its target
                target, ambiguous = program.resolve_function_name(func.id, scope.file_path)
                if target is not None:
                    add(scope, target, CALL)
                elif ambiguous:
                    unresolved.add(func.id)
                else:
                    cls = program.resolve_class(func, scope.file_path)
                    if cls:
                        add(scope, program.lookup_method(cls, "__init__"), CALL)
                continue
            if not isinstance(func, ast.Attribute):
                continue

            obj, attr = func.value, func.attr
            if enclosing and isinstance(obj, ast.Name) and obj.id in ("self", "cls"):
                add(scope, program.lookup_method(enclosing, attr), CALL)
                continue
            if (
                enclosing
                and isinstance(obj, ast.Call)
                and isinstance(obj.func, ast.Name)
                and obj.func.id == "super"
            ):
                for base in program.classes[enclosing].bases if enclosing in program.classes else []:
                    base_key = program.resolve_class(base, scope.file_path)
                    found = program.lookup_method(base_key, attr) if base_key else None
                    if found:
                        add(scope, found, CALL)
                        break
                continue

            receiver = program.type_of(obj, scope, local_types, local_bound)
            if receiver:
                add(scope, program.lookup_method(receiver, attr), CALL)
                continue

            dotted = _dotted_name(func)
            if dotted and (dotted[0] not in local_bound or scope.is_module):
                cls = program.resolve_class(obj, scope.file_path)
                if cls:                                   # Cls.method(...)
                    add(scope, program.lookup_method(cls, attr), CALL)
                    continue
                fn, klass, import_rooted = program.resolve_module_attr(dotted, scope.file_path)
                if import_rooted:
                    if fn is not None:
                        add(scope, fn, CALL)
                    elif klass is not None:               # module.Cls(...)
                        add(scope, program.lookup_method(klass, "__init__"), CALL)
                    continue                               # resolved - ours or third-party

            if attr in TASK_INVOKE_ATTRS:
                target = program.function_reference(obj, scope, local_bound)
                if target is not None:
                    add(scope, target, REFERENCE)
                    continue
            if not invoker:   # add_task & co. are understood, whatever object they're called on
                unresolved.add(attr)

        # Functions mentioned as plain values: `HANDLERS = {"a": handle_a}`, `return fn`.
        for node in nodes:
            if id(node) in consumed or not isinstance(node, (ast.Name, ast.Attribute)):
                continue
            if not isinstance(getattr(node, "ctx", None), ast.Load):
                continue
            target = program.function_reference(node, scope, local_bound)
            if target is not None:
                add(scope, target, WEAK_REFERENCE)
                consumed.update(id(n) for n in ast.walk(node))

    return CallEdges(edges=edges, kinds=kinds, unresolved_call_targets=unresolved)


def _is_invoker_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
    return name in INVOKER_NAMES


def build_call_edges(
    functions: list[FunctionSpan],
    import_tables: Optional[dict[str, dict[str, Union[str, ImportBinding]]]] = None,
) -> tuple[dict[str, set[str]], set[str]]:
    """Map each function's qualified name -> the set of our-own-code functions it calls.

    Returns (edges, unresolved_call_targets). Thin wrapper over resolve_edges for callers
    that only have a function table and Phase 1-style import tables (no module trees,
    so no base classes, module-level instances or module nodes). engine.build_call_graph
    uses Program + resolve_edges directly and gets the full picture.
    """
    result = resolve_edges(Program(functions, import_tables))
    return result.edges, result.unresolved_call_targets


def resolve_containing_function(
    functions: list[FunctionSpan], file_path: str, line: int
) -> Optional[FunctionSpan]:
    """Given a finding's file:line, find which function contains it.

    Innermost (smallest span) match wins. Zero matches means module-level code; the
    engine then falls back to that file's module node.
    """
    candidates = [
        f for f in functions
        if f.file_path == file_path and not f.is_module and f.span_start <= line <= f.span_end
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda f: f.span_end - f.span_start)
