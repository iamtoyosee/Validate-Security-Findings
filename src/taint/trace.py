"""Phase 3: does attacker-controlled data actually reach the dangerous call?

Reachability answers "can execution get here". This answers the next question, and it
is still plain static analysis - no model involved. Starting at the dangerous argument
on the finding's line, it walks *backward*:

  inside the function   which variables and expressions feed the argument
  across each call      which caller argument became this parameter, hop by hop up the
                        reachability path, until the entry point
  at the entry point    what kind of input the parameter is (a query string, a task
                        message, a CLI argument)

and records two things along the way: every step the value took, and everything that
could have neutralized it (an int() cast, shlex.quote, an allowlist check that exits
early). The result is evidence, deliberately not a verdict: exploitability/ turns it
into one, and hands it to the agent as a starting point it is told to check.

What it will not do: follow values through object state it can't see (`self.x` set from
a constructor argument), dynamic dispatch, or data that round-trips through a database.
Those come back as "unknown" or "stored", never as a guess.
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

from reachability.engine import CallGraph, entry_paths
from reachability.entry_points import HTTP_SERVER_BASES, EntryPoint
from reachability.graph import TASK_INVOKE_ATTRS, FunctionSpan, _dotted_name, _local_bindings, _own_nodes
from schemas import NormalizedFinding, ReachabilityVerdict
from taint import catalog
from taint.catalog import final_name, root_name
from weakness import classify_finding

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
MAX_WORK = 4000          # expression evaluations per finding before giving up
MAX_CALL_DEPTH = 4       # how deep to follow our own functions' return values
MAX_PATHS = 5


@dataclass(frozen=True)
class Step:
    file_path: str
    line: int
    function: str
    text: str


@dataclass(frozen=True)
class Sanitizer:
    description: str
    file_path: str
    line: int
    classes: Optional[frozenset] = None    # weakness classes it protects; None = all of them

    def effective(self, weakness: Optional[str]) -> bool:
        return self.classes is None or (weakness is not None and weakness in self.classes)


@dataclass(frozen=True)
class Origin:
    """One place a value can come from. `steps` run from the sink back toward the source."""
    kind: str                      # "source" | "stored" | "const" | "server" | "unknown" | "param"
    detail: str
    source_kind: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None
    steps: tuple = ()
    sanitizers: tuple = ()


@dataclass
class TaintTrace:
    finding_id: str
    weakness: Optional[str]
    # "tainted" | "sanitized" | "not_tainted" | "stored" | "unknown"
    status: str
    attacker_controlled: Optional[bool]
    summary: str
    sink: Optional[dict] = None
    source: Optional[dict] = None
    source_kind: Optional[str] = None
    reach: Optional[str] = None            # "remote" | "indirect" | "local" | "second-order"
    steps: list = field(default_factory=list)        # source -> sink
    sanitizers: list = field(default_factory=list)
    notes: list = field(default_factory=list)        # what the tracer could not follow
    path: list = field(default_factory=list)
    safe_sink: Optional[str] = None        # set when the call's own form is the safe one

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _text(node: ast.AST, limit: int = 80) -> str:
    try:
        text = " ".join(ast.unparse(node).split())
    except Exception:
        text = type(node).__name__
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Tracer:
    def __init__(self, graph: CallGraph, weakness: Optional[str]):
        self.graph = graph
        self.program = graph.program
        self.weakness = weakness
        self._parents: dict[str, dict[int, ast.AST]] = {}
        self._scope_info: dict[str, tuple[set, dict]] = {}
        self._work = 0
        self._active: set[tuple[int, str]] = set()
        self._call_stack: list[str] = []
        self.notes: list[str] = []

    # ---- tree navigation ----------------------------------------------------------

    def parents(self, file_path: str) -> dict[int, ast.AST]:
        if file_path not in self._parents:
            mapping: dict[int, ast.AST] = {}
            tree = self.program.trees.get(file_path)
            if tree is not None:
                for node in ast.walk(tree):
                    for child in ast.iter_child_nodes(node):
                        mapping[id(child)] = node
            self._parents[file_path] = mapping
        return self._parents[file_path]

    def statement_of(self, node: ast.AST, file_path: str) -> Optional[ast.stmt]:
        parents = self.parents(file_path)
        while node is not None and not isinstance(node, ast.stmt):
            node = parents.get(id(node))
        return node

    def scope_info(self, scope: FunctionSpan) -> tuple[set, dict]:
        if scope.qualified_name not in self._scope_info:
            self._scope_info[scope.qualified_name] = (_local_bindings(scope.node), self.program.local_types(scope))
        return self._scope_info[scope.qualified_name]

    def _step(self, scope: FunctionSpan, node: ast.AST, text: str) -> Step:
        return Step(scope.file_path, getattr(node, "lineno", scope.span_start), scope.qualified_name, text)

    @staticmethod
    def _extend(origins: list[Origin], step: Optional[Step] = None, sanitizers: tuple = ()) -> list[Origin]:
        """Add a step/sanitizers that sit *closer to the sink* than what's already recorded."""
        if step is None and not sanitizers:
            return origins
        return [
            Origin(o.kind, o.detail, o.source_kind, o.file_path, o.line,
                   ((step,) if step else ()) + o.steps, tuple(sanitizers) + o.sanitizers)
            for o in origins
        ]

    @staticmethod
    def _chain(downstream: Origin, upstream: list[Origin], step: Optional[Step] = None) -> list[Origin]:
        """Replace a parameter origin with where its argument came from."""
        return [
            Origin(u.kind, u.detail, u.source_kind, u.file_path, u.line,
                   downstream.steps + ((step,) if step else ()) + u.steps,
                   downstream.sanitizers + u.sanitizers)
            for u in upstream
        ]

    # ---- expressions --------------------------------------------------------------

    def origins(self, node: Optional[ast.AST], scope: FunctionSpan) -> list[Origin]:
        """Everything the value of `node` can derive from, evaluated inside `scope`."""
        if node is None:
            return []
        self._work += 1
        if self._work > MAX_WORK:
            return [Origin("unknown", "the trace got too large to finish")]
        key = (id(node), scope.qualified_name)
        if key in self._active:
            return []            # a loop variable feeding itself adds nothing new
        self._active.add(key)
        try:
            return self._origins(node, scope)
        finally:
            self._active.discard(key)

    def _union(self, nodes, scope) -> list[Origin]:
        out: list[Origin] = []
        for n in nodes:
            out.extend(self.origins(n, scope))
        return out

    def _origins(self, node: ast.AST, scope: FunctionSpan) -> list[Origin]:
        if isinstance(node, ast.Constant):
            return []
        if isinstance(node, ast.Name):
            return self._name_origins(node, scope)
        if isinstance(node, ast.Attribute):
            return self._attribute_origins(node, scope)
        if isinstance(node, ast.Call):
            return self._call_origins(node, scope)
        if isinstance(node, ast.Subscript):
            return self.origins(node.value, scope)   # an element of X comes from X; the key only selects
        if isinstance(node, ast.JoinedStr):
            return self._union([v.value for v in node.values if isinstance(v, ast.FormattedValue)], scope)
        if isinstance(node, ast.FormattedValue):
            return self.origins(node.value, scope)
        if isinstance(node, ast.BinOp):
            return self._union([node.left, node.right], scope)
        if isinstance(node, ast.BoolOp):
            return self._union(node.values, scope)
        if isinstance(node, ast.IfExp):
            return self._union([node.body, node.orelse], scope)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._union(node.elts, scope)
        if isinstance(node, ast.Dict):
            return self._union([v for v in [*node.keys, *node.values] if v is not None], scope)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.origins(node.elt, scope)
        if isinstance(node, ast.DictComp):
            return self._union([node.key, node.value], scope)
        if isinstance(node, (ast.Await, ast.Starred, ast.UnaryOp)):
            return self.origins(getattr(node, "value", None) or getattr(node, "operand", None), scope)
        if isinstance(node, ast.NamedExpr):
            return self.origins(node.value, scope)
        if isinstance(node, ast.Compare):
            return []            # a boolean
        return []

    # ---- names --------------------------------------------------------------------

    def _name_origins(self, node: ast.Name, scope: FunctionSpan) -> list[Origin]:
        name = node.id
        local_bound, _ = self.scope_info(scope)

        bound_by_comprehension = self._comprehension_source(node, scope)
        if bound_by_comprehension is not None:
            return self.origins(bound_by_comprehension, scope)

        if name == "request" and (name not in local_bound or scope.is_module) and self._is_framework_request(scope):
            return [Origin("source", "the request object", "http", scope.file_path, node.lineno)]
        if name in ("self", "cls") and scope.class_name:
            return [Origin("unknown", "state held on the object itself")]

        defs, definite = self._reaching(name, node, scope)
        out: list[Origin] = []
        for kind, value, stmt in defs:
            if value is None:
                continue
            words = {"assign": "is set from", "aug": "is extended with", "for": "iterates over", "with": "is bound to"}[kind]
            step = self._step(scope, stmt, f"`{name}` {words} `{_text(value, 70)}`")
            out.extend(self._extend(self.origins(value, scope), step))

        if not definite:
            if self._is_parameter(name, scope):
                out.append(Origin("param", name, file_path=scope.file_path, line=scope.span_start))
            elif not defs:
                out.extend(self._outer_name_origins(name, scope, node))

        guards = self._guards(name, node, scope)
        return self._extend(out, sanitizers=tuple(guards)) if guards else out

    def _is_parameter(self, name: str, scope: FunctionSpan) -> bool:
        if not isinstance(scope.node, _FUNCTION_NODES):
            return False
        args = scope.node.args
        names = [a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]]
        names += [a.arg for a in (args.vararg, args.kwarg) if a]
        return name in names

    def _is_framework_request(self, scope: FunctionSpan) -> bool:
        binding = self.program.imports.get(scope.file_path, {}).get("request")
        if binding is None:
            return False
        return (binding.module or "").split(".")[0] in catalog.REQUEST_MODULES

    def _comprehension_source(self, node: ast.Name, scope: FunctionSpan) -> Optional[ast.AST]:
        parents = self.parents(scope.file_path)
        current = parents.get(id(node))
        while current is not None and not isinstance(current, ast.stmt):
            if isinstance(current, _COMPREHENSIONS):
                for generator in current.generators:
                    if any(isinstance(n, ast.Name) and n.id == node.id for n in ast.walk(generator.target)):
                        return generator.iter
            current = parents.get(id(current))
        return None

    def _outer_name_origins(self, name: str, scope: FunctionSpan, node: ast.AST) -> list[Origin]:
        """A name this function doesn't define: a module-level variable or an import."""
        module = self.graph.modules.get(scope.file_path)
        if module is not None and not scope.is_module:
            values = [
                value for stmt in _own_nodes(module.node)
                for target, value in _assignments(stmt)
                if target == name and value is not None
            ]
            if values:
                return self._union(values, module)
        binding = self.program.imports.get(scope.file_path, {}).get(name)
        if binding is not None and binding.name is not None:
            for path in self.program._module_files(binding.module):
                other = self.graph.modules.get(path)
                if other is None:
                    continue
                values = [
                    value for stmt in _own_nodes(other.node)
                    for target, value in _assignments(stmt)
                    if target == binding.name and value is not None
                ]
                if values:
                    return self._union(values, other)
        return []   # a builtin, a module, or configuration imported from elsewhere: the server's own

    # ---- reaching definitions -----------------------------------------------------

    def _reaching(self, name: str, use: ast.AST, scope: FunctionSpan) -> tuple[list, bool]:
        """Assignments to `name` that can reach `use`, nearest first.

        Block-aware rather than a full dataflow solver: walking outward from the use,
        an unconditional assignment in the same block kills everything before it; an
        assignment inside an `if`/loop/`try` only *may* reach, so earlier ones are kept
        too. Returns (definitions, definite) - definite means the parameter of the same
        name, if there is one, can no longer be what's read.
        """
        parents = self.parents(scope.file_path)
        current = self.statement_of(use, scope.file_path)
        found: list = []
        while current is not None and current is not scope.node:
            parent = parents.get(id(current))
            if parent is None:
                break
            for block_name in ("body", "orelse", "finalbody"):
                block = getattr(parent, block_name, None)
                if isinstance(block, list) and any(s is current for s in block):
                    index = next(i for i, s in enumerate(block) if s is current)
                    for previous in reversed(block[:index]):
                        defs, definite = self._defs_in_statement(previous, name)
                        found.extend(defs)
                        if definite:
                            return found, True
            if isinstance(parent, (ast.For, ast.AsyncFor)) and any(s is current for s in parent.body):
                if _binds(parent.target, name):
                    found.append(("for", parent.iter, parent))
                    return found, True
                found.extend(self._block_defs(parent.body, name)[0])       # the loop's back edge
            elif isinstance(parent, ast.While) and any(s is current for s in parent.body):
                found.extend(self._block_defs(parent.body, name)[0])
            elif isinstance(parent, (ast.With, ast.AsyncWith)):
                for item in parent.items:
                    if item.optional_vars is not None and _binds(item.optional_vars, name):
                        found.append(("with", item.context_expr, parent))
                        return found, True
            elif isinstance(parent, ast.ExceptHandler) and parent.name == name:
                return found, True
            elif isinstance(parent, ast.Try) and isinstance(current, ast.ExceptHandler):
                found.extend(self._block_defs(parent.body, name)[0])
            current = parent
        return found, False

    def _block_defs(self, block: list, name: str) -> tuple[list, bool]:
        found: list = []
        for statement in reversed(block):
            defs, definite = self._defs_in_statement(statement, name)
            found.extend(defs)
            if definite:
                return found, True
        return found, False

    def _defs_in_statement(self, statement: ast.stmt, name: str) -> tuple[list, bool]:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if _binds(target, name):
                    return [("assign", _unpack(target, statement.value, name), statement)], True
            return [], False
        if isinstance(statement, ast.AnnAssign):
            if _binds(statement.target, name) and statement.value is not None:
                return [("assign", statement.value, statement)], True
            return [], False
        if isinstance(statement, ast.AugAssign):
            if _binds(statement.target, name):
                return [("aug", statement.value, statement)], False
            return [], False
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            bound = {(a.asname or a.name).split(".")[0] for a in statement.names}
            return ([], True) if name in bound else ([], False)
        if isinstance(statement, (*_FUNCTION_NODES, ast.ClassDef)):
            return ([], True) if statement.name == name else ([], False)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            found, definite = self._block_defs(statement.body, name)
            if definite:
                return found, True
            for item in statement.items:
                if item.optional_vars is not None and _binds(item.optional_vars, name):
                    return [*found, ("with", item.context_expr, statement)], True
            return found, False
        if isinstance(statement, ast.If):
            body, body_definite = self._block_defs(statement.body, name)
            other, other_definite = self._block_defs(statement.orelse, name)
            return body + other, bool(statement.orelse) and body_definite and other_definite
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            found = [("for", statement.iter, statement)] if _binds(statement.target, name) else []
            return found + self._block_defs(statement.body, name)[0] + self._block_defs(statement.orelse, name)[0], False
        if isinstance(statement, ast.While):
            return self._block_defs(statement.body, name)[0] + self._block_defs(statement.orelse, name)[0], False
        if isinstance(statement, ast.Try):
            found = self._block_defs(statement.body, name)[0]
            for handler in statement.handlers:
                found += self._block_defs(handler.body, name)[0]
            found += self._block_defs(statement.orelse, name)[0] + self._block_defs(statement.finalbody, name)[0]
            return found, False
        return [], False

    # ---- validation that guards a use ---------------------------------------------

    def _guards(self, name: str, use: ast.AST, scope: FunctionSpan) -> list[Sanitizer]:
        """Checks on `name` that every execution reaching `use` must have passed.

        Two shapes count:  `if not ok(x): return/raise/abort(...)` before the use, and
        the use sitting inside `if ok(x):`. `ok` is an allowlist membership test,
        `str.isdigit()` and friends, a full regex match, or a path-containment check.
        A denylist (`if x in BLOCKED: abort()`) is reported as a note, not a guard.
        """
        parents = self.parents(scope.file_path)
        # A check on something computed *from* the value only vouches for the value when
        # that part is what the sink acts on: an allowlisted hostname does make the URL
        # safe to request, but `name[:3].isdigit()` says nothing about the rest of `name`.
        names = self._derived_names(name, scope) if self.weakness == "ssrf" else {name}
        guards: list[Sanitizer] = []
        current = self.statement_of(use, scope.file_path)
        while current is not None and current is not scope.node:
            parent = parents.get(id(current))
            if parent is None:
                break
            for block_name in ("body", "orelse", "finalbody"):
                block = getattr(parent, block_name, None)
                if not (isinstance(block, list) and any(s is current for s in block)):
                    continue
                index = next(i for i, s in enumerate(block) if s is current)
                for position, previous in enumerate(block[:index]):
                    if isinstance(previous, ast.If) and _terminates(previous.body):
                        check = self._classify_test(previous.test, names, scope)
                        reassigned = any(self._defs_in_statement(later, name)[0] for later in block[position + 1:index])
                        if check and check[1] and reassigned:
                            self.notes.append(
                                f"{scope.file_path}:{previous.lineno} validates `{name}`, but it is assigned again "
                                "before it is used, so the check does not cover the value that is used."
                            )
                        elif check and check[1]:                    # "if NOT valid: leave"
                            guards.append(Sanitizer(check[0], scope.file_path, previous.lineno, check[2]))
                        elif check and check[3]:
                            self.notes.append(
                                f"{scope.file_path}:{previous.lineno} rejects known-bad values of `{name}` "
                                "(a denylist), which does not make the remaining values safe."
                            )
                    elif isinstance(previous, ast.Assert):
                        check = self._classify_test(previous.test, names, scope)
                        if check and not check[1]:
                            self.notes.append(
                                f"{scope.file_path}:{previous.lineno} asserts a check on `{name}`; "
                                "asserts are removed under `python -O`, so it is not counted as validation."
                            )
                if isinstance(parent, ast.If):
                    check = self._classify_test(parent.test, names, scope)
                    if check:
                        inside_body = block_name == "body"
                        if (inside_body and not check[1]) or (not inside_body and check[1]):
                            guards.append(Sanitizer(check[0], scope.file_path, parent.lineno, check[2]))
            current = parent
        return guards

    def _derived_names(self, name: str, scope: FunctionSpan) -> set[str]:
        """`name` plus variables computed from it (`host = urlparse(url).hostname`)."""
        names = {name}
        for _ in range(2):
            for node in _own_nodes(scope.node):
                for target, value in _assignments(node):
                    if value is not None and target not in names and _mentions(value, names):
                        names.add(target)
        return names

    def _classify_test(self, test: ast.AST, names: set[str], scope: FunctionSpan):
        """-> (description, negated, classes, is_denylist) or None."""
        negated = False
        while isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            negated = not negated
            test = test.operand
        if isinstance(test, ast.BoolOp):
            for value in test.values:
                found = self._classify_test(value, names, scope)
                if found:
                    return (found[0], found[1] != negated, found[2], found[3])
            return None
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and _mentions(test.left, names):
            op, right = test.ops[0], test.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)) and self._is_fixed_collection(right, scope):
                label = _text(right, 40)
                if any(hint in label.lower() for hint in catalog.DENYLIST_HINT):
                    return (f"denylist check against `{label}`", False, None, True)
                return (f"allowlist check: must be one of `{label}`", negated != isinstance(op, ast.NotIn), None, False)
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(right, ast.Constant) and right.value is None:
                return None
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.Is, ast.IsNot)):
            # `if re.fullmatch(p, x) is None: abort()`
            inner = self._classify_test(test.left, names, scope)
            if inner and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
                flipped = isinstance(test.ops[0], ast.Is)
                return (inner[0], (inner[1] != flipped) != negated, inner[2], inner[3])
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute):
            method, receiver = test.func.attr, test.func.value
            if method in catalog.VALIDATION_METHODS and _mentions(receiver, names):
                return (f"`.{method}()` check", negated, None, False)
            if method in catalog.REGEX_FULL and (any(_mentions(a, names) for a in test.args) or _mentions(receiver, names)):
                pattern = self._regex_text(test, scope)
                if pattern is not None and not _regex_is_restrictive(pattern):
                    self.notes.append(
                        f"{scope.file_path}:{test.lineno} matches against `{pattern}`, which still allows "
                        "arbitrary characters, so it is not counted as validation."
                    )
                    return None
                shown = f" against `{pattern}`" if pattern else ""
                return (f"full-match regex validation{shown}", negated, None, False)
            if method in catalog.PATH_CONTAINMENT and (_mentions(receiver, names) or any(_mentions(a, names) for a in test.args)):
                return ("path containment check (`is_relative_to`)", negated, frozenset({"path"}), False)
            if method == "startswith" and _mentions(receiver, names) and test.args and not isinstance(test.args[0], ast.Constant):
                return ("path prefix check (`startswith`)", negated, frozenset({"path"}), False)
        if isinstance(test, ast.Call):
            return self._classify_validator_call(test, names, scope, negated)
        return None

    def _classify_validator_call(self, test: ast.Call, names: set[str], scope: FunctionSpan, negated: bool):
        """`if not is_hostname(host): abort()` - one of our own functions whose every
        return is itself a recognized check on the argument we care about."""
        callee = self._resolve_callee(test, scope, *self.scope_info(scope))
        if callee is None or not isinstance(callee.node, _FUNCTION_NODES) or callee.qualified_name in self._call_stack:
            return None
        bound = _bind(callee, test.args, test.keywords)
        parameters = {p for p, (expression, in_callee) in bound.items() if not in_callee and _mentions(expression, names)}
        returned = [n.value for n in _own_nodes(callee.node) if isinstance(n, ast.Return) and n.value is not None]
        if not parameters or not returned:
            return None
        self._call_stack.append(callee.qualified_name)
        try:
            checks = [self._classify_test(value, parameters, callee) for value in returned]
        finally:
            self._call_stack.pop()
        if any(c is None or c[3] for c in checks) or len({c[1] for c in checks}) != 1:
            return None
        description, inner_negated, classes, _ = checks[0]
        return (f"`{callee.qualified_name}()`: {description}", negated != inner_negated, classes, False)

    def _regex_text(self, call: ast.Call, scope: FunctionSpan) -> Optional[str]:
        """The pattern a `fullmatch` call uses, when it is a literal we can find."""
        receiver = call.func.value
        candidates = []
        if isinstance(receiver, ast.Name) and receiver.id == "re" and call.args:
            candidates.append(call.args[0])
        else:      # PATTERN.fullmatch(x): look for PATTERN = re.compile("...")
            module = self.graph.modules.get(scope.file_path)
            target = receiver.id if isinstance(receiver, ast.Name) else None
            for stmt in (_own_nodes(module.node) if module is not None and target else []):
                for assigned, value in _assignments(stmt):
                    if assigned == target and isinstance(value, ast.Call) and final_name(value.func) == "compile" and value.args:
                        candidates.append(value.args[0])
        for candidate in candidates:
            if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                return candidate.value
        return None

    def _is_fixed_collection(self, node: ast.AST, scope: FunctionSpan) -> bool:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            return all(isinstance(e, ast.Constant) for e in (node.keys if isinstance(node, ast.Dict) else node.elts))
        if isinstance(node, (ast.Name, ast.Attribute)):
            return not self.origins(node, scope)     # nothing variable feeds it: a module-level constant
        return False

    # ---- attributes ---------------------------------------------------------------

    def _attribute_origins(self, node: ast.Attribute, scope: FunctionSpan) -> list[Origin]:
        dotted = _dotted_name(node)
        local_bound, _ = self.scope_info(scope)
        if dotted:
            root = dotted[0]
            if root == "request" and (root not in local_bound or scope.is_module) and self._is_framework_request(scope):
                return [Origin("source", ".".join(dotted[:2]), "http", scope.file_path, node.lineno)]
            if dotted[:2] == ["sys", "argv"]:
                return [Origin("source", "sys.argv", "cli", scope.file_path, node.lineno)]
            if dotted[:2] == ["os", "environ"]:
                return [Origin("source", "os.environ", "environment", scope.file_path, node.lineno)]
            if root == "self" and scope.class_name and len(dotted) >= 2:
                if dotted[1] in catalog.HTTP_HANDLER_ATTRIBUTES and self._is_http_handler(scope):
                    return [Origin("source", f"self.{dotted[1]}", "http", scope.file_path, node.lineno)]
                return self._instance_attribute_origins(dotted[1], scope)
            binding = self.program.imports.get(scope.file_path, {}).get(root)
            if binding is not None and root not in local_bound and binding.name is None:
                return []        # module.CONSTANT from an import: the server's own configuration
        return self.origins(node.value, scope)

    def _is_http_handler(self, scope: FunctionSpan) -> bool:
        seen: set = set()
        pending = [(scope.file_path, scope.class_name)]
        while pending:
            key = pending.pop()
            if key in seen or key not in self.program.classes:
                continue
            seen.add(key)
            for base in self.program.classes[key].bases:
                if final_name(base) in HTTP_SERVER_BASES:
                    return True
                resolved = self.program.resolve_class(base, key[0])
                if resolved:
                    pending.append(resolved)
        return False

    def _instance_attribute_origins(self, attr: str, scope: FunctionSpan) -> list[Origin]:
        info = self.program.classes.get((scope.file_path, scope.class_name))
        out: list[Origin] = []
        for method in (info.methods.values() if info else []):
            for node in _own_nodes(method.node):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute) and target.attr == attr
                        and isinstance(target.value, ast.Name) and target.value.id == "self"
                        and node.value is not None
                    ):
                        out.extend(self.origins(node.value, method))
        resolved = []
        for origin in out:
            if origin.kind == "param":
                resolved.append(Origin("unknown", f"`self.{attr}` is set from a constructor or method argument"))
            else:
                resolved.append(origin)
        return resolved

    # ---- calls --------------------------------------------------------------------

    def _call_origins(self, call: ast.Call, scope: FunctionSpan) -> list[Origin]:
        func = call.func
        name = final_name(func)
        root = root_name(func)
        receiver = func.value if isinstance(func, ast.Attribute) else None
        arguments = [*call.args, *(kw.value for kw in call.keywords)]
        local_bound, local_types = self.scope_info(scope)

        if name in catalog.TYPE_CASTS and receiver is None:
            guard = Sanitizer(f"`{name}()` conversion", scope.file_path, call.lineno)
            return self._extend(self._union(arguments, scope), sanitizers=(guard,))
        if name in catalog.CLASS_SANITIZERS:
            classes, roots = catalog.CLASS_SANITIZERS[name]
            if roots is None or root in roots:
                guard = Sanitizer(f"`{_text(func, 40)}()`", scope.file_path, call.lineno, classes)
                inputs = arguments if arguments else ([receiver] if receiver is not None else [])
                return self._extend(self._union(inputs, scope), sanitizers=(guard,))

        if receiver is None and name == "input":
            return [Origin("source", "input()", "cli", scope.file_path, call.lineno)]
        if name == "getenv" and root == "os":
            return [Origin("source", "os.getenv()", "environment", scope.file_path, call.lineno)]

        if name in catalog.DATABASE_READS or name in {"execute", "executemany"}:
            return [Origin("stored", f"`{_text(call, 60)}`", "database", scope.file_path, call.lineno)]

        callee = self._resolve_callee(call, scope, local_bound, local_types)
        if callee is not None:
            return self._return_origins(callee, call, scope)
        if self.program.resolve_class(func, scope.file_path) is not None:
            return self._union(arguments, scope)     # an object built from these values carries them

        receiver_origins = self.origins(receiver, scope) if receiver is not None else []
        if name in catalog.FILE_READS and not any(o.kind in ("source", "param") for o in receiver_origins):
            return [Origin("stored", f"`{_text(call, 60)}`", "file", scope.file_path, call.lineno)]
        if name in catalog.SERVER_VALUES and not arguments:
            return receiver_origins
        if name in {"get", "pop", "setdefault", "getlist"} and receiver is not None:
            return receiver_origins + self._union(call.args[1:], scope)   # the key selects; a default flows
        return receiver_origins + self._union(arguments, scope)

    def _resolve_callee(self, call: ast.Call, scope, local_bound, local_types) -> Optional[FunctionSpan]:
        func = call.func
        if isinstance(func, ast.Name):
            if func.id in local_bound and not scope.is_module:
                return None
            return self.program.resolve_function_name(func.id, scope.file_path)[0]
        if not isinstance(func, ast.Attribute):
            return None
        if isinstance(func.value, ast.Name) and func.value.id in ("self", "cls") and scope.class_name:
            return self.program.lookup_method((scope.file_path, scope.class_name), func.attr)
        receiver = self.program.type_of(func.value, scope, local_types, local_bound)
        if receiver:
            return self.program.lookup_method(receiver, func.attr)
        dotted = _dotted_name(func)
        if dotted and dotted[0] not in local_bound:
            cls = self.program.resolve_class(func.value, scope.file_path)
            if cls:
                return self.program.lookup_method(cls, func.attr)
            return self.program.resolve_module_attr(dotted, scope.file_path)[0]
        return None

    def _return_origins(self, callee: FunctionSpan, call: ast.Call, scope: FunctionSpan) -> list[Origin]:
        """What a call to one of our own functions returns, in terms of its arguments."""
        if len(self._call_stack) >= MAX_CALL_DEPTH or callee.qualified_name in self._call_stack:
            return self._union([*call.args, *(kw.value for kw in call.keywords)], scope)
        self._call_stack.append(callee.qualified_name)
        try:
            returned = [
                n.value for n in _own_nodes(callee.node)
                if isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) and n.value is not None
            ]
            bound = _bind(callee, call.args, call.keywords)
            out: list[Origin] = []
            for origin in self._union(returned, callee):
                if origin.kind != "param":
                    out.append(origin)
                elif origin.detail in bound:
                    expression, in_callee = bound[origin.detail]
                    out.extend(self._chain(origin, self.origins(expression, callee if in_callee else scope)))
                else:
                    out.append(Origin("unknown", f"argument `{origin.detail}` of `{callee.qualified_name}` could not be matched"))
            return out
        finally:
            self._call_stack.pop()

    # ---- across the call path -----------------------------------------------------

    def resolve_parameters(self, origins: list[Origin], path: list[str], index: int, entry_known: bool) -> list[Origin]:
        """Turn "this came in as parameter p" into where p's value came from, one hop up."""
        out: list[Origin] = []
        for origin in origins:
            if origin.kind != "param":
                out.append(origin)
                continue
            callee = self.graph.span(path[index])
            if index == 0:
                entry = self.graph.entry_info.get(path[0]) if entry_known else None
                if entry is None or callee is None:
                    out.extend(self._chain(origin, [Origin("unknown", f"no caller of `{path[0]}` was resolved, so `{origin.detail}` could not be followed")]))
                else:
                    out.extend(self._chain(origin, self._entry_parameter(origin.detail, callee, entry)))
                continue
            caller = self.graph.span(path[index - 1])
            sites = self._call_sites(caller, callee) if caller is not None and callee is not None else []
            resolved_any = False
            for site_kind, positional, keywords, site in sites:
                if site_kind == "inject":      # Depends(fn): the framework fills fn's parameters from the request
                    entry = self.graph.entry_info.get(path[0]) or EntryPoint(None, "", "http", "request")
                    out.extend(self._chain(origin, self._entry_parameter(origin.detail, callee, entry)))
                    resolved_any = True
                    continue
                bound = _bind(callee, positional, keywords)
                if origin.detail not in bound:
                    continue
                expression, in_callee = bound[origin.detail]
                step = self._step(caller, site, f"`{caller.qualified_name}` passes `{_text(expression, 60)}` as `{origin.detail}`")
                if in_callee:
                    upstream = self.origins(expression, callee)
                else:
                    upstream = self.resolve_parameters(self.origins(expression, caller), path, index - 1, entry_known)
                out.extend(self._chain(origin, upstream, None if in_callee else step))
                resolved_any = True
            if not resolved_any:
                out.extend(self._chain(origin, [Origin(
                    "unknown",
                    f"`{path[index - 1]}` reaches `{path[index]}` indirectly, so the value passed as `{origin.detail}` could not be followed",
                )]))
        return out

    def _call_sites(self, caller: FunctionSpan, callee: FunctionSpan) -> list:
        """Calls inside `caller` that invoke `callee`: (kind, positional, keywords, node)."""
        bare = (callee.local_name or callee.qualified_name).rsplit(".", 1)[-1]
        nodes = list(_own_nodes(caller.node))
        if isinstance(caller.node, _FUNCTION_NODES):
            for decorator in caller.node.decorator_list:
                nodes.extend(ast.walk(decorator))
        sites = []
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            name = final_name(node.func)
            if name == bare or (bare == "__init__" and name == callee.class_name):
                sites.append(("call", node.args, node.keywords, node))
                continue
            if isinstance(node.func, ast.Attribute) and name in TASK_INVOKE_ATTRS and final_name(node.func.value) == bare:
                args_kw = next((kw.value for kw in node.keywords if kw.arg == "args"), None)
                positional = list(args_kw.elts) if isinstance(args_kw, (ast.List, ast.Tuple)) else node.args
                sites.append(("call", positional, [], node))
                continue
            values = [*node.args, *(kw.value for kw in node.keywords)]
            position = next((i for i, v in enumerate(node.args) if final_name(v) == bare), None)
            if not any(final_name(v) == bare for v in values if isinstance(v, (ast.Name, ast.Attribute))):
                continue
            if name in {"Depends", "Security"}:
                sites.append(("inject", [], [], node))
            elif position is not None and name in {"add_task", "submit", "to_thread", "run_in_executor", "start_new_thread", "call_soon", "create_task"}:
                sites.append(("call", node.args[position + 1:], node.keywords, node))
            elif any(kw.arg == "target" for kw in node.keywords):
                args_kw = next((kw.value for kw in node.keywords if kw.arg == "args"), None)
                sites.append(("call", list(args_kw.elts) if isinstance(args_kw, (ast.List, ast.Tuple)) else [], [], node))
        return sites

    def _entry_parameter(self, name: str, entry_span: FunctionSpan, entry: EntryPoint) -> list[Origin]:
        """What kind of outside input a parameter of an entry point is."""
        node = entry_span.node
        if not isinstance(node, _FUNCTION_NODES):
            return []
        if name in ("self", "cls"):
            return [Origin("unknown", "state held on the handler object")]
        args = node.args
        ordered = [*args.posonlyargs, *args.args]
        defaults = dict(zip([a.arg for a in ordered][len(ordered) - len(args.defaults):], args.defaults))
        defaults.update({a.arg: d for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None})
        parameter = next((a for a in [*ordered, *args.kwonlyargs] if a.arg == name), None)
        annotation = parameter.annotation if parameter else None
        annotation_name = final_name(annotation.value if isinstance(annotation, ast.Subscript) else annotation) if annotation is not None else None
        here = dict(file_path=entry_span.file_path, line=node.lineno)
        word = catalog.SOURCE_WORDS.get(entry.kind, "outside input")

        default = defaults.get(name)
        if isinstance(default, ast.Call) and final_name(default.func) in {"Depends", "Security"} and default.args:
            local_bound, local_types = self.scope_info(entry_span)
            dependency = self.program.function_reference(default.args[0], entry_span, local_bound)
            if dependency is not None and dependency.qualified_name not in self._call_stack:
                self._call_stack.append(dependency.qualified_name)
                try:
                    returned = [n.value for n in _own_nodes(dependency.node) if isinstance(n, ast.Return) and n.value is not None]
                    out: list[Origin] = []
                    for origin in self._union(returned, dependency):
                        if origin.kind == "param":
                            out.extend(self._chain(origin, self._entry_parameter(origin.detail, dependency, entry)))
                        else:
                            out.append(origin)
                    step = Step(entry_span.file_path, node.lineno, entry_span.qualified_name,
                                f"`{name}` is supplied by the dependency `{dependency.qualified_name}`")
                    return self._extend(out, step)
                finally:
                    self._call_stack.pop()
            return [Origin("unknown", f"`{name}` comes from a dependency that could not be resolved")]

        if name in ("request", "req") or annotation_name in {"Request", "HttpRequest", "WebSocket"}:
            return [Origin("source", "the request object", "http", **here)]
        if annotation_name in catalog.INFRASTRUCTURE_ANNOTATIONS:
            return []

        origin = Origin("source", f"parameter `{name}` of {entry.label}", entry.kind if entry.kind in catalog.SOURCE_WORDS else "http", **here)
        step = Step(entry_span.file_path, node.lineno, entry_span.qualified_name,
                    f"`{name}` arrives from {word} ({entry.label})")
        guards: list[Sanitizer] = []
        if annotation_name in catalog.NUMERIC_ANNOTATIONS:
            guards.append(Sanitizer(f"typed parameter: the framework only accepts a valid `{annotation_name}`", **here))
        elif annotation_name == "Literal" or self._is_enum(annotation, entry_span):
            guards.append(Sanitizer("parameter is restricted to a fixed set of values by its type", **here))
        converter = re.search(rf"<(\w+):{re.escape(name)}>", entry.label)
        if converter and converter.group(1) in catalog.NUMERIC_CONVERTERS:
            guards.append(Sanitizer(f"URL converter `<{converter.group(1)}:{name}>` only matches a number", **here))
        return self._extend([origin], step, tuple(guards))

    def _is_enum(self, annotation: Optional[ast.AST], scope: FunctionSpan) -> bool:
        cls = self.program.annotation_class(annotation, scope.file_path) if annotation is not None else None
        info = self.program.classes.get(cls) if cls else None
        return bool(info) and any((final_name(b) or "").endswith("Enum") for b in info.bases)


# ---- small AST helpers -------------------------------------------------------------

def _binds(target: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(target)) and not isinstance(target, (ast.Attribute, ast.Subscript))


def _unpack(target: ast.AST, value: ast.AST, name: str) -> ast.AST:
    """`a, b = x, y` -> for `b`, just `y`."""
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
        for element, part in zip(target.elts, value.elts):
            if _binds(element, name):
                return _unpack(element, part, name)
    return value


def _assignments(node: ast.AST):
    if isinstance(node, ast.Assign):
        for target in node.targets:
            for n in ast.walk(target):
                if isinstance(n, ast.Name) and not isinstance(target, (ast.Attribute, ast.Subscript)):
                    yield n.id, node.value
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        yield node.target.id, node.value


def _mentions(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))


def _regex_is_restrictive(pattern: str) -> bool:
    """False when the pattern lets arbitrary characters through: an unescaped `.`, a
    negated class, or one of the catch-all escapes. `[a-z0-9.-]+` is restrictive;
    `.+\\.tar` is not."""
    without_classes = re.sub(r"\[(?!\^)(?:\\.|[^\]\\])*\]", "", pattern)
    if re.search(r"\[\^", pattern):
        return False
    return not re.search(r"(?<!\\)\.|\\[SWD]", without_classes)


def _terminates(block: list) -> bool:
    if not block:
        return False
    last = block[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        return final_name(last.value.func) in catalog.TERMINATORS
    return False


def _bind(callee: FunctionSpan, positional: list, keywords: list) -> dict:
    """parameter name -> (expression, evaluated_in_callee). Defaults are evaluated in the callee."""
    node = callee.node
    if not isinstance(node, _FUNCTION_NODES):
        return {}
    args = node.args
    parameters = [a.arg for a in [*args.posonlyargs, *args.args]]
    is_static = any(final_name(d) == "staticmethod" for d in node.decorator_list)
    if callee.class_name and parameters and parameters[0] in ("self", "cls") and not is_static:
        parameters = parameters[1:]
    bound: dict = {}
    for parameter, expression in zip(parameters, positional):
        if not isinstance(expression, ast.Starred):
            bound[parameter] = (expression, False)
    for keyword in keywords:
        if keyword.arg:
            bound[keyword.arg] = (keyword.value, False)
    all_positional = [a.arg for a in [*args.posonlyargs, *args.args]]
    for parameter, default in zip(all_positional[len(all_positional) - len(args.defaults):], args.defaults):
        bound.setdefault(parameter, (default, True))
    for parameter, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None:
            bound.setdefault(parameter.arg, (default, True))
    return bound


# ---- locating the sink -------------------------------------------------------------

def _sink_candidates(scope: FunctionSpan, finding: NormalizedFinding, weakness: Optional[str]) -> list:
    """(dangerous expression, call node or None, weakness class) on the finding's lines."""
    start, end = finding.line_start, finding.line_end or finding.line_start
    statements = [
        n for n in _own_nodes(scope.node)
        if isinstance(n, ast.stmt) and n.lineno <= end and (n.end_lineno or n.lineno) >= start
        and not isinstance(n, (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith))
    ]
    if not statements:      # the finding points into a compound statement's header
        statements = [
            n for n in _own_nodes(scope.node)
            if isinstance(n, ast.stmt) and n.lineno <= end and (n.end_lineno or n.lineno) >= start
        ][-1:]

    matches = []
    for statement in statements:
        for call in (n for n in ast.walk(statement) if isinstance(n, ast.Call)):
            sink = _match_sink(call, weakness)
            if sink is None:
                continue
            cls, position = sink
            if position == "receiver":
                expression = call.func.value if isinstance(call.func, ast.Attribute) else None
            else:
                expression = call.args[position] if len(call.args) > position else next(
                    (kw.value for kw in call.keywords if kw.arg in {"url", "args", "sql", "query", "cmd", "path", "source"}), None
                )
            if expression is not None:
                matches.append((expression, call, cls))
    preferred = [m for m in matches if weakness and m[2] == weakness]
    if preferred or matches:
        return preferred or matches

    # No recognized call on the flagged line (a scanner pointing at the line where the
    # query string is built, say): the value being built there is what matters.
    fallback = []
    for statement in statements:
        value = getattr(statement, "value", None)
        if value is not None:
            fallback.append((value, None, weakness))
    return fallback


def _match_sink(call: ast.Call, weakness: Optional[str]) -> Optional[tuple[str, object]]:
    name = final_name(call.func)
    root = root_name(call.func)
    shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords)
    if name in catalog.SHELL_KEYWORD_SINKS and (shell or root == "subprocess"):
        return ("command", 0)
    entry = catalog.SINKS.get(name)
    if entry is None:
        return None
    cls = entry[0]
    if name in catalog.CLASS_GATED:
        if cls == "deserialization" and root not in catalog.DESERIALIZATION_ROOTS:
            return None
        if cls == "ssrf" and weakness != "ssrf" and root not in {"requests", "httpx", "urllib3"}:
            return None
        if cls == "command" and weakness != "command":
            return None
        if cls == "path" and name == "open" and isinstance(call.func, ast.Attribute) and weakness != "path":
            return None
        if cls in {"sql", "template"} and weakness not in (cls, None):
            return None
    return entry


def _safe_form(call: Optional[ast.Call], cls: Optional[str]) -> Optional[str]:
    """The call is written in the form that is safe no matter what flows into it."""
    if call is None:
        return None
    if cls == "sql" and call.args and isinstance(call.args[0], ast.Constant) and len(call.args) > 1:
        return "the query text is a constant and the values are bound as parameters"
    if cls == "deserialization":
        loader = next((kw.value for kw in call.keywords if kw.arg == "Loader"), None)
        if loader is None and len(call.args) > 1 and root_name(call.func) == "yaml":
            loader = call.args[1]
        if loader is not None and "Safe" in (final_name(loader) or ""):
            return "the YAML is loaded with a safe loader"
    if cls == "command":
        shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call.keywords)
        if not shell and final_name(call.func) in catalog.SHELL_KEYWORD_SINKS and call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
            first = call.args[0].elts[0] if call.args[0].elts else None
            if isinstance(first, ast.Constant):
                return "the command is a fixed program run without a shell, so the value is a single argument"
    return None


# ---- the public entry point --------------------------------------------------------

_STATUS_RANK = {"tainted": 0, "stored": 1, "unknown": 2, "sanitized": 3, "not_tainted": 4}
_REACH_RANK = {"remote": 0, "indirect": 1, "local": 2, "second-order": 3}


def trace_finding(finding: NormalizedFinding, verdict: ReachabilityVerdict, graph: CallGraph) -> Optional[TaintTrace]:
    """Trace one finding. Returns None when there is nothing to trace (unreachable, or
    not in code the call graph parsed)."""
    if verdict.status == "unreachable" or verdict.containing_function is None or graph.program is None:
        return None
    scope = graph.span(verdict.containing_function)
    if scope is None:
        return None
    weakness = classify_finding(finding)

    paths = entry_paths(graph, scope.qualified_name)[:MAX_PATHS]
    entry_known = bool(paths)
    if not paths:
        paths = [[scope.qualified_name]]

    best: Optional[TaintTrace] = None
    for path in paths:
        trace = _trace_on_path(finding, scope, path, entry_known, graph, weakness)
        if best is None or _rank(trace) < _rank(best):
            best = trace
    return best


def _rank(trace: TaintTrace) -> tuple:
    return (_STATUS_RANK[trace.status], _REACH_RANK.get(trace.reach or "", 4))


def _trace_on_path(finding, scope, path, entry_known, graph, weakness) -> TaintTrace:
    tracer = Tracer(graph, weakness)
    candidates = _sink_candidates(scope, finding, weakness)
    if not candidates:
        return TaintTrace(
            finding.finding_id, weakness, "unknown", None,
            "Couldn't identify which expression on the flagged line is the dangerous one.",
            path=path,
        )
    sink_class = weakness or next((c for _, _, c in candidates if c), None)
    tracer.weakness = sink_class

    origins: list[Origin] = []
    safe = None
    for expression, call, cls in candidates:
        safe = safe or _safe_form(call, cls)
        origins.extend(tracer.resolve_parameters(tracer.origins(expression, scope), path, len(path) - 1, entry_known))

    expression, call, _ = candidates[0]
    sink_node = call or expression
    sink = {
        "file_path": scope.file_path,
        "line": getattr(sink_node, "lineno", finding.line_start),
        "description": _text(sink_node, 110),
    }

    def live(o: Origin) -> bool:
        return not any(s.effective(sink_class) for s in o.sanitizers)

    sources = [o for o in origins if o.kind == "source"]
    tainted = sorted((o for o in sources if live(o)), key=lambda o: _REACH_RANK.get(catalog.SOURCE_REACH.get(o.source_kind, ""), 4))
    stored = [o for o in origins if o.kind == "stored" and live(o)]
    unknown = [o for o in origins if o.kind == "unknown" and live(o)]
    neutralized = [o for o in origins if o.kind in ("source", "stored", "unknown") and not live(o)]

    if safe:
        status, chosen = "sanitized", (tainted or sources or [None])[0]
    elif tainted:
        status, chosen = "tainted", tainted[0]
    elif stored:
        status, chosen = "stored", stored[0]
    elif unknown:
        status, chosen = "unknown", unknown[0]
    elif neutralized:
        status, chosen = "sanitized", neutralized[0]
    else:
        status, chosen = "not_tainted", None

    notes = list(dict.fromkeys(tracer.notes + [o.detail for o in unknown]))
    sanitizer_origins = neutralized if status == "sanitized" else ([chosen] if chosen else [])
    sanitizers = list(dict.fromkeys(
        s for o in sanitizer_origins if o is not None for s in o.sanitizers
    ))
    # checks that exist but protect a different weakness class are worth saying out loud
    for s in sanitizers:
        if status == "tainted" and not s.effective(sink_class):
            notes.append(f"`{s.description}` at {s.file_path}:{s.line} does not protect against this kind of injection.")

    source = None
    source_kind = None
    if chosen is not None and chosen.kind in ("source", "stored"):
        source_kind = chosen.source_kind
        source = {"file_path": chosen.file_path, "line": chosen.line, "description": chosen.detail}
    steps = [s.__dict__ for s in reversed(chosen.steps)] if chosen is not None else []
    reach = catalog.SOURCE_REACH.get(source_kind) if source_kind else None

    phrase = catalog.SINK_PHRASE.get(sink_class or "", "reaches the flagged call")
    if safe:
        summary = f"The flagged call is written safely: {safe}."
    elif status == "tainted":
        summary = f"Input from {catalog.SOURCE_WORDS.get(source_kind, 'outside')} ({chosen.detail}) {phrase}, and nothing on the way neutralizes it."
    elif status == "sanitized":
        what = "; ".join(s.description for s in sanitizers) or "a validation step"
        summary = f"Outside input does flow toward the call, but it is neutralized first: {what}."
    elif status == "stored":
        summary = (f"The value comes from {catalog.SOURCE_WORDS.get(source_kind, 'stored data')} ({chosen.detail}). "
                   "Whether an attacker controls it depends on who can write that data.")
    elif status == "unknown":
        summary = f"The value could not be followed back to an input: {chosen.detail}."
    else:
        summary = "Only constants and values the server computes itself reach the flagged call."

    return TaintTrace(
        finding_id=finding.finding_id,
        weakness=sink_class,
        status=status,
        attacker_controlled={"tainted": True, "sanitized": True, "not_tainted": False}.get(status),
        summary=summary,
        sink=sink,
        source=source,
        source_kind=source_kind,
        reach=reach,
        steps=steps,
        sanitizers=[{"file_path": s.file_path, "line": s.line, "description": s.description} for s in sanitizers],
        notes=notes,
        path=path,
        safe_sink=safe,
    )
