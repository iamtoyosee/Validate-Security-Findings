"""Pluggable entry-point detectors, one per framework/pattern.

Nothing in a call graph derives these automatically - a framework invokes them by
convention (http.server's method-name dispatch) or registration (Flask's decorators),
not by a literal call anywhere in the source. Each detector is a small, independently
testable function; add more here as new frameworks come up, don't merge them.

Two layers:
- `find_*` return EntryPoint records: which file, which function, what kind of way in
  (HTTP, task queue, CLI, startup), a human label ("GET /salary/employees") and any
  auth-looking guards on the handler. The engine and the exploitability stage use these.
- `detect_*` are the original Phase 1 functions, kept as thin wrappers that return just
  the set of names.
"""

import ast
import re
from dataclasses import dataclass
from typing import Iterator, Optional

from reachability.graph import build_import_bindings, build_import_table, files_for_module


@dataclass(frozen=True)
class EntryPoint:
    file_path: Optional[str]   # None when a registration names the function but not its file
    local_name: str             # name within the file ("home", "TodoHandler.do_GET"); "" = module code
    kind: str                   # "http" | "task" | "cli" | "startup"
    label: str                  # shown to people: "GET /salary/employees", "Celery task salary.search"
    guards: tuple = ()          # auth-looking decorators/dependencies seen on the handler


HTTP_SERVER_METHODS = {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_HEAD", "do_PATCH", "do_OPTIONS"}
HTTP_SERVER_BASES = {"BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "CGIHTTPRequestHandler"}
DECORATOR_ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch", "head", "options", "websocket", "api_route"}
# Decorators that register a function the framework calls around requests, not at a path.
HOOK_DECORATORS = {
    "before_request", "after_request", "teardown_request", "before_first_request",
    "errorhandler", "app_errorhandler", "before_app_request", "after_app_request",
    "teardown_appcontext", "context_processor", "middleware", "exception_handler", "on_event",
}
DJANGO_URL_FUNCTIONS = {"path", "re_path", "url"}
CELERY_TASK_NAMES = {"task", "shared_task"}
OTHER_TASK_DECORATORS = {"actor", "periodic_task", "scheduled_job", "db_task", "db_periodic_task"}
CLI_DECORATORS = {"command", "group"}
ROUTER_CONSTRUCTORS = {"APIRouter", "Blueprint"}
MOUNT_METHODS = {"include_router", "register_blueprint"}
CELERY_CONSTRUCTORS = {"Celery"}
REGISTRATION_METHODS = {"add_url_rule", "add_api_route", "add_route", "add_websocket_route"}
# Methods a framework dispatches to on a class-based view, by name.
VIEW_METHODS = {
    "get", "post", "put", "delete", "patch", "head", "options", "dispatch", "dispatch_request",
    "list", "create", "retrieve", "update", "partial_update", "destroy",
}
GUARD_PATTERN = re.compile(r"(login|auth|permission|jwt|token|admin|role|require|protect|verify|staff|superuser)", re.I)


def _resolve_reference(node: ast.AST, import_table: dict[str, str]) -> Optional[str]:
    """Same final-name convention the Django detector already uses for dotted refs."""
    if isinstance(node, ast.Name):
        return import_table.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _iter_functions(tree: ast.Module) -> Iterator[tuple[str, ast.AST, Optional[str]]]:
    """(local_name, node, class_name) for every def, named exactly as graph.py names them."""
    def walk(node: ast.AST, class_name: Optional[str]):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                yield from walk(child, child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield (f"{class_name}.{child.name}" if class_name else child.name), child, class_name
                yield from walk(child, class_name)
            else:
                yield from walk(child, class_name)
    yield from walk(tree, None)


def _final_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _const_str(node: Optional[ast.AST]) -> Optional[str]:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _locate(node: ast.AST, file_path: str, tree: ast.Module, trees: dict[str, ast.Module]) -> tuple[Optional[str], Optional[str]]:
    """Pin a `name` / `module.name` reference to (file, original name) via this file's imports.

    file is None when the name clearly comes from elsewhere but we can't say where.
    """
    bindings = build_import_bindings(tree, file_path)
    if isinstance(node, ast.Name):
        binding = bindings.get(node.id)
        if binding is None:
            return file_path, node.id
        if binding.name is None:
            return None, node.id
        matches = files_for_module(binding.module, trees) if binding.module else []
        return (matches[0] if matches else None), binding.name
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        binding = bindings.get(node.value.id)
        if binding is not None:
            module = binding.module if binding.name is None else ".".join(p for p in (binding.module, binding.name) if p)
            matches = files_for_module(module, trees) if module else []
            return (matches[0] if matches else None), node.attr
        return None, node.attr
    return None, None


def _guards(func: ast.AST, skip: Optional[ast.AST] = None) -> tuple:
    """Decorators and FastAPI dependencies on a handler whose names look like access control.

    Purely informative: the exploitability stage uses it to say "an attacker needs to be
    authenticated first", never to rule a finding out.
    """
    found: list[str] = []
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _final_name(target)
        if decorator is not skip and name and GUARD_PATTERN.search(name):
            found.append(name)
        if isinstance(decorator, ast.Call):   # @router.get(..., dependencies=[Depends(require_admin)])
            found.extend(_dependency_guards(decorator))
    for default in [*func.args.defaults, *[d for d in func.args.kw_defaults if d is not None]]:
        found.extend(_dependency_guards(default))
    return tuple(dict.fromkeys(found))


def _dependency_guards(node: ast.AST) -> list[str]:
    guards = []
    for call in ast.walk(node):
        if isinstance(call, ast.Call) and _final_name(call.func) in {"Depends", "Security"} and call.args:
            name = _final_name(call.args[0])
            if name and GUARD_PATTERN.search(name):
                guards.append(f"Depends({name})")
    return guards


# ---- Routers and blueprints: defined is not the same as mounted --------------------

def _mountables(trees: dict[str, ast.Module]) -> tuple[dict[tuple[str, str], str], set[tuple[Optional[str], str]], dict[tuple[Optional[str], str], str]]:
    """Every `X = APIRouter(...)` / `X = Blueprint(...)`, and which of them are live.

    Returns (defined, live, mount_prefixes):
    - defined: (file, name) -> its own prefix
    - live: the routers that are mounted on something real. A router included into
      another router only counts if that parent is itself live, so a whole unmounted
      subtree stays dead instead of each member vouching for the next.
    - mount_prefixes: prefix given at the mount call, keyed like `live`.
    A reference we can't pin to a file is kept as (None, name) and matches by name.
    """
    defined: dict[tuple[str, str], str] = {}
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and _final_name(node.value.func) in ROUTER_CONSTRUCTORS
            ):
                prefix = _const_str(_keyword(node.value, "prefix")) or _const_str(_keyword(node.value, "url_prefix")) or ""
                defined[(file_path, node.targets[0].id)] = prefix

    def tracked(ref: tuple[Optional[str], Optional[str]]) -> list[tuple[str, str]]:
        file_path, name = ref
        if name is None:
            return []
        if file_path is not None:
            return [(file_path, name)] if (file_path, name) in defined else []
        return [key for key in defined if key[1] == name]

    mounts: list[tuple[list[tuple[str, str]], tuple[Optional[str], Optional[str]], str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in MOUNT_METHODS
                and node.args
            ):
                parent = tracked(_locate(node.func.value, file_path, tree, trees))
                child = _locate(node.args[0], file_path, tree, trees)
                prefix = _const_str(_keyword(node, "prefix")) or _const_str(_keyword(node, "url_prefix")) or ""
                mounts.append((parent, child, prefix))

    live: set[tuple[Optional[str], str]] = set()
    mount_prefixes: dict[tuple[Optional[str], str], str] = {}
    changed = True
    while changed:
        changed = False
        for parent, child, prefix in mounts:
            if child[1] is None or child in live:
                continue
            # a parent we don't track is the application object itself - trusted
            if not parent or any(p in live or (None, p[1]) in live for p in parent):
                live.add(child)
                mount_prefixes[child] = prefix
                changed = True
    return defined, live, mount_prefixes


def _route_label(decorator: ast.Call, prefix: str) -> str:
    attr = decorator.func.attr
    path = _const_str(decorator.args[0]) if decorator.args else None
    if attr in {"route", "api_route"}:
        methods = _keyword(decorator, "methods")
        verbs = [
            e.value.upper() for e in getattr(methods, "elts", [])
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ] or ["GET"]
        verb = "|".join(verbs)
    elif attr == "websocket":
        verb = "WS"
    else:
        verb = attr.upper()
    return f"{verb} {prefix}{path}" if path is not None else f"{verb} route"


def find_http_server_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """Any do_GET/do_POST/etc. method on a class that subclasses BaseHTTPRequestHandler,
    directly or through another handler class in the codebase."""
    classes = [(path, node) for path, tree in trees.items() for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    handler_names = set(HTTP_SERVER_BASES)
    changed = True
    while changed:
        changed = False
        for _, node in classes:
            if node.name not in handler_names and any(_final_name(b) in handler_names for b in node.bases):
                handler_names.add(node.name)
                changed = True

    entry_points = []
    for path, node in classes:
        if node.name in HTTP_SERVER_BASES or node.name not in handler_names:
            continue
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in HTTP_SERVER_METHODS:
                entry_points.append(EntryPoint(
                    path, f"{node.name}.{item.name}", "http", f"{item.name[3:]} (http.server)", _guards(item)
                ))
    return entry_points


def find_decorator_route_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """A function decorated with @app.route(...) or a shorthand like @app.get(...)/@app.post(...).

    Matches on the decorator's attribute *name*, not a specific framework object - this
    is why it covers Flask, FastAPI, and (untested but same decorator shape) Starlette,
    Sanic, and bottle with no extra code. FastAPI apps use identical `@app.get("/path")`-
    style decorators; the AST looks the same regardless of what `app` actually is.

    One check beyond decorator shape: if the decorated object is a *tracked* APIRouter or
    Blueprint (an `X = APIRouter(...)` assignment we saw), it only counts as an entry
    point when that router is actually mounted via `.include_router(...)` /
    `.register_blueprint(...)` on something live. Anything else decorating (an `app`/`api`
    object we never try to verify) is treated as reachable-from-outside, same as before -
    this is what excludes a router defined but never wired into the app.

    Also covers request hooks (`@app.before_request`, `@app.errorhandler(404)`,
    `@app.middleware("http")`): no path of their own, but the framework runs them on
    requests, so code inside one is as exposed as code inside a route.
    """
    defined, live, mount_prefixes = _mountables(trees)

    entry_points = []
    for file_path, tree in trees.items():
        for local_name, node, _ in _iter_functions(tree):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if not isinstance(target, ast.Attribute):
                    continue
                is_route = isinstance(decorator, ast.Call) and target.attr in DECORATOR_ROUTE_METHODS
                is_hook = target.attr in HOOK_DECORATORS
                if not (is_route or is_hook):
                    continue
                owner = _locate(target.value, file_path, tree, trees)
                owner_keys = (
                    [owner] if owner[0] is not None and owner in defined
                    else [key for key in defined if owner[0] is None and key[1] == owner[1]]
                )
                prefix = ""
                if owner_keys:
                    mounted = [k for k in owner_keys if k in live or (None, k[1]) in live]
                    if not mounted:
                        break   # decorated on a router/blueprint that's never mounted - not an entry point
                    key = mounted[0]
                    prefix = mount_prefixes.get(key, mount_prefixes.get((None, key[1]), "")) + defined[key]
                label = _route_label(decorator, prefix) if is_route else f"{target.attr} hook"
                entry_points.append(EntryPoint(file_path, local_name, "http", label, _guards(node, skip=decorator)))
                break
    return entry_points


def _class_view_entry_points(
    class_ref: ast.AST, file_path: str, tree: ast.Module, trees: dict[str, ast.Module], label: str
) -> list[EntryPoint]:
    """Methods a framework will dispatch to on a class-based view (`X.as_view()`, a DRF
    viewset, a Flask-RESTful resource), including ones inherited from our own base classes."""
    owner_file, class_name = _locate(class_ref, file_path, tree, trees)
    if class_name is None:
        return []
    classes = {
        (path, node.name): node
        for path, t in trees.items() for node in ast.walk(t) if isinstance(node, ast.ClassDef)
    }
    pending = [key for key in classes if key[1] == class_name and (owner_file is None or key[0] == owner_file)]
    if not pending:
        pending = [key for key in classes if key[1] == class_name]
    seen: set[tuple[str, str]] = set()
    entry_points = []
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        node = classes[key]
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_action = any(_final_name(d.func if isinstance(d, ast.Call) else d) == "action" for d in item.decorator_list)
            if item.name in VIEW_METHODS or is_action:
                entry_points.append(EntryPoint(key[0], f"{node.name}.{item.name}", "http", label, _guards(item)))
        for base in node.bases:
            base_name = _final_name(base)
            pending.extend(k for k in classes if k[1] == base_name)
    return entry_points


def _as_view_class(node: ast.AST) -> Optional[ast.AST]:
    """`SomeView.as_view(...)` -> the `SomeView` expression."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
        return node.func.value
    return None


def find_django_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """Django's URLconf: a module-level `urlpatterns` list of path()/re_path()/url() calls.

    Structurally different from decorators - the route lives in a separate list, not
    attached to the view function itself. Recognizes the URL function by name whether
    imported directly (`path(...)`) or accessed via a module prefix (`django.urls.path(...)`).
    The view reference (2nd positional arg) can be a bare name (`admin_view`), a dotted
    attribute (`views.admin_view`) or a class-based view (`AdminView.as_view()`).
    """
    entry_points = []
    for file_path, tree in trees.items():
        for node in tree.body:
            value = None
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets):
                value = node.value
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == "urlpatterns":
                value = node.value
            if not isinstance(value, ast.List):
                continue
            for element in value.elts:
                if not isinstance(element, ast.Call):
                    continue
                if _final_name(element.func) not in DJANGO_URL_FUNCTIONS or len(element.args) < 2:
                    continue
                route = _const_str(element.args[0])
                label = f"Django URL {route}" if route is not None else "Django URL"
                view_ref = element.args[1]
                view_class = _as_view_class(view_ref)
                if view_class is not None:
                    entry_points.extend(_class_view_entry_points(view_class, file_path, tree, trees, label))
                elif isinstance(view_ref, (ast.Name, ast.Attribute)):
                    owner_file, name = _locate(view_ref, file_path, tree, trees)
                    if name:
                        entry_points.append(EntryPoint(owner_file, name, "http", label))
    return entry_points


def find_registered_view_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """Views registered by a call instead of a decorator or a URLconf.

    `app.add_url_rule("/x", view_func=f)`, `app.add_api_route("/x", f)`, Starlette's
    `Route("/x", f)`, Flask-RESTful's `api.add_resource(Resource, "/x")` and DRF's
    `router.register("x", ViewSet)`.
    """
    entry_points = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _final_name(node.func)
            refs: list[ast.AST] = []
            class_refs: list[ast.AST] = []
            if name in REGISTRATION_METHODS or name in {"Route", "WebSocketRoute"}:
                refs = [v for v in (_keyword(node, "view_func"), _keyword(node, "endpoint"), _keyword(node, "route")) if v is not None]
                refs += node.args[1:]
            elif name == "add_resource" and node.args:
                class_refs = [node.args[0]]
            elif name == "register" and isinstance(node.func, ast.Attribute) and len(node.args) >= 2:
                class_refs = [node.args[1]]
            else:
                continue
            path = next((_const_str(a) for a in node.args if _const_str(a) is not None), None)
            label = f"route {path}" if path else f"registered via {name}"
            for ref in refs:
                view_class = _as_view_class(ref)
                if view_class is not None:
                    class_refs.append(view_class)
                elif isinstance(ref, (ast.Name, ast.Attribute)):
                    owner_file, ref_name = _locate(ref, file_path, tree, trees)
                    if ref_name:
                        entry_points.append(EntryPoint(owner_file, ref_name, "http", label))
            for class_ref in class_refs:
                entry_points.extend(_class_view_entry_points(class_ref, file_path, tree, trees, label))
    return entry_points


def _module_to_file(module_name: str) -> str:
    """`include=["tasks"]` / `include=["app.tasks"]` name modules, not files - convert
    `"tasks"` -> `"tasks.py"`, `"app.tasks"` -> `"app/tasks.py"`, matching how Python's own
    import system resolves a dotted module name to a file on disk.
    """
    return module_name.replace(".", "/") + ".py"


def _file_matches_module(file_path: str, module_name: str) -> bool:
    """Whether `file_path` is the file `module_name` would resolve to.

    Tolerant of `file_path` carrying a leading directory prefix the module name never
    mentions - e.g. uploading a whole project folder stores paths as
    'celery_reachability_lab/tasks.py', but `include=["tasks"]` only ever names "tasks".
    Python's import system resolves a module relative to sys.path, not to whatever root
    our own file-key scheme happens to use, so an exact full-path match is too strict -
    a suffix match (on a directory boundary) is what "would this module load this file"
    actually means here.
    """
    candidate = _module_to_file(module_name)
    return file_path == candidate or file_path.endswith("/" + candidate)


def _celery_apps_and_autodiscover(trees: dict[str, ast.Module]) -> tuple[list[dict], set[str]]:
    """Every `X = Celery(...)` instantiation (bare name, defining file, `include=[...]`
    resolved to file paths) plus every bare name ever seen calling `.autodiscover_tasks(...)`.

    Same file-agnostic, codebase-wide-namespace convention `_router_names_and_mounts`
    already uses for routers - two distinctly-purposed Celery apps sharing a variable name
    is the same accepted, documented gap as two same-named routers (phase-1-foundations.md,
    "Open questions").
    """
    apps: list[dict] = []
    autodiscover_names: set[str] = set()
    for file_path, tree in trees.items():
        import_table = build_import_table(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and _resolve_reference(node.value.func, import_table) in CELERY_CONSTRUCTORS
            ):
                include_modules = set()
                for kw in node.value.keywords:
                    if kw.arg == "include" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        include_modules = {
                            elt.value
                            for elt in kw.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        }
                apps.append({"name": node.targets[0].id, "file": file_path, "include_modules": include_modules})
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "autodiscover_tasks"
                and isinstance(node.func.value, ast.Name)
            ):
                autodiscover_names.add(_resolve_reference(node.func.value, import_table))
    return apps, autodiscover_names


def _file_is_imported_anywhere(target_file: str, trees: dict[str, ast.Module]) -> bool:
    """Whether `target_file` is named in a plain `import`/`from ... import` anywhere.

    Checked against every file's own top-level imports, not just one - same codebase-wide
    scope `build_import_table` already uses. A plain import is Python's own static,
    unambiguous proof a module gets loaded, no guessing required, same certainty as the
    rest of this project's confident-edge resolution. Matched via `_file_matches_module`
    (a suffix match), not exact equality - same directory-prefix tolerance as the
    `include=[...]` check above, and for the same reason.
    """
    for tree in trees.values():
        for node in tree.body:
            if isinstance(node, ast.Import):
                if any(_file_matches_module(target_file, alias.name) for alias in node.names):
                    return True
            elif isinstance(node, ast.ImportFrom) and node.module:
                if _file_matches_module(target_file, node.module):
                    return True
                if any(_file_matches_module(target_file, f"{node.module}.{alias.name}") for alias in node.names):
                    return True
    return False


def find_celery_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """A function decorated with @task/@shared_task (bare, called or not) or @X.task.

    Celery tasks are triggered by a message queue, not HTTP - a genuinely different
    entry-point category. Two decorator shapes, trusted differently:

    **Bare** (`@task`, `@shared_task(bind=True)`) is intentionally app-agnostic in Celery
    itself - unconditionally trusted, same as always.

    **Attribute-style** (`@X.task`) additionally checks whether X's app is ever actually
    wired up to load the file the decorated function lives in - same class of fix as
    `detect_decorator_route_entry_points`'s unmounted-router check above. X is resolved
    back to its `Celery(...)` instantiation (same file, or via `build_import_table()` if
    imported, same as a mounted router's alias). If it's the only `Celery(...)` instance
    anywhere - the common single-app case, which often has no `include=` at all - or X
    can't be resolved to any tracked instance (an object we never try to verify, same
    default as an unrecognized `app`/`api` in the route-mounting fix), trust
    unconditionally. Otherwise, a decorated function only counts as an entry point if its
    file is reachable through a real, verifiable loading channel: named in X's own
    `include=[...]`, `X.autodiscover_tasks(...)` appearing anywhere (presence alone is an
    explicit config signal, not something we try to resolve further), or a plain import of
    that file anywhere in the codebase.

    **Deliberately not a fourth channel: "same file as X's own instantiation."** It reads
    like a real signal (many small real Celery apps put the app object and its tasks in
    one file), but it isn't independently verifiable - it's already exactly the plain-
    import check above whenever it's ever legitimately true (something has to actually
    load that file), and an unconditional pass on file-locality alone would silently
    re-admit the exact orphan-app bug this fix targets: confirmed against
    celery_reachability_lab's `orphan_app`, whose two tasks live in the very file that
    instantiates it and are still correctly unreachable, since nothing ever imports or
    includes that file. See phase-1-foundations.md for the full trace.
    """
    apps, autodiscover_names = _celery_apps_and_autodiscover(trees)
    apps_by_name: dict[str, list[dict]] = {}
    for app in apps:
        apps_by_name.setdefault(app["name"], []).append(app)
    single_app = len(apps) <= 1

    entry_points = []
    for file_path, tree in trees.items():
        import_table = build_import_table(tree)
        for local_name, node, _ in _iter_functions(tree):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                is_bare_task = isinstance(target, ast.Name) and target.id in CELERY_TASK_NAMES
                is_attr_task = isinstance(target, ast.Attribute) and target.attr == "task"
                if not (is_bare_task or is_attr_task):
                    continue
                task_name = _const_str(_keyword(decorator, "name")) if isinstance(decorator, ast.Call) else None
                entry = EntryPoint(file_path, local_name, "task", f"Celery task {task_name or node.name}")
                if is_bare_task:
                    entry_points.append(entry)
                    break
                app_name = (
                    _resolve_reference(target.value, import_table)
                    if isinstance(target.value, ast.Name)
                    else None
                )
                trusted = (
                    single_app
                    or app_name not in apps_by_name
                    or app_name in autodiscover_names
                    or any(
                        _file_matches_module(file_path, module_name)
                        for app in apps_by_name[app_name]
                        for module_name in app["include_modules"]
                    )
                    or _file_is_imported_anywhere(file_path, trees)
                )
                if trusted:
                    entry_points.append(entry)
                break
    return entry_points


def find_other_task_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """Background work registered by decorator outside Celery: Dramatiq actors, Huey
    tasks, APScheduler's `@scheduler.scheduled_job(...)`, Celery beat's `@periodic_task`."""
    entry_points = []
    for file_path, tree in trees.items():
        for local_name, node, _ in _iter_functions(tree):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                name = _final_name(target)
                if name in OTHER_TASK_DECORATORS:
                    entry_points.append(EntryPoint(file_path, local_name, "task", f"{name} {node.name}"))
                    break
    return entry_points


def find_cli_entry_points(trees: dict[str, ast.Module]) -> list[EntryPoint]:
    """Click/Typer commands, and any file with an `if __name__ == "__main__":` block.

    A command is a real way in, but its input comes from whoever runs the program, not
    from a remote request - the exploitability stage treats it as a local source.
    """
    entry_points = []
    for file_path, tree in trees.items():
        import_table = build_import_table(tree)
        for local_name, node, _ in _iter_functions(tree):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                is_attr = isinstance(target, ast.Attribute) and target.attr in CLI_DECORATORS
                is_bare = isinstance(target, ast.Name) and import_table.get(target.id) in CLI_DECORATORS
                if is_attr or is_bare:
                    entry_points.append(EntryPoint(file_path, local_name, "cli", f"CLI command {node.name}"))
                    break
        if has_main_guard(tree):
            entry_points.append(EntryPoint(file_path, "", "cli", f"script {file_path}"))
    return entry_points


def has_main_guard(tree: ast.Module) -> bool:
    for node in tree.body:
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        parts = [node.test.left, *node.test.comparators]
        names = {p.id for p in parts if isinstance(p, ast.Name)}
        strings = {p.value for p in parts if isinstance(p, ast.Constant)}
        if "__name__" in names and "__main__" in strings:
            return True
    return False


def module_is_loaded(file_path: str, trees: dict[str, ast.Module]) -> bool:
    """Whether some other file imports this one, at module level or inside a function."""
    for other_path, tree in trees.items():
        if other_path == file_path:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(_file_matches_module(file_path, alias.name) for alias in node.names):
                    return True
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module and _file_matches_module(file_path, module):
                    return True
                if any(_file_matches_module(file_path, ".".join(p for p in (module, alias.name) if p)) for alias in node.names):
                    return True
    return False


# ---- Phase 1 API: the same detectors, returning just names -------------------------

def detect_http_server_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    return {e.local_name for e in find_http_server_entry_points(trees)}


def detect_decorator_route_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    return {e.local_name for e in find_decorator_route_entry_points(trees)}


def detect_django_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    return {e.local_name for e in find_django_entry_points(trees)}


def detect_celery_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    return {e.local_name for e in find_celery_entry_points(trees)}


DEFAULT_ENTRY_POINT_DETECTORS = [
    find_http_server_entry_points,
    find_decorator_route_entry_points,
    find_django_entry_points,
    find_registered_view_entry_points,
    find_celery_entry_points,
    find_other_task_entry_points,
    find_cli_entry_points,
]
