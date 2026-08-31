"""Pluggable entry-point detectors, one per framework/pattern.

Nothing in a call graph derives these automatically - a framework invokes them by
convention (http.server's method-name dispatch) or registration (Flask's decorators),
not by a literal call anywhere in the source. Each detector is a small, independently
testable function; add more here as new frameworks come up (Phase 2+), don't merge them.
"""

import ast
from typing import Optional

from reachability.graph import build_import_table

HTTP_SERVER_METHODS = {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_HEAD", "do_PATCH", "do_OPTIONS"}
DECORATOR_ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch"}
DJANGO_URL_FUNCTIONS = {"path", "re_path", "url"}
CELERY_TASK_NAMES = {"task", "shared_task"}
ROUTER_CONSTRUCTORS = {"APIRouter"}
CELERY_CONSTRUCTORS = {"Celery"}


def _resolve_reference(node: ast.AST, import_table: dict[str, str]) -> Optional[str]:
    """Same final-name convention the Django detector already uses for dotted refs."""
    if isinstance(node, ast.Name):
        return import_table.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _router_names_and_mounts(trees: dict[str, ast.Module]) -> tuple[set[str], set[str]]:
    """Every `X = APIRouter(...)` name, and every name ever passed to `.include_router(...)`.

    Both sets are file-agnostic bare names, matching the rest of this codebase's
    single-namespace, no-cross-file-scoping model (see phase-1-foundations.md, "Open
    questions"). `include_router`'s argument is resolved through its own file's import
    table first, since a mounted router is usually imported under a local alias, e.g.
    `from app.routes.public import router as public_router` then `include_router(public_router)`.
    """
    router_names: set[str] = set()
    mounted: set[str] = set()
    for tree in trees.values():
        import_table = build_import_table(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in ROUTER_CONSTRUCTORS
            ):
                router_names.add(node.targets[0].id)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "include_router"
                and node.args
            ):
                resolved = _resolve_reference(node.args[0], import_table)
                if resolved:
                    mounted.add(resolved)
    return router_names, mounted


def detect_http_server_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    """Any do_GET/do_POST/etc. method on a class directly subclassing BaseHTTPRequestHandler."""
    entry_points = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(isinstance(base, ast.Name) and base.id == "BaseHTTPRequestHandler" for base in node.bases):
                continue
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in HTTP_SERVER_METHODS:
                    entry_points.add(f"{node.name}.{item.name}")
    return entry_points


def detect_decorator_route_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    """A function decorated with @app.route(...) or a shorthand like @app.get(...)/@app.post(...).

    Matches on the decorator's attribute *name*, not a specific framework object - this
    is why it covers Flask, FastAPI, and (untested but same decorator shape) Starlette,
    Sanic, and bottle with no extra code. FastAPI apps use identical `@app.get("/path")`-
    style decorators; the AST looks the same regardless of what `app` actually is.

    One check beyond decorator shape: if the decorated object is a *tracked* APIRouter
    variable (an `X = APIRouter(...)` assignment we saw), it only counts as an entry
    point when that router is actually mounted somewhere via `.include_router(...)`.
    Anything else decorating (an `app`/`api` object we never try to verify, or a router
    we do verify as mounted) is trivially treated as reachable-from-outside, same as
    before - this is what excludes a router defined but never wired into the app.
    """
    router_names, mounted_routers = _router_names_and_mounts(trees)

    entry_points = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in DECORATOR_ROUTE_METHODS
                ):
                    continue
                value = decorator.func.value
                if isinstance(value, ast.Name) and value.id in router_names and value.id not in mounted_routers:
                    break   # decorated on an APIRouter that's never mounted anywhere - not an entry point
                entry_points.add(node.name)   # routes are module-level functions, bare name
                break
    return entry_points


def detect_django_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    """Django's URLconf: a module-level `urlpatterns` list of path()/re_path()/url() calls.

    Structurally different from decorators - the route lives in a separate list, not
    attached to the view function itself. Recognizes the URL function by name whether
    imported directly (`path(...)`) or accessed via a module prefix (`django.urls.path(...)`).
    The view reference (2nd positional arg) can be a bare name (`admin_view`) or a dotted
    attribute (`views.admin_view`); either way we only need the final name component,
    since that's how it appears in our codebase-wide, file-agnostic function table.
    """
    entry_points = set()
    for tree in trees.values():
        for node in tree.body:
            if not (
                isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "urlpatterns" for t in node.targets)
                and isinstance(node.value, ast.List)
            ):
                continue
            for element in node.value.elts:
                if not isinstance(element, ast.Call):
                    continue
                func = element.func
                is_url_call = (isinstance(func, ast.Name) and func.id in DJANGO_URL_FUNCTIONS) or (
                    isinstance(func, ast.Attribute) and func.attr in DJANGO_URL_FUNCTIONS
                )
                if not is_url_call or len(element.args) < 2:
                    continue
                view_ref = element.args[1]
                if isinstance(view_ref, ast.Name):
                    entry_points.add(view_ref.id)
                elif isinstance(view_ref, ast.Attribute):
                    entry_points.add(view_ref.attr)   # dotted ref (views.admin_view) - final component
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


def detect_celery_entry_points(trees: dict[str, ast.Module]) -> set[str]:
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

    entry_points = set()
    for file_path, tree in trees.items():
        import_table = build_import_table(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                is_bare_task = isinstance(target, ast.Name) and target.id in CELERY_TASK_NAMES
                is_attr_task = isinstance(target, ast.Attribute) and target.attr == "task"
                if is_bare_task:
                    entry_points.add(node.name)
                    break
                if is_attr_task:
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
                        entry_points.add(node.name)
                    break
    return entry_points


DEFAULT_ENTRY_POINT_DETECTORS = [
    detect_http_server_entry_points,
    detect_decorator_route_entry_points,
    detect_django_entry_points,
    detect_celery_entry_points,
]
