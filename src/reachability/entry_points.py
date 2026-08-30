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


def detect_celery_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    """A function decorated with @task/@shared_task (bare, called or not) or @app.task/@celery.task.

    Celery tasks are triggered by a message queue, not HTTP - a genuinely different
    entry-point category. Two decorator shapes: a bare imported name (`@shared_task`,
    `@shared_task(bind=True)`) and an attribute access ending in `.task` (`@app.task`),
    same attribute-name matching as the decorator-route detector.
    """
    entry_points = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                is_bare_task = isinstance(target, ast.Name) and target.id in CELERY_TASK_NAMES
                is_attr_task = isinstance(target, ast.Attribute) and target.attr == "task"
                if is_bare_task or is_attr_task:
                    entry_points.add(node.name)
                    break
    return entry_points


DEFAULT_ENTRY_POINT_DETECTORS = [
    detect_http_server_entry_points,
    detect_decorator_route_entry_points,
    detect_django_entry_points,
    detect_celery_entry_points,
]
