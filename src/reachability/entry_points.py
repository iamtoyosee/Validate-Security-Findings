"""Pluggable entry-point detectors, one per framework/pattern.

Nothing in a call graph derives these automatically - a framework invokes them by
convention (http.server's method-name dispatch) or registration (Flask's decorators),
not by a literal call anywhere in the source. Each detector is a small, independently
testable function; add more here as new frameworks come up (Phase 2+), don't merge them.
"""

import ast

HTTP_SERVER_METHODS = {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_HEAD", "do_PATCH", "do_OPTIONS"}
FLASK_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}


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


def detect_flask_entry_points(trees: dict[str, ast.Module]) -> set[str]:
    """A function decorated with @app.route(...) or a shorthand like @app.get(...)/@app.post(...)."""
    entry_points = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in FLASK_ROUTE_DECORATORS
                ):
                    entry_points.add(node.name)   # Flask routes are module-level functions, bare name
                    break
    return entry_points


DEFAULT_ENTRY_POINT_DETECTORS = [detect_http_server_entry_points, detect_flask_entry_points]
