import ast
from pathlib import Path

from reachability.entry_points import detect_flask_entry_points, detect_http_server_entry_points

TODO_APP = (Path(__file__).parent.parent / "src" / "sample-apps" / "todo-list-app" / "app.py").read_text()
ECOMMERCE_APP = Path("/Users/ausman/Workload/Ecommerce-app/app.py").read_text()


def test_http_server_detector_tags_do_get_and_do_post_on_the_real_todo_app():
    trees = {"app.py": ast.parse(TODO_APP)}
    entry_points = detect_http_server_entry_points(trees)
    assert entry_points == {"TodoHandler.do_GET", "TodoHandler.do_POST"}


def test_http_server_detector_ignores_methods_not_on_a_basehttprequesthandler_subclass():
    source = """
class NotAHandler:
    def do_GET(self):
        pass
"""
    trees = {"f.py": ast.parse(source)}
    assert detect_http_server_entry_points(trees) == set()


def test_flask_detector_tags_route_and_shorthand_decorators_on_the_real_ecommerce_app():
    trees = {"app.py": ast.parse(ECOMMERCE_APP)}
    entry_points = detect_flask_entry_points(trees)
    assert {"home", "product", "login", "inventory", "promotion", "receipt"} <= entry_points
    assert "add_to_cart" in entry_points   # @app.post shorthand
    assert "checkout" in entry_points       # @app.post shorthand
    # plain functions never decorated with a route are not entry points
    assert "find_products" not in entry_points
    assert "calculate_adjustment" not in entry_points


def test_flask_detector_ignores_undecorated_functions():
    source = """
def plain_function():
    pass
"""
    trees = {"f.py": ast.parse(source)}
    assert detect_flask_entry_points(trees) == set()
