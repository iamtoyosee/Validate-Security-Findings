import ast

from reachability.graph import build_call_edges, build_function_table, resolve_containing_function

TODO_APP = (
    __import__("pathlib").Path(__file__).parent.parent
    / "src" / "sample-apps" / "todo-list-app" / "app.py"
).read_text()


def test_build_function_table_records_qualified_names_and_spans():
    tree = ast.parse(TODO_APP)
    functions = build_function_table("app.py", tree)
    by_name = {f.qualified_name: f for f in functions}

    assert "add_todo" in by_name
    assert "TodoHandler.do_GET" in by_name
    assert "TodoHandler.do_POST" in by_name
    # bare function, no decorators - span starts at the `def` line
    assert by_name["add_todo"].span_start == 32
    assert by_name["add_todo"].span_end == 34


def test_decorator_line_counts_as_part_of_the_span():
    source = """
@some_decorator
def handler():
    pass
"""
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    handler = functions[0]
    assert handler.span_start == 2   # the @some_decorator line, not the `def` line
    assert handler.span_end == 4


def test_bare_name_call_builds_a_confident_edge():
    tree = ast.parse(TODO_APP)
    functions = build_function_table("app.py", tree)
    edges = build_call_edges(functions)
    assert "add_todo" in edges["TodoHandler.do_POST"]


def test_self_method_call_builds_a_confident_edge_scoped_to_its_own_class():
    source = """
class A:
    def outer(self):
        return self.inner()

    def inner(self):
        return 1


class B:
    def inner(self):
        return 2
"""
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    edges = build_call_edges(functions)
    assert edges["A.outer"] == {"A.inner"}   # not B.inner, even though it's also named "inner"


def test_inherited_method_call_never_gets_an_edge_no_special_casing_needed():
    # self.send_response(...) is inherited from BaseHTTPRequestHandler, which we never
    # parse - it simply never appears in the table, so no edge is possible.
    tree = ast.parse(TODO_APP)
    functions = build_function_table("app.py", tree)
    edges = build_call_edges(functions)
    assert "send_response" not in edges["TodoHandler.do_GET"]
    assert not any("send_response" in v for v in edges.values())


def test_ambiguous_attribute_call_never_builds_an_edge_even_if_the_name_exists_in_the_table():
    # This is the exact shape that produced atom's confirmed false positive: a method
    # call on an untyped parameter/variable. Here "execute" genuinely IS a method in our
    # table (Connection.execute) - naive name-matching would wrongly connect it.
    source = """
class Connection:
    def execute(self, query):
        return query


def open_connection():
    return Connection()


def dead_code(connection, query):
    return connection.execute(query)


def entry(request):
    conn = open_connection()
    return conn.execute("select 1")
"""
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    edges = build_call_edges(functions)

    assert edges["dead_code"] == set()   # no edge to Connection.execute
    assert edges["entry"] == {"open_connection"}   # only the resolvable bare call


def test_resolve_containing_function_picks_innermost_span():
    source = """
def outer():
    def inner():
        return 1
    return inner()
"""
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    result = resolve_containing_function(functions, "f.py", 4)
    assert result.qualified_name == "inner"


def test_resolve_containing_function_returns_none_for_module_level_code():
    source = "x = 1\n"
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    result = resolve_containing_function(functions, "f.py", 1)
    assert result is None


def test_resolve_containing_function_matches_real_finding_lines():
    tree = ast.parse(TODO_APP)
    functions = build_function_table("app.py", tree)
    assert resolve_containing_function(functions, "app.py", 34).qualified_name == "add_todo"
    assert resolve_containing_function(functions, "app.py", 39).qualified_name == "search_todos"
    assert resolve_containing_function(functions, "app.py", 94).qualified_name == "find_old_todos"
