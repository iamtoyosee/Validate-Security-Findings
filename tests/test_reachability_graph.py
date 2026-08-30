import ast

from reachability.graph import (
    build_call_edges,
    build_function_table,
    build_import_table,
    resolve_containing_function,
)

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
    edges, _ = build_call_edges(functions)
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
    edges, _ = build_call_edges(functions)
    assert edges["A.outer"] == {"A.inner"}   # not B.inner, even though it's also named "inner"


def test_inherited_method_call_never_gets_an_edge_no_special_casing_needed():
    # self.send_response(...) is inherited from BaseHTTPRequestHandler, which we never
    # parse - it simply never appears in the table, so no edge is possible.
    tree = ast.parse(TODO_APP)
    functions = build_function_table("app.py", tree)
    edges, _ = build_call_edges(functions)
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
    edges, _ = build_call_edges(functions)

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


# ---- build_import_table: the shared per-file "what does this bare name mean" utility ----

def test_import_table_maps_bare_and_aliased_imports_to_their_canonical_name():
    source = """
import subprocess
import sqlite3 as db
from app import services
from app.routes.public import router as public_router
"""
    tree = ast.parse(source)
    table = build_import_table(tree)
    assert table == {
        "subprocess": "subprocess",   # bare import - identity mapping
        "db": "sqlite3",                # aliased import
        "services": "services",         # bare from-import - identity mapping
        "public_router": "router",      # aliased from-import - canonical is the original name
    }


# ---- Fix 2: module-qualified calls (name.attr() where `name` is an import) ----

def test_module_qualified_call_resolves_with_the_same_confidence_as_a_bare_call():
    source = """
from app import repository


def find_employees(name):
    return repository.lookup_employees(name)
"""
    repository_source = "def lookup_employees(name):\n    pass\n"
    services_tree = ast.parse(source)
    repository_tree = ast.parse(repository_source)
    functions = build_function_table("services.py", services_tree) + build_function_table(
        "repository.py", repository_tree
    )
    import_tables = {"services.py": build_import_table(services_tree)}
    edges, unresolved = build_call_edges(functions, import_tables)

    assert edges["find_employees"] == {"lookup_employees"}
    assert "lookup_employees" not in unresolved


def test_module_qualified_call_to_a_function_not_in_our_table_is_not_ambiguous():
    # subprocess.check_output isn't our code - correctly no edge - but it's still a
    # *resolved* reference (we know exactly what "subprocess" is), not a genuinely
    # ambiguous one, so it must NOT be recorded as an unresolved call target.
    source = """
import subprocess


def run_diagnostic(host):
    return subprocess.check_output("ping " + host, shell=True)
"""
    tree = ast.parse(source)
    functions = build_function_table("services.py", tree)
    import_tables = {"services.py": build_import_table(tree)}
    edges, unresolved = build_call_edges(functions, import_tables)

    assert edges["run_diagnostic"] == set()
    assert "check_output" not in unresolved


# ---- Fix 3: local direct-instantiation method calls (name = ClassRef() then name.method()) ----

def test_local_instantiation_of_a_known_class_resolves_the_later_method_call():
    # ClassRef must be a class we actually parsed for this to count - "SalaryCalculator"
    # is only recognized because "SalaryCalculator.calculate" is in our own function
    # table, same convention graph.py already uses to qualify method names.
    source = """
def salary_formula(expression):
    calculator = SalaryCalculator()
    return calculator.calculate(expression)


class SalaryCalculator:
    def calculate(self, expression):
        return eval(expression)
"""
    tree = ast.parse(source)
    functions = build_function_table("services.py", tree)
    edges, unresolved = build_call_edges(functions, {})

    assert edges["salary_formula"] == {"SalaryCalculator.calculate"}
    assert "calculate" not in unresolved


def test_module_qualified_local_instantiation_of_a_known_class_also_resolves():
    # The real salary_formula (services.SalaryCalculator()) - module-qualified class ref.
    source = """
import services


def salary_formula(expression):
    calculator = services.SalaryCalculator()
    return calculator.calculate(expression)
"""
    services_source = """
class SalaryCalculator:
    def calculate(self, expression):
        return eval(expression)
"""
    public_tree = ast.parse(source)
    services_tree = ast.parse(services_source)
    functions = build_function_table("public.py", public_tree) + build_function_table(
        "services.py", services_tree
    )
    import_tables = {"public.py": build_import_table(public_tree)}
    edges, unresolved = build_call_edges(functions, import_tables)

    assert edges["salary_formula"] == {"SalaryCalculator.calculate"}
    assert "calculate" not in unresolved


def test_reassignment_drops_tracked_local_instantiation_rather_than_guessing():
    source = """
def handler(flag):
    calculator = SalaryCalculator()
    calculator = "not a calculator anymore"
    return calculator.calculate("1+1")


class SalaryCalculator:
    def calculate(self, expression):
        return eval(expression)
"""
    tree = ast.parse(source)
    functions = build_function_table("services.py", tree)
    edges, unresolved = build_call_edges(functions, {})

    assert edges["handler"] == set()   # tracking dropped on reassignment, not guessed
    assert "calculate" in unresolved


def test_module_qualified_instantiation_is_not_confused_with_an_arbitrary_module_call():
    # sqlite3.connect(...) is the exact ambiguous shape this project deliberately
    # refuses to resolve - fix 3 must not sweep it in just because it's spelled
    # "module.Something()" the same way a real class instantiation is.
    source = """
import sqlite3


def lookup_employees(name):
    connection = sqlite3.connect("salary.db")
    query = "SELECT * FROM employees WHERE name = '" + name + "'"
    return connection.execute(query).fetchall()
"""
    tree = ast.parse(source)
    functions = build_function_table("repository.py", tree)
    import_tables = {"repository.py": build_import_table(tree)}
    edges, unresolved = build_call_edges(functions, import_tables)

    assert edges["lookup_employees"] == set()
    assert "execute" in unresolved
    assert "fetchall" in unresolved


# ---- Fix 4: BackgroundTasks.add_task isn't a call, but it schedules one ----

def test_add_task_first_argument_is_resolved_as_a_call_edge():
    source = """
import services


def import_payroll(payload, background_tasks):
    background_tasks.add_task(services.decode_payroll_import, payload)
    return "scheduled"
"""
    services_source = "def decode_payroll_import(payload):\n    pass\n"
    public_tree = ast.parse(source)
    services_tree = ast.parse(services_source)
    functions = build_function_table("public.py", public_tree) + build_function_table(
        "services.py", services_tree
    )
    import_tables = {"public.py": build_import_table(public_tree)}

    edges, unresolved = build_call_edges(functions, import_tables)
    assert edges["import_payroll"] == {"decode_payroll_import"}
    assert "add_task" not in unresolved


def test_add_task_with_a_bare_function_reference_also_resolves():
    source = """
def decode_payroll_import(payload):
    return payload


def import_payroll(payload, background_tasks):
    background_tasks.add_task(decode_payroll_import, payload)
    return "scheduled"
"""
    tree = ast.parse(source)
    functions = build_function_table("public.py", tree)
    edges, _ = build_call_edges(functions, {})
    assert edges["import_payroll"] == {"decode_payroll_import"}


# ---- unresolved_call_targets: the raw material for build_verdict's unknown-vs-unreachable split ----

def test_ambiguous_attribute_call_is_recorded_in_unresolved_call_targets():
    source = """
def dead_code(connection, query):
    return connection.execute(query)
"""
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    _, unresolved = build_call_edges(functions, {})
    assert "execute" in unresolved


def test_self_method_call_never_counts_as_unresolved_even_when_not_in_the_table():
    # self.send_response(...) is inherited, not ours - we know exactly what "self" is,
    # this just isn't our code, so it must not be treated as genuinely ambiguous.
    source = """
class Handler:
    def do_GET(self):
        self.send_response(200)
"""
    tree = ast.parse(source)
    functions = build_function_table("f.py", tree)
    _, unresolved = build_call_edges(functions, {})
    assert "send_response" not in unresolved
