import sqlite3

DATABASE = "salary.db"


def lookup_employees(name: str):
    # VULN-R1: SQL injection reachable through public.employee_search -> services.
    connection = sqlite3.connect(DATABASE)
    query = "SELECT id, name, salary FROM employees WHERE name = '" + name + "'"
    rows = connection.execute(query).fetchall()
    connection.close()
    return rows
