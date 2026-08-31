import sqlite3


def lookup_employees(name: str):
    # VULN-R1: SQL injection reachable from the registered search task.
    connection = sqlite3.connect("salary_tasks.db")
    query = "SELECT id, name, salary FROM employees WHERE name = '" + name + "'"
    rows = connection.execute(query).fetchall()
    connection.close()
    return rows
