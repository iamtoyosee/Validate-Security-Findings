"""Tasks registered only on an unrelated Celery app that no configured worker loads."""

import sqlite3
import subprocess

from celery import Celery

orphan_app = Celery("retired_worker", broker="memory://")


@orphan_app.task(name="retired.search_employees")
def orphan_search(name: str):
    # VULN-U1: SQL injection on an orphan Celery application.
    connection = sqlite3.connect("salary_tasks.db")
    query = "SELECT id, name FROM employees WHERE name = '" + name + "'"
    return connection.execute(query).fetchall()


@orphan_app.task(name="retired.run_diagnostic")
def orphan_diagnostic(host: str):
    # VULN-U2: command injection on an orphan Celery application.
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)
