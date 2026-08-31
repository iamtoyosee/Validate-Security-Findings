"""Decorated routes on a router that main.py deliberately never mounts."""

import sqlite3
import subprocess

from fastapi import APIRouter

orphan_router = APIRouter(prefix="/legacy-admin")


@orphan_router.get("/employees")
def orphan_employee_search(name: str):
    # VULN-U1: SQL injection on an unmounted router; no actual HTTP path exists.
    connection = sqlite3.connect("salary.db")
    query = "SELECT id, name FROM employees WHERE name = '" + name + "'"
    return connection.execute(query).fetchall()


@orphan_router.get("/diagnostics")
def orphan_diagnostics(host: str):
    # VULN-U2: command injection on an unmounted router.
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)
