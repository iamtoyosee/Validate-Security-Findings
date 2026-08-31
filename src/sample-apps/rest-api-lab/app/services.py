import base64
import pickle
import subprocess

import requests
import yaml

from app import repository


def find_employees(name: str):
    return repository.lookup_employees(name)


def run_diagnostic(host: str):
    # VULN-R2: command injection reachable from an included router.
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)


def fetch_benefit_provider(url: str):
    # VULN-R3: SSRF reachable through a FastAPI dependency and service call.
    return requests.get(url, timeout=3).text


class SalaryCalculator:
    def calculate(self, expression: str):
        # VULN-R4: eval injection reachable through an instantiated class method.
        return eval(expression)


def decode_payroll_import(payload: str):
    # VULN-R5: pickle deserialization reachable through BackgroundTasks.add_task.
    return pickle.loads(base64.b64decode(payload))


def parse_policy(policy: str):
    # VULN-R6: unsafe YAML loading reachable from upload_policy.
    return yaml.load(policy, Loader=yaml.Loader)
