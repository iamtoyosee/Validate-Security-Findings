import base64
import pickle
import subprocess

import requests
import yaml

import repository


def find_employees(name: str):
    return repository.lookup_employees(name)


def run_diagnostic(host: str):
    # VULN-R2: command injection reachable from a registered Celery task.
    return subprocess.check_output("ping -c 1 " + host, shell=True, text=True)


class BonusCalculator:
    def calculate(self, expression: str):
        # VULN-R3: eval injection reached through a task-created object.
        return eval(expression)


def fetch_provider(url: str):
    # VULN-R4: SSRF reachable from a registered Celery task message.
    return requests.get(url, timeout=3).text


def decode_import(payload: str):
    # VULN-R5: pickle deserialization reachable from a registered task.
    return pickle.loads(base64.b64decode(payload))


def load_policy(policy: str):
    # VULN-R6: unsafe YAML loading reachable from a registered task.
    return yaml.load(policy, Loader=yaml.Loader)
