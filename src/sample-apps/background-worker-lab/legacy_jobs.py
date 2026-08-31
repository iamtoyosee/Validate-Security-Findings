"""Legacy job helpers with no calls from the configured worker or its tasks."""

import base64
import pickle

import requests
import yaml


def old_bonus(expression: str):
    # VULN-U3: unreachable eval injection.
    return eval(expression)


def old_provider(url: str):
    # VULN-U4: unreachable SSRF.
    return requests.get(url, timeout=3).text


def old_import(payload: str):
    # VULN-U5: unreachable pickle deserialization.
    return pickle.loads(base64.b64decode(payload))


def old_policy(policy: str):
    # VULN-U6: unreachable unsafe YAML loading.
    return yaml.load(policy, Loader=yaml.Loader)
