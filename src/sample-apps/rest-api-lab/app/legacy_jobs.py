"""Legacy helpers with no imports or calls from the FastAPI application."""

import base64
import pickle

import requests
import yaml


def fetch_old_provider(url: str):
    # VULN-U3: unreachable SSRF sink.
    return requests.get(url, timeout=3).text


def old_formula(expression: str):
    # VULN-U4: unreachable eval injection sink.
    return eval(expression)


def decode_old_import(payload: str):
    # VULN-U5: unreachable pickle deserialization sink.
    return pickle.loads(base64.b64decode(payload))


def load_old_policy(policy: str):
    # VULN-U6: unreachable unsafe YAML loading sink.
    return yaml.load(policy, Loader=yaml.Loader)
