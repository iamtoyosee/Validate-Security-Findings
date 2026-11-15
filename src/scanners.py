"""The scanners this service can run itself, when the caller doesn't bring findings.

Each runner returns that scanner's own raw result records; ingest.py and
semgrep_adapter.py turn them into NormalizedFinding. A scanner that fails (not
installed, no network for Semgrep's `--config=auto`) raises ScannerError, and the
pipeline reports it per scanner instead of failing the whole scan.
"""

import json
import subprocess
import sys
from pathlib import Path

from semgrep_adapter import run_semgrep as _run_semgrep

SEMGREP_RULESETS = {"auto", "p/python", "p/owasp-top-ten", "p/security-audit", "p/secrets"}
SCANNER_TIMEOUT_SECONDS = 300


class ScannerError(RuntimeError):
    pass


def run_semgrep(codebase_path: Path, ruleset: str = "auto") -> list[dict]:
    if ruleset not in SEMGREP_RULESETS:
        raise ScannerError(f"Unsupported Semgrep ruleset '{ruleset}'.")
    try:
        return _run_semgrep(codebase_path, ruleset)
    except FileNotFoundError as error:
        raise ScannerError("Semgrep is not installed on the server.") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise ScannerError(f"Semgrep exited with an error: {detail[0][:300]}") from error
    except (json.JSONDecodeError, KeyError) as error:
        raise ScannerError("Semgrep produced output that could not be read.") from error


def run_bandit(codebase_path: Path) -> list[dict]:
    """Bandit runs fully offline, so it works where Semgrep's registry is unreachable."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", ".", "-f", "json", "-q"],
            cwd=codebase_path,
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise ScannerError("Bandit timed out.") from error
    # exit code 1 just means "issues found"
    if result.returncode not in (0, 1) or not result.stdout.strip():
        detail = (result.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise ScannerError(f"Bandit could not run: {detail[0][:300]}")
    try:
        return json.loads(result.stdout)["results"]
    except (json.JSONDecodeError, KeyError) as error:
        raise ScannerError("Bandit produced output that could not be read.") from error


def scanner_version(name: str) -> str:
    try:
        if name == "semgrep":
            out = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=30).stdout
        elif name == "bandit":
            import bandit
            return getattr(bandit, "__version__", "")
        else:
            return ""
        return out.strip().splitlines()[-1] if out.strip() else ""
    except Exception:
        return ""
