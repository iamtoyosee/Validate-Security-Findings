"""Which kind of weakness a finding is about, for analysis purposes only.

Scanners disagree about labels for the same bug: Bandit files `yaml.load` under CWE-20
and `eval` under CWE-78, Semgrep files them under CWE-502 and CWE-95. Two stages need a
shared answer to "what kind of bug is this": deduplication (are these two findings the
same bug?) and the taint/exploitability stage (which call on this line is the dangerous
one, and what would make it safe?).

This is deliberately *not* a new field on NormalizedFinding. `vulnerability_type` stays
`rule_ids[0]` as decided in docs/phase-0-foundations.md; this is a derived, best-effort
bucket that the analysis recomputes whenever it needs it.
"""

import re
from typing import Iterable, Optional

CWE_CLASSES = {
    "sql": {89, 564, 943},
    "command": {77, 78, 88},
    "code": {94, 95},
    "template": {96, 1336},
    "deserialization": {502},
    "xss": {79, 80, 83, 87, 116},
    "path": {22, 23, 35, 36, 73, 98},
    "ssrf": {918, 939},
    "redirect": {601},
    "xxe": {611, 776},
    "crypto": {326, 327, 328, 330, 338, 916},
    "secret": {259, 321, 798},
}

# Checked in order; the first pattern that matches a rule id or message wins. Rule ids
# are more trustworthy than a scanner's CWE mapping, so these are consulted first.
KEYWORD_CLASSES = [
    ("sql", r"sql|B608|B610|B611"),
    ("template", r"template-string|ssti|jinja|render_template_string|B701|B702|B704"),
    ("deserialization", r"pickle|deserial|marshal|yaml|shelve|dill|B301|B302|B506"),
    ("code", r"\beval\b|eval-|exec-|exec\b|code-injection|B307|B102"),
    ("command", r"command|subprocess|shell|os-system|popen|B60[1-7]|B609"),
    ("xss", r"xss|markup|unescape|B703|B308"),
    ("path", r"path-traversal|traversal|tainted-path|B202"),
    ("ssrf", r"ssrf|urllib|urlopen|tainted-url|requests?-|B310"),
    ("redirect", r"open-redirect|redirect"),
    ("xxe", r"xxe|xml|B31[3-9]|B320"),
    ("secret", r"hardcoded|secret|password|B105|B106|B107"),
    ("crypto", r"md5|sha1|weak-hash|insecure-hash|cipher|B303|B304|B305|B324"),
]


def cwe_numbers(cwes: Iterable[str]) -> set[int]:
    numbers = set()
    for cwe in cwes or []:
        match = re.search(r"(\d+)", str(cwe))
        if match:
            numbers.add(int(match.group(1)))
    return numbers


def classify(cwes: Iterable[str], rule_ids: Iterable[str] = (), message: str = "") -> Optional[str]:
    """Best-effort weakness class, or None when nothing recognizable is present."""
    text = " ".join(rule_ids or [])
    for name, pattern in KEYWORD_CLASSES:
        if re.search(pattern, text, re.IGNORECASE):
            return name
    numbers = cwe_numbers(cwes)
    for name, members in CWE_CLASSES.items():
        if numbers & members:
            return name
    for name, pattern in KEYWORD_CLASSES:
        if re.search(pattern, message or "", re.IGNORECASE):
            return name
    return None


def classify_finding(finding) -> Optional[str]:
    return classify(finding.cwe, finding.rule_ids, finding.message)
