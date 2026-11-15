"""What counts as a dangerous call, an untrusted input, and a neutralizing step.

Kept as plain data so it can be read, argued with, and extended without touching the
tracer. Every entry is a name the tracer matches against the *final* component of a
call (`subprocess.check_output` -> "check_output"), sometimes narrowed by the root
(`shlex.quote` vs `urllib.parse.quote`).
"""

import ast
from typing import Optional

# ---- Sinks --------------------------------------------------------------------------
# name -> (weakness class, which argument is dangerous). "receiver" means the object the
# method is called on (`path.read_text()`), an int is a positional index.

SINKS: dict[str, tuple[str, object]] = {
    # SQL
    "execute": ("sql", 0), "executemany": ("sql", 0), "executescript": ("sql", 0),
    "raw": ("sql", 0), "read_sql": ("sql", 0), "read_sql_query": ("sql", 0),
    # OS command
    "system": ("command", 0), "popen": ("command", 0), "check_output": ("command", 0),
    "check_call": ("command", 0), "call": ("command", 0), "Popen": ("command", 0),
    "getoutput": ("command", 0), "getstatusoutput": ("command", 0),
    # code execution
    "eval": ("code", 0), "exec": ("code", 0),
    # server-side template injection
    "render_template_string": ("template", 0), "from_string": ("template", 0), "Template": ("template", 0),
    # deserialization
    "loads": ("deserialization", 0), "load": ("deserialization", 0), "load_all": ("deserialization", 0),
    "unsafe_load": ("deserialization", 0), "full_load": ("deserialization", 0), "decode": ("deserialization", 0),
    # HTML that bypasses escaping
    "Markup": ("xss", 0), "mark_safe": ("xss", 0),
    # filesystem
    "open": ("path", 0), "read_text": ("path", "receiver"), "read_bytes": ("path", "receiver"),
    "write_text": ("path", "receiver"), "write_bytes": ("path", "receiver"), "unlink": ("path", "receiver"),
    "send_file": ("path", 0), "send_from_directory": ("path", 1), "remove": ("path", 0), "rmtree": ("path", 0),
    # outbound requests
    "urlopen": ("ssrf", 0), "get": ("ssrf", 0), "post": ("ssrf", 0), "put": ("ssrf", 0),
    "request": ("ssrf", 1), "head": ("ssrf", 0), "delete": ("ssrf", 0), "patch": ("ssrf", 0),
    # open redirect
    "redirect": ("redirect", 0),
}
# Names too generic to be a sink unless the finding's own class asks for them:
# `.get()` is an outbound request only when the finding is about SSRF.
CLASS_GATED = {"get", "post", "put", "request", "head", "delete", "patch", "loads", "load", "decode",
               "open", "call", "run", "remove", "raw", "Template"}
# `subprocess.run(cmd, shell=True)` - "run" is far too common to list above.
SHELL_KEYWORD_SINKS = {"run", "call", "check_call", "check_output", "Popen"}
DESERIALIZATION_ROOTS = {"pickle", "cPickle", "yaml", "marshal", "dill", "jsonpickle", "shelve", "_pickle"}
HTTP_CLIENT_ROOTS = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "session", "client", "http"}

SINK_PHRASE = {
    "sql": "is built into the SQL text",
    "command": "is built into a shell command",
    "code": "is evaluated as Python code",
    "template": "is rendered as a template",
    "deserialization": "is deserialized with an unsafe loader",
    "xss": "is marked as safe HTML without escaping",
    "path": "decides which file is opened",
    "ssrf": "decides which URL the server requests",
    "redirect": "decides where the user is redirected",
}
SUGGESTED_FIX = {
    "sql": "Pass the value as a bound parameter (`execute(\"... WHERE x = ?\", (value,))`) instead of formatting it into the query text.",
    "command": "Pass the command as a list without `shell=True`, so the value is one argument and never parsed by a shell.",
    "code": "Don't evaluate request data. Use `ast.literal_eval` for literals, or parse the expression with an explicit grammar.",
    "template": "Render a fixed template and pass the value in as a variable, rather than building the template source from it.",
    "deserialization": "Use a data-only format: `json.loads`, or `yaml.safe_load` for YAML. Never unpickle data a client can send.",
    "xss": "Let the template engine escape the value. If markup is required, sanitize it with an allowlist first.",
    "path": "Resolve the final path and check it is still inside the intended directory before opening it.",
    "ssrf": "Check the URL's scheme and host against an allowlist before requesting it, and refuse redirects to other hosts.",
    "redirect": "Only redirect to relative paths or to hosts on an allowlist.",
}

# ---- Sources ------------------------------------------------------------------------

REQUEST_ATTRIBUTES = {
    "args", "form", "values", "json", "data", "cookies", "headers", "files", "GET", "POST", "FILES",
    "META", "body", "query_params", "path_params", "url", "path", "full_path", "query_string",
    "host", "get_json", "stream", "COOKIES", "content", "text", "query", "match_info", "view_args",
}
REQUEST_MODULES = {"flask", "quart", "sanic", "bottle", "django", "starlette", "fastapi", "aiohttp"}
HTTP_HANDLER_ATTRIBUTES = {"path", "headers", "rfile", "requestline", "command"}
SOURCE_WORDS = {
    "http": "an HTTP request",
    "task": "a task-queue message",
    "cli": "command-line input",
    "environment": "an environment variable",
    "database": "data read back from the database",
    "file": "data read from a file",
}
# How far an outside attacker is from each kind of input. "remote" is anyone who can
# send a request; the others need something first (a foothold, a way to enqueue work,
# an earlier write).
SOURCE_REACH = {
    "http": "remote", "task": "indirect", "cli": "local", "environment": "local",
    "database": "second-order", "file": "second-order",
}

# ---- Things that neutralize, by weakness class (None = every class) -------------------

# A value forced into a number / UUID / IP address can't carry injection syntax.
TYPE_CASTS = {"int", "float", "bool", "Decimal", "UUID", "ip_address", "IPv4Address", "IPv6Address", "len", "ord", "abs", "round"}
CLASS_SANITIZERS: dict[str, tuple[Optional[frozenset], Optional[set]]] = {
    # name: (classes it protects, required root names or None)
    "quote": (frozenset({"command"}), {"shlex"}),
    "escape": (frozenset({"xss"}), None),
    "conditional_escape": (frozenset({"xss"}), None),
    "clean": (frozenset({"xss"}), {"bleach", "nh3"}),
    "secure_filename": (frozenset({"path"}), None),
    "basename": (frozenset({"path"}), None),
    "hexdigest": (None, None),
    "literal_eval": (frozenset({"code"}), None),
    "safe_load": (frozenset({"deserialization"}), None),
}
VALIDATION_METHODS = {"isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier"}
REGEX_FULL = {"fullmatch"}
PATH_CONTAINMENT = {"is_relative_to"}
DENYLIST_HINT = ("block", "deny", "bad", "forbid", "banned", "blacklist")
TERMINATORS = {"abort", "exit", "_exit", "quit", "fail"}
NUMERIC_ANNOTATIONS = {"int", "float", "bool", "UUID", "Decimal", "date", "datetime", "PositiveInt", "NonNegativeInt", "conint", "confloat"}
INFRASTRUCTURE_ANNOTATIONS = {"BackgroundTasks", "Session", "AsyncSession", "Response", "Request", "WebSocket", "HttpRequest"}
NUMERIC_CONVERTERS = {"int", "float", "uuid"}

# ---- Calls whose result is the server's own, not the caller's --------------------------

SERVER_VALUES = {
    "uuid4", "uuid1", "token_hex", "token_urlsafe", "token_bytes", "urandom", "now", "utcnow", "today",
    "time", "getcwd", "gettempdir", "mkdtemp", "mkstemp", "range", "sum", "count", "getpid", "randint",
    "random", "choice", "connect", "cursor", "Path", "PurePath", "resolve", "absolute", "parent",
}
DATABASE_READS = {"fetchall", "fetchone", "fetchmany", "scalar", "scalars", "first", "all", "one", "one_or_none"}
FILE_READS = {"read", "readline", "readlines", "read_text", "read_bytes"}


def final_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def root_name(node: ast.AST) -> Optional[str]:
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None
