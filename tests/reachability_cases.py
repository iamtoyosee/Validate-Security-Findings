"""Reachability hardening cases (Phase 2).

Each case is a tiny multi-file codebase with one line marked `# FINDING`, plus the
verdict a careful human reader would give. They target one resolution rule each, so a
failure names the rule that regressed. The Phase 1 engine gets 3 of these 30 right;
see docs/phase-2-reachability-hardening.md for the table.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Case:
    name: str
    files: dict
    status: str                       # expected ReachabilityVerdict.status
    entry: Optional[str] = None       # expected entry_point (None = don't check / not reachable)
    confidence: Optional[str] = None  # expected confidence when it matters
    kind: Optional[str] = None        # expected entry_point_kind
    why: str = ""


FLASK = "from flask import Flask, request\napp = Flask(__name__)\n"

CASES = [
    Case(
        "collision_dead_twin_is_not_reachable",
        {
            "handlers.py": FLASK + "@app.route('/export')\ndef export():\n    return 'ok'\n",
            "legacy.py": "import os\ndef export(name):\n    os.system('tar ' + name)  # FINDING\n",
        },
        "unreachable",
        why="Two files define `export`; only the route is live. One shared node made the dead copy reachable.",
    ),
    Case(
        "collision_live_twin_shows_both_hops",
        {
            "tasks.py": FLASK + "import services\n@app.route('/run')\ndef run():\n    return services.run(request.args['x'])\n",
            "services.py": "import os\ndef run(x):\n    os.system(x)  # FINDING\n",
        },
        "reachable",
        entry="tasks.run",
        why="Same name on both sides of a call: the path must name both functions.",
    ),
    Case(
        "builtin_name_is_not_our_function",
        {
            "app.py": FLASK + "@app.route('/read')\ndef read():\n    return open(request.args['p']).read()\n",
            "legacy.py": "import os\ndef open(path):\n    os.system('cat ' + path)  # FINDING\n",
        },
        "unreachable",
        why="`open(...)` in app.py is the builtin - legacy.open is neither defined nor imported there.",
    ),
    Case(
        "calling_a_parameter_is_not_calling_a_namesake",
        {
            "app.py": FLASK + "def apply(callback, x):\n    return callback(x)\n\n"
                      "@app.route('/a')\ndef a():\n    return apply(str, request.args['x'])\n\n"
                      "def callback(x):\n    return eval(x)  # FINDING\n",
        },
        "unreachable",
        why="`callback(x)` calls the parameter, not the unrelated module-level function with the same name.",
    ),
    Case(
        "local_variable_is_not_a_function_reference",
        {
            "app.py": FLASK + "def load():\n    return {}\n\n@app.route('/o')\ndef show():\n    order = load()\n    return order\n\n"
                      "def order(x):\n    return eval(x)  # FINDING\n",
        },
        "unreachable",
        why="`return order` returns the local variable; it must not be read as a reference to function `order`.",
    ),
    Case(
        "inherited_method_via_self",
        {
            "app.py": "from http.server import BaseHTTPRequestHandler\nimport os\n\n"
                      "class Base(BaseHTTPRequestHandler):\n    def run(self, cmd):\n        os.system(cmd)  # FINDING\n\n"
                      "class Handler(Base):\n    def do_GET(self):\n        self.run(self.path)\n",
        },
        "reachable",
        entry="Handler.do_GET",
        why="self.run() is defined on a base class.",
    ),
    Case(
        "super_call",
        {
            "views.py": FLASK + "import os\n\nclass Base:\n    def render(self, name):\n        return os.popen('cat ' + name).read()  # FINDING\n\n"
                        "class Page(Base):\n    def render(self, name):\n        return super().render(name)\n\n"
                        "@app.route('/p')\ndef page():\n    p = Page()\n    return p.render(request.args['n'])\n",
        },
        "reachable",
        entry="page",
    ),
    Case(
        "self_attribute_instantiated_in_init",
        {
            "repo.py": "import sqlite3\nclass Repo:\n    def find(self, q):\n        c = sqlite3.connect('x')\n        return c.execute('select ' + q)  # FINDING\n",
            "service.py": "from repo import Repo\nclass Service:\n    def __init__(self):\n        self.repo = Repo()\n    def search(self, q):\n        return self.repo.find(q)\n",
            "app.py": FLASK + "from service import Service\n@app.route('/s')\ndef search():\n    svc = Service()\n    return svc.search(request.args['q'])\n",
        },
        "reachable",
        entry="search",
        why="self.repo is a Repo because __init__ says so.",
    ),
    Case(
        "self_attribute_injected_with_annotation",
        {
            "repo.py": "import sqlite3\nclass Repo:\n    def find(self, q):\n        c = sqlite3.connect('x')\n        return c.execute('select ' + q)  # FINDING\n",
            "app.py": FLASK + "from repo import Repo\nclass Service:\n    def __init__(self, repo: Repo):\n        self.repo = repo\n    def search(self, q):\n        return self.repo.find(q)\n\n"
                      "@app.route('/s')\ndef search():\n    svc = Service(Repo())\n    return svc.search(request.args['q'])\n",
        },
        "reachable",
        entry="search",
    ),
    Case(
        "module_level_singleton",
        {
            "app.py": FLASK + "import os\nclass Runner:\n    def run(self, cmd):\n        return os.popen(cmd).read()  # FINDING\n\nrunner = Runner()\n\n"
                      "@app.route('/r')\ndef r():\n    return runner.run(request.args['c'])\n",
        },
        "reachable",
        entry="r",
    ),
    Case(
        "imported_singleton",
        {
            "deps.py": "import os\nclass Runner:\n    def run(self, cmd):\n        return os.popen(cmd).read()  # FINDING\n\nrunner = Runner()\n",
            "app.py": FLASK + "from deps import runner\n@app.route('/r')\ndef r():\n    return runner.run(request.args['c'])\n",
        },
        "reachable",
        entry="r",
    ),
    Case(
        "annotated_parameter",
        {
            "app.py": "from fastapi import FastAPI, Depends\nimport os\napp = FastAPI()\n\nclass Runner:\n    def run(self, cmd):\n        return os.popen(cmd).read()  # FINDING\n\n"
                      "def get_runner():\n    return Runner()\n\n@app.get('/r')\ndef r(c: str, runner: Runner = Depends(get_runner)):\n    return runner.run(c)\n",
        },
        "reachable",
        entry="r",
    ),
    Case(
        "annotated_return_type",
        {
            "app.py": FLASK + "import os\nclass Runner:\n    def run(self, cmd):\n        return os.popen(cmd).read()  # FINDING\n\n"
                      "def get_runner() -> Runner:\n    return Runner()\n\n@app.route('/r')\ndef r():\n    return get_runner().run(request.args['c'])\n",
        },
        "reachable",
        entry="r",
    ),
    Case(
        "fastapi_dependency_function",
        {
            "app.py": "from fastapi import FastAPI, Depends, Header\nimport pickle, base64\napp = FastAPI()\n\n"
                      "def session(token: str = Header()):\n    return pickle.loads(base64.b64decode(token))  # FINDING\n\n"
                      "@app.get('/me')\ndef me(s = Depends(session)):\n    return s\n",
        },
        "reachable",
        entry="me",
        why="FastAPI calls the dependency on every request to /me.",
    ),
    Case(
        "constructor_body",
        {
            "app.py": FLASK + "import os\nclass Report:\n    def __init__(self, name):\n        self.body = os.popen('cat ' + name).read()  # FINDING\n\n"
                      "@app.route('/rep')\ndef rep():\n    return Report(request.args['n']).body\n",
        },
        "reachable",
        entry="rep",
    ),
    Case(
        "static_method_call",
        {
            "util.py": "import os\nclass Shell:\n    @staticmethod\n    def run(cmd):\n        return os.popen(cmd).read()  # FINDING\n",
            "app.py": FLASK + "from util import Shell\n@app.route('/x')\ndef x():\n    return Shell.run(request.args['c'])\n",
        },
        "reachable",
        entry="x",
    ),
    Case(
        "dispatch_table",
        {
            "app.py": FLASK + "import os\ndef ping(host):\n    return os.popen('ping ' + host).read()  # FINDING\n\ndef noop(host):\n    return ''\n\n"
                      "ACTIONS = {'ping': ping, 'noop': noop}\n\n@app.route('/act')\ndef act():\n    return ACTIONS[request.args['a']](request.args['h'])\n",
        },
        "reachable",
        confidence="medium",
        why="Stored in a module-level table and dispatched by key: reachable, but through a reference, so medium.",
    ),
    Case(
        "thread_target",
        {
            "app.py": FLASK + "import os, threading\ndef worker(cmd):\n    os.system(cmd)  # FINDING\n\n"
                      "@app.route('/bg')\ndef bg():\n    threading.Thread(target=worker, args=(request.args['c'],)).start()\n    return 'ok'\n",
        },
        "reachable",
        entry="bg",
        confidence="high",
    ),
    Case(
        "star_import",
        {
            "helpers.py": "import os\ndef run(cmd):\n    return os.popen(cmd).read()  # FINDING\n",
            "app.py": FLASK + "from helpers import *\n@app.route('/x')\ndef x():\n    return run(request.args['c'])\n",
        },
        "reachable",
        entry="x",
    ),
    Case(
        "blueprint_never_registered",
        {
            "admin.py": "from flask import Blueprint, request\nimport os\nbp = Blueprint('admin', __name__)\n\n@bp.route('/exec')\ndef run():\n    return os.popen(request.args['c']).read()  # FINDING\n",
            "app.py": FLASK + "@app.route('/')\ndef home():\n    return 'hi'\n",
        },
        "unreachable",
        why="The blueprint is defined but app.register_blueprint(bp) never happens.",
    ),
    Case(
        "blueprint_registered_with_prefix",
        {
            "admin.py": "from flask import Blueprint, request\nimport os\nbp = Blueprint('admin', __name__)\n\n@bp.route('/exec')\ndef run():\n    return os.popen(request.args['c']).read()  # FINDING\n",
            "app.py": FLASK + "from admin import bp\napp.register_blueprint(bp, url_prefix='/admin')\n",
        },
        "reachable",
        entry="run",
        kind="http",
    ),
    Case(
        "router_nested_under_unmounted_parent",
        {
            "child.py": "from fastapi import APIRouter\nimport os\nchild = APIRouter()\n\n@child.get('/x')\ndef x(c: str):\n    return os.popen(c).read()  # FINDING\n",
            "parent.py": "from fastapi import APIRouter\nfrom child import child\nparent = APIRouter()\nparent.include_router(child)\n",
            "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        },
        "unreachable",
        why="child is included into parent, but parent itself is never mounted on the app.",
    ),
    Case(
        "django_class_based_view",
        {
            "views.py": "import os\nfrom django.views import View\n\nclass Export(View):\n    def get(self, request):\n        return os.popen(request.GET['f']).read()  # FINDING\n",
            "urls.py": "from django.urls import path\nfrom views import Export\nurlpatterns = [path('export/', Export.as_view())]\n",
        },
        "reachable",
        entry="Export.get",
    ),
    Case(
        "view_registered_by_call",
        {
            "app.py": FLASK + "import os\ndef export():\n    return os.popen(request.args['f']).read()  # FINDING\n\napp.add_url_rule('/export', view_func=export)\n",
        },
        "reachable",
        entry="export",
        kind="http",
    ),
    Case(
        "request_hook",
        {
            "app.py": FLASK + "import pickle, base64\n@app.before_request\ndef load_session():\n    request.s = pickle.loads(base64.b64decode(request.cookies['s']))  # FINDING\n",
        },
        "reachable",
        entry="load_session",
    ),
    Case(
        "click_command",
        {
            "cli.py": "import click, os\n\n@click.command()\n@click.argument('name')\ndef backup(name):\n    os.system('tar czf ' + name)  # FINDING\n",
        },
        "reachable",
        entry="backup",
        kind="cli",
    ),
    Case(
        "script_main_guard",
        {
            "job.py": "import os, sys\ndef main(target):\n    os.system('rsync ' + target)  # FINDING\n\nif __name__ == '__main__':\n    main(sys.argv[1])\n",
        },
        "reachable",
        entry="<module job.py>",
        kind="cli",
    ),
    Case(
        "module_level_code_in_the_app_module",
        {
            "app.py": FLASK + "import os, yaml\nCONFIG = yaml.load(open(os.environ['CFG']), Loader=yaml.Loader)  # FINDING\n\n@app.route('/')\ndef home():\n    return 'hi'\n",
        },
        "reachable",
        confidence="medium",
        kind="startup",
        why="Top-level code of the module that holds the routes: it runs at import.",
    ),
    Case(
        "module_level_code_nobody_loads",
        {
            "app.py": FLASK + "@app.route('/')\ndef home():\n    return 'hi'\n",
            "scratch.py": "import os\nos.system('echo ' + os.environ.get('X', ''))  # FINDING\n",
        },
        "unreachable",
        why="Nothing imports scratch.py and it has no main guard.",
    ),
    Case(
        "celery_delay_from_a_route",
        {
            "app.py": FLASK + "import os\ndef send_report(name):\n    os.system('mail ' + name)  # FINDING\n\n"
                      "@app.route('/send')\ndef send():\n    send_report.delay(request.args['n'])\n    return 'queued'\n",
        },
        "reachable",
        entry="send",
    ),
]


def finding_line(case: Case) -> tuple:
    for path, source in case.files.items():
        for number, line in enumerate(source.splitlines(), start=1):
            if "# FINDING" in line:
                return path, number
    raise AssertionError(f"{case.name}: no # FINDING marker")
