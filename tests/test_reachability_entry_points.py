import ast
from pathlib import Path

from reachability.entry_points import (
    detect_celery_entry_points,
    detect_decorator_route_entry_points,
    detect_django_entry_points,
    detect_http_server_entry_points,
)

TODO_APP = (Path(__file__).parent.parent / "src" / "sample-apps" / "todo-list-app" / "app.py").read_text()
ECOMMERCE_APP = Path("/Users/ausman/Workload/Ecommerce-app/app.py").read_text()


def test_http_server_detector_tags_do_get_and_do_post_on_the_real_todo_app():
    trees = {"app.py": ast.parse(TODO_APP)}
    entry_points = detect_http_server_entry_points(trees)
    assert entry_points == {"TodoHandler.do_GET", "TodoHandler.do_POST"}


def test_http_server_detector_ignores_methods_not_on_a_basehttprequesthandler_subclass():
    source = """
class NotAHandler:
    def do_GET(self):
        pass
"""
    trees = {"f.py": ast.parse(source)}
    assert detect_http_server_entry_points(trees) == set()


def test_decorator_route_detector_tags_route_and_shorthand_decorators_on_the_real_ecommerce_app():
    trees = {"app.py": ast.parse(ECOMMERCE_APP)}
    entry_points = detect_decorator_route_entry_points(trees)
    assert {"home", "product", "login", "inventory", "promotion", "receipt"} <= entry_points
    assert "add_to_cart" in entry_points   # @app.post shorthand
    assert "checkout" in entry_points       # @app.post shorthand
    # plain functions never decorated with a route are not entry points
    assert "find_products" not in entry_points
    assert "calculate_adjustment" not in entry_points


def test_decorator_route_detector_ignores_undecorated_functions():
    source = """
def plain_function():
    pass
"""
    trees = {"f.py": ast.parse(source)}
    assert detect_decorator_route_entry_points(trees) == set()


def test_django_detector_tags_views_referenced_from_urlpatterns():
    source = """
from django.urls import path, re_path
from . import views

urlpatterns = [
    path("admin/", views.admin_view),
    path("users/<int:id>/", user_detail),
    re_path(r"^legacy/$", views.legacy_handler),
]
"""
    trees = {"urls.py": ast.parse(source)}
    assert detect_django_entry_points(trees) == {"admin_view", "user_detail", "legacy_handler"}


def test_django_detector_recognizes_module_prefixed_url_functions():
    source = """
import django.urls

urlpatterns = [
    django.urls.path("ping/", ping_view),
]
"""
    trees = {"urls.py": ast.parse(source)}
    assert detect_django_entry_points(trees) == {"ping_view"}


def test_django_detector_ignores_files_with_no_urlpatterns():
    source = """
def plain_function():
    pass
"""
    trees = {"f.py": ast.parse(source)}
    assert detect_django_entry_points(trees) == set()


# ---- Fix 1: a decorated router that's never mounted isn't an entry point ----

def test_decorator_route_detector_excludes_a_router_never_passed_to_include_router():
    main_source = """
from fastapi import FastAPI

from app.routes.public import router as public_router

app = FastAPI()
app.include_router(public_router)


@app.get("/")
def home():
    pass
"""
    public_source = """
from fastapi import APIRouter

router = APIRouter(prefix="/salary")


@router.get("/employees")
def employee_search(name):
    pass
"""
    orphan_source = """
from fastapi import APIRouter

orphan_router = APIRouter(prefix="/legacy-admin")


@orphan_router.get("/employees")
def orphan_employee_search(name):
    pass
"""
    trees = {
        "main.py": ast.parse(main_source),
        "routes/public.py": ast.parse(public_source),
        "orphan_routes.py": ast.parse(orphan_source),
    }
    entry_points = detect_decorator_route_entry_points(trees)

    assert "home" in entry_points                 # decorated on the app object directly
    assert "employee_search" in entry_points       # decorated on a router that IS mounted
    assert "orphan_employee_search" not in entry_points   # router defined but never mounted


def test_decorator_route_detector_tags_mounted_router_even_without_an_import_alias():
    # router mounted under its own name, no `as` - canonical name resolution must still
    # work via identity mapping when there's no alias.
    main_source = """
from fastapi import FastAPI
from routes import router

app = FastAPI()
app.include_router(router)
"""
    routes_source = """
from fastapi import APIRouter

router = APIRouter()


@router.post("/thing")
def create_thing():
    pass
"""
    trees = {"main.py": ast.parse(main_source), "routes.py": ast.parse(routes_source)}
    assert detect_decorator_route_entry_points(trees) == {"create_thing"}


def test_celery_detector_tags_bare_and_attribute_style_task_decorators():
    source = """
from celery import shared_task

@shared_task
def process_upload(file_id):
    pass

@shared_task(bind=True)
def send_email(self, to, subject):
    pass

@app.task
def cleanup():
    pass

def not_a_task():
    pass
"""
    trees = {"tasks.py": ast.parse(source)}
    entry_points = detect_celery_entry_points(trees)
    assert entry_points == {"process_upload", "send_email", "cleanup"}
    assert "not_a_task" not in entry_points
