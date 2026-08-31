"""Configured Celery application for the reachability fixture."""

from celery import Celery

celery_app = Celery(
    "payroll_worker",
    broker="memory://",
    backend="cache+memory://",
    include=["tasks"],
)

celery_app.conf.update(
    task_always_eager=True,
    task_store_eager_result=True,
)
