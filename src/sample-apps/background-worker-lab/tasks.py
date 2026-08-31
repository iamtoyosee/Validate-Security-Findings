"""Externally reachable Celery message entry points."""

from celery_app import celery_app
import services


@celery_app.task(name="salary.search_employees")
def search_employees(name: str):
    # Entry point for R1: task -> service -> repository.
    return services.find_employees(name)


@celery_app.task(name="salary.run_diagnostic")
def run_diagnostic(host: str):
    # Entry point for R2: task -> service.
    return services.run_diagnostic(host)


@celery_app.task(name="salary.calculate_bonus")
def calculate_bonus(expression: str):
    # Entry point for R3: task -> instantiated class method.
    calculator = services.BonusCalculator()
    return calculator.calculate(expression)


@celery_app.task(name="salary.fetch_provider")
def fetch_provider(url: str):
    # Entry point for R4: task -> service.
    return services.fetch_provider(url)


@celery_app.task(name="salary.decode_import")
def decode_import(payload: str):
    # Entry point for R5: task -> service.
    return repr(services.decode_import(payload))


@celery_app.task(name="salary.load_policy")
def load_policy(policy: str):
    # Entry point for R6: task -> service.
    return repr(services.load_policy(policy))
