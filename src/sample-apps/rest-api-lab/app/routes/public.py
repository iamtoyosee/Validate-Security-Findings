from fastapi import APIRouter, BackgroundTasks, Depends, Query

from app import services

router = APIRouter(prefix="/salary")


def requested_url(url: str = Query(default="https://example.com")) -> str:
    return url


@router.get("/employees")
def employee_search(name: str = Query(default="Ada")):
    # Entry point for R1; sink is two calls away in repository.py.
    return {"employees": services.find_employees(name)}


@router.get("/diagnostics")
def payroll_diagnostics(host: str = Query(default="127.0.0.1")):
    # Entry point for R2; sink is in services.py.
    return {"output": services.run_diagnostic(host)}


@router.get("/benefit-preview")
def benefit_preview(url: str = Depends(requested_url)):
    # Entry point for R3; attacker input arrives through a FastAPI dependency.
    return {"preview": services.fetch_benefit_provider(url)}


@router.get("/formula")
def salary_formula(expression: str = Query(default="40000 + 2000")):
    # Entry point for R4; sink is reached through a class method.
    calculator = services.SalaryCalculator()
    return {"salary": calculator.calculate(expression)}


@router.post("/imports")
def import_payroll(payload: str, background_tasks: BackgroundTasks):
    # Entry point for R5; the vulnerable sink executes as an HTTP-scheduled task.
    background_tasks.add_task(services.decode_payroll_import, payload)
    return {"status": "scheduled"}


@router.post("/policy")
def upload_policy(policy: str):
    # Entry point for R6; sink is in services.py.
    return {"policy": repr(services.parse_policy(policy))}
