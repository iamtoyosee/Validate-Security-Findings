"""Salary reachability lab. Intentionally unsafe; local SAST testing only."""

from fastapi import FastAPI

from app.routes.public import router as public_router

app = FastAPI(title="Salary Starship — Reachability Lab")
app.include_router(public_router)


@app.get("/")
def home():
    return {
        "warning": "Intentionally vulnerable. Never deploy.",
        "ground_truth": {"reachable": 6, "unreachable": 6},
    }
