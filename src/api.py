import dataclasses
import os
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from semgrep_adapter import from_semgrep, group_raw_results, read_snippet, run_semgrep
from codebase_source import CodebaseTooLargeError, LocalPathSource
from reachability.engine import build_call_graph, build_verdict

app = FastAPI()

SAMPLE_APPS_DIR = Path(__file__).parent / "sample-apps"

# One-liner descriptions only - each app's own README/ground_truth.md carries the full
# story; this is just enough for a card in the picker UI.
SAMPLE_APPS = {
    "todo-list-app": {
        "name": "Todo App",
        "description": "A small http.server app with no framework - the original ground-truth fixture.",
    },
    "ecommerce-app": {
        "name": "E-commerce App",
        "description": "A real Flask app with templates, sessions, and a mix of reachable and dead code.",
    },
    "rest-api-lab": {
        "name": "REST API",
        "description": "A layered FastAPI app - services, a repository, background tasks, and one router "
        "that's never mounted.",
    },
    "background-worker-lab": {
        "name": "Background Worker",
        "description": "A Celery task queue - one configured worker, and one orphaned app nothing ever loads.",
    },
}

# ALLOWED_ORIGINS: comma-separated list, e.g. "https://my-frontend.vercel.app". Falls
# back to local dev defaults so `uvicorn api:app --reload` keeps working with no setup.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
allowed_origins = os.environ.get("ALLOWED_ORIGINS", _default_origins).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def run_pipeline(codebase_path: Path) -> dict:
    """Shared by both /api/scan (an upload) and /api/scan-sample (a bundled demo app) -
    everything past "here's a directory of Python files on disk" is identical either way.
    """
    raw_results = run_semgrep(codebase_path)
    groups = group_raw_results(raw_results)
    findings = [from_semgrep(g) for g in groups]
    # from_semgrep() leaves code_snippet=None - fill it in now that the codebase is on disk
    findings = [
        dataclasses.replace(
            f, code_snippet=read_snippet(codebase_path, f.file_path, f.line_start, f.line_end)
        )
        for f in findings
    ]

    python_files = {
        str(p.relative_to(codebase_path)): p.read_text()
        for p in codebase_path.rglob("*.py")
    }
    graph = build_call_graph(python_files)
    reachability = [build_verdict(f, graph) for f in findings]

    return {
        "raw_result_count": len(raw_results),
        "findings": [
            {k: v for k, v in dataclasses.asdict(f).items() if k != "raw"}
            for f in findings
        ],
        "reachability": [dataclasses.asdict(v) for v in reachability],
    }


@app.post("/api/scan")
async def scan(files: list[UploadFile]):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # recreate the uploaded folder's relative structure on disk - resolve and
        # verify containment first, since an unvalidated filename (e.g. "../../etc/x",
        # or an absolute path, which Path.__truediv__ lets override the base entirely)
        # would otherwise let a crafted upload write outside temp_dir.
        temp_dir_resolved = temp_dir.resolve()
        for upload in files:
            dest = (temp_dir / upload.filename).resolve()
            if not dest.is_relative_to(temp_dir_resolved):
                raise HTTPException(status_code=400, detail="Invalid file path in upload.")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(await upload.read())

        try:
            codebase_path = LocalPathSource(temp_dir).materialize()
        except CodebaseTooLargeError as e:
            raise HTTPException(status_code=413, detail=str(e))

        return JSONResponse(run_pipeline(codebase_path))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/api/samples")
async def list_samples():
    return [{"id": sample_id, **meta} for sample_id, meta in SAMPLE_APPS.items()]


class ScanSampleRequest(BaseModel):
    sample_id: str


@app.post("/api/scan-sample")
async def scan_sample(request: ScanSampleRequest):
    if request.sample_id not in SAMPLE_APPS:
        raise HTTPException(status_code=404, detail=f"No sample app '{request.sample_id}'.")
    codebase_path = SAMPLE_APPS_DIR / request.sample_id
    return JSONResponse(run_pipeline(codebase_path))
