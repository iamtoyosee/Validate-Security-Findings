import dataclasses
import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from semgrep_adapter import from_semgrep, group_raw_results, read_snippet, run_semgrep
from codebase_source import CodebaseTooLargeError, LocalPathSource

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["POST"],
    allow_headers=["*"],
)


@app.post("/api/scan")
async def scan(files: list[UploadFile]):
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # recreate the uploaded folder's relative structure on disk
        for upload in files:
            dest = temp_dir / upload.filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(await upload.read())

        try:
            codebase_path = LocalPathSource(temp_dir).materialize()
        except CodebaseTooLargeError as e:
            raise HTTPException(status_code=413, detail=str(e))

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

        return JSONResponse({
            "raw_result_count": len(raw_results),
            "findings": [
                {k: v for k, v in dataclasses.asdict(f).items() if k != "raw"}
                for f in findings
            ],
        })
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
