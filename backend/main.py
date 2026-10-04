"""The web server (FastAPI). It serves the JSON API under /api and the web page at /.
Run it with:  cd backend && uvicorn main:app --reload
"""
import logging
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import db
import github
import llm
import queries
import ratelimit
from errors import AppError
from npm_parser import analyze_inputs
from scanner import now, run_scan

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
SAMPLES = Path(__file__).resolve().parent / "samples"
MAX_UPLOAD = 5 * 1024 * 1024  # 5 MB per file

# Load backend/.env or ./.env if present (simple KEY=VALUE lines) so you do not need extra libraries.
for env_file in (ROOT / ".env", Path(__file__).resolve().parent / ".env"):
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("devguard")
# DEVGUARD_PUBLIC=1 (set on the hosted site): hides API docs, disables delete, rate-limits expensive calls.
PUBLIC = os.environ.get("DEVGUARD_PUBLIC") == "1"

db.init_db()
app = FastAPI(title="DevGuard", description="Dependency security analytics. Uploaded code is never executed.",
              docs_url=None if PUBLIC else "/docs", redoc_url=None if PUBLIC else "/redoc",
              openapi_url=None if PUBLIC else "/openapi.json")


def limit(bucket, max_calls):
    def check(request: Request):
        ratelimit.check(request.client.host if request.client else "unknown", bucket, max_calls)
    return Depends(check)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


class UrlBody(BaseModel):
    url: str


class AskBody(BaseModel):
    question: str


@app.exception_handler(AppError)
async def app_error(_: Request, exc: AppError):
    return JSONResponse(status_code=exc.status, content=exc.to_dict())


@app.exception_handler(Exception)
async def unexpected(_: Request, exc: Exception):
    ref = uuid.uuid4().hex[:8]
    log.exception("Unhandled error (reference %s)", ref)  # details only in the server log
    return JSONResponse(status_code=500, content={"error": {"code": "internal_error", "message": f"Unexpected server error (reference {ref}).", "hint": None}})


# ---- helpers ------------------------------------------------------------------------------------
def save_project(name, source_type, manifest, lock, repo_url=None, branch=None):
    """Create the project, or update its stored files if it already exists (this makes re-uploads new scans)."""
    existing = db.query("SELECT id FROM projects WHERE name=? AND source_type=?", (name, source_type), one=True)
    if existing:
        db.execute("UPDATE projects SET manifest_text=?, lock_text=?, repo_url=?, branch=? WHERE id=?",
                   (manifest, lock, repo_url, branch, existing["id"]))
        return existing["id"]
    return db.execute("INSERT INTO projects (name, source_type, repo_url, branch, manifest_text, lock_text, created_at) "
                      "VALUES (?,?,?,?,?,?,?)", (name, source_type, repo_url, branch, manifest, lock, now()))


def import_and_scan(name_hint, source_type, manifest, lock, repo_url=None, branch=None):
    try:
        parsed = analyze_inputs(manifest, lock)  # validate before saving anything
    except ValueError as e:
        raise AppError(422, "invalid_project_files", str(e), "Check that the files are valid package.json / package-lock.json (npm 7+).")
    project_id = save_project(name_hint or parsed.root_name, source_type, manifest, lock, repo_url, branch)
    scan_id = run_scan(project_id)
    return {"project_id": project_id, "scan_id": scan_id}


async def read_upload(upload, label):
    if upload is None:
        return None
    data = await upload.read(MAX_UPLOAD + 1)  # the uploaded filename is never used
    if len(data) > MAX_UPLOAD:
        raise AppError(413, "file_too_large", f"{label} is larger than 5 MB.")
    if not data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise AppError(422, "not_text", f"{label} is not a text file.")


# ---- import / scan ------------------------------------------------------------------------------
@app.post("/api/import/github", dependencies=[limit("scan", 20)])
def import_github(body: UrlBody):
    files = github.fetch_repo_files(body.url)
    return import_and_scan(f"{files['owner']}/{files['repo']}", "github", files["package_json"], files["package_lock"],
                           f"https://github.com/{files['owner']}/{files['repo']}", files["branch"])


@app.post("/api/import/upload", dependencies=[limit("scan", 20)])
async def import_upload(package_json: UploadFile = File(...), package_lock: Optional[UploadFile] = File(None)):
    pkg = await read_upload(package_json, "package.json")
    lock = await read_upload(package_lock, "package-lock.json")
    if not pkg:
        raise AppError(422, "package_json_missing", "package.json is required.")
    return await run_in_threadpool(import_and_scan, None, "upload", pkg, lock)


@app.post("/api/demo/{variant}", dependencies=[limit("scan", 20)])
def load_demo(variant: str):
    """Demo = real npm package versions (no code). Vulnerabilities come live from OSV, not from this repo."""
    if variant not in ("before", "after"):
        raise AppError(404, "unknown_demo", "Demo variant must be 'before' or 'after'.")
    pkg = (SAMPLES / variant / "package.json").read_text()
    lock = (SAMPLES / variant / "package-lock.json").read_text()
    return import_and_scan("devguard-demo", "demo", pkg, lock)


@app.post("/api/projects/{project_id}/scan", dependencies=[limit("scan", 20)])
def rescan(project_id: int):
    project = db.query("SELECT * FROM projects WHERE id=?", (project_id,), one=True)
    if project is None:
        raise AppError(404, "project_not_found", "Project not found.")
    if project["source_type"] == "github" and project["repo_url"]:  # pick up new commits
        files = github.fetch_repo_files(project["repo_url"])
        db.execute("UPDATE projects SET manifest_text=?, lock_text=?, branch=? WHERE id=?",
                   (files["package_json"], files["package_lock"], files["branch"], project_id))
    return {"project_id": project_id, "scan_id": run_scan(project_id)}


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: int):
    if PUBLIC:
        raise AppError(403, "disabled", "Deleting projects is disabled on this public demo.")
    queries.get_project(project_id)
    db.execute("DELETE FROM projects WHERE id=?", (project_id,))
    return {"ok": True}


# ---- read ---------------------------------------------------------------------------------------
@app.get("/api/health")
def health():
    db.query("SELECT 1")
    return {"ok": True, "ai": llm.configured(), "public": PUBLIC}


@app.get("/api/projects")
def projects():
    return {"projects": queries.list_projects()}


@app.get("/api/projects/{project_id}/summary")
def summary(project_id: int):
    return queries.summary(project_id)


@app.get("/api/projects/{project_id}/scans")
def scans(project_id: int):
    queries.get_project(project_id)
    return {"scans": queries.list_scans(project_id)}


@app.get("/api/scans/{scan_id}/findings")
def findings(scan_id: int):
    queries.get_scan(scan_id)
    return {"findings": queries.findings(scan_id)}


@app.get("/api/scans/{scan_id}/dependencies")
def dependencies(scan_id: int):
    queries.get_scan(scan_id)
    return {"dependencies": queries.dependencies(scan_id)}


@app.get("/api/scans/{scan_id}/export.csv")
def export_csv(scan_id: int):
    queries.get_scan(scan_id)
    return Response(queries.findings_csv(scan_id), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="devguard-scan-{scan_id}.csv"'})


@app.get("/api/findings/{finding_id}")
def finding(finding_id: int):
    return queries.finding_detail(finding_id)


@app.get("/api/scans/{new_id}/compare/{old_id}")
def compare(new_id: int, old_id: int):
    return queries.compare(new_id, old_id)


# ---- AI -----------------------------------------------------------------------------------------
@app.post("/api/scans/{scan_id}/explain", dependencies=[limit("ai", 15)])
def explain(scan_id: int):
    queries.get_scan(scan_id)
    return llm.explain(scan_id)


@app.post("/api/scans/{scan_id}/ask", dependencies=[limit("ai", 15)])
def ask(scan_id: int, body: AskBody):
    queries.get_scan(scan_id)
    return llm.ask(scan_id, body.question)


# ---- web page -----------------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
