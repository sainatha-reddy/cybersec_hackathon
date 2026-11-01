"""Local web dashboard (FastAPI).

Security choices:
* bound to 127.0.0.1 by default (see ``packetdoctor serve``);
* uploads are streamed to a randomly named file inside a private temporary
  directory with a hard size cap, analysed, then deleted; nothing is stored,
  logged or cached server-side;
* sample analysis only accepts names from a fixed allow-list (no paths);
* strict Content-Security-Policy: the page loads no third-party code, and
  all report data is inserted with textContent (no HTML injection);
* bounded request admission limits concurrent uploads and analysis workers.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
import threading
import time
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .. import __version__
from ..config import Limits, Settings
from ..worker import analyze_isolated
from ..ingest import CaptureError

HERE = Path(__file__).resolve().parent
SAMPLES_DIR = HERE.parent.parent / "samples"
MAX_UPLOAD_MB = int(os.environ.get("PACKETDOCTOR_MAX_UPLOAD_MB", "200"))
MAX_UPLOAD = MAX_UPLOAD_MB * 1024 * 1024
CHUNK = 1024 * 1024
SETTINGS = Settings(limits=Limits(max_file_bytes=MAX_UPLOAD, timeout_seconds=180))
_jobs = {}
MAX_JOBS = 2
# Hosted demo mode (e.g. a Hugging Face Space): captures travel to the server, so the
# UI says so, and the Space page on huggingface.co is allowed to embed the app.
HOSTED = os.environ.get("PACKETDOCTOR_HOSTED", "").lower() in ("1", "true", "yes")
FRAME_ANCESTORS = "https://huggingface.co" if HOSTED else "'none'"


class UploadGuard:
    def __init__(self, app):
        self.application = app
        self.active = 0

    async def __call__(self, scope, receive, send):
        protected = scope["type"] == "http" and scope.get("method") == "POST" and scope.get("path", "").startswith("/api/analyze")
        if not protected:
            return await self.application(scope, receive, send)
        running = sum(job["status"] == "running" for job in _jobs.values())
        if self.active + running >= MAX_JOBS:
            return await JSONResponse({"detail": "Both analysis slots are busy. Retry after an analysis finishes."}, status_code=429)(scope, receive, send)
        maximum = MAX_UPLOAD + 65_536
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            length = maximum + 1
        if length > maximum:
            return await JSONResponse({"detail": "Request exceeds the upload limit."}, status_code=413)(scope, receive, send)
        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > maximum:
                raise HTTPException(413, "Request exceeds the upload limit.")
            return message

        self.active += 1
        try:
            await self.application(scope, bounded_receive, send)
        finally:
            self.active -= 1

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors " + FRAME_ANCESTORS
)

@asynccontextmanager
async def lifespan(application):
    yield
    tasks = []
    for job in list(_jobs.values()):
        job["cancelled"].set()
        if job.get("task"):
            tasks.append(job["task"])
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _jobs.clear()


app = FastAPI(title="PacketDoctor", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(UploadGuard)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not HOSTED:
        response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _sample_files() -> dict[str, Path]:
    if not SAMPLES_DIR.is_dir():
        return {}
    return {p.name: p for p in sorted(SAMPLES_DIR.iterdir()) if p.suffix in (".pcap", ".pcapng") and p.is_file()}


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(HERE / "templates" / "index.html", media_type="text/html")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": __version__, "max_upload_mb": MAX_UPLOAD_MB, "timeout_seconds": SETTINGS.limits.timeout_seconds, "max_memory_mb": SETTINGS.limits.max_memory_mb, "hosted": HOSTED}


@app.get("/api/samples")
async def samples():
    return [{"name": n, "kb": p.stat().st_size // 1024} for n, p in _sample_files().items()]


async def _run(path: Path, anonymize: bool) -> dict:
    return await run_in_threadpool(analyze_isolated, path, SETTINGS, anonymize)


async def _background(job_id, path, anonymize, temporary, display_name):
    job = _jobs[job_id]
    operation = asyncio.create_task(run_in_threadpool(analyze_isolated, path, SETTINGS, anonymize, job["cancelled"]))
    try:
        report = await asyncio.shield(operation)
        if not anonymize:
            report["capture"]["file_name"] = display_name
        job.update(status="complete", report=report)
    except CaptureError as error:
        job.update(status="cancelled" if job["cancelled"].is_set() else "failed", error=str(error).replace(path.name, "the uploaded file"))
    except asyncio.CancelledError:
        job["cancelled"].set()
        try:
            await operation
        except (CaptureError, asyncio.CancelledError):
            pass
        raise
    except Exception:
        job.update(status="failed", error="Analysis could not finish. Try a smaller capture.")
    finally:
        if temporary:
            shutil.rmtree(temporary, ignore_errors=True)
        job["finished"] = time.monotonic()
        asyncio.get_running_loop().call_later(120, _jobs.pop, job_id, None)


def _start(path, anonymize, temporary=None, display_name=None):
    if sum(job["status"] == "running" for job in _jobs.values()) >= MAX_JOBS or len(_jobs) >= 8:
        raise HTTPException(429, "Analysis capacity is full. Retry shortly.")
    job_id = secrets.token_urlsafe(24)
    _jobs[job_id] = {"status": "running", "cancelled": threading.Event(), "started": time.monotonic()}
    _jobs[job_id]["task"] = asyncio.create_task(_background(job_id, path, anonymize, temporary, display_name or path.name))
    return JSONResponse({"job_id": job_id}, status_code=202)


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Analysis expired or was not found. Start a new analysis.")
    return {"status": job["status"], "elapsed_s": round(time.monotonic() - job["started"], 1), "report": job.get("report"), "error": job.get("error")}


@app.delete("/api/jobs/{job_id}")
async def cancel_job(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Unknown analysis.")
    job["cancelled"].set()
    if job["status"] != "running":
        _jobs.pop(job_id, None)
    return {"status": "cancelling"}


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...), anonymize: bool = Form(False), background: bool = False):
    if background:
        temporary = tempfile.mkdtemp(prefix="packetdoctor-")
        target = Path(temporary) / f"{secrets.token_hex(16)}.cap"
        try:
            size = 0
            with target.open("wb") as output:
                while chunk := await file.read(CHUNK):
                    size += len(chunk)
                    if size > MAX_UPLOAD:
                        raise HTTPException(413, "File exceeds the upload limit.")
                    output.write(chunk)
            if not size:
                raise HTTPException(400, "The uploaded file is empty.")
            return _start(target, anonymize, temporary, _display_name(file.filename))
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        finally:
            await file.close()
    with tempfile.TemporaryDirectory(prefix="packetdoctor-") as tmp:
        target = Path(tmp) / f"{secrets.token_hex(16)}.cap"  # never use the client's file name as a path
        size = 0
        with target.open("wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, f"File is larger than the {MAX_UPLOAD_MB} MB upload limit.")
                out.write(chunk)
        await file.close()
        if size == 0:
            raise HTTPException(400, "The uploaded file is empty.")
        try:
            report = await _run(target, anonymize)
        except CaptureError as exc:
            raise HTTPException(400, str(exc).replace(target.name, "the uploaded file")) from None
        except Exception:
            raise HTTPException(500, "The capture could not be analysed.") from None
    if not anonymize:
        report["capture"]["file_name"] = _display_name(file.filename)
    return JSONResponse(report)


@app.post("/api/analyze-sample/{name}")
async def analyze_sample(name: str, anonymize: bool = Form(False), background: bool = False):
    files = _sample_files()
    if name not in files:  # allow-list lookup: no path traversal possible
        raise HTTPException(404, "Unknown sample.")
    if background:
        return _start(files[name], anonymize)
    try:
        return JSONResponse(await _run(files[name], anonymize))
    except CaptureError as exc:
        raise HTTPException(400, str(exc)) from None


def _display_name(name: str | None) -> str:
    if not name:
        return "upload"
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    clean = "".join(c for c in base if c.isalnum() or c in "._- ")[:80]
    return clean or "upload"
