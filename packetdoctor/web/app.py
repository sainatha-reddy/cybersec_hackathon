"""Local web dashboard (FastAPI).

Security choices:
* bound to 127.0.0.1 by default (see ``packetdoctor serve``);
* uploads are streamed to a randomly named file inside a private temporary
  directory with a hard size cap, analysed, then deleted; nothing is stored,
  logged or cached server-side;
* sample analysis only accepts names from a fixed allow-list (no paths);
* strict Content-Security-Policy: the page loads no third-party code, and
  all report data is inserted with textContent (no HTML injection);
* a small semaphore limits concurrent analyses (no resource exhaustion).
"""

from __future__ import annotations

import asyncio
import os
import secrets
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .. import __version__
from ..config import Limits, Settings
from ..engine import analyze
from ..ingest import CaptureError

HERE = Path(__file__).resolve().parent
SAMPLES_DIR = HERE.parent.parent / "samples"
MAX_UPLOAD_MB = int(os.environ.get("PACKETDOCTOR_MAX_UPLOAD_MB", "200"))
MAX_UPLOAD = MAX_UPLOAD_MB * 1024 * 1024
CHUNK = 1024 * 1024
SETTINGS = Settings(limits=Limits(max_file_bytes=MAX_UPLOAD, timeout_seconds=180))
_slots = asyncio.Semaphore(2)

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

app = FastAPI(title="PacketDoctor", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
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
    return {"status": "ok", "version": __version__, "max_upload_mb": MAX_UPLOAD_MB}


@app.get("/api/samples")
async def samples():
    return [{"name": n, "kb": p.stat().st_size // 1024} for n, p in _sample_files().items()]


async def _run(path: Path, anonymize: bool) -> dict:
    async with _slots:
        return await run_in_threadpool(analyze, path, SETTINGS, anonymize)


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...), anonymize: bool = Form(False)):
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
async def analyze_sample(name: str, anonymize: bool = Form(False)):
    files = _sample_files()
    if name not in files:  # allow-list lookup: no path traversal possible
        raise HTTPException(404, "Unknown sample.")
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
