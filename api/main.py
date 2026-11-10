"""PhishGuard AI - FastAPI backend (Phase 1: URL detection module only).

Run:  uvicorn api.main:app --reload
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishguard import __version__
from phishguard.storage import HistoryStore
from phishguard.url_module.model import URLDetector
from phishguard.url_module.validation import MAX_URL_LENGTH, URLValidationError, redact_for_storage, validate_url

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = Path(os.environ.get("PHISHGUARD_MODEL", ROOT / "models" / "url_model.joblib"))
DB_PATH = Path(os.environ.get("PHISHGUARD_DB", ROOT / "data" / "phishguard.db"))
log = logging.getLogger("phishguard")

MODULE_STATUS = {
    "url_detection": "implemented",
    "website_analysis": "planned (Phase 3)",
    "social_engineering": "planned (Phase 4)",
    "risk_engine": "partial - URL-only risk bands; multi-module aggregation planned (Phase 5)",
    "frontend": "partial - React dashboard for the URL module (Phase 6)",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.history = HistoryStore(DB_PATH)
    try:
        app.state.detector = URLDetector.load(MODEL_PATH)  # loaded once, reused for all requests
        app.state.model_error = None
    except (FileNotFoundError, ValueError) as exc:
        app.state.detector = None
        app.state.model_error = str(exc)
        log.warning("URL model unavailable: %s", exc)
    yield


app = FastAPI(title="PhishGuard AI", version=__version__, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:3000"],
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error")  # details stay in server logs, not in the response
    return JSONResponse(status_code=500, content={"detail": "Internal error while processing the request."})


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    save_to_history: bool = True


def _detector(request: Request) -> URLDetector:
    det = request.app.state.detector
    if det is None:
        raise HTTPException(503, "URL detection model is not loaded. Train it with scripts/train_url_model.py.")
    return det


@app.get("/api/health")
def health(request: Request):
    return {"status": "ok", "url_model_loaded": request.app.state.detector is not None}


@app.post("/api/url/analyze")
def analyze_url(body: URLRequest, request: Request):
    det = _detector(request)
    try:
        result = det.predict(body.url)
    except URLValidationError as exc:
        raise HTTPException(422, str(exc))
    if body.save_to_history:
        redacted = redact_for_storage(validate_url(body.url))
        result["history_id"] = request.app.state.history.add("url_detection", redacted, result)
    return result


@app.get("/api/history")
def history(request: Request, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    return request.app.state.history.list(limit, offset)


@app.get("/api/history/{analysis_id}")
def history_item(analysis_id: int, request: Request):
    item = request.app.state.history.get(analysis_id)
    if not item:
        raise HTTPException(404, "Analysis not found.")
    return item


@app.get("/api/stats")
def stats(request: Request):
    return request.app.state.history.stats()


REPORT_PATH = ROOT / "reports" / "url_model_metrics.json"


def _model_comparison() -> dict | None:
    """Per-model metrics from the last training run (error examples omitted)."""
    if not REPORT_PATH.exists():
        return None
    report = json.loads(REPORT_PATH.read_text())
    keep = ("train_seconds", "decision_threshold", "validation", "test", "external_test", "test_risk_bands",
            "external_risk_bands")
    return {"selected_model": report.get("selected_model"),
            "selection_criterion": report.get("selection_criterion"),
            "models": {name: {k: m[k] for k in keep if k in m} for name, m in report["models"].items()}}


@app.get("/api/info")
def info(request: Request):
    det = request.app.state.detector
    return {
        "application": "PhishGuard AI", "version": __version__, "modules": MODULE_STATUS,
        "url_model": det.info() if det else {"loaded": False, "error": "model not trained"},
        "training_report": _model_comparison(),
    }


# Serve the built React app (frontend/dist) from the same server, if it has been built.
DIST = ROOT / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Not found.")
        target = (DIST / path).resolve()
        if path and target.is_file() and DIST.resolve() in target.parents:
            return FileResponse(target)
        return FileResponse(DIST / "index.html")
