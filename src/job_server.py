# job_server.py — FastAPI job queue for Samsung ping agent
#
# Endpoints:
#   GET  /ping-jobs          → list of CIDRs to ping (up to 10)
#   POST /ping-results       → submit ping result for a CIDR
#   GET  /health             → {"ok": true}
#
# Auth: X-Secret: <PING_AGENT_SECRET> on all endpoints.
# Run:  uvicorn src.job_server:app --host 0.0.0.0 --port 8888

from __future__ import annotations

import os
import threading
try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

import structlog
from fastapi import Depends, FastAPI, HTTPException, Header
from pydantic import BaseModel

log = structlog.get_logger(__name__)

app = FastAPI(title="ping-job-server", docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_lock = threading.Lock()

# cidr → threading.Event (set when result arrives)
_pending_jobs: dict[str, threading.Event] = {}

# cidr → alive count
_results: dict[str, int] = {}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_SECRET = os.environ.get("PING_AGENT_SECRET", "")


def _check_secret(x_secret: Annotated[str, Header()] = "") -> None:
    if not _SECRET:
        return  # secret not configured → open (dev mode)
    if x_secret != _SECRET:
        raise HTTPException(status_code=403, detail="Invalid X-Secret")


Auth = Annotated[None, Depends(_check_secret)]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class PingResult(BaseModel):
    cidr: str
    alive: int
    total: int = 254


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/ping-jobs")
def get_ping_jobs(_: Auth) -> list[str]:
    """Return up to 10 pending CIDRs that haven't received a result yet."""
    with _lock:
        jobs = [
            cidr for cidr, evt in _pending_jobs.items()
            if cidr not in _results
        ]
    batch = jobs[:10]
    log.info("job_server.jobs_dispatched", count=len(batch))
    return batch


@app.post("/ping-results", status_code=204)
def post_ping_results(result: PingResult, _: Auth) -> None:
    """Accept a ping result from Samsung agent."""
    with _lock:
        if result.cidr not in _pending_jobs:
            log.warning("job_server.unexpected_result", cidr=result.cidr)
            raise HTTPException(status_code=404, detail="Unknown CIDR")
        _results[result.cidr] = result.alive
        _pending_jobs[result.cidr].set()
    log.info("job_server.result_received",
             cidr=result.cidr, alive=result.alive, total=result.total)


# ---------------------------------------------------------------------------
# Internal API — called by orchestrator (same process)
# ---------------------------------------------------------------------------

def enqueue(cidr: str) -> threading.Event:
    """Add a CIDR to the job queue. Returns an Event that fires when result arrives."""
    evt = threading.Event()
    with _lock:
        _pending_jobs[cidr] = evt
        _results.pop(cidr, None)
    log.info("job_server.enqueued", cidr=cidr)
    return evt


def get_result(cidr: str) -> int | None:
    """Return alive count if result is ready, else None."""
    with _lock:
        return _results.get(cidr)


def clear(cidr: str) -> None:
    """Remove a job and its result from state."""
    with _lock:
        _pending_jobs.pop(cidr, None)
        _results.pop(cidr, None)
