"""In-process scan job registry — fire-and-forget + poll.

Mirrors the MCP "Tasks" pattern (SEP-1686): start a scan, get a scan_id back
immediately, poll for status. A scan takes many minutes, far longer than any MCP
client will hold a tool call open, so scan_target must return at once.

MVP scope: jobs live in this process's memory and run on a daemon thread. If the
MCP server stops, in-flight scans die — acceptable for a local stdio server.
Durable jobs (survive restart) need the Postgres/state layer + a worker; that's
the documented upgrade path.

Single-flight: a scan hammers Ollama + SpiderFoot, so only one runs at a time.
"""

from __future__ import annotations

import threading
import uuid
from typing import Literal, TypedDict, cast

from eidolon.core.runner import run_scan

JobStatus = Literal["running", "done", "error"]


class Job(TypedDict):
    scan_id: str
    status: JobStatus
    result: dict | None  # ScanResult.model_dump() when done
    error: str | None  # message when status == "error"


_JOBS: dict[str, Job] = {}
_LOCK = threading.Lock()


def start_scan(
    *,
    email: str | None = None,
    phone: str | None = None,
    name: str | None = None,
    city: str | None = None,
    state: str | None = None,
    zip_code: str | None = None,
) -> dict:
    """Kick off a scan on a background thread. Returns immediately with the
    scan_id, or an error dict if a scan is already running."""
    with _LOCK:
        if any(j["status"] == "running" for j in _JOBS.values()):
            running = next(
                j["scan_id"] for j in _JOBS.values() if j["status"] == "running"
            )
            return {
                "error": f"a scan is already running (scan_id={running}); "
                "one at a time — poll scan_status until it finishes."
            }
        scan_id = uuid.uuid4().hex[:8]
        _JOBS[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "result": None,
            "error": None,
        }

    def _work() -> None:
        try:
            result = run_scan(
                email=email,
                phone=phone,
                name=name,
                city=city,
                state=state,
                zip_code=zip_code,
                run_id=scan_id,
            )
            with _LOCK:
                _JOBS[scan_id]["status"] = "done"
                _JOBS[scan_id]["result"] = result.model_dump()
        except Exception as exc:  # never let the thread die silently
            with _LOCK:
                _JOBS[scan_id]["status"] = "error"
                _JOBS[scan_id]["error"] = str(exc)

    threading.Thread(target=_work, daemon=True, name=f"scan-{scan_id}").start()
    return {"scan_id": scan_id, "status": "running"}


def get_job(scan_id: str) -> Job | None:
    """Current state of a scan job, or None if unknown to this process."""
    with _LOCK:
        job = _JOBS.get(scan_id)
        return cast(Job, dict(job)) if job else None  # copy so callers can't mutate
