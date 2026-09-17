"""In-process scan job registry — fire-and-forget + poll.

Mirrors the MCP "Tasks" pattern (SEP-1686): start a scan, get a scan_id back
immediately, poll for status. A scan takes many minutes, far longer than any MCP
client will hold a tool call open, so scan_target must return at once.

MVP scope: jobs live in this process's memory and run on a daemon thread. If the
MCP server stops, in-flight scans die — acceptable for a local stdio server.
Durable jobs (survive restart) need the Postgres/state layer + a worker; that's
the documented upgrade path.

Single-flight: a scan hammers Ollama + SpiderFoot, so only one scan or batch
runs at a time (TASKING.2 — a batch owns the same runway a single scan does).
"""

from __future__ import annotations

import threading
import uuid
from typing import Callable, Literal, TypedDict, cast

from eidolon.core.runner import run_scan

JobStatus = Literal["running", "done", "error"]


class Job(TypedDict):
    scan_id: str
    status: JobStatus
    result: dict | None  # ScanResult.model_dump() when done
    error: str | None  # message when status == "error"


class BatchJob(TypedDict):
    batch_id: str
    status: JobStatus
    total: int
    scan_ids: list[str] | None  # child run_ids, in submission order, when done
    reports: list[dict] | None  # [{scan_id, report}] when done
    error: str | None


_JOBS: dict[str, Job] = {}
_BATCHES: dict[str, BatchJob] = {}
_LOCK = threading.Lock()


def _busy_error() -> dict:
    if any(j["status"] == "running" for j in _JOBS.values()):
        running = next(j["scan_id"] for j in _JOBS.values() if j["status"] == "running")
        return {
            "error": f"a scan is already running (scan_id={running}); "
            "one at a time — poll scan_status until it finishes."
        }
    batch = next((b for b in _BATCHES.values() if b["status"] == "running"), None)
    if batch is not None:
        return {
            "error": f"a batch is already running (batch_id={batch['batch_id']}); "
            "one at a time — poll scan_status until it finishes."
        }
    return {"error": "runway busy; poll scan_status and retry"}


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
    scan_id, or an error dict if a scan/batch is already running."""
    with _LOCK:
        if any(j["status"] == "running" for j in _JOBS.values()) or any(
            b["status"] == "running" for b in _BATCHES.values()
        ):
            return _busy_error()
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


def start_batch(
    targets: list[dict[str, str]],
    max_concurrency: int = 3,
    *,
    _runner: Callable[[list[dict[str, str]], int], list] | None = None,
) -> dict:
    """Kick off a batch of targets on a background thread (SCALE.1 + TASKING.2).

    Returns immediately with a ``batch_id`` — poll ``get_batch`` / MCP
    ``scan_status`` for aggregate progress. ``_runner`` is a test seam defaulting
    to ``core.batch.run_batch``.
    """
    from eidolon.core.batch import run_batch as _default_runner

    run_each = _runner or _default_runner
    with _LOCK:
        if any(j["status"] == "running" for j in _JOBS.values()) or any(
            b["status"] == "running" for b in _BATCHES.values()
        ):
            return _busy_error()
        batch_id = uuid.uuid4().hex[:8]
        _BATCHES[batch_id] = {
            "batch_id": batch_id,
            "status": "running",
            "total": len(targets),
            "scan_ids": None,
            "reports": None,
            "error": None,
        }

    def _work() -> None:
        try:
            states = run_each(targets, max_concurrency)
            scan_ids = [s.run_id for s in states]
            reports = []
            for i, state in enumerate(states):
                from eidolon.core.repository import report_paths

                paths = report_paths(state.run_id)
                reports.append(
                    {
                        "index": i,
                        "scan_id": state.run_id,
                        "report": paths.get("md") or paths.get("json", ""),
                    }
                )
            with _LOCK:
                _BATCHES[batch_id]["status"] = "done"
                _BATCHES[batch_id]["scan_ids"] = scan_ids
                _BATCHES[batch_id]["reports"] = reports
        except Exception as exc:  # never let the thread die silently
            with _LOCK:
                _BATCHES[batch_id]["status"] = "error"
                _BATCHES[batch_id]["error"] = str(exc)

    threading.Thread(target=_work, daemon=True, name=f"batch-{batch_id}").start()
    return {"batch_id": batch_id, "status": "running", "total": len(targets)}


def get_job(scan_id: str) -> Job | None:
    """Current state of a scan job, or None if unknown to this process."""
    with _LOCK:
        job = _JOBS.get(scan_id)
        return cast(Job, dict(job)) if job else None  # copy so callers can't mutate


def get_batch(batch_id: str) -> BatchJob | None:
    """Current aggregate state of a batch, or None if unknown to this process."""
    with _LOCK:
        job = _BATCHES.get(batch_id)
        return (
            cast(BatchJob, dict(job)) if job else None
        )  # copy so callers can't mutate
