"""Eidolon MCP server (Phase 1 — stateless).

Exposes a *small* high-level surface over the same `run_scan` core the CLI uses,
so any MCP client (Claude Desktop / Code, or a local-model agent) can drive a
scan and read results. No database: reads go through the report repository, which
today is files and tomorrow is Postgres — the tool contract won't change.

Privacy posture — redact by default:
  - ``scan_target`` / ``get_report`` never include the plaintext-password dossier.
  - ``reveal_credentials`` is the explicit, separate gate that returns it.
So the sensitive data only crosses to the LLM client when deliberately requested.

Transport: stdio (``python -m eidolon.mcp``). The same image can later serve
HTTP for the managed/background tier without changing these tools.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from eidolon.core import jobs, repository
from eidolon.core.authorization import Authorization

mcp = FastMCP("eidolon")


def _authorization(authorized_by: str, reason: str) -> Authorization | None:
    """Build an Authorization from the required MCP args, or None if either is
    empty (the caller returns _authorization_error)."""
    try:
        return Authorization(operator=authorized_by, reason=reason)
    except ValueError:
        return None


def _authorization_error() -> dict:
    return {
        "status": "error",
        "error": (
            "authorization required: pass a non-empty authorized_by (operator) "
            "and reason. A scan targets a real person and is written to the audit log."
        ),
    }


@mcp.tool()
def scan_target(
    authorized_by: str,
    reason: str,
    email: str | None = None,
    phone: str | None = None,
    name: str | None = None,
    city: str | None = None,
    state: str | None = None,
    zip_code: str | None = None,
) -> dict:
    """Start a privacy-OSINT scan. Returns immediately with a scan_id.

    ``authorized_by`` (the operator) and ``reason`` (why this target is being
    scanned) are REQUIRED — a scan targets a real person, so every scan is
    attributable and written to an append-only audit log. Both must be non-empty.

    The scan runs in the background and takes several minutes. Poll
    scan_status(scan_id) until it reports "done", then call get_report(scan_id).
    Only one scan runs at a time. Provide at least one of email / phone / name
    (name works best with a city/state). Leaked credentials are never in the
    headline result — use reveal_credentials(scan_id) for those.
    """
    auth = _authorization(authorized_by, reason)
    if auth is None:
        return _authorization_error()
    return jobs.start_scan(
        email=email,
        phone=phone,
        name=name,
        city=city,
        state=state,
        zip_code=zip_code,
        authorization=auth,
    )


@mcp.tool()
def scan_batch(
    authorized_by: str,
    reason: str,
    targets: list[dict[str, str]],
    max_concurrency: int = 3,
) -> dict:
    """Start a batch of privacy-OSINT scans (SCALE.1). Returns immediately with
    a batch_id.

    ``authorized_by`` (operator) and ``reason`` are REQUIRED and cover the whole
    batch; each target's scan is audit-logged individually.

    Each target is a dict with keys email / phone / name / city / state /
    zip_code (at least one of email/phone/name; name needs a city/state/zip).
    Only one scan OR batch runs at a time — poll scan_status(batch_id) until it
    reports "done" (aggregate: total / done / report paths per child), then read
    each child with get_report(scan_id).
    """
    auth = _authorization(authorized_by, reason)
    if auth is None:
        return _authorization_error()
    return jobs.start_batch(targets, max_concurrency, authorization=auth)


@mcp.tool()
def scan_status(scan_id: str) -> dict:
    """Check a scan or batch started by a scan_* tool: status is
    running | done | error.

    For a single target scan: when done, includes the headline result (risk,
    summary, top risks, report paths) and which sources were skipped because no
    API token was configured. For a batch id, aggregates child scans: total /
    done / error counts plus each child's scan_id and report path when done.
    Then call get_report(scan_id).
    """
    batch = jobs.get_batch(scan_id)
    if batch is not None:
        return _batch_status(batch)
    job = jobs.get_job(scan_id)
    if job is None:
        # Unknown to this process (e.g. the server restarted) — recover from disk.
        if repository.report_paths(scan_id):
            return {
                "scan_id": scan_id,
                "status": "done",
                "skipped_sources": _skipped_sources(scan_id),
                "note": "recovered from a saved report (not tracked in memory)",
            }
        return {
            "scan_id": scan_id,
            "status": "unknown",
            "error": "no such scan in this server",
        }
    out: dict = {"scan_id": scan_id, "status": job["status"]}
    if job["status"] == "done":
        out["result"] = job["result"]
        out["skipped_sources"] = _skipped_sources(scan_id)
    elif job["status"] == "error":
        out["error"] = job["error"]
    return out


def _batch_status(batch: jobs.BatchJob) -> dict:
    """Aggregate view of a batch job for scan_status (TASKING.2)."""
    out: dict = {"batch_id": batch["batch_id"], "status": batch["status"]}
    if batch["status"] == "running":
        out["total"] = batch["total"]
        out["done"] = 0
        out["error"] = "still running"
    elif batch["status"] == "error":
        out["error"] = batch["error"]
    elif batch["status"] == "done":
        scans = batch["scan_ids"] or []
        reports = batch["reports"] or []
        out["total"] = batch["total"]
        out["done"] = len(scans)
        out["error"] = 0
        out["scan_ids"] = scans
        out["reports"] = reports
    return out


def _skipped_sources(scan_id: str) -> list[str]:
    """Sources that were not checked (no token), read from the saved scan state.

    New artifacts carry the typed ``results`` envelope — read it through the
    domain API. Old (pre-Finding-domain) artifacts fall back to scanning the
    legacy ``*_result`` entries.
    """
    from eidolon.core.state import ScanState

    try:
        data = repository.load_scan_state(scan_id)
    except Exception:
        return []
    if data.get("results"):
        state = ScanState.model_validate(data)
        return [
            f"{c.name}: {c.detail or 'not checked'}"
            for c in state.coverage()
            if c.status == "skipped"
        ]
    return [
        f"{val.get('tool', key)}: {val.get('error', 'not checked')}"
        for key, val in data.items()
        if isinstance(val, dict) and val.get("status") == "skipped"
    ]


@mcp.tool()
def list_scans() -> list[dict]:
    """List previously run scans (newest first): scan_id, identifier, date, paths."""
    return [ref.model_dump() for ref in repository.list_scans()]


@mcp.tool()
def get_report(scan_id: str, fmt: str = "md") -> str:
    """Return a scan's report. ``fmt`` is 'md' (default) or 'json'.

    The markdown is returned with the leaked-credentials section removed; call
    reveal_credentials(scan_id) to see those.
    """
    content = repository.get_report(scan_id, fmt)
    if fmt == "md":
        return _strip_dossier(content)
    return content


@mcp.tool()
def reveal_credentials(scan_id: str) -> str:
    """Return the leaked-credentials dossier for a scan (plaintext passwords).

    This is the explicit gate for the most sensitive output — only call it when
    the user has clearly asked to see the actual leaked credentials.
    """
    from eidolon.core.state import ScanState
    from eidolon.report import dossier_lines

    state = ScanState.model_validate(repository.load_scan_state(scan_id))
    lines = dossier_lines(state)
    if not lines:
        return f"No leaked credentials on record for scan {scan_id}."
    return "\n".join(lines)


@mcp.tool()
def get_evidence(scan_id: str, source: str | None = None) -> dict:
    """Return per-source provenance for a scan (EVIDENCE.3).

    Operator/audit surface: for each ran source, the tool version, vendor host,
    latency, the sha256 of the raw response (replayable), whether the request
    egressed via a proxy, and the source's status/reason. Optional ``source``
    filters to one source name. Never contains the target's harvested data —
    provenance only.
    """
    from eidolon.core.state import ScanState

    try:
        state = ScanState.model_validate(repository.load_scan_state(scan_id))
    except Exception as exc:
        return {"scan_id": scan_id, "error": f"cannot load scan state: {exc}"}

    rows = []
    for name, sr in state.results.items():
        if source and name != source:
            continue
        ev = sr.evidence
        rows.append(
            {
                "source": name,
                "status": sr.status,
                "detail": sr.detail,
                "tool_version": ev.tool_version if ev else "",
                "source_host": ev.source_host if ev else "",
                "latency_ms": ev.latency_ms if ev else 0,
                "response_sha256": ev.response_sha256 if ev else "",
                "egress_proxied": bool(ev.egress_proxied) if ev else False,
            }
        )
    return {"scan_id": scan_id, "sources": rows}


def _strip_dossier(md: str) -> str:
    """Remove the leaked-data dossier section from a rendered markdown report.

    Keep this heading in sync with report.py's dossier heading.
    """
    lines = md.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.strip() == "## Your Actual Leaked Data"),
        None,
    )
    if start is None:
        return md
    # absorb the '---' separator that precedes the heading
    cut = start
    j = start - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j >= 0 and lines[j].strip() == "---":
        cut = j
    # the section runs until the next H2
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    notice = [
        "",
        "_Leaked credentials hidden. Call reveal_credentials(scan_id) to view._",
        "",
    ]
    return "\n".join(lines[:cut] + notice + lines[end:])
