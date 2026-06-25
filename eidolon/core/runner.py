"""The programmatic scan core — one function behind every interface.

``run_scan(...)`` validates inputs, runs the LangGraph pipeline, and returns a
small typed ``ScanResult`` (scan_id + headline risk + report paths). The CLI
(``main.py``) and the MCP server both call it; neither rebuilds the graph or
reaches into pipeline internals.

Input normalization lives here (single source of truth) so the CLI and MCP agree
on what a valid email/phone/name is. The argparse layer in ``main.py`` wraps the
``normalize_*`` functions for its own error type.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from eidolon.core.models import PipelineState

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def normalize_email(value: str) -> str:
    v = (value or "").strip().lower()
    if not _EMAIL_RE.match(v):
        raise ValueError(f"invalid email address: {value!r}")
    return v


def normalize_phone(value: str) -> str:
    digits = re.sub(r"[^\d+]", "", (value or "").strip())
    if len(re.sub(r"\D", "", digits)) < 7:
        raise ValueError(f"phone number too short: {value!r}")
    if not digits.startswith("+"):
        digits = f"+1{digits}" if len(digits) == 10 else f"+{digits}"
    return digits


def normalize_name(value: str) -> str:
    v = " ".join((value or "").strip().split())
    v = re.sub(r"[^\w\s\-']", "", v)
    if len(v) < 2:
        raise ValueError(f"name too short: {value!r}")
    return v


def normalize_city(value: str) -> str:
    v = " ".join((value or "").strip().split())
    v = re.sub(r"[^\w\s\-']", "", v)
    if not v:
        raise ValueError("city cannot be empty")
    return v


def normalize_state(value: str) -> str:
    v = (value or "").strip()
    if not v:
        raise ValueError("state cannot be empty")
    return v


def normalize_zip(value: str) -> str:
    v = re.sub(r"\D", "", (value or "").strip())
    if len(v) not in (5, 9):
        raise ValueError(f"zip code must be 5 or 9 digits: {value!r}")
    return v[:5]


class ScanResult(BaseModel):
    scan_id: str
    identifier: str
    risk_score: int | None = None
    risk_level: str | None = None
    summary: str = ""
    top_risks: list[str] = []
    report_json: str | None = None
    report_md: str | None = None
    report_pdf: str | None = None


def build_raw_input(
    *,
    email: str | None = None,
    phone: str | None = None,
    name: str | None = None,
    city: str | None = None,
    state: str | None = None,
    zip_code: str | None = None,
) -> str:
    """Normalize inputs into the ``type:value`` line format intake_node parses."""
    parts: list[str] = []
    if email:
        parts.append(f"email:{normalize_email(email)}")
    if phone:
        parts.append(f"phone:{normalize_phone(phone)}")
    if name:
        parts.append(f"name:{normalize_name(name)}")
    if city:
        parts.append(f"city:{normalize_city(city)}")
    if state:
        parts.append(f"state:{normalize_state(state)}")
    if zip_code:
        parts.append(f"zip:{normalize_zip(zip_code)}")
    if not any([email, phone, name]):
        raise ValueError("at least one of email, phone, or name is required")
    return "\n".join(parts)


def run_scan(
    *,
    email: str | None = None,
    phone: str | None = None,
    name: str | None = None,
    city: str | None = None,
    state: str | None = None,
    zip_code: str | None = None,
    run_id: str | None = None,
) -> ScanResult:
    """Run a full scan and return its headline result + report paths.

    ``run_id`` may be supplied so a caller (e.g. the async MCP job) knows the
    scan_id before the scan finishes; intake reuses it instead of minting one.

    Blocks until the pipeline finishes (a real scan can take several minutes —
    SpiderFoot alone runs up to ~10). Artifacts are written by report_node; the
    repository locates them by ``scan_id``.
    """
    from eidolon.agent.graph import build_graph
    from eidolon.core.repository import report_paths

    raw_input = build_raw_input(
        email=email,
        phone=phone,
        name=name,
        city=city,
        state=state,
        zip_code=zip_code,
    )

    graph = build_graph()
    final = graph.invoke(PipelineState(raw_input=raw_input, run_id=run_id or ""))
    scan_state = (
        final
        if isinstance(final, PipelineState)
        else PipelineState.model_validate(final)
    )

    analysis = scan_state.analysis_result or {}
    paths = report_paths(scan_state.run_id)
    return ScanResult(
        scan_id=scan_state.run_id,
        identifier=_identifier(scan_state),
        risk_score=analysis.get("overall_risk_score"),
        risk_level=analysis.get("overall_risk_level"),
        summary=analysis.get("identity_summary", ""),
        top_risks=analysis.get("top_risks") or [],
        report_json=paths.get("json"),
        report_md=paths.get("md"),
        report_pdf=paths.get("pdf"),
    )


def _identifier(state: PipelineState) -> str:
    primary = state.classifications[0] if state.classifications else None
    return primary.value if primary else "unknown"
