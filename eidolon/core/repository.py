"""Report repository — the read seam between callers and stored scans.

Today a scan's artifacts live as files in ``RESULTS_OUTPUT_PATH``
(``{identifier}_{date}_{scan_id}.{json,md,pdf}``), written by report_node. This
module is the *only* place that knows that. When scans move to Postgres (Phase 2),
swap these implementations and every caller (CLI, MCP) is unchanged.

``scan_id`` is the 8-char ``run_id`` minted in intake_node.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from eidolon import config

# Identifier preference, mirrors report._build_identifier (email > phone > name > org).
_IDENTIFIER_PRIORITY = ("email", "phone", "name", "org")


class ScanRef(BaseModel):
    scan_id: str
    identifier: str
    date: str
    json_path: str | None = None
    md_path: str | None = None
    pdf_path: str | None = None


def _output_dir() -> Path:
    return Path(config.get("RESULTS_OUTPUT_PATH"))


def report_paths(scan_id: str) -> dict[str, str]:
    """{ext: path} for the artifacts of a scan, by ``scan_id`` (run_id)."""
    out = _output_dir()
    paths: dict[str, str] = {}
    if not scan_id or not out.exists():
        return paths
    for ext in ("json", "md", "pdf"):
        matches = sorted(out.glob(f"*_{scan_id}.{ext}"))
        if matches:
            paths[ext] = str(matches[-1])
    return paths


def get_report(scan_id: str, fmt: str = "md") -> str:
    """Return a rendered report's contents. ``fmt`` is ``md`` or ``json``.

    For ``pdf`` there's nothing to return as text — use ``report_paths`` for the
    file path. Raises FileNotFoundError if the scan/format isn't present.
    """
    if fmt not in ("md", "json"):
        raise ValueError(f"fmt must be 'md' or 'json', got {fmt!r}")
    paths = report_paths(scan_id)
    path = paths.get(fmt)
    if not path:
        raise FileNotFoundError(f"no {fmt} report for scan {scan_id!r}")
    return Path(path).read_text()


def load_scan_state(scan_id: str) -> dict:
    """The full persisted PipelineState dump for a scan (the ``.json``)."""
    return json.loads(get_report(scan_id, "json"))


def _best_identifier(classifications: list) -> str:
    """The real (pre-sanitization) target identifier from the scan's own data,
    same email > phone > name > org preference the filename used to encode."""
    by_type: dict[str, str] = {}
    for c in classifications:
        if isinstance(c, dict) and c.get("type") and c.get("value"):
            by_type.setdefault(str(c["type"]), str(c["value"]))
    for kind in _IDENTIFIER_PRIORITY:
        if by_type.get(kind):
            return by_type[kind]
    return "unknown"


def list_scans() -> list[ScanRef]:
    """All scans on disk, newest first.

    The index is derived from each artifact's JSON *content* — the persisted
    ``run_id`` and ``classifications`` are authoritative — not parsed out of the
    filename. So an identifier containing underscores lists correctly, and a
    non-scan or corrupt ``.json`` sitting in the output dir is skipped, never
    fatal. The filename is treated as an opaque handle (``report_paths`` locates
    the siblings by ``scan_id``). Ordered by file mtime, newest first.
    """
    out = _output_dir()
    if not out.exists():
        return []
    dated: list[tuple[float, ScanRef]] = []
    for jp in out.glob("*.json"):
        try:
            data = json.loads(jp.read_text())
        except (json.JSONDecodeError, OSError, ValueError):
            continue  # unreadable / not JSON — not a scan artifact
        if not isinstance(data, dict) or not data.get("run_id"):
            continue  # not a scan-state dump
        scan_id = str(data["run_id"])
        mtime = jp.stat().st_mtime
        paths = report_paths(scan_id)
        dated.append(
            (
                mtime,
                ScanRef(
                    scan_id=scan_id,
                    identifier=_best_identifier(data.get("classifications") or []),
                    date=datetime.fromtimestamp(mtime).strftime("%Y-%m-%d"),
                    json_path=paths.get("json") or str(jp),
                    md_path=paths.get("md"),
                    pdf_path=paths.get("pdf"),
                ),
            )
        )
    dated.sort(key=lambda t: t[0], reverse=True)
    return [ref for _, ref in dated]
