"""Report repository — the read seam between callers and stored scans.

Today a scan's artifacts live as files in ``RESULTS_OUTPUT_PATH``
(``{identifier}_{date}_{scan_id}.{json,md,pdf}``), written by report_node. This
module is the *only* place that knows that. When scans move to Postgres (Phase 2),
swap these implementations and every caller (CLI, MCP) is unchanged.

``scan_id`` is the 8-char ``run_id`` minted in intake_node.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from eidolon import config


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


def list_scans() -> list[ScanRef]:
    """All scans on disk, newest first, parsed from ``{id}_{date}_{run}.json``."""
    out = _output_dir()
    if not out.exists():
        return []
    refs: list[ScanRef] = []
    for jp in out.glob("*.json"):
        stem = jp.stem
        parts = stem.rsplit("_", 2)
        if len(parts) != 3:
            continue  # not a scan artifact (e.g. analysis_raw_*.txt siblings)
        identifier, date, scan_id = parts
        paths = report_paths(scan_id)
        refs.append(
            ScanRef(
                scan_id=scan_id,
                identifier=identifier,
                date=date,
                json_path=paths.get("json"),
                md_path=paths.get("md"),
                pdf_path=paths.get("pdf"),
            )
        )
    refs.sort(key=lambda r: (r.date, r.scan_id), reverse=True)
    return refs
