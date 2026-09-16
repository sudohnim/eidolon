"""The report package (REFACTOR.3): content defined once, laid out thrice.

``write_report(state)`` is the pipeline entry point: it persists the
scan artifacts — the state dump (``.json``, the repository/MCP reload path),
the markdown report (``.md``), and the PDF (``.pdf``) — and returns the
markdown path.

The content itself is derived once into a ``ReportModel`` (``model.py``);
``markdown`` / ``pdf`` / ``json`` only lay the model out, so the renderers
cannot drift apart — pinned by the renderer-parity test.
"""

from __future__ import annotations

# stdlib json, aliased: importing the `eidolon.report.json` submodule below
# rebinds the package-level `json` attribute to that submodule, which would
# otherwise shadow this binding (json.dumps -> AttributeError).
import json as _stdlib_json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path

from eidolon import config
from eidolon.core.state import PipelineState
from eidolon.report.json import render_json
from eidolon.report.markdown import render_markdown
from eidolon.report.model import ReportModel, build_report_model  # noqa: F401
from eidolon.report.pdf import render_pdf

logger = logging.getLogger(__name__)

__all__ = [
    "build_report_model",
    "dossier_lines",
    "render_markdown",
    "render_pdf",
    "render_json",
    "write_report",
]


def _build_identifier(state: PipelineState) -> str:
    """Pick the best identifier for the filename (email > phone > name > org)."""
    priority = ["email", "phone", "name", "org"]
    classifications_by_type = {c.type: c for c in state.classifications}
    for kind in priority:
        if kind in classifications_by_type:
            value = classifications_by_type[kind].value
            safe = re.sub(r"[^\w.\-]", "_", value)
            safe = re.sub(r"_+", "_", safe).strip("_")
            return safe
    return "unknown"


def dossier_lines(state: PipelineState) -> list[str]:
    """The leaked-credentials dossier as markdown lines (the reveal surface).

    This is the gated path MCP ``reveal_credentials`` calls — the only caller
    of ``DossierRecord.display()`` outside the renderers. Returns [] when the
    scan surfaced no leaked credentials.
    """
    model = build_report_model(state)
    if model.dossier is None or not model.dossier.groups:
        return []
    n = sum(len(g.records) for g in model.dossier.groups)
    intro = (
        "_Actual records found in breach dumps for this exact mailbox — "
        f"{n} record(s) across {len(model.dossier.groups)} source(s). "
        "Passwords are shown exactly as they leaked._"
    )
    lines = ["---", "", "## Your Actual Leaked Data", "", intro, ""]
    for group in model.dossier.groups:
        lines += (
            [f"### {group.source}", ""]
            + [f"- {rec.display(reveal=True)}" for rec in group.records]
            + [""]
        )
    return lines


def write_report(state: PipelineState) -> str:
    """Write the scan's artifacts and return the markdown report path."""
    output_dir = Path(config.get("RESULTS_OUTPUT_PATH"))
    output_dir.mkdir(parents=True, exist_ok=True)

    identifier = _build_identifier(state)
    date_str = datetime.now().strftime("%Y-%m-%d")
    # Reuse the run_id bound at intake so logs and the report filename match.
    run_id = state.run_id or uuid.uuid4().hex[:8]
    base_name = f"{identifier}_{date_str}_{run_id}"

    json_path = output_dir / f"{base_name}.json"
    md_path = output_dir / f"{base_name}.md"
    pdf_path = output_dir / f"{base_name}.pdf"

    # The persisted state artifact (the repository/MCP reload path reads this).
    json_path.write_text(_stdlib_json.dumps(state.model_dump(), indent=2, default=str))

    model = build_report_model(state, results_json_path=str(json_path))

    md_content = render_markdown(model)
    md_path.write_text(md_content)

    try:
        render_pdf(model, pdf_path)
        logger.info("PDF written to %s", pdf_path)
    except Exception as exc:
        logger.warning("PDF generation failed: %s", exc)
        pdf_path = None

    print(md_content)
    print(f"\nFull results saved to: {json_path}")
    print(f"Report saved to:       {md_path}")
    if pdf_path:
        print(f"PDF saved to:          {pdf_path}")

    logger.info("report written to %s", md_path)
    return str(md_path)
