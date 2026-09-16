"""JSON layout for a ReportModel (REFACTOR.3).

Dumb renderer: the model serialized as structured JSON — sections, not
prose. Note this is distinct from the scan's persisted state artifact (the
``{id}_{date}_{run}.json`` state dump the repository/MCP reload path reads);
that artifact is written by ``write_report`` alongside this renderer's output.
"""

from __future__ import annotations

import json

from eidolon.report.model import ReportModel


def render_json(model: ReportModel) -> str:
    """The model as pretty-printed JSON."""
    return json.dumps(model.model_dump(mode="json"), indent=2)
