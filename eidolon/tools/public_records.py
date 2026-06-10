"""Public records aggregation.

CourtListener (federal court dockets) and OpenCorporates (officer records) are
two independent vendor tools. ``lookup`` runs both and combines them into a
single public_records ToolResult for the pipeline — the node-level aggregation
for this multi-vendor source.
"""

import re
from datetime import datetime, timezone

from pydantic import BaseModel

from eidolon.core.models import ToolResult
from eidolon.tools.base import run_to_result
from eidolon.tools.courtlistener import CourtCase, CourtListener, CourtListenerInput
from eidolon.tools.opencorporates import (
    CorporateRecord,
    OpenCorporates,
    OpenCorporatesInput,
)


class PublicRecordsOutput(BaseModel):
    query: str = ""
    court_cases: list[CourtCase] = []
    corporate_records: list[CorporateRecord] = []
    court_case_count: int = 0
    corporate_record_count: int = 0


def lookup(name: str, state: str | None = None) -> ToolResult:
    """Run CourtListener + OpenCorporates and combine into one ToolResult.

    Each vendor degrades independently — a failure in one still yields the
    other's results.
    """
    # Sanitise name — strip anything that looks like SQL/URL injection
    clean = re.sub(r"[^\w\s\-.]", "", name).strip()

    court = run_to_result(CourtListener(), CourtListenerInput(name=clean, state=state))
    corp = run_to_result(OpenCorporates(), OpenCorporatesInput(name=clean))

    cases = court.data.get("cases", []) if court.success else []
    records = corp.data.get("records", []) if corp.success else []

    out = PublicRecordsOutput(
        query=clean,
        court_cases=cases,
        corporate_records=records,
        court_case_count=len(cases),
        corporate_record_count=len(records),
    )
    return ToolResult(
        success=True,
        tool="public_records",
        input_type="name",
        input_value=clean,
        timestamp=datetime.now(timezone.utc),
        data=out.model_dump(),
    )
