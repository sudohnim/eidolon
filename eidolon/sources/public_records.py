"""Public records aggregation.

CourtListener (federal court dockets) and OpenCorporates (officer records) are
two independent vendor tools. ``PublicRecords`` (the Tool) runs both and
combines them into a single public_records source — each vendor degrades
independently, a failure in one still yields the other's results. ``lookup``
is a backward-compatible wrapper returning the ToolResult envelope.
"""

import re

import structlog
from pydantic import BaseModel

from eidolon.core.findings import (
    Confidence,
)
from eidolon.core.findings import CorporateRecord as CorporateRecordFinding
from eidolon.core.findings import (
    CourtRecord,
    Finding,
    Severity,
)
from eidolon.core.logging import get_logger
from eidolon.core.state import ToolResult
from eidolon.sources.base import Tool, run_to_result
from eidolon.sources.courtlistener import CourtCase, CourtListener, CourtListenerInput
from eidolon.sources.opencorporates import (
    CorporateRecord,
    OpenCorporates,
    OpenCorporatesInput,
)


class PublicRecordsInput(BaseModel):
    name: str
    state: str | None = None


class PublicRecordsOutput(BaseModel):
    query: str = ""
    court_cases: list[CourtCase] = []
    corporate_records: list[CorporateRecord] = []
    court_case_count: int = 0
    corporate_record_count: int = 0


class PublicRecords(Tool[PublicRecordsInput, PublicRecordsOutput]):
    """Composite source: CourtListener dockets + OpenCorporates roles."""

    name = "public_records"
    input_schema = PublicRecordsInput
    output_schema = PublicRecordsOutput
    input_type = "name"
    #: multi-vendor composite (courtlistener.com + opencorporates.com)
    vendor = ""

    def run(self, inp: PublicRecordsInput) -> PublicRecordsOutput:
        # Composite: no single fixture — each vendor loads its own in TEST_MODE.
        log = get_logger(f"eidolon.sources.{self.name}").bind(tool=self.name)
        return self._run(inp, log)

    def _input_value(self, inp: PublicRecordsInput) -> str:
        return inp.name

    def _run(
        self, inp: PublicRecordsInput, log: structlog.stdlib.BoundLogger
    ) -> PublicRecordsOutput:
        # Sanitise name — strip anything that looks like SQL/URL injection
        clean = re.sub(r"[^\w\s\-.]", "", inp.name).strip()

        cases: list[CourtCase] = []
        records: list[CorporateRecord] = []
        # Each vendor degrades independently — a failure in one still yields
        # the other's results.
        try:
            court = CourtListener().run(CourtListenerInput(name=clean, state=inp.state))
            cases = list(court.cases)
        except Exception as exc:
            log.warning(
                "courtlistener failed — degrading independently", error=str(exc)
            )
        try:
            corp = OpenCorporates().run(OpenCorporatesInput(name=clean))
            records = list(corp.records)
        except Exception as exc:
            log.warning(
                "opencorporates failed — degrading independently", error=str(exc)
            )

        return PublicRecordsOutput(
            query=clean,
            court_cases=cases,
            corporate_records=records,
            court_case_count=len(cases),
            corporate_record_count=len(records),
        )

    def to_findings(self, out: PublicRecordsOutput) -> list[Finding]:
        """CourtRecord per case + CorporateRecord per company role — public
        record facts, INFO severity (presence, not exposure)."""
        findings: list[Finding] = [
            CourtRecord(
                confidence=Confidence.UNVERIFIED,
                dedup_key=f"court:{c.case_name}:{c.docket_number}",
                title=c.case_name,
                severity=Severity.INFO,
                case_name=c.case_name,
                court=c.court,
                date_filed=c.date_filed,
                nature_of_suit=c.nature_of_suit,
            )
            for c in out.court_cases
            if c.case_name
        ]
        findings += [
            CorporateRecordFinding(
                # officer search matches on name only — namesake-prone
                confidence=Confidence.UNVERIFIED,
                dedup_key=f"corp:{r.company_name}:{r.company_number}",
                title=r.company_name,
                severity=Severity.INFO,
                company_name=r.company_name,
                role=r.role,
                jurisdiction=r.jurisdiction,
                status=r.status,
            )
            for r in out.corporate_records
            if r.company_name
        ]
        return findings

    def run_summary(self, out: PublicRecordsOutput) -> str:
        if not (out.court_case_count or out.corporate_record_count):
            return ""
        return (
            f"{out.court_case_count} court cases, "
            f"{out.corporate_record_count} corporate records"
        )


def lookup(name: str, state: str | None = None) -> ToolResult:
    """Backward-compatible envelope wrapper over ``PublicRecords``."""
    return run_to_result(PublicRecords(), PublicRecordsInput(name=name, state=state))
