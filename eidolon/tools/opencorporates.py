"""OpenCorporates — officer/director records (opencorporates.com).

Business registrations across 140+ jurisdictions. Requires a free
OPENCORPORATES_API_KEY. Returns company name, role, jurisdiction, and status
for a person's name.
"""

import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.tools.base import Tool

OPENCORPORATES_OFFICERS_URL = "https://api.opencorporates.com/v0.4/officers/search"
_HEADERS = {"User-Agent": "eidolon/1.0 (privacy research tool; not for commercial use)"}


class CorporateRecord(BaseModel):
    company_name: str
    role: str  # director, officer, registered-agent, etc.
    company_number: str = ""
    jurisdiction: str = ""  # us_de, us_ca, gb, etc.
    status: str = ""  # active / inactive / dissolved
    start_date: str = ""
    end_date: str = ""
    source_url: str = ""


class OpenCorporatesInput(BaseModel):
    name: str


class OpenCorporatesOutput(BaseModel):
    records: list[CorporateRecord] = []
    count: int = 0


class OpenCorporates(Tool[OpenCorporatesInput, OpenCorporatesOutput]):
    name = "opencorporates"
    input_type = "name"
    input_schema = OpenCorporatesInput
    output_schema = OpenCorporatesOutput

    def available(self) -> bool:
        return bool(config.get("OPENCORPORATES_API_KEY"))

    def _input_value(self, inp: OpenCorporatesInput) -> str:
        return inp.name

    def _run(
        self, inp: OpenCorporatesInput, log: structlog.stdlib.BoundLogger
    ) -> OpenCorporatesOutput:
        import requests

        api_key = config.get("OPENCORPORATES_API_KEY")
        resp = requests.get(
            OPENCORPORATES_OFFICERS_URL,
            params={"q": inp.name, "per_page": "10", "api_token": api_key},
            headers=_HEADERS,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("results", {}).get("officers") or data.get("officers") or []

        records = []
        for item in items:
            officer = item.get("officer", item)  # API wraps in {"officer": {...}}
            company = officer.get("company") or {}
            raw_jur = (
                company.get("jurisdiction_code")
                or officer.get("jurisdiction_code")
                or ""
            )
            records.append(
                CorporateRecord(
                    company_name=(
                        company.get("name") or officer.get("company_name") or ""
                    ),
                    role=officer.get("position") or officer.get("role") or "",
                    company_number=company.get("company_number") or "",
                    # Normalise jurisdiction: "us_de" → "US/DE"
                    jurisdiction=raw_jur.upper().replace("_", "/") if raw_jur else "",
                    status=company.get("current_status") or "",
                    start_date=officer.get("start_date") or "",
                    end_date=officer.get("end_date") or "",
                    source_url=(
                        f"https://opencorporates.com{officer['opencorporates_url']}"
                        if officer.get("opencorporates_url")
                        else ""
                    ),
                )
            )
        log.info("ok", records=len(records))
        return OpenCorporatesOutput(records=records, count=len(records))
