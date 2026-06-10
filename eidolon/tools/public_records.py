"""Public records tool.

Two free, no-auth-required data sources:

1. CourtListener (courtlistener.com)
   - Federal court dockets — PACER alternative, fully open
   - REST v4 API, no API key needed for basic search
   - Returns: case name, docket number, court, dates, nature of suit

2. OpenCorporates (opencorporates.com)
   - Business registrations and officer records across 140+ jurisdictions
   - Free tier: 500 req/month, no key needed for officer/company search
   - Returns: company name, role (director/officer/agent), jurisdiction, status

Both skip gracefully on network failure or empty results.
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class CourtCase(BaseModel):
    case_name: str
    docket_number: str
    court: str
    date_filed: str
    date_terminated: str | None = None
    nature_of_suit: str = ""
    cause: str = ""
    source_url: str = ""


class CorporateRecord(BaseModel):
    company_name: str
    role: str  # director, officer, registered-agent, etc.
    company_number: str = ""
    jurisdiction: str = ""  # us_de, us_ca, gb, etc.
    status: str = ""  # active / inactive / dissolved
    start_date: str = ""
    end_date: str = ""
    source_url: str = ""


class PublicRecordsOutput(BaseModel):
    query: str
    court_cases: list[CourtCase] = []
    corporate_records: list[CorporateRecord] = []
    court_case_count: int = 0
    corporate_record_count: int = 0


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "public_records_response.json"
)

COURTLISTENER_URL = "https://www.courtlistener.com/api/rest/v4/search/"
OPENCORPORATES_OFFICERS_URL = "https://api.opencorporates.com/v0.4/officers/search"

_HEADERS = {
    "User-Agent": "osint-agent/1.0 (privacy research tool; not for commercial use)"
}


def _search_courtlistener(name: str, state: str | None = None) -> list[CourtCase]:
    """Search CourtListener dockets for a person's name.

    Requires COURTLISTENER_API_TOKEN (free — register at courtlistener.com).
    Skips gracefully when token is not set.
    """
    token = config.get("COURTLISTENER_API_TOKEN")
    if not token:
        logger.info(
            "public_records: COURTLISTENER_API_TOKEN not set — skipping "
            "(free token at courtlistener.com)"
        )
        return []

    # type=r = RECAP/PACER federal dockets — searches by party name via full-text index.
    # /dockets/ endpoint is for fetching a specific docket by ID, not name search.
    params: dict[str, str] = {
        "q": f'"{name}"',  # quoted for exact-phrase match
        "type": "r",  # r = RECAP dockets (federal cases)
        "order_by": "score desc",
        "page_size": "10",
    }
    # CourtListener jurisdiction codes: "fd" = federal district, "fb" = bankruptcy
    # Passing state narrows to that state's federal courts
    if state:
        params["court"] = state.lower()  # e.g. "ca" for California federal courts

    headers = {**_HEADERS, "Authorization": f"Token {token}"}

    try:
        resp = requests.get(
            COURTLISTENER_URL,
            params=params,
            headers=headers,
            timeout=20,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception as exc:
        logger.warning("public_records: CourtListener search failed — %s", exc)
        return []

    cases = []
    for item in results:
        # Search API returns court as a string slug (e.g. "cacd"), not a nested object
        court_name = item.get("court") or item.get("court_id") or ""

        cases.append(
            CourtCase(
                case_name=item.get("caseName") or item.get("case_name") or "",
                docket_number=item.get("docketNumber")
                or item.get("docket_number")
                or "",
                court=court_name,
                date_filed=item.get("dateFiled") or item.get("date_filed") or "",
                date_terminated=item.get("dateTerminated")
                or item.get("date_terminated"),
                nature_of_suit=item.get("suitNature")
                or item.get("nature_of_suit")
                or "",
                cause=item.get("cause") or "",
                source_url=(
                    f"https://www.courtlistener.com{item['absolute_url']}"
                    if item.get("absolute_url")
                    else ""
                ),
            )
        )

    logger.info("public_records: CourtListener returned %d cases", len(cases))
    return cases


def _search_opencorporates(name: str) -> list[CorporateRecord]:
    """Search OpenCorporates for officer/director roles under a name.

    Requires OPENCORPORATES_API_KEY (free tier — register at
    opencorporates.com/api_access). Skips gracefully when key is not set.
    """
    api_key = config.get("OPENCORPORATES_API_KEY")
    if not api_key:
        logger.info(
            "public_records: OPENCORPORATES_API_KEY not set — skipping "
            "(free key at opencorporates.com/api_access)"
        )
        return []

    try:
        resp = requests.get(
            OPENCORPORATES_OFFICERS_URL,
            params={"q": name, "per_page": "10", "api_token": api_key},
            headers=_HEADERS,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("results", {}).get("officers") or data.get("officers") or []
    except Exception as exc:
        logger.warning("public_records: OpenCorporates search failed — %s", exc)
        return []

    records = []
    for item in items:
        officer = item.get("officer", item)  # API wraps in {"officer": {...}}
        company = officer.get("company") or {}

        # Normalise jurisdiction: "us_de" → "US/DE"
        raw_jur = (
            company.get("jurisdiction_code") or officer.get("jurisdiction_code") or ""
        )
        jurisdiction = raw_jur.upper().replace("_", "/") if raw_jur else ""

        records.append(
            CorporateRecord(
                company_name=company.get("name") or officer.get("company_name") or "",
                role=officer.get("position") or officer.get("role") or "",
                company_number=company.get("company_number") or "",
                jurisdiction=jurisdiction,
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

    logger.info("public_records: OpenCorporates returned %d records", len(records))
    return records


def run(name: str, state: str | None = None) -> ToolResult:
    """Look up public court and corporate records for a person's name.

    Args:
        name: Full name to search (e.g. "John Smith")
        state: Optional 2-letter state code to narrow court results
    """
    logger.info(
        "public_records: searching for name=%s state=%s", name, state or "(any)"
    )

    if config.is_test_mode():
        import json

        raw = json.loads(FIXTURE_PATH.read_text())
        return ToolResult(**raw)

    # Sanitise name — strip anything that looks like a SQL/URL injection
    clean_name = re.sub(r"[^\w\s\-\.]", "", name).strip()
    if not clean_name:
        logger.warning("public_records: empty name after sanitisation, skipping")
        output = PublicRecordsOutput(query=name)
        return ToolResult(
            success=True,
            tool="public_records",
            input_type="name",
            input_value=name,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    court_cases = _search_courtlistener(clean_name, state)
    corporate_records = _search_opencorporates(clean_name)

    output = PublicRecordsOutput(
        query=clean_name,
        court_cases=court_cases,
        corporate_records=corporate_records,
        court_case_count=len(court_cases),
        corporate_record_count=len(corporate_records),
    )

    logger.info(
        "public_records: OK — court_cases=%d corporate_records=%d",
        output.court_case_count,
        output.corporate_record_count,
    )

    return ToolResult(
        success=True,
        tool="public_records",
        input_type="name",
        input_value=clean_name,
        timestamp=datetime.now(timezone.utc),
        data=output.model_dump(),
    )
