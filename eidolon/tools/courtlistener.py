"""CourtListener — federal court docket search (courtlistener.com).

REST v4 API. Requires a free COURTLISTENER_API_TOKEN. Returns case name, docket
number, court, dates, and nature of suit for a person's name.
"""

import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.tools.base import Tool

COURTLISTENER_URL = "https://www.courtlistener.com/api/rest/v4/search/"
_HEADERS = {"User-Agent": "eidolon/1.0 (privacy research tool; not for commercial use)"}


class CourtCase(BaseModel):
    case_name: str
    docket_number: str
    court: str
    date_filed: str
    date_terminated: str | None = None
    nature_of_suit: str = ""
    cause: str = ""
    source_url: str = ""


class CourtListenerInput(BaseModel):
    name: str
    state: str | None = None


class CourtListenerOutput(BaseModel):
    cases: list[CourtCase] = []
    count: int = 0


class CourtListener(Tool[CourtListenerInput, CourtListenerOutput]):
    name = "courtlistener"
    requires = ["COURTLISTENER_API_TOKEN"]
    input_type = "name"
    input_schema = CourtListenerInput
    output_schema = CourtListenerOutput

    def available(self) -> bool:
        return bool(config.get("COURTLISTENER_API_TOKEN"))

    def _input_value(self, inp: CourtListenerInput) -> str:
        return inp.name

    def _run(
        self, inp: CourtListenerInput, log: structlog.stdlib.BoundLogger
    ) -> CourtListenerOutput:
        import requests

        token = config.get("COURTLISTENER_API_TOKEN")
        # type=r = RECAP/PACER federal dockets — searches by party name via the
        # full-text index. /dockets/ fetches a docket by ID, not a name search.
        params: dict[str, str] = {
            "q": f'"{inp.name}"',  # quoted for exact-phrase match
            "type": "r",
            "order_by": "score desc",
            "page_size": "10",
        }
        if inp.state:
            params["court"] = inp.state.lower()  # e.g. "ca" for CA federal courts

        resp = requests.get(
            COURTLISTENER_URL,
            params=params,
            headers={**_HEADERS, "Authorization": f"Token {token}"},
            timeout=20,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])

        cases = [
            CourtCase(
                case_name=item.get("caseName") or item.get("case_name") or "",
                docket_number=(
                    item.get("docketNumber") or item.get("docket_number") or ""
                ),
                court=item.get("court") or item.get("court_id") or "",
                date_filed=item.get("dateFiled") or item.get("date_filed") or "",
                date_terminated=(
                    item.get("dateTerminated") or item.get("date_terminated")
                ),
                nature_of_suit=(
                    item.get("suitNature") or item.get("nature_of_suit") or ""
                ),
                cause=item.get("cause") or "",
                source_url=(
                    f"https://www.courtlistener.com{item['absolute_url']}"
                    if item.get("absolute_url")
                    else ""
                ),
            )
            for item in results
        ]
        log.info("ok", cases=len(cases))
        return CourtListenerOutput(cases=cases, count=len(cases))
