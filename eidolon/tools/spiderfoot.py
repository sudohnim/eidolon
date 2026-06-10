import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast

import requests
from pydantic import BaseModel, field_validator

from eidolon import config
from eidolon.core.models import ToolResult


class SpiderfootInput(BaseModel):
    target: str
    target_type: Literal["emailaddr", "phone", "human_name", "company_name"]
    modules: list[str] = [
        # Fast API-based modules only. sfp_social/sfp_pastebin do extensive
        # crawling and routinely cause timeouts — social coverage is handled
        # better by Holehe/Blackbird/Maigret. sfp_hunter removed: it makes
        # unauthenticated calls to hunter.io that stall without an API key
        # and contribute to the status="-" queueing delay.
        "sfp_hibp",  # breach cross-check
        "sfp_emailrep",  # email reputation + risk score
        "sfp_gravatar",  # profile photo, display name, linked accounts
        "sfp_pgp",  # PGP key lookup — confirms real identity
        "sfp_whois",  # domain registration info for email domain
    ]


class SpiderfootElement(BaseModel):
    fp: int
    confidence: int
    risk: int
    source: str
    date_found: str
    module: str
    data: str
    type: str

    @field_validator("module", "source", "data", "type", "date_found", mode="before")
    @classmethod
    def coerce_to_str(cls, v: object) -> str:
        """SpiderFoot partial results sometimes return int fields (e.g. module=100).
        Coerce everything to string so validation never fails on numeric values."""
        return str(v) if v is not None else ""


class SpiderfootOutput(BaseModel):
    scan_id: str
    target: str
    status: Literal["FINISHED", "FAILED", "RUNNING", "ABORTED", "PARTIAL"]
    element_count: int
    elements: list[SpiderfootElement]
    duration_seconds: int


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "spiderfoot_response.json"
)

INPUT_TYPE_MAP = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}

POLL_INTERVAL = 10
# Configurable via SPIDERFOOT_TIMEOUT env var (default 600s).
# status="-" means SpiderFoot queued the scan but hasn't started yet —
# this can take 60-120s before the first results appear, so 300s was
# cutting off scans before they even ran. 600s gives a full run window.
POLL_TIMEOUT = int(config.get("SPIDERFOOT_TIMEOUT") or 600)


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: SpiderfootInput) -> ToolResult:
    logger.info("spiderfoot: scanning target_type=%s", inp.target_type)

    if config.is_test_mode():
        return _load_fixture()

    base = config.get("SPIDERFOOT_HOST")
    start_time = time.time()

    # SpiderFoot auto-detects the target type from the value. Human and company
    # names are only recognized when wrapped in double quotes — without them
    # SpiderFoot returns "Unrecognised target type." for a bare name.
    scantarget = inp.target
    if inp.target_type in ("human_name", "company_name") and not (
        scantarget.startswith('"') and scantarget.endswith('"')
    ):
        scantarget = f'"{scantarget}"'

    try:
        scan_resp = requests.post(
            f"{base}/startscan",
            headers={"Accept": "application/json"},
            data={
                "scanname": f"osint-{inp.target_type}-{int(start_time)}",
                "scantarget": scantarget,
                "modulelist": ",".join(inp.modules),
                "typelist": "",
                "usecase": "all",
            },
            timeout=30,
        )
        scan_resp.raise_for_status()
        resp_json = scan_resp.json()
        if isinstance(resp_json, list) and resp_json[0] == "ERROR":
            raise RuntimeError(f"SpiderFoot startscan error: {resp_json[1]}")
        if isinstance(resp_json, list) and resp_json[0] == "SUCCESS":
            scan_id = resp_json[1]
        else:
            raise RuntimeError(f"Unexpected startscan response: {resp_json}")

        timed_out = False
        while True:
            elapsed = time.time() - start_time
            if elapsed > POLL_TIMEOUT:
                # Don't discard 10 minutes of collected data — abort the scan
                # and fetch whatever SpiderFoot found so far
                logger.warning(
                    "spiderfoot: scan %s timed out after %.0fs — "
                    "aborting and fetching partial results",
                    scan_id,
                    elapsed,
                )
                try:
                    requests.get(f"{base}/stopscan", params={"id": scan_id}, timeout=10)
                except Exception:
                    pass
                timed_out = True
                status = "PARTIAL"
                break

            status_resp = requests.get(
                f"{base}/scanstatus",
                params={"id": scan_id},
                headers={"Accept": "application/json"},
                timeout=10,
            )
            status_resp.raise_for_status()
            status_data = status_resp.json()
            # returns [[id, name, target, started, ended, status, ...]]
            status = (
                status_data[0][5]
                if isinstance(status_data, list) and status_data
                else "RUNNING"
            )

            logger.info(
                "spiderfoot: scan %s status=%s elapsed=%.0fs", scan_id, status, elapsed
            )
            if status in ("FINISHED", "FAILED", "ABORTED", "ERROR-FAILED"):
                break
            time.sleep(POLL_INTERVAL)

        results_resp = requests.get(
            f"{base}/scaneventresults",
            params={"id": scan_id},
            headers={"Accept": "application/json"},
            timeout=60,
        )
        results_resp.raise_for_status()
        raw_elements = results_resp.json()

        # SpiderFoot returns rows as arrays:
        # [lastseen, type, data, source_event_type, module, confidence, fp, risk, ...]
        elements = []
        for row in raw_elements:
            if not isinstance(row, list) or len(row) < 8:
                continue
            elements.append(
                SpiderfootElement(
                    date_found=row[0],
                    type=row[1],
                    data=row[2],
                    source=row[3],
                    module=row[4],
                    confidence=int(row[5]) if str(row[5]).isdigit() else 0,
                    fp=int(row[6]) if str(row[6]).isdigit() else 0,
                    risk=int(row[7]) if str(row[7]).isdigit() else 0,
                )
            )
        if timed_out:
            logger.info(
                "spiderfoot: partial results — %d elements collected before timeout",
                len(elements),
            )
        _sf_status = cast(
            Literal["FINISHED", "FAILED", "RUNNING", "ABORTED", "PARTIAL"], status
        )
        output = SpiderfootOutput(
            scan_id=scan_id,
            target=inp.target,
            status=_sf_status,
            element_count=len(elements),
            elements=elements,
            duration_seconds=int(time.time() - start_time),
        )
        _input_type = cast(
            Literal["email", "phone", "name", "org"],
            next(k for k, v in INPUT_TYPE_MAP.items() if v == inp.target_type),
        )
        return ToolResult(
            success=True,
            tool="spiderfoot",
            input_type=_input_type,
            input_value=inp.target,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("spiderfoot: FAILED — %s", exc, exc_info=True)
        _err_input_type = cast(
            Literal["email", "phone", "name", "org"],
            next(
                (k for k, v in INPUT_TYPE_MAP.items() if v == inp.target_type), "email"
            ),
        )
        return ToolResult(
            success=False,
            tool="spiderfoot",
            input_type=_err_input_type,
            input_value=inp.target,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"SpiderFoot error: {exc}",
        )
