import hashlib
import logging
import time
from typing import Literal, cast

import httpx
import structlog
from pydantic import BaseModel, field_validator

from eidolon import config
from eidolon.core.findings import Finding, Severity
from eidolon.core.state import InputType
from eidolon.sources._http import client
from eidolon.sources.base import Tool


class SpiderfootInput(BaseModel):
    target: str
    target_type: Literal["emailaddr", "phone", "human_name", "company_name"]
    modules: list[str] = [
        "sfp_hibp",
        "sfp_emailrep",
        "sfp_gravatar",
        "sfp_pgp",
        "sfp_whois",
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
        return str(v) if v is not None else ""


class SpiderfootOutput(BaseModel):
    scan_id: str = ""
    target: str = ""
    status: Literal["FINISHED", "FAILED", "RUNNING", "ABORTED", "PARTIAL"] = "FAILED"
    element_count: int = 0
    elements: list[SpiderfootElement] = []
    duration_seconds: int = 0


logger = logging.getLogger(__name__)

INPUT_TYPE_MAP = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}

POLL_INTERVAL = 10
POLL_TIMEOUT = int(config.get("SPIDERFOOT_TIMEOUT") or 600)


class Spiderfoot(Tool[SpiderfootInput, SpiderfootOutput]):
    name = "spiderfoot"
    input_schema = SpiderfootInput
    output_schema = SpiderfootOutput

    def _input_type(self, inp: SpiderfootInput) -> InputType:
        return cast(
            InputType,
            next(
                (k for k, v in INPUT_TYPE_MAP.items() if v == inp.target_type),
                "email",
            ),
        )

    def _input_value(self, inp: SpiderfootInput) -> str:
        return inp.target

    def to_findings(self, out: SpiderfootOutput) -> list[Finding]:
        findings: list[Finding] = []
        for el in out.elements:
            value = (el.data or "").strip()
            if not value:
                continue
            etype = el.type or "UNKNOWN"
            findings.append(
                Finding(
                    kind="footprint_element",
                    dedup_key=(
                        f"sf:{etype}:"
                        f"{hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]}"
                    ),
                    title=value,
                    severity=Severity.INFO,
                    payload={"element_type": etype, "value": value},
                )
            )
        return findings

    def run_summary(self, out: SpiderfootOutput) -> str:
        return f"{out.element_count} elements"

    def _run(
        self, inp: SpiderfootInput, log: structlog.stdlib.BoundLogger
    ) -> SpiderfootOutput:
        base = config.get("SPIDERFOOT_HOST")
        start_time = time.time()

        scantarget = inp.target
        if inp.target_type in ("human_name", "company_name") and not (
            scantarget.startswith('"') and scantarget.endswith('"')
        ):
            scantarget = f'"{scantarget}"'

        with client(
            timeout=httpx.Timeout(connect=5.0, read=60.0, write=60.0, pool=10.0)
        ) as http:
            scan_resp = http.post(
                f"{base}/startscan",
                headers={"Accept": "application/json"},
                data={
                    "scanname": f"osint-{inp.target_type}-{int(start_time)}",
                    "scantarget": scantarget,
                    "modulelist": ",".join(inp.modules),
                    "typelist": "",
                    "usecase": "all",
                },
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
                logger.warning(
                    "spiderfoot: scan %s timed out after %.0fs — "
                    "aborting and fetching partial results",
                    scan_id,
                    elapsed,
                )
                try:
                    with client(
                        timeout=httpx.Timeout(
                            connect=5.0, read=10.0, write=10.0, pool=10.0
                        )
                    ) as http:
                        http.get(f"{base}/stopscan", params={"id": scan_id})
                except Exception:
                    pass
                timed_out = True
                status = "PARTIAL"
                break

            with client(
                timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=10.0)
            ) as http:
                status_resp = http.get(
                    f"{base}/scanstatus",
                    params={"id": scan_id},
                    headers={"Accept": "application/json"},
                )
            status_resp.raise_for_status()
            status_data = status_resp.json()
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

        with client(
            timeout=httpx.Timeout(connect=5.0, read=60.0, write=60.0, pool=10.0)
        ) as http:
            results_resp = http.get(
                f"{base}/scaneventresults",
                params={"id": scan_id},
                headers={"Accept": "application/json"},
            )
        results_resp.raise_for_status()
        raw_elements = results_resp.json()

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
        return SpiderfootOutput(
            scan_id=scan_id,
            target=inp.target,
            status=_sf_status,
            element_count=len(elements),
            elements=elements,
            duration_seconds=int(time.time() - start_time),
        )
