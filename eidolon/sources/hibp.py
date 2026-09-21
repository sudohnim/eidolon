import time
from datetime import date
from typing import Literal

import httpx
import structlog
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_pascal

from eidolon import config
from eidolon.core.findings import Breach, Confidence, Finding, Severity
from eidolon.core.state import InputType
from eidolon.sources._http import client
from eidolon.sources.base import Tool


class HibpInput(BaseModel):
    input_type: Literal["email", "phone"]
    value: str


class BreachRecord(BaseModel):
    model_config = ConfigDict(alias_generator=to_pascal, populate_by_name=True)

    name: str
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    added_date: str = ""
    modified_date: str = ""
    pwn_count: int = 0
    description: str = ""
    logo_path: str = ""
    data_classes: list[str] = []
    is_verified: bool = False
    is_fabricated: bool = False
    is_sensitive: bool = False
    is_retired: bool = False
    is_spam_list: bool = False
    is_malware: bool = False


class HibpOutput(BaseModel):
    query_value: str = ""
    breach_count: int = 0
    breaches: list[BreachRecord] = []
    paste_count: int = 0


class Hibp(Tool[HibpInput, HibpOutput]):
    name = "hibp"
    requires = ["HIBP_API_KEY"]
    input_schema = HibpInput
    output_schema = HibpOutput
    vendor = "haveibeenpwned.com"

    def _input_type(self, inp: HibpInput) -> InputType:
        return inp.input_type

    def _input_value(self, inp: HibpInput) -> str:
        return inp.value

    def to_findings(self, out: HibpOutput) -> list[Finding]:
        """One Breach per HIBP breach record; password-class breaches rank HIGH,
        spam lists LOW, everything else MEDIUM."""
        findings: list[Finding] = []
        for b in out.breaches:
            name = b.name or b.title
            if not name:
                continue
            raw_date = (b.breach_date or "").strip()[:10]
            try:
                breach_date = date.fromisoformat(raw_date) if raw_date else None
            except ValueError:  # malformed date — keep the fact, drop the date
                breach_date = None
            pw_class = any("password" in c.lower() for c in b.data_classes)
            severity = (
                Severity.HIGH
                if pw_class
                else Severity.LOW if b.is_spam_list else Severity.MEDIUM
            )
            findings.append(
                Breach(
                    dedup_key=f"breach:{name}",
                    title=b.title or name,
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    breach_date=breach_date,
                    data_classes=list(b.data_classes),
                    is_spam_list=b.is_spam_list,
                )
            )
        return findings

    def run_summary(self, out: HibpOutput) -> str:
        return f"{out.breach_count} breaches"

    def _run(self, inp: HibpInput, log: structlog.stdlib.BoundLogger) -> HibpOutput:
        api_key = config.get("HIBP_API_KEY")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{inp.value}"
        headers = {"hibp-api-key": api_key}
        params = {"truncateResponse": "false"}

        with client(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)
        ) as http:
            resp = http.get(url, headers=headers, params=params)

        if resp.status_code == 404:
            return HibpOutput(query_value=inp.value, paste_count=0)

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("retry-after", 2))
            time.sleep(retry_after)
            with client(
                timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)
            ) as http:
                resp = http.get(url, headers=headers, params=params)

        resp.raise_for_status()
        breaches = [BreachRecord.model_validate(b) for b in resp.json()]
        log.info("ok", breach_count=len(breaches))
        return HibpOutput(
            query_value=inp.value,
            breach_count=len(breaches),
            breaches=breaches,
            paste_count=-1,
        )
