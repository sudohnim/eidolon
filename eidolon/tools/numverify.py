"""Numverify — optional real-time phone carrier/line-type confirmation.

Supplements the offline libphonenumber baseline with a real-time carrier name
and confirmed line type. Requires NUMVERIFY_API_KEY (free tier: 100 req/month).
Free tier uses HTTP (not HTTPS) — the number is not sensitive here.
"""

import requests
import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.tools.base import Tool

NUMVERIFY_URL = "http://apilayer.net/api/validate"


class NumverifyInput(BaseModel):
    phone: str


class NumverifyOutput(BaseModel):
    valid: bool = False
    carrier: str = ""
    line_type: str = ""
    country_name: str = ""
    location: str = ""


class Numverify(Tool[NumverifyInput, NumverifyOutput]):
    name = "numverify"
    requires = ["NUMVERIFY_API_KEY"]
    input_type = "phone"
    input_schema = NumverifyInput
    output_schema = NumverifyOutput

    def available(self) -> bool:
        return bool(config.get("NUMVERIFY_API_KEY"))

    def _input_value(self, inp: NumverifyInput) -> str:
        return inp.phone

    def _run(
        self, inp: NumverifyInput, log: structlog.stdlib.BoundLogger
    ) -> NumverifyOutput:
        resp = requests.get(
            NUMVERIFY_URL,
            params={
                "access_key": config.get("NUMVERIFY_API_KEY"),
                "number": inp.phone,
                "country_code": "",
                "format": "1",
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if not data.get("valid") and "error" in data:
            log.warning("numverify error", info=data["error"].get("info", "unknown"))
            return NumverifyOutput(valid=False)

        return NumverifyOutput(
            valid=bool(data.get("valid")),
            carrier=data.get("carrier") or "",
            line_type=(data.get("line_type") or "").lower(),
            country_name=data.get("country_name") or "",
            location=data.get("location") or "",
        )
