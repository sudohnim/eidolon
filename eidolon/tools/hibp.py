import time
from typing import Literal

import requests
import structlog
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_pascal

from eidolon import config
from eidolon.core.models import InputType
from eidolon.tools.base import Tool


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

    def _input_type(self, inp: HibpInput) -> InputType:
        return inp.input_type

    def _input_value(self, inp: HibpInput) -> str:
        return inp.value

    def _run(self, inp: HibpInput, log: structlog.stdlib.BoundLogger) -> HibpOutput:
        api_key = config.get("HIBP_API_KEY")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{inp.value}"
        headers = {"hibp-api-key": api_key, "user-agent": "eidolon"}
        params = {"truncateResponse": "false"}
        resp = requests.get(url, headers=headers, params=params, timeout=10)

        if resp.status_code == 404:
            return HibpOutput(query_value=inp.value, paste_count=0)

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("retry-after", 2))
            time.sleep(retry_after)
            resp = requests.get(url, headers=headers, params=params, timeout=10)

        resp.raise_for_status()
        breaches = [BreachRecord.model_validate(b) for b in resp.json()]
        log.info("ok", breach_count=len(breaches))
        return HibpOutput(
            query_value=inp.value,
            breach_count=len(breaches),
            breaches=breaches,
            paste_count=-1,
        )
