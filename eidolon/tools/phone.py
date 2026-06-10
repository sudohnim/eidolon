"""Phone number pivot tool.

Two-layer approach — works with zero API keys:

Layer 1 — phonenumbers (Google libphonenumber, free, offline)
  - Validates E.164 format and parses number structure
  - Carrier hint from number-range database (not real-time, but reliable for
    determining mobile vs landline vs VoIP class)
  - Geographic region / geocode
  - IANA timezone(s) for the number's area
  - Fully offline, no API calls, no keys required

Layer 2 — Numverify (apilayer.net, optional)
  - Real-time carrier name and line type confirmation
  - Requires NUMVERIFY_API_KEY in .env (free tier: 100 req/month)
  - Results merged on top of Layer 1 if key is set
  - Free tier uses HTTP (not HTTPS) — number is not sensitive here

VoIP detection: line_type == "voip" → is_voip flag set in output.
VoIP numbers are often throwaway/anonymous and indicate higher fraud risk.
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import requests
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class PhoneInput(BaseModel):
    phone: str  # raw or E.164 format


class PhoneCarrierInfo(BaseModel):
    name: str
    type: Literal["mobile", "landline", "voip", "prepaid", "unknown"] = "unknown"


class PhoneLookupOutput(BaseModel):
    phone: str
    valid: bool
    carrier: PhoneCarrierInfo | None = None
    line_type: str = "unknown"  # mobile / landline / voip / prepaid
    country_code: str = ""
    country_name: str = ""
    location: str = ""  # city or region where the number was registered
    geocode: str = ""  # human-readable geographic description (from libphonenumber)
    timezone: list[str] = []  # IANA timezone(s) for the number's area
    international_format: str = ""
    local_format: str = ""
    # True when line_type is voip — throwaway/anonymous number risk flag
    is_voip: bool = False


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "phone_response.json"
)

NUMVERIFY_URL = "http://apilayer.net/api/validate"

# Maps phonenumbers library line-type constants to our Literal values
_LINE_TYPE_MAP = {
    0: "mobile",
    1: "landline",  # FIXED_LINE
    2: "mobile",  # FIXED_LINE_OR_MOBILE (conservative: treat as mobile)
    3: "unknown",  # TOLL_FREE
    4: "prepaid",  # PREMIUM_RATE (closest approximation)
    5: "unknown",  # SHARED_COST
    6: "voip",  # VOIP
    7: "unknown",  # PERSONAL_NUMBER
    8: "unknown",  # PAGER
    9: "unknown",  # UAN
    10: "unknown",  # VOICEMAIL
    99: "unknown",  # UNKNOWN
}


def _normalize_phone(raw: str) -> str:
    """Strip everything except digits and leading +."""
    digits = re.sub(r"[^\d+]", "", raw)
    if re.match(r"^\d{10}$", digits):
        return f"+1{digits}"
    return digits


def _lookup_phonenumbers(phone: str) -> PhoneLookupOutput:
    """Layer 1: free offline lookup using Google's libphonenumber."""
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder
        from phonenumbers import timezone as pn_tz

        parsed = phonenumbers.parse(phone)
        valid = phonenumbers.is_valid_number(parsed)

        if not valid:
            return PhoneLookupOutput(phone=phone, valid=False)

        # Line type
        number_type = phonenumbers.number_type(parsed)
        line_type = _LINE_TYPE_MAP.get(number_type, "unknown")

        # Carrier name (from number-range DB — not real-time)
        carrier_name = carrier.name_for_number(parsed, "en") or ""

        # Geocode (e.g. "San Francisco, CA")
        geo = geocoder.description_for_number(parsed, "en") or ""

        # Timezones (IANA)
        timezones = list(pn_tz.time_zones_for_number(parsed))

        # Country
        region = phonenumbers.region_code_for_number(parsed) or ""

        # Formatted versions
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        national = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        )

        carrier_info: PhoneCarrierInfo | None = None
        if carrier_name:
            ctype = (
                line_type
                if line_type in ("mobile", "landline", "voip", "prepaid")
                else "unknown"
            )
            carrier_info = PhoneCarrierInfo(
                name=carrier_name,
                type=ctype,  # type: ignore[arg-type]
            )

        return PhoneLookupOutput(
            phone=e164,
            valid=True,
            carrier=carrier_info,
            line_type=line_type,
            country_code=region,
            geocode=geo,
            timezone=timezones,
            international_format=e164,
            local_format=national,
            is_voip=(line_type == "voip"),
        )

    except Exception as exc:
        logger.warning("phone_lookup: phonenumbers lookup failed — %s", exc)
        return PhoneLookupOutput(phone=phone, valid=False)


def _supplement_numverify(output: PhoneLookupOutput, api_key: str) -> PhoneLookupOutput:
    """Layer 2: optional real-time supplement via Numverify.

    Merges carrier name and line type on top of the phonenumbers baseline.
    Returns the original output unchanged on any error.
    """
    try:
        resp = requests.get(
            NUMVERIFY_URL,
            params={
                "access_key": api_key,
                "number": output.phone,
                "country_code": "",
                "format": "1",
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        if not data.get("valid") and "error" in data:
            err = data["error"].get("info", "unknown error")
            logger.warning(
                "phone_lookup: Numverify error — %s (using phonenumbers baseline)", err
            )
            return output

        # Merge real-time fields on top of offline baseline
        nv_carrier = data.get("carrier") or ""
        nv_line_type = (data.get("line_type") or "").lower()
        if nv_line_type not in ("mobile", "landline", "voip", "prepaid"):
            nv_line_type = output.line_type

        carrier_info: PhoneCarrierInfo | None = output.carrier
        if nv_carrier:
            ctype = (
                nv_line_type
                if nv_line_type in ("mobile", "landline", "voip", "prepaid")
                else "unknown"
            )
            carrier_info = PhoneCarrierInfo(
                name=nv_carrier,
                type=ctype,  # type: ignore[arg-type]
            )

        return output.model_copy(
            update={
                "carrier": carrier_info,
                "line_type": nv_line_type or output.line_type,
                "country_name": data.get("country_name") or output.country_name,
                "location": data.get("location") or output.location,
                "is_voip": (nv_line_type == "voip"),
            }
        )

    except Exception as exc:
        logger.warning(
            "phone_lookup: Numverify supplement failed — %s "
            "(using phonenumbers baseline)",
            exc,
        )
        return output


def run(inp: PhoneInput) -> ToolResult:
    logger.info("phone_lookup: looking up %s", inp.phone)

    if config.is_test_mode():
        import json

        raw = json.loads(FIXTURE_PATH.read_text())
        return ToolResult(**raw)

    phone = _normalize_phone(inp.phone)

    # Layer 1: free offline lookup
    output = _lookup_phonenumbers(phone)

    # Layer 2: optional real-time supplement
    api_key = config.get("NUMVERIFY_API_KEY")
    if api_key and output.valid:
        output = _supplement_numverify(output, api_key)

    logger.info(
        "phone_lookup: valid=%s carrier=%s line_type=%s is_voip=%s geocode=%s",
        output.valid,
        output.carrier.name if output.carrier else "unknown",
        output.line_type,
        output.is_voip,
        output.geocode,
    )

    return ToolResult(
        success=True,
        tool="phone_lookup",
        input_type="phone",
        input_value=phone,
        timestamp=datetime.now(timezone.utc),
        data=output.model_dump(),
    )
