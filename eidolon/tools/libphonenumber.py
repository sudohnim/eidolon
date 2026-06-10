"""libphonenumber — free, offline phone number parsing (Google's library).

Validates E.164 format, classifies line type (mobile/landline/voip/...), and
returns carrier hint, geocode, and timezone — all without any API calls or keys.
VoIP numbers are flagged (is_voip) as a higher fraud-risk signal.
"""

import re
from typing import Literal

import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool


class PhoneInput(BaseModel):
    phone: str  # raw or E.164 format


class PhoneCarrierInfo(BaseModel):
    name: str
    type: Literal["mobile", "landline", "voip", "prepaid", "unknown"] = "unknown"


class PhoneLookupOutput(BaseModel):
    phone: str = ""
    valid: bool = False
    carrier: PhoneCarrierInfo | None = None
    line_type: str = "unknown"  # mobile / landline / voip / prepaid
    country_code: str = ""
    country_name: str = ""
    location: str = ""  # city or region where the number was registered
    geocode: str = ""  # human-readable geographic description
    timezone: list[str] = []  # IANA timezone(s) for the number's area
    international_format: str = ""
    local_format: str = ""
    # True when line_type is voip — throwaway/anonymous number risk flag
    is_voip: bool = False


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


def normalize_phone(raw: str) -> str:
    """Strip everything except digits and leading +; assume US for 10 digits."""
    digits = re.sub(r"[^\d+]", "", raw)
    if re.match(r"^\d{10}$", digits):
        return f"+1{digits}"
    return digits


class Libphonenumber(Tool[PhoneInput, PhoneLookupOutput]):
    name = "libphonenumber"
    input_type = "phone"
    input_schema = PhoneInput
    output_schema = PhoneLookupOutput

    def _input_value(self, inp: PhoneInput) -> str:
        return inp.phone

    def _run(
        self, inp: PhoneInput, log: structlog.stdlib.BoundLogger
    ) -> PhoneLookupOutput:
        phone = normalize_phone(inp.phone)
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder
            from phonenumbers import timezone as pn_tz

            parsed = phonenumbers.parse(phone)
            if not phonenumbers.is_valid_number(parsed):
                return PhoneLookupOutput(phone=phone, valid=False)

            number_type = phonenumbers.number_type(parsed)
            line_type = _LINE_TYPE_MAP.get(number_type, "unknown")
            carrier_name = carrier.name_for_number(parsed, "en") or ""
            geo = geocoder.description_for_number(parsed, "en") or ""
            timezones = list(pn_tz.time_zones_for_number(parsed))
            region = phonenumbers.region_code_for_number(parsed) or ""
            e164 = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )
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
            log.warning("phonenumbers lookup failed", error=str(exc))
            return PhoneLookupOutput(phone=phone, valid=False)
