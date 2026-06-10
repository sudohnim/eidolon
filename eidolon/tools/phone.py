"""Phone number aggregation.

Two layers, combined into one phone_lookup ToolResult:
  1. libphonenumber — free, offline baseline (always runs)
  2. numverify — optional real-time carrier/line-type, merged on top when keyed

``lookup`` is the node-level aggregation for this multi-vendor source.
PhoneInput / PhoneLookupOutput are re-exported here for backward-compatible
imports.
"""

from datetime import datetime, timezone

from eidolon.core.models import ToolResult
from eidolon.tools.base import run_to_result
from eidolon.tools.libphonenumber import (
    Libphonenumber,
    PhoneCarrierInfo,
    PhoneInput,
    PhoneLookupOutput,
    normalize_phone,
)
from eidolon.tools.numverify import Numverify, NumverifyInput

__all__ = ["PhoneInput", "PhoneLookupOutput", "lookup"]

_LINE_TYPES = ("mobile", "landline", "voip", "prepaid")


def _merge_numverify(baseline: PhoneLookupOutput, nv: dict) -> PhoneLookupOutput:
    """Merge Numverify's real-time carrier/line-type on top of the baseline."""
    nv_carrier = nv.get("carrier") or ""
    nv_line_type = (nv.get("line_type") or "").lower()
    if nv_line_type not in _LINE_TYPES:
        nv_line_type = baseline.line_type

    carrier_info = baseline.carrier
    if nv_carrier:
        ctype = nv_line_type if nv_line_type in _LINE_TYPES else "unknown"
        carrier_info = PhoneCarrierInfo(
            name=nv_carrier,
            type=ctype,  # type: ignore[arg-type]
        )

    return baseline.model_copy(
        update={
            "carrier": carrier_info,
            "line_type": nv_line_type or baseline.line_type,
            "country_name": nv.get("country_name") or baseline.country_name,
            "location": nv.get("location") or baseline.location,
            "is_voip": (nv_line_type == "voip"),
        }
    )


def lookup(phone: str) -> ToolResult:
    """Resolve a phone number via libphonenumber (+ Numverify when configured)."""
    normalized = normalize_phone(phone)
    baseline = Libphonenumber().run(PhoneInput(phone=normalized))

    numverify = Numverify()
    if numverify.available() and baseline.valid:
        nv_res = run_to_result(numverify, NumverifyInput(phone=baseline.phone))
        if nv_res.success and nv_res.data.get("valid"):
            baseline = _merge_numverify(baseline, nv_res.data)

    return ToolResult(
        success=True,
        tool="phone_lookup",
        input_type="phone",
        input_value=normalized,
        timestamp=datetime.now(timezone.utc),
        data=baseline.model_dump(),
    )
