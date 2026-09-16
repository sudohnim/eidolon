"""Phone number aggregation.

Two layers, combined into one phone_lookup source:
  1. libphonenumber — free, offline baseline (always runs)
  2. numverify — optional real-time carrier/line-type, merged on top when keyed

``PhoneLookup`` (the Tool) is the source-level aggregation for this
multi-layer lookup; ``lookup`` is a backward-compatible wrapper returning the
ToolResult envelope. PhoneInput / PhoneLookupOutput are re-exported here for
backward-compatible imports.
"""

import structlog

from eidolon.core.findings import Finding, PhoneIntel, Severity
from eidolon.core.state import ToolResult
from eidolon.sources.base import Tool, run_to_result
from eidolon.sources.libphonenumber import (
    Libphonenumber,
    PhoneCarrierInfo,
    PhoneInput,
    PhoneLookupOutput,
    normalize_phone,
)
from eidolon.sources.numverify import Numverify, NumverifyInput

__all__ = ["PhoneInput", "PhoneLookupOutput", "PhoneLookup", "lookup"]

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


class PhoneLookup(Tool[PhoneInput, PhoneLookupOutput]):
    """Composite source: offline libphonenumber baseline + Numverify on top."""

    name = "phone_lookup"
    input_schema = PhoneInput
    output_schema = PhoneLookupOutput
    input_type = "phone"
    #: offline baseline + optional apilayer.net call — no single vendor host
    vendor = ""

    def run(self, inp: PhoneInput) -> PhoneLookupOutput:
        # Composite: no single fixture — libphonenumber (offline) and numverify
        # each take their own TEST_MODE path, so always run the real layers.
        return self._run_layers(inp.phone)

    def _input_value(self, inp: PhoneInput) -> str:
        try:
            return normalize_phone(inp.phone)
        except ValueError:
            return inp.phone

    def _run_layers(self, phone: str) -> PhoneLookupOutput:
        normalized = normalize_phone(phone)
        baseline = Libphonenumber().run(PhoneInput(phone=normalized))

        numverify = Numverify()
        if numverify.available() and baseline.valid:
            try:
                nv = numverify.run(NumverifyInput(phone=baseline.phone))  # typed
                if nv.valid:
                    baseline = _merge_numverify(
                        baseline,
                        {
                            "carrier": nv.carrier,
                            "line_type": nv.line_type,
                            "country_name": nv.country_name,
                            "location": nv.location,
                        },
                    )
            except Exception:
                pass  # optional layer — degrade to the offline baseline

        return baseline

    def _run(
        self, inp: PhoneInput, log: structlog.stdlib.BoundLogger
    ) -> PhoneLookupOutput:
        return self._run_layers(inp.phone)

    def to_findings(self, out: PhoneLookupOutput) -> list[Finding]:
        """One PhoneIntel per valid number — what the number itself reveals
        (line type, carrier, location). An invalid number is the absence of a
        fact, not a finding."""
        if not out.valid:
            return []
        return [
            PhoneIntel(
                dedup_key=f"phone:{out.phone}",
                title=out.international_format or out.phone,
                severity=Severity.LOW,
                phone=out.phone,
                valid=out.valid,
                line_type=out.line_type,
                is_voip=out.is_voip,
                carrier=(out.carrier.name if out.carrier else ""),
                location=out.geocode or out.location,
                timezones=list(out.timezone),
                country_code=out.country_code,
            )
        ]

    def run_summary(self, out: PhoneLookupOutput) -> str:
        if not out.valid:
            return "invalid"
        carrier = out.carrier.name if out.carrier else "unknown carrier"
        return f"valid=true {out.line_type} via {carrier}"


def lookup(phone: str) -> ToolResult:
    """Backward-compatible envelope wrapper over ``PhoneLookup``."""
    return run_to_result(PhoneLookup(), PhoneInput(phone=phone))
