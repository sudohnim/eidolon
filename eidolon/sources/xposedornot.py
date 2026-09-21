"""XposedOrNot — free, keyless breach data by email (a HIBP substitute).

`GET https://api.xposedornot.com/v1/breach-analytics?email=<email>` returns, with
no API key, the breaches an email appears in plus a risk score and a
password-strength breakdown (how many plaintext vs strong-hash). This is the
free-tier breach source: it populates Breach findings the same way HIBP would, so
the deterministic risk score has real breach signal without a paid key.
"""

from __future__ import annotations

from datetime import date

import structlog
from pydantic import BaseModel

from eidolon.core.findings import Breach, Confidence, Finding, Severity
from eidolon.sources._http import client
from eidolon.sources.base import Tool


class XposedOrNotInput(BaseModel):
    email: str


class XonBreach(BaseModel):
    name: str = ""
    year: str = ""
    data_classes: list[str] = []
    records: int = 0
    password_risk: str = ""
    domain: str = ""
    industry: str = ""


class XposedOrNotOutput(BaseModel):
    breach_count: int = 0
    breaches: list[XonBreach] = []
    risk_score: int = 0
    risk_label: str = ""
    plaintext_password_count: int = 0
    hashed_password_count: int = 0


class XposedOrNot(Tool[XposedOrNotInput, XposedOrNotOutput]):
    name = "xposedornot"
    input_schema = XposedOrNotInput
    output_schema = XposedOrNotOutput
    input_type = "email"
    vendor = "api.xposedornot.com"
    # no `requires` — free, keyless API; always available

    def _input_value(self, inp: XposedOrNotInput) -> str:
        return inp.email

    def to_findings(self, out: XposedOrNotOutput) -> list[Finding]:
        """One Breach per exposed breach; password-class breaches rank HIGH."""
        findings: list[Finding] = []
        for b in out.breaches:
            if not b.name:
                continue
            year = (b.year or "").strip()[:4]
            breach_date = date(int(year), 1, 1) if year.isdigit() else None
            pw_class = any("password" in c.lower() for c in b.data_classes)
            findings.append(
                Breach(
                    dedup_key=f"breach:{b.name}",
                    title=b.name,
                    severity=Severity.HIGH if pw_class else Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    breach_date=breach_date,
                    data_classes=list(b.data_classes),
                )
            )
        return findings

    def run_summary(self, out: XposedOrNotOutput) -> str:
        return f"{out.breach_count} breaches"

    def _run(
        self, inp: XposedOrNotInput, log: structlog.stdlib.BoundLogger
    ) -> XposedOrNotOutput:
        url = "https://api.xposedornot.com/v1/breach-analytics"
        with client() as http:
            resp = http.get(url, params={"email": inp.email})

        # A clean email yields 404 (nothing found) — a legitimate empty result.
        if resp.status_code == 404:
            return XposedOrNotOutput()
        resp.raise_for_status()

        data = resp.json()
        if not isinstance(data, dict) or "ExposedBreaches" not in data:
            return XposedOrNotOutput()  # error/"not found" shape

        details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
        breaches: list[XonBreach] = []
        for d in details:
            classes = [
                c.strip() for c in (d.get("xposed_data") or "").split(";") if c.strip()
            ]
            try:
                records = int(d.get("xposed_records") or 0)
            except (TypeError, ValueError):
                records = 0
            breaches.append(
                XonBreach(
                    name=d.get("breach", ""),
                    year=str(d.get("xposed_date", "")),
                    data_classes=classes,
                    records=records,
                    password_risk=str(d.get("password_risk", "")),
                    domain=str(d.get("domain", "")),
                    industry=str(d.get("industry", "")),
                )
            )

        metrics = data.get("BreachMetrics") or {}
        risk = (metrics.get("risk") or [{}])[0]
        pw = (metrics.get("passwords_strength") or [{}])[0]

        def _int(v: object) -> int:
            try:
                return int(v)  # type: ignore[call-overload]
            except (TypeError, ValueError):
                return 0

        log.info("ok", breach_count=len(breaches))
        return XposedOrNotOutput(
            breach_count=len(breaches),
            breaches=breaches,
            risk_score=_int(risk.get("risk_score")),
            risk_label=str(risk.get("risk_label", "")),
            plaintext_password_count=_int(pw.get("PlainText")),
            hashed_password_count=_int(pw.get("StrongHash")),
        )
