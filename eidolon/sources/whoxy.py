"""Whoxy reverse WHOIS tool.

Given an email address, returns all domains that person has ever registered.
This is genuinely person-specific data — reveals business activity, old projects,
and company names not found through breach or social media scanning.

Key signals surfaced:
  - Domains registered to the email (active and expired)
  - Company names from registrant records — pivot to OpenCorporates
  - Physical addresses from WHOIS registrant data — fills physical data gap
  - Expired domains — risk finding (can be re-registered for phishing/impersonation)

API: GET https://api.whoxy.com/?key=KEY&reverse=email&value=EMAIL&page=1
Auth: ?key= query param
Requires: WHOXY_API_KEY in .env

Pricing: free tier 100 queries/month; paid from $3/month for 500/month.
"""

from datetime import datetime, timezone

import httpx
import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.core.findings import Finding, Severity
from eidolon.sources._http import client
from eidolon.sources.base import Tool


class WhoxyInput(BaseModel):
    email: str


class WhoxyDomain(BaseModel):
    domain_name: str = ""
    create_date: str = ""
    update_date: str = ""
    expiry_date: str = ""
    registrar_name: str = ""
    registrant_name: str = ""
    registrant_email: str = ""
    registrant_company: str = ""
    registrant_address: str = ""


class WhoxyOutput(BaseModel):
    query_email: str = ""
    query_name: str = ""
    total_results: int = 0
    domains: list[WhoxyDomain] = []

    unique_registrar_names: list[str] = []
    unique_company_names: list[str] = []
    unique_addresses: list[str] = []
    active_domain_count: int = 0
    expired_domain_count: int = 0


WHOXY_URL = "https://api.whoxy.com/"


class Whoxy(Tool[WhoxyInput, WhoxyOutput]):
    name = "whoxy"
    requires = ["WHOXY_API_KEY"]
    input_schema = WhoxyInput
    output_schema = WhoxyOutput
    vendor = "api.whoxy.com"

    def available(self) -> bool:
        return bool(config.get("WHOXY_API_KEY"))

    def _input_value(self, inp: WhoxyInput) -> str:
        return inp.email

    def to_findings(self, out: WhoxyOutput) -> list[Finding]:
        today = datetime.now(timezone.utc).date().isoformat()
        findings: list[Finding] = []
        for d in out.domains:
            if not d.domain_name:
                continue
            active = bool(d.expiry_date) and d.expiry_date >= today
            findings.append(
                Finding(
                    kind="registered_domain",
                    dedup_key=f"domain:{d.domain_name}",
                    title=d.domain_name,
                    severity=Severity.LOW if active else Severity.INFO,
                    payload={
                        "domain": d.domain_name,
                        "registrar": d.registrar_name,
                        "company": d.registrant_company,
                        "address": d.registrant_address,
                        "create_date": d.create_date,
                        "expiry_date": d.expiry_date,
                        "active": active,
                    },
                )
            )
        return findings

    def run_summary(self, out: WhoxyOutput) -> str:
        if not out.total_results:
            return ""
        return (
            f"{out.total_results} domains registered — "
            f"{out.active_domain_count} active, "
            f"{out.expired_domain_count} expired"
        )

    def _run(self, inp: WhoxyInput, log: structlog.stdlib.BoundLogger) -> WhoxyOutput:
        email = inp.email
        api_key = config.get("WHOXY_API_KEY")
        all_domains: list[WhoxyDomain] = []
        page = 1

        with client(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)
        ) as http:
            while page <= 5:
                params = {
                    "key": api_key,
                    "reverse": "whois",
                    "email": email,
                    "page": str(page),
                }
                resp = http.get(WHOXY_URL, params=params)
                resp.raise_for_status()
                data = resp.json()

                if data.get("status") != 1:
                    log.warning(
                        "whoxy api error",
                        status=data.get("status"),
                        reason=data.get("status_reason", "unknown error"),
                    )
                    break

                records = data.get("search_result") or []
                if not records:
                    break

                for rec in records:
                    contact = rec.get("registrant_contact") or {}
                    all_domains.append(
                        WhoxyDomain(
                            domain_name=rec.get("domain_name") or "",
                            create_date=rec.get("create_date") or "",
                            update_date=rec.get("update_date") or "",
                            expiry_date=rec.get("expiry_date") or "",
                            registrar_name=rec.get("domain_registrar", {}).get(
                                "registrar_name"
                            )
                            or "",
                            registrant_name=contact.get("full_name") or "",
                            registrant_email=contact.get("email_address") or "",
                            registrant_company=contact.get("company_name") or "",
                            registrant_address=_format_address(contact),
                        )
                    )

                total = data.get("total_results", 0)
                per_page = data.get("per_page", 100)
                if page * per_page >= total:
                    break
                page += 1

        today = datetime.now(timezone.utc).date().isoformat()

        companies: list[str] = []
        addresses: list[str] = []
        registrars: list[str] = []
        active_count = 0
        expired_count = 0

        for d in all_domains:
            if d.registrant_company and d.registrant_company not in companies:
                companies.append(d.registrant_company)
            if d.registrant_address and d.registrant_address not in addresses:
                addresses.append(d.registrant_address)
            if d.registrar_name and d.registrar_name not in registrars:
                registrars.append(d.registrar_name)
            if d.expiry_date and d.expiry_date >= today:
                active_count += 1
            else:
                expired_count += 1

        output = WhoxyOutput(
            query_email=email,
            total_results=len(all_domains),
            domains=all_domains,
            unique_registrar_names=registrars,
            unique_company_names=companies,
            unique_addresses=addresses,
            active_domain_count=active_count,
            expired_domain_count=expired_count,
        )

        log.info(
            "ok",
            total=output.total_results,
            active=output.active_domain_count,
            expired=output.expired_domain_count,
            companies=len(output.unique_company_names),
            addresses=len(output.unique_addresses),
        )
        return output


def _format_address(contact: dict) -> str:
    parts = [
        contact.get("mailing_address", ""),
        contact.get("city_name", ""),
        contact.get("state_name", ""),
        contact.get("zip_code", ""),
        contact.get("country_name", ""),
    ]
    return ", ".join(p for p in parts if p)
