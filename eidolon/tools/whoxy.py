"""Whoxy reverse WHOIS tool.

Given an email address, returns all domains that person has ever registered.
This is genuinely person-specific data — reveals business activity, old projects,
and company names not found through breach or social media scanning.

Key signals surfaced:
  - Domains registered to the email (active and expired)
  - Company names from registrant records → pivot to OpenCorporates
  - Physical addresses from WHOIS registrant data → fills physical data gap
  - Expired domains → risk finding (can be re-registered for phishing/impersonation)

API: GET https://api.whoxy.com/?key=KEY&reverse=email&value=EMAIL&page=1
Auth: ?key= query param
Requires: WHOXY_API_KEY in .env

Pricing: free tier 100 queries/month; paid from $3/month for 500/month.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

import requests
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class WhoxyDomain(BaseModel):
    domain_name: str = ""
    create_date: str = ""  # "2018-04-12"
    update_date: str = ""
    expiry_date: str = ""
    registrar_name: str = ""
    registrant_name: str = ""
    registrant_email: str = ""
    registrant_company: str = ""
    registrant_address: str = ""  # may include city/state/country


class WhoxyOutput(BaseModel):
    query_email: str = ""
    query_name: str = ""
    total_results: int = 0
    domains: list[WhoxyDomain] = []

    # Aggregated signals for LLM digest
    unique_registrar_names: list[str] = []
    unique_company_names: list[str] = []  # pivot targets for OpenCorporates
    unique_addresses: list[str] = []  # physical data from WHOIS records
    active_domain_count: int = 0  # domains not yet expired
    expired_domain_count: int = 0


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "whoxy_response.json"
)

WHOXY_URL = "https://api.whoxy.com/"


def run(email: str) -> ToolResult:
    logger.info("whoxy: reverse WHOIS for email=%s", email)

    if config.is_test_mode():
        import json

        raw = json.loads(FIXTURE_PATH.read_text())
        return ToolResult(**raw)

    api_key = config.get("WHOXY_API_KEY")
    if not api_key:
        logger.info(
            "whoxy: WHOXY_API_KEY not set — skipping "
            "(register at whoxy.com, free tier: 100 queries/month)"
        )
        output = WhoxyOutput(query_email=email)
        return ToolResult(
            success=True,
            tool="whoxy",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    try:
        all_domains: list[WhoxyDomain] = []
        page = 1

        # Paginate until we have all results or hit 5 pages (500 domains max)
        while page <= 5:
            resp = requests.get(
                WHOXY_URL,
                params={
                    "key": api_key,
                    "reverse": "whois",  # not "email" — reverse=whois is the operation
                    "email": email,  # field name is "email", not "value"
                    "page": str(page),
                },
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("status") != 1:
                logger.warning(
                    "whoxy: API returned status=%s — %s",
                    data.get("status"),
                    data.get("status_reason", "unknown error"),
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

        # Aggregate signals
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

        logger.info(
            "whoxy: OK — total=%d active=%d expired=%d companies=%d addresses=%d",
            output.total_results,
            output.active_domain_count,
            output.expired_domain_count,
            len(output.unique_company_names),
            len(output.unique_addresses),
        )

        return ToolResult(
            success=True,
            tool="whoxy",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("whoxy: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="whoxy",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"whoxy error: {exc}",
        )


def _format_address(contact: dict) -> str:
    """Flatten registrant contact fields into a single address string."""
    parts = [
        contact.get("mailing_address", ""),
        contact.get("city_name", ""),
        contact.get("state_name", ""),
        contact.get("zip_code", ""),
        contact.get("country_name", ""),
    ]
    return ", ".join(p for p in parts if p)
