"""Paste site search via HIBP /pasteAccount endpoint.

HIBP monitors Pastebin, Pastie, and other major paste services and exposes
a dedicated paste lookup endpoint. We already have the HIBP API key so this
costs nothing extra and is far more reliable than scraping psbdmp.ws.

  GET https://haveibeenpwned.com/api/v3/pasteaccount/{email}
  Auth: hibp-api-key header
  200 -> list of paste objects (source, id, title, date, email_count)
  404 -> no pastes found (treat as success with empty list)
  429 -> rate limited (retry with backoff -- breach_check fires concurrently)

HIBP does not expose paste content, so credential extraction (email:password
lines) is not possible here. What we get: which paste services the email
appeared in, when, and approximately how many addresses were in each paste.
"""

import time
from datetime import datetime, timezone

import httpx
import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.core.findings import Finding
from eidolon.core.findings import Paste as PasteFinding
from eidolon.core.findings import Severity
from eidolon.sources._http import client
from eidolon.sources.base import Tool

HIBP_PASTE_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"

_RECENT_DAYS = 90
_MAX_RETRIES = 3


def _is_recent(date_str: str) -> bool:
    if not date_str:
        return False
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days <= _RECENT_DAYS
    except Exception:
        return False


def _paste_url(source: str, paste_id: str) -> str:
    sources = {
        "Pastebin": f"https://pastebin.com/{paste_id}",
        "Pastie": f"http://pastie.org/pastes/{paste_id}",
        "Slexy": f"https://slexy.org/view/{paste_id}",
        "Snipplr": f"https://snipplr.com/view/{paste_id}",
        "Ghostbin": f"https://ghostbin.co/paste/{paste_id}",
    }
    return sources.get(source, f"{source.lower()}.com/{paste_id}")


def _truncate_password(pw: str) -> str:
    if len(pw) <= 4:
        return pw + "****"
    return pw[:4] + "****"


class PasteInput(BaseModel):
    email: str


class PasteEntry(BaseModel):
    paste_id: str = ""
    url: str = ""
    date: str = ""
    credential_count: int = 0
    has_plaintext_password: bool = False
    password_samples: list[str] = []


class PasteOutput(BaseModel):
    query_email: str = ""
    paste_count: int = 0
    credential_paste_count: int = 0
    recent_paste_count: int = 0
    pastes: list[PasteEntry] = []
    plaintext_passwords_found: int = 0


class Paste(Tool[PasteInput, PasteOutput]):
    name = "paste"
    input_schema = PasteInput
    output_schema = PasteOutput
    vendor = "haveibeenpwned.com"
    requires = ["HIBP_API_KEY"]

    def _input_value(self, inp: PasteInput) -> str:
        return inp.email

    def to_findings(self, out: PasteOutput) -> list[Finding]:
        findings: list[Finding] = []
        for p in out.pastes:
            if not p.url:
                continue
            findings.append(
                PasteFinding(
                    dedup_key=f"paste:{p.url}",
                    title=f"Paste {p.paste_id}" if p.paste_id else "Paste dump",
                    severity=Severity.HIGH if p.credential_count else Severity.LOW,
                    paste_id=p.paste_id,
                    url=p.url,
                    date=p.date,
                    credential_count=p.credential_count,
                    has_plaintext_password=p.has_plaintext_password,
                    recent=_is_recent(p.date),
                )
            )
        return findings

    def run_summary(self, out: PasteOutput) -> str:
        if not out.paste_count:
            return ""
        return (
            f"{out.paste_count} pastes -- "
            f"{out.recent_paste_count} posted within 90 days"
        )

    def _run(self, inp: PasteInput, log: structlog.stdlib.BoundLogger) -> PasteOutput:
        email = inp.email
        headers = {"hibp-api-key": config.get("HIBP_API_KEY")}

        resp = None
        for attempt in range(1, _MAX_RETRIES + 1):
            with client(
                timeout=httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)
            ) as http:
                resp = http.get(HIBP_PASTE_URL.format(email=email), headers=headers)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("retry-after", 2))
                log.info("rate-limited", wait=retry_after, attempt=attempt)
                time.sleep(retry_after + 0.5)
                continue
            break

        if resp is None:
            raise RuntimeError("no response after retries")

        if resp.status_code == 404:
            return PasteOutput(query_email=email, paste_count=0)

        resp.raise_for_status()
        raw_pastes = resp.json() or []

        entries: list[PasteEntry] = []
        recent_count = 0
        for item in raw_pastes:
            source = item.get("Source", "")
            paste_id = item.get("Id", "")
            date_str = item.get("Date") or ""
            email_count = item.get("EmailCount", 0)
            date_short = date_str[:10] if date_str else ""
            if _is_recent(date_str):
                recent_count += 1
            entries.append(
                PasteEntry(
                    paste_id=paste_id,
                    url=_paste_url(source, paste_id),
                    date=date_short,
                    credential_count=email_count,
                    has_plaintext_password=False,
                    password_samples=[],
                )
            )

        log.info("ok", pastes=len(entries), recent=recent_count)
        return PasteOutput(
            query_email=email,
            paste_count=len(entries),
            credential_paste_count=0,
            recent_paste_count=recent_count,
            pastes=entries,
            plaintext_passwords_found=0,
        )
