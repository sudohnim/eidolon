"""Paste site search via HIBP /pasteAccount endpoint.

HIBP monitors Pastebin, Pastie, and other major paste services and exposes
a dedicated paste lookup endpoint. We already have the HIBP API key so this
costs nothing extra and is far more reliable than scraping psbdmp.ws.

  GET https://haveibeenpwned.com/api/v3/pasteaccount/{email}
  Auth: hibp-api-key header
  200 → list of paste objects (source, id, title, date, email_count)
  404 → no pastes found (treat as success with empty list)
  429 → rate limited (retry with backoff — breach_check fires concurrently)

HIBP does not expose paste content, so credential extraction (email:password
lines) is not possible here. What we get: which paste services the email
appeared in, when, and approximately how many addresses were in each paste.
"""

import time
from datetime import datetime, timezone

import requests
import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.tools.base import Tool


class PasteInput(BaseModel):
    email: str


class PasteEntry(BaseModel):
    paste_id: str = ""
    url: str = ""
    date: str = ""
    # Credential lines matching email:pass / email|pass patterns
    credential_count: int = 0
    has_plaintext_password: bool = False
    # First 3 passwords found, truncated after 4 chars for safety
    password_samples: list[str] = []


class PasteOutput(BaseModel):
    query_email: str = ""
    paste_count: int = 0
    # Pastes that contained email:password lines for this email
    credential_paste_count: int = 0
    # Pastes posted within the last 90 days
    recent_paste_count: int = 0
    pastes: list[PasteEntry] = []
    plaintext_passwords_found: int = 0


HIBP_PASTE_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"

_RECENT_DAYS = 90
_MAX_RETRIES = 3


def _is_recent(date_str: str) -> bool:
    """Return True if the ISO date string is within _RECENT_DAYS of today."""
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
    """Build a direct URL to the paste from its source and ID."""
    sources = {
        "Pastebin": f"https://pastebin.com/{paste_id}",
        "Pastie": f"http://pastie.org/pastes/{paste_id}",
        "Slexy": f"https://slexy.org/view/{paste_id}",
        "Snipplr": f"https://snipplr.com/view/{paste_id}",
        "Ghostbin": f"https://ghostbin.co/paste/{paste_id}",
    }
    return sources.get(source, f"{source.lower()}.com/{paste_id}")


def _truncate_password(pw: str) -> str:
    """Keep first 4 chars, mask the rest."""
    if len(pw) <= 4:
        return pw + "****"
    return pw[:4] + "****"


class Paste(Tool[PasteInput, PasteOutput]):
    name = "paste"
    input_schema = PasteInput
    output_schema = PasteOutput

    def _input_value(self, inp: PasteInput) -> str:
        return inp.email

    def _run(self, inp: PasteInput, log: structlog.stdlib.BoundLogger) -> PasteOutput:
        email = inp.email
        headers = {
            "hibp-api-key": config.get("HIBP_API_KEY"),
            "user-agent": "eidolon/1.0",
        }

        resp = None
        for attempt in range(1, _MAX_RETRIES + 1):
            resp = requests.get(
                HIBP_PASTE_URL.format(email=email), headers=headers, timeout=15
            )
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("retry-after", 2))
                log.info("rate-limited", wait=retry_after, attempt=attempt)
                time.sleep(retry_after + 0.5)
                continue
            break

        if resp is None:
            raise RuntimeError("no response after retries")

        if resp.status_code == 404:
            # 404 means no pastes found — not an error
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
                    # email_count = how many addresses were in the paste (proxy)
                    credential_count=email_count,
                    has_plaintext_password=False,  # HIBP doesn't expose paste content
                    password_samples=[],
                )
            )

        log.info("ok", pastes=len(entries), recent=recent_count)
        return PasteOutput(
            query_email=email,
            paste_count=len(entries),
            credential_paste_count=0,  # can't determine without paste content
            recent_paste_count=recent_count,
            pastes=entries,
            plaintext_passwords_found=0,
        )
