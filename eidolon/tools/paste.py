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

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


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


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "paste_response.json"
)

HIBP_PASTE_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{email}"

_RECENT_DAYS = 90
_MAX_RETRIES = 3


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


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


def run(email: str) -> ToolResult:
    logger.info("paste: querying HIBP paste endpoint for email=%s", email)

    if config.is_test_mode():
        return _load_fixture()

    api_key = config.get("HIBP_API_KEY")
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "osint-agent/1.0",
    }

    try:
        resp = None
        for attempt in range(1, _MAX_RETRIES + 1):
            resp = requests.get(
                HIBP_PASTE_URL.format(email=email),
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("retry-after", 2))
                logger.info(
                    "paste: HIBP rate-limited, waiting %ds (attempt %d/%d)",
                    retry_after,
                    attempt,
                    _MAX_RETRIES,
                )
                time.sleep(retry_after + 0.5)
                continue
            break

        if resp is None:
            raise RuntimeError("no response after retries")

        if resp.status_code == 404:
            # 404 means no pastes found — not an error
            logger.info("paste: no paste records found for %s", email)
            output = PasteOutput(query_email=email, paste_count=0)
            return ToolResult(
                success=True,
                tool="paste",
                input_type="email",
                input_value=email,
                timestamp=datetime.now(timezone.utc),
                data=output.model_dump(),
            )

        resp.raise_for_status()
        raw_pastes = resp.json() or []

        entries: list[PasteEntry] = []
        recent_count = 0

        for item in raw_pastes:
            source = item.get("Source", "")
            paste_id = item.get("Id", "")
            date_str = item.get("Date") or ""
            email_count = item.get("EmailCount", 0)

            # Normalise date — HIBP returns ISO 8601
            date_short = date_str[:10] if date_str else ""
            if _is_recent(date_str):
                recent_count += 1

            entries.append(
                PasteEntry(
                    paste_id=paste_id,
                    url=_paste_url(source, paste_id),
                    date=date_short,
                    # email_count is the closest proxy HIBP gives us — how many
                    # addresses were in the paste (not the same as credential lines,
                    # but useful for sizing the exposure)
                    credential_count=email_count,
                    has_plaintext_password=False,  # HIBP doesn't expose paste content
                    password_samples=[],
                )
            )

        output = PasteOutput(
            query_email=email,
            paste_count=len(entries),
            credential_paste_count=0,  # can't determine without paste content
            recent_paste_count=recent_count,
            pastes=entries,
            plaintext_passwords_found=0,
        )

        logger.info(
            "paste: OK — pastes=%d recent=%d",
            len(entries),
            recent_count,
        )
        return ToolResult(
            success=True,
            tool="paste",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.warning("paste: FAILED — %s", exc)
        return ToolResult(
            success=False,
            tool="paste",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"paste error: {exc}",
        )
