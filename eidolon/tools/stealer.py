"""Hudson Rock Cavalier — infostealer log lookup.

Free, no API key required.
GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?login=EMAIL

Infostealer logs differ fundamentally from breach databases:
- Breaches: one service's user table was stolen
- Stealer logs: malware ran on the victim's machine and exfiltrated ALL saved
  credentials from their browser, plus cookies, session tokens, and installed apps

A hit here means an attacker may have had live session access, not just a
password for one site.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class StealerLog(BaseModel):
    computer_name: str = ""
    operating_system: str = ""
    ip: str = ""
    date_compromised: str = ""
    malware_family: str = ""
    # How many saved credentials were on the infected machine
    credential_count: int = 0
    # How many applications were fingerprinted
    application_count: int = 0


class StealerOutput(BaseModel):
    query_email: str = ""
    found: bool = False
    stealer_count: int = 0
    logs: list[StealerLog] = []
    malware_families: list[str] = []
    # ISO date strings — earliest/latest known compromise
    earliest_compromise: str = ""
    latest_compromise: str = ""


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "stealer_response.json"
)

CAVALIER_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(email: str) -> ToolResult:
    logger.info("stealer: checking Hudson Rock Cavalier for email=%s", email)

    if config.is_test_mode():
        return _load_fixture()

    try:
        # Build URL manually — requests percent-encodes @ as %40,
        # which Hudson Rock rejects
        url = f"{CAVALIER_URL}?email={email}"
        resp = requests.get(
            url,
            headers={"User-Agent": "osint-agent/1.0"},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()

        raw_logs = data.get("stealers") or []

        if not raw_logs:
            logger.info("stealer: no hits for %s", email)
            output = StealerOutput(query_email=email, found=False)
            return ToolResult(
                success=True,
                tool="stealer",
                input_type="email",
                input_value=email,
                timestamp=datetime.now(timezone.utc),
                data=output.model_dump(),
            )

        logs: list[StealerLog] = []
        families: list[str] = []
        dates: list[str] = []

        for raw in raw_logs:
            # Normalize date — API returns ISO strings
            raw_date = str(raw.get("date_compromised") or "")
            date_str = raw_date[:10] if raw_date else ""
            if date_str:
                dates.append(date_str)

            # Infer malware family from the malware_path field
            fam_name = _infer_family(raw.get("malware_path") or "") or "Unknown"
            if fam_name not in families:
                families.append(fam_name)

            # API returns total_user_services (saved credentials count) and
            # total_corporate_services (work/corporate credentials count)
            total_creds = (raw.get("total_user_services") or 0) + (
                raw.get("total_corporate_services") or 0
            )

            logs.append(
                StealerLog(
                    computer_name=raw.get("computer_name", ""),
                    operating_system=raw.get("operating_system", ""),
                    ip=raw.get("ip", ""),  # already partially masked by Hudson Rock
                    date_compromised=date_str,
                    malware_family=fam_name,
                    credential_count=total_creds,
                    application_count=0,  # not exposed in free tier response
                )
            )

        dates.sort()
        output = StealerOutput(
            query_email=email,
            found=True,
            stealer_count=len(logs),
            logs=logs,
            malware_families=families,
            earliest_compromise=dates[0] if dates else "",
            latest_compromise=dates[-1] if dates else "",
        )

        logger.info(
            "stealer: OK — hits=%d families=%s earliest=%s latest=%s",
            len(logs),
            families,
            output.earliest_compromise,
            output.latest_compromise,
        )
        return ToolResult(
            success=True,
            tool="stealer",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("stealer: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="stealer",
            input_type="email",
            input_value=email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"stealer error: {exc}",
        )


def _infer_family(malware_path: str) -> str:
    """Best-effort malware family name from the file path string."""
    path_lower = malware_path.lower()
    for name in ("redline", "vidar", "raccoon", "azorult", "lumma", "stealc", "meta"):
        if name in path_lower:
            return name.capitalize()
    return ""
