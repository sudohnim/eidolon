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

import requests
import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool


class StealerInput(BaseModel):
    email: str


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


CAVALIER_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login"


class Stealer(Tool[StealerInput, StealerOutput]):
    name = "stealer"
    input_schema = StealerInput
    output_schema = StealerOutput

    def _input_value(self, inp: StealerInput) -> str:
        return inp.email

    def _run(
        self, inp: StealerInput, log: structlog.stdlib.BoundLogger
    ) -> StealerOutput:
        email = inp.email
        # Build URL manually — requests percent-encodes @ as %40, which HR rejects
        resp = requests.get(
            f"{CAVALIER_URL}?email={email}",
            headers={"User-Agent": "eidolon/1.0"},
            timeout=20,
        )
        resp.raise_for_status()
        raw_logs = resp.json().get("stealers") or []

        if not raw_logs:
            log.info("ok", found=False)
            return StealerOutput(query_email=email, found=False)

        logs: list[StealerLog] = []
        families: list[str] = []
        dates: list[str] = []

        for raw in raw_logs:
            raw_date = str(raw.get("date_compromised") or "")
            date_str = raw_date[:10] if raw_date else ""
            if date_str:
                dates.append(date_str)

            fam_name = _infer_family(raw.get("malware_path") or "") or "Unknown"
            if fam_name not in families:
                families.append(fam_name)

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
        log.info("ok", found=True, hits=len(logs), families=families)
        return output


def _infer_family(malware_path: str) -> str:
    """Best-effort malware family name from the file path string."""
    path_lower = malware_path.lower()
    for name in ("redline", "vidar", "raccoon", "azorult", "lumma", "stealc", "meta"):
        if name in path_lower:
            return name.capitalize()
    return ""
