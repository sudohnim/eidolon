from typing import Any

import httpx
import structlog
import trio
from pydantic import BaseModel

from eidolon.core.findings import Account, Confidence, Finding, Severity
from eidolon.sources.base import Tool


class HoleheInput(BaseModel):
    email: str


class HoleheMatch(BaseModel):
    platform: str
    exists: bool
    email_recovery: str | None = None
    phone_number: str | None = None
    rate_limited: bool = False


class HoleheOutput(BaseModel):
    email: str = ""
    platforms_checked: int = 0
    platforms_found: list[HoleheMatch] = []
    found_count: int = 0


class Holehe(Tool[HoleheInput, HoleheOutput]):
    name = "holehe"
    input_schema = HoleheInput
    output_schema = HoleheOutput
    #: no single vendor — probes ~121 platforms' password-reset flows
    vendor = ""

    def _input_value(self, inp: HoleheInput) -> str:
        return inp.email

    def to_findings(self, out: HoleheOutput) -> list[Finding]:
        """One Account per confirmed registration (password-reset probing is
        confirmation the address is registered, so active=True)."""
        return [
            Account(
                dedup_key=f"account:{m.platform.lower()}",
                title=m.platform,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                platform=m.platform,
                active=True,
            )
            for m in out.platforms_found
            if m.platform and m.exists
        ]

    def run_summary(self, out: HoleheOutput) -> str:
        return f"{out.found_count} registrations found"

    def _run(self, inp: HoleheInput, log: structlog.stdlib.BoundLogger) -> HoleheOutput:
        results = trio.run(_run_async, inp.email)
        matches = [
            HoleheMatch(
                platform=r["name"],
                exists=r.get("exists", False),
                email_recovery=r.get("emailrecovery"),
                phone_number=r.get("phoneNumber"),
                rate_limited=r.get("rateLimit", False),
            )
            for r in results
        ]
        found = [m for m in matches if m.exists]
        log.info("ok", checked=len(matches), found=len(found))
        return HoleheOutput(
            email=inp.email,
            platforms_checked=len(matches),
            platforms_found=found,
            found_count=len(found),
        )


async def _run_async(email: str) -> list[dict]:
    import holehe.modules
    from holehe.core import get_functions, import_submodules

    modules = import_submodules(holehe.modules)
    functions = get_functions(modules)

    # OPSEC.3: build the client through the shared egress-aware helper so the
    # active policy (proxy, UA, timeouts, trust_env=False) applies to every one
    # of the ~121 platform probes instead of a bare client.
    from eidolon.sources._http import async_client

    out: list[dict] = []
    async with async_client() as client:
        async with trio.open_nursery() as nursery:
            for func in functions:
                nursery.start_soon(_check_one, func, email, client, out)

    return out


async def _check_one(
    func: Any, email: str, client: httpx.AsyncClient, out: list
) -> None:
    try:
        await func(email, client, out)
    except Exception:
        pass
