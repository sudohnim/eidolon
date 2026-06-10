import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import trio
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class HoleheInput(BaseModel):
    email: str


class HoleheMatch(BaseModel):
    platform: str
    exists: bool
    email_recovery: str | None = None
    phone_number: str | None = None
    rate_limited: bool = False


class HoleheOutput(BaseModel):
    email: str
    platforms_checked: int
    platforms_found: list[HoleheMatch]
    found_count: int


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "holehe_response.json"
)


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: HoleheInput) -> ToolResult:
    logger.info("holehe: checking email=%s", inp.email)

    if config.is_test_mode():
        return _load_fixture()

    try:
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
        output = HoleheOutput(
            email=inp.email,
            platforms_checked=len(matches),
            platforms_found=found,
            found_count=len(found),
        )
        logger.info("holehe: checked %d platforms, found %d", len(matches), len(found))
        return ToolResult(
            success=True,
            tool="holehe",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("holehe: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="holehe",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"holehe error: {exc}",
        )


async def _run_async(email: str) -> list[dict]:
    import holehe.modules
    from holehe.core import get_functions, import_submodules

    modules = import_submodules(holehe.modules)
    functions = get_functions(modules)

    out: list[dict] = []
    async with httpx.AsyncClient() as client:
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
