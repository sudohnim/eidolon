import asyncio
import logging
from pathlib import Path

import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool


class MaigretInput(BaseModel):
    username: str
    timeout: int = 10
    max_connections: int = 50


class MaigretProfile(BaseModel):
    platform: str
    url: str
    status: str = "CLAIMED"
    ids_found: list[str] = []
    links: list[str] = []


class MaigretOutput(BaseModel):
    username: str = ""
    platforms_checked: int = 0
    profiles_found: list[MaigretProfile] = []
    found_count: int = 0


class Maigret(Tool[MaigretInput, MaigretOutput]):
    name = "maigret"
    input_type = "name"
    input_schema = MaigretInput
    output_schema = MaigretOutput

    def _input_value(self, inp: MaigretInput) -> str:
        return inp.username

    def _run(
        self, inp: MaigretInput, log: structlog.stdlib.BoundLogger
    ) -> MaigretOutput:
        profiles, checked = asyncio.run(_run_async(inp))
        log.info("ok", checked=checked, found=len(profiles))
        return MaigretOutput(
            username=inp.username,
            platforms_checked=checked,
            profiles_found=profiles,
            found_count=len(profiles),
        )


async def _run_async(inp: MaigretInput) -> tuple[list[MaigretProfile], int]:
    import inspect

    from maigret.checking import maigret as maigret_check
    from maigret.result import MaigretCheckStatus
    from maigret.sites import MaigretDatabase

    db = MaigretDatabase()
    db_file = Path(inspect.getfile(MaigretDatabase)).parent / "resources" / "data.json"
    db.load_from_path(str(db_file))

    site_dict = {s.name: s for s in db.sites if not s.disabled}

    # Suppress maigret's own logging
    maigret_logger = logging.getLogger("maigret")
    maigret_logger.setLevel(logging.CRITICAL)

    results: dict = await maigret_check(
        username=inp.username,
        site_dict=site_dict,
        logger=maigret_logger,
        timeout=inp.timeout,
        max_connections=inp.max_connections,
        no_progressbar=True,
    )

    profiles: list[MaigretProfile] = []
    for site_name, result in results.items():
        status = result.get("status")
        if (
            status
            and hasattr(status, "status")
            and status.status == MaigretCheckStatus.CLAIMED
        ):
            site_obj = result.get("site", {})
            url = result.get("url_user", "") or (
                site_obj.url.replace("{username}", inp.username)
                if hasattr(site_obj, "url")
                else ""
            )
            ids = [str(v) for k, v in (result.get("ids_userdata") or {}).items() if v]
            links = result.get("links", []) or []
            profiles.append(
                MaigretProfile(
                    platform=site_name,
                    url=url,
                    status="CLAIMED",
                    ids_found=ids,
                    links=links if isinstance(links, list) else [],
                )
            )

    return profiles, len(site_dict)
