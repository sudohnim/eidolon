import json
import logging
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class GHuntInput(BaseModel):
    email: str


class GHuntOutput(BaseModel):
    email: str
    found: bool
    name: str = ""
    profile_photo_url: str = ""
    google_services: list[str] = []
    maps_reviews_count: int = 0
    youtube_channel: str = ""
    raw: dict = {}


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "ghunt_response.json"
)
CREDS_PATH = Path.home() / ".malfrats" / "ghunt" / "creds.m"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: GHuntInput) -> ToolResult:
    logger.info("ghunt: searching email=%s", inp.email)

    if config.is_test_mode():
        return _load_fixture()

    if not CREDS_PATH.exists():
        logger.warning(
            "ghunt: no credentials found at %s — run 'ghunt login' to enable",
            CREDS_PATH,
        )
        output = GHuntOutput(email=inp.email, found=False)
        return ToolResult(
            success=True,
            tool="ghunt",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        # ghunt has no __main__, must be called via its installed CLI entrypoint
        ghunt_bin = Path(sys.executable).parent / "ghunt"
        result = subprocess.run(
            [str(ghunt_bin), "email", "--json", out_path, inp.email],
            capture_output=True,
            text=True,
            timeout=60,
        )

        raw: dict = {}
        if Path(out_path).exists():
            content = Path(out_path).read_text().strip()
            Path(out_path).unlink(missing_ok=True)
            if content:
                try:
                    raw = json.loads(content)
                except json.JSONDecodeError:
                    logger.warning(
                        "ghunt: output file was not valid JSON — treating as no results"
                    )

        if not raw or result.returncode != 0:
            if result.stderr:
                logger.warning("ghunt: stderr:\n%s", result.stderr[:2000])
            if result.stdout:
                logger.warning("ghunt: stdout:\n%s", result.stdout[:500])
            logger.info(
                "ghunt: no results for %s (returncode=%s)", inp.email, result.returncode
            )
            output = GHuntOutput(email=inp.email, found=False)
        else:
            profile = raw.get("profile", raw)
            output = GHuntOutput(
                email=inp.email,
                found=True,
                name=(
                    profile.get("name", {}).get("fullname", "")
                    if isinstance(profile.get("name"), dict)
                    else str(profile.get("name", ""))
                ),
                profile_photo_url=(
                    profile.get("profile_photos", [{}])[0].get("url", "")
                    if profile.get("profile_photos")
                    else ""
                ),
                google_services=(
                    list(profile.get("activated_services", {}).keys())
                    if isinstance(profile.get("activated_services"), dict)
                    else []
                ),
                maps_reviews_count=(
                    profile.get("maps", {}).get("reviews_count", 0)
                    if isinstance(profile.get("maps"), dict)
                    else 0
                ),
                youtube_channel=(
                    profile.get("youtube", {}).get("channel_url", "")
                    if isinstance(profile.get("youtube"), dict)
                    else ""
                ),
                raw=raw,
            )

        logger.info("ghunt: found=%s services=%s", output.found, output.google_services)
        return ToolResult(
            success=True,
            tool="ghunt",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("ghunt: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="ghunt",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"ghunt error: {exc}",
        )
