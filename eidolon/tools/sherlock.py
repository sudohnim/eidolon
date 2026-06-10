import json
import logging
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class SherlockInput(BaseModel):
    username: str


class SherlockProfile(BaseModel):
    platform: str
    url: str


class SherlockOutput(BaseModel):
    username: str
    platforms_checked: int
    profiles_found: list[SherlockProfile]
    found_count: int


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "sherlock_response.json"
)
FOUND_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)", re.MULTILINE)
CHECKED_RE = re.compile(r"(\d+)\s+sites?", re.IGNORECASE)


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: SherlockInput) -> ToolResult:
    logger.info("sherlock: searching username=%s", inp.username)

    if config.is_test_mode():
        return _load_fixture()

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "sherlock_project",
                "--print-found",
                "--no-color",
                "--no-txt",
                inp.username,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        stdout = result.stdout + result.stderr
        profiles = [
            SherlockProfile(platform=m.group(1).strip(), url=m.group(2).strip())
            for m in FOUND_RE.finditer(stdout)
        ]

        checked_match = CHECKED_RE.search(stdout)
        platforms_checked = int(checked_match.group(1)) if checked_match else 0

        output = SherlockOutput(
            username=inp.username,
            platforms_checked=platforms_checked,
            profiles_found=profiles,
            found_count=len(profiles),
        )
        logger.info(
            "sherlock: checked %d platforms, found %d profiles",
            platforms_checked,
            len(profiles),
        )
        return ToolResult(
            success=True,
            tool="sherlock",
            input_type="name",
            input_value=inp.username,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("sherlock: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="sherlock",
            input_type="name",
            input_value=inp.username,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"sherlock error: {exc}",
        )
