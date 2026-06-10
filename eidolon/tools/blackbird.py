import glob
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class BlackbirdInput(BaseModel):
    email: str


class BlackbirdAccount(BaseModel):
    platform: str
    url: str
    category: str = ""
    metadata: list[dict] = []


class BlackbirdOutput(BaseModel):
    email: str
    platforms_checked: int
    accounts_found: list[BlackbirdAccount]
    found_count: int


logger = logging.getLogger(__name__)

FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "blackbird_response.json"
)
BLACKBIRD_DIR = (
    Path("/opt/blackbird")
    if Path("/opt/blackbird").exists()
    else Path(__file__).parent.parent / "vendor" / "blackbird"
)


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def run(inp: BlackbirdInput) -> ToolResult:
    logger.info("blackbird: searching email=%s", inp.email)

    if config.is_test_mode():
        return _load_fixture()

    if not BLACKBIRD_DIR.exists():
        logger.warning("blackbird: vendor/blackbird not found, skipping")
        output = BlackbirdOutput(
            email=inp.email, platforms_checked=0, accounts_found=[], found_count=0
        )
        return ToolResult(
            success=True,
            tool="blackbird",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    try:
        env = {"PYTHONPATH": str(BLACKBIRD_DIR / "src")}
        import os

        env.update({k: v for k, v in os.environ.items() if k not in env})

        subprocess.run(
            [sys.executable, "blackbird.py", "--json", "-e", inp.email, "--no-update"],
            cwd=str(BLACKBIRD_DIR),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Find the output JSON file in results/
        pattern = str(BLACKBIRD_DIR / "results" / f"*{inp.email}*" / "*.json")
        json_files = sorted(
            glob.glob(pattern), key=lambda f: Path(f).stat().st_mtime, reverse=True
        )

        accounts: list[BlackbirdAccount] = []
        platforms_checked = 16  # default from blackbird email-data.json

        if json_files:
            raw_accounts = json.loads(Path(json_files[0]).read_text())
            for item in raw_accounts:
                if item.get("status") == "FOUND":
                    accounts.append(
                        BlackbirdAccount(
                            platform=item.get("name", ""),
                            url=item.get("url", ""),
                            category=item.get("category", ""),
                            metadata=item.get("metadata") or [],
                        )
                    )
        else:
            # No file = no results found
            logger.info("blackbird: no accounts found for %s", inp.email)

        output = BlackbirdOutput(
            email=inp.email,
            platforms_checked=platforms_checked,
            accounts_found=accounts,
            found_count=len(accounts),
        )
        logger.info("blackbird: found %d accounts", len(accounts))
        return ToolResult(
            success=True,
            tool="blackbird",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("blackbird: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="blackbird",
            input_type="email",
            input_value=inp.email,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"blackbird error: {exc}",
        )
