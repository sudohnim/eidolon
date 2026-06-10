import glob
import json
import subprocess
import sys
from pathlib import Path

import structlog
from pydantic import BaseModel

from eidolon.tools.base import Tool


class BlackbirdInput(BaseModel):
    email: str


class BlackbirdAccount(BaseModel):
    platform: str
    url: str
    category: str = ""
    metadata: list[dict] = []


class BlackbirdOutput(BaseModel):
    email: str = ""
    platforms_checked: int = 0
    accounts_found: list[BlackbirdAccount] = []
    found_count: int = 0


BLACKBIRD_DIR = (
    Path("/opt/blackbird")
    if Path("/opt/blackbird").exists()
    else Path(__file__).parent.parent / "vendor" / "blackbird"
)


class Blackbird(Tool[BlackbirdInput, BlackbirdOutput]):
    name = "blackbird"
    input_schema = BlackbirdInput
    output_schema = BlackbirdOutput

    def available(self) -> bool:
        return BLACKBIRD_DIR.exists()

    def _input_value(self, inp: BlackbirdInput) -> str:
        return inp.email

    def _run(
        self, inp: BlackbirdInput, log: structlog.stdlib.BoundLogger
    ) -> BlackbirdOutput:
        import os

        env = {"PYTHONPATH": str(BLACKBIRD_DIR / "src")}
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

        log.info("ok", found=len(accounts))
        return BlackbirdOutput(
            email=inp.email,
            platforms_checked=platforms_checked,
            accounts_found=accounts,
            found_count=len(accounts),
        )
