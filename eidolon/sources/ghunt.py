import json
import subprocess
import sys
import tempfile
from pathlib import Path

import structlog
from pydantic import BaseModel

from eidolon.core.findings import Finding, GoogleFootprint, Severity
from eidolon.sources.base import Tool


class GHuntInput(BaseModel):
    email: str


class GHuntOutput(BaseModel):
    email: str = ""
    found: bool = False
    name: str = ""
    profile_photo_url: str = ""
    google_services: list[str] = []
    maps_reviews_count: int = 0
    youtube_channel: str = ""
    raw: dict = {}


CREDS_PATH = Path.home() / ".malfrats" / "ghunt" / "creds.m"


class Ghunt(Tool[GHuntInput, GHuntOutput]):
    name = "ghunt"
    input_schema = GHuntInput
    output_schema = GHuntOutput
    vendor = "google.com"

    def available(self) -> bool:
        return CREDS_PATH.exists()

    def _input_value(self, inp: GHuntInput) -> str:
        return inp.email

    def to_findings(self, out: GHuntOutput) -> list[Finding]:
        """One GoogleFootprint per found Google account — the target's public
        Google surface (name, services, YouTube channel, Maps activity)."""
        if not out.found:
            return []
        return [
            GoogleFootprint(
                dedup_key="google:account",
                title=f"Google account: {out.name}" if out.name else "Google account",
                severity=Severity.LOW,
                account_name=out.name,
                services=list(out.google_services),
                youtube_channel=out.youtube_channel,
                maps_reviews_count=out.maps_reviews_count,
            )
        ]

    def run_summary(self, out: GHuntOutput) -> str:
        return "Found" if out.found else "Not found"

    def _run(self, inp: GHuntInput, log: structlog.stdlib.BoundLogger) -> GHuntOutput:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name

        # ghunt has no __main__, must be called via its installed CLI entrypoint
        ghunt_bin = Path(sys.executable).parent / "ghunt"
        # OPSEC.4: pass the active policy's proxy through the child env so this
        # subprocess doesn't egress in the clear while HTTP tools are proxied.
        from eidolon.core.egress import subprocess_env

        result = subprocess.run(
            [str(ghunt_bin), "email", "--json", out_path, inp.email],
            capture_output=True,
            text=True,
            timeout=60,
            env=subprocess_env("ghunt"),
        )

        raw: dict = {}
        if Path(out_path).exists():
            content = Path(out_path).read_text().strip()
            Path(out_path).unlink(missing_ok=True)
            if content:
                try:
                    raw = json.loads(content)
                except json.JSONDecodeError:
                    log.warning("ghunt output not valid JSON — treating as no results")

        if not raw or result.returncode != 0:
            if result.stderr:
                log.warning("ghunt stderr", stderr=result.stderr[:2000])
            if result.stdout:
                log.warning("ghunt stdout", stdout=result.stdout[:500])
            return GHuntOutput(email=inp.email, found=False)

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
        log.info("ok", found=output.found, services=output.google_services)
        return output
