"""FastPeopleSearch — broker profiles scraped via Scrapfly.

Requires SCRAPFLY_API_KEY (render_js + asp bypass). Returns name, age, current
location, and address history.
"""

import re

import requests
import structlog

from eidolon import config
from eidolon.tools.base import Tool
from eidolon.tools.broker_scan import (
    BrokerProfile,
    BrokerProfilesOutput,
    BrokerScanInput,
    state_to_abbrev,
)

FPS_BASE = "https://www.fastpeoplesearch.com/name"


class FastPeopleSearch(Tool[BrokerScanInput, BrokerProfilesOutput]):
    name = "fastpeoplesearch"
    input_type = "name"
    input_schema = BrokerScanInput
    output_schema = BrokerProfilesOutput

    def available(self) -> bool:
        return bool(config.get("SCRAPFLY_API_KEY"))

    def _run(
        self, inp: BrokerScanInput, log: structlog.stdlib.BoundLogger
    ) -> BrokerProfilesOutput:
        name_slug = re.sub(r"[^a-zA-Z0-9\s]", "", inp.value).strip().lower()
        name_slug = re.sub(r"\s+", "-", name_slug)
        if inp.state:
            url = f"{FPS_BASE}/{name_slug}/{state_to_abbrev(inp.state)}"
        else:
            url = f"{FPS_BASE}/{name_slug}"

        resp = requests.get(
            "https://api.scrapfly.io/scrape",
            params={
                "key": config.get("SCRAPFLY_API_KEY"),
                "url": url,
                "render_js": "true",
                "asp": "true",
                "country": "us",
            },
            timeout=60,
        )
        resp.raise_for_status()
        result_obj = resp.json().get("result", {})
        sc = result_obj.get("status_code")
        html = result_obj.get("content", "")
        if sc and sc != 200:
            log.warning("non-200 from target site", status=sc)
            return BrokerProfilesOutput()

        profiles: list[BrokerProfile] = []
        cards = re.findall(
            r'<div class="card-block">(.*?)</div>\s*</div>\s*</div>', html, re.DOTALL
        )
        for card in cards[:10]:
            name_m = re.search(r'<span class="larger">(.*?)</span>', card)
            if not name_m:
                continue
            name = re.sub(r"<[^>]+>", "", name_m.group(1)).strip()
            sub_m = re.search(r"Age\s+(\d+).*?([\w\s]+,\s+[A-Z]{2})", card)
            age = sub_m.group(1) if sub_m else ""
            location = sub_m.group(2).strip() if sub_m else ""
            addresses = re.findall(
                r'title="Property Details[^"]*?for the address ([^"]+)"', card
            )
            addresses = list(dict.fromkeys(addresses))[:3]
            href_m = re.search(r'href="(/[^"]+)"', card)
            profile_url = (
                f"https://www.fastpeoplesearch.com{href_m.group(1)}" if href_m else url
            )

            data_found = ["name"]
            if age:
                data_found.append("age")
            if location:
                data_found.append("address")
            if addresses:
                data_found.append("address_history")

            profiles.append(
                BrokerProfile(
                    broker_name=(
                        f"FastPeopleSearch ({name})" if name else "FastPeopleSearch"
                    ),
                    broker_domain="fastpeoplesearch.com",
                    source="scrapfly",
                    profile_url=profile_url,
                    data_found=data_found,
                    confidence="high",
                    optout_url="https://www.fastpeoplesearch.com/removal",
                )
            )
        log.info("ok", profiles=len(profiles))
        return BrokerProfilesOutput(profiles=profiles, count=len(profiles))
