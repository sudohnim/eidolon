"""TruePeopleSearch — broker profiles scraped via Scrapfly.

Requires SCRAPFLY_API_KEY. Returns name, age, current location, address history,
and relatives — all free, no account required.
"""

import re
import urllib.parse

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

TPS_BASE = "https://www.truepeoplesearch.com/results"


class TruePeopleSearch(Tool[BrokerScanInput, BrokerProfilesOutput]):
    name = "truepeoplesearch"
    requires = ["SCRAPFLY_API_KEY"]
    input_type = "name"
    input_schema = BrokerScanInput
    output_schema = BrokerProfilesOutput

    def available(self) -> bool:
        return bool(config.get("SCRAPFLY_API_KEY"))

    def _run(
        self, inp: BrokerScanInput, log: structlog.stdlib.BoundLogger
    ) -> BrokerProfilesOutput:
        location_parts = []
        if inp.city:
            location_parts.append(inp.city)
        if inp.state:
            location_parts.append(state_to_abbrev(inp.state).upper())
        location = ", ".join(location_parts) if location_parts else inp.zip_code or ""

        qs_params: dict = {"name": inp.value}
        if location:
            qs_params["citystatezip"] = location
        target_url = f"{TPS_BASE}?{urllib.parse.urlencode(qs_params)}"

        resp = requests.get(
            "https://api.scrapfly.io/scrape",
            params={
                "key": config.get("SCRAPFLY_API_KEY"),
                "url": target_url,
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
            r'<div[^>]*class="[^"]*card-block[^"]*shadow-form[^"]*"[^>]*>'
            r"(.*?)</div>\s*</div>\s*</div>",
            html,
            re.DOTALL,
        )
        for card in cards[:10]:
            name_m = re.search(
                r'class="h4[^"]*"[^>]*>(.*?)</(?:span|div)>', card, re.DOTALL
            )
            if not name_m:
                continue
            name = re.sub(r"<[^>]+>", "", name_m.group(1)).strip()
            age_m = re.search(r"Age[:\s]+(\d+)", card)
            age = age_m.group(1) if age_m else ""
            loc_m = re.search(r"([\w\s]+,\s+[A-Z]{2})", card)
            current_loc = loc_m.group(1).strip() if loc_m else ""
            past_addresses = re.findall(
                r"(?:lived in|previous address)[^<]*?([A-Z][^<]{5,40},\s+[A-Z]{2})",
                card,
                re.IGNORECASE,
            )
            relatives = re.findall(
                r"(?:Relatives|Associated)[^<]*?<[^>]+>([A-Z][a-z]+ [A-Z][a-z]+)",
                card,
            )
            href_m = re.search(r'href="(/find/[^"]+)"', card)
            profile_url = (
                f"https://www.truepeoplesearch.com{href_m.group(1)}"
                if href_m
                else TPS_BASE
            )

            data_found = ["name"]
            if age:
                data_found.append("age")
            if current_loc:
                data_found.append("address")
            if past_addresses:
                data_found.append("address_history")
            if relatives:
                data_found.append("relatives")

            profiles.append(
                BrokerProfile(
                    broker_name=(
                        f"TruePeopleSearch ({name})" if name else "TruePeopleSearch"
                    ),
                    broker_domain="truepeoplesearch.com",
                    source="scrapfly",
                    profile_url=profile_url,
                    data_found=data_found,
                    confidence="high",
                    optout_url="https://www.truepeoplesearch.com/removal",
                )
            )
        log.info("ok", profiles=len(profiles))
        return BrokerProfilesOutput(profiles=profiles, count=len(profiles))
