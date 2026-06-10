import json
import logging
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import requests
from apify_client import ApifyClient
from pydantic import BaseModel

from eidolon import config
from eidolon.core.models import ToolResult


class BrokerScanInput(BaseModel):
    input_type: Literal["email", "phone", "name", "org"]
    value: str
    first_name: str | None = None
    last_name: str | None = None
    city: str | None = None
    state: str | None = None
    zip_code: str | None = None


class BrokerProfile(BaseModel):
    broker_name: str
    broker_domain: str
    source: Literal["apify", "google_cse", "scrapfly"]
    profile_url: str | None
    data_found: list[str]
    confidence: Literal["high", "medium", "low"]
    optout_url: str


class BrokerScanOutput(BaseModel):
    query_value: str
    brokers_found_count: int
    brokers_found: list[BrokerProfile]
    exposure_score: int
    easyoptouts_url: str = "https://easyoptouts.com/dashboard"
    priority_optouts: list[str]
    bazzell_tier1_found: list[str] = []
    manual_removal_required: list[str] = []
    easyoptouts_covers: int = 0


logger = logging.getLogger(__name__)

# Maps full state names to 2-letter abbreviations for FastPeopleSearch URL slugs
_STATE_ABBREVS = {
    "alabama": "al",
    "alaska": "ak",
    "arizona": "az",
    "arkansas": "ar",
    "california": "ca",
    "colorado": "co",
    "connecticut": "ct",
    "delaware": "de",
    "florida": "fl",
    "georgia": "ga",
    "hawaii": "hi",
    "idaho": "id",
    "illinois": "il",
    "indiana": "in",
    "iowa": "ia",
    "kansas": "ks",
    "kentucky": "ky",
    "louisiana": "la",
    "maine": "me",
    "maryland": "md",
    "massachusetts": "ma",
    "michigan": "mi",
    "minnesota": "mn",
    "mississippi": "ms",
    "missouri": "mo",
    "montana": "mt",
    "nebraska": "ne",
    "nevada": "nv",
    "new hampshire": "nh",
    "new jersey": "nj",
    "new mexico": "nm",
    "new york": "ny",
    "north carolina": "nc",
    "north dakota": "nd",
    "ohio": "oh",
    "oklahoma": "ok",
    "oregon": "or",
    "pennsylvania": "pa",
    "rhode island": "ri",
    "south carolina": "sc",
    "south dakota": "sd",
    "tennessee": "tn",
    "texas": "tx",
    "utah": "ut",
    "vermont": "vt",
    "virginia": "va",
    "washington": "wa",
    "west virginia": "wv",
    "wisconsin": "wi",
    "wyoming": "wy",
    "district of columbia": "dc",
}


def _state_to_abbrev(state: str) -> str:
    """Convert full state name or abbreviation to 2-letter lowercase slug."""
    s = state.strip().lower()
    # Already a 2-letter abbreviation
    if len(re.sub(r"[^a-z]", "", s)) == 2:
        return re.sub(r"[^a-z]", "", s)
    return _STATE_ABBREVS.get(s, s[:2])


FIXTURE_PATH = (
    Path(__file__).parent.parent.parent
    / "tests"
    / "fixtures"
    / "broker_apify_response.json"
)
FPS_BASE = "https://www.fastpeoplesearch.com/name"


def _load_fixture() -> ToolResult:
    raw = json.loads(FIXTURE_PATH.read_text())
    return ToolResult(**raw)


def _run_apify(inp: BrokerScanInput) -> list[BrokerProfile]:
    token = config.get("APIFY_API_TOKEN")
    actor_id = config.get("APIFY_ACTOR_ID")
    scrapfly_key = config.get("SCRAPFLY_API_KEY")

    run_input: dict = {
        "scrapFlyApiKey": scrapfly_key,
        "searches": [],
    }

    # Actor requires name + address together — skip if we have no location
    if inp.input_type != "name":
        logger.info(
            "broker_scan: apify skipped for input_type=%s (name required)",
            inp.input_type,
        )
        return []

    # Build best-available address string: "City, ST  ZIP" or just state, etc.
    addr_parts = []
    if inp.city:
        addr_parts.append(inp.city)
    if inp.state:
        addr_parts.append(inp.state)
    if inp.zip_code:
        addr_parts.append(inp.zip_code)
    address = ", ".join(addr_parts)

    if not address:
        logger.info(
            "broker_scan: apify skipped — actor requires an "
            "address/state alongside name"
        )
        return []

    run_input["name"] = inp.value
    run_input["address"] = address
    run_input["maxConcurrency"] = 3

    logger.info(
        "broker_scan: starting apify actor %s name=%r address=%r",
        actor_id,
        inp.value,
        address,
    )
    client = ApifyClient(token)
    # ApifyClient.call() returns a pydantic Run object (or None), NOT a dict —
    # access fields as attributes (run.id / run.status / run.default_dataset_id).
    run = client.actor(actor_id).call(run_input=run_input)
    if run is None:
        logger.warning("broker_scan: apify returned no Run object — no results")
        return []
    run_id = run.id
    status = run.status
    dataset_id = run.default_dataset_id
    logger.info(
        "broker_scan: apify run finished run_id=%s status=%s dataset_id=%s",
        run_id,
        status,
        dataset_id,
    )

    if not dataset_id:
        logger.warning("broker_scan: apify returned no defaultDatasetId — no results")
        return []

    profiles = []
    for item in client.dataset(dataset_id).iterate_items():
        profiles.append(
            BrokerProfile(
                broker_name=item.get("source", "Unknown"),
                broker_domain=item.get("domain", ""),
                source="apify",
                profile_url=item.get("profileUrl"),
                data_found=item.get("dataFound", []),
                confidence="high" if item.get("exactMatch") else "medium",
                optout_url=item.get("optoutUrl", ""),
            )
        )

    logger.info("broker_scan: apify returned %d profiles", len(profiles))
    return profiles


def _run_fastpeoplesearch(inp: BrokerScanInput) -> list[BrokerProfile]:
    """Scrape FastPeopleSearch via Scrapfly (requires render_js + asp bypass)."""
    try:
        scrapfly_key = config.get("SCRAPFLY_API_KEY")
    except RuntimeError:
        scrapfly_key = ""
    if not scrapfly_key:
        logger.info("broker_scan: SCRAPFLY_API_KEY not set, skipping FastPeopleSearch")
        return []

    # Build URL: /name/john-smith or /name/john-smith/ca for state-scoped search
    name_slug = re.sub(r"[^a-zA-Z0-9\s]", "", inp.value).strip().lower()
    name_slug = re.sub(r"\s+", "-", name_slug)
    if inp.state:
        state_slug = _state_to_abbrev(inp.state)
        url = f"{FPS_BASE}/{name_slug}/{state_slug}"
    else:
        url = f"{FPS_BASE}/{name_slug}"

    logger.info("broker_scan: scraping FastPeopleSearch url=%s", url)
    try:
        resp = requests.get(
            "https://api.scrapfly.io/scrape",
            params={
                "key": scrapfly_key,
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
        logger.info(
            "broker_scan: FastPeopleSearch scrapfly status=%s html_len=%d",
            sc,
            len(html),
        )
        if sc and sc != 200:
            logger.warning(
                "broker_scan: FastPeopleSearch non-200 from target site: %s", sc
            )
            return []
    except Exception as exc:
        logger.warning("broker_scan: FastPeopleSearch scrape failed: %s", exc)
        return []

    # Parse person cards
    profiles: list[BrokerProfile] = []
    cards = re.findall(
        r'<div class="card-block">(.*?)</div>\s*</div>\s*</div>', html, re.DOTALL
    )
    for card in cards[:10]:  # cap at 10 results
        # Name
        name_m = re.search(r'<span class="larger">(.*?)</span>', card)
        if not name_m:
            continue
        name = re.sub(r"<[^>]+>", "", name_m.group(1)).strip()

        # Age + location from subtitle
        sub_m = re.search(r"Age\s+(\d+).*?([\w\s]+,\s+[A-Z]{2})", card)
        age = sub_m.group(1) if sub_m else ""
        location = sub_m.group(2).strip() if sub_m else ""

        # Addresses from title attributes
        addresses = re.findall(
            r'title="Property Details[^"]*?for the address ([^"]+)"', card
        )
        addresses = list(dict.fromkeys(addresses))[:3]  # dedup, cap at 3

        # Profile URL
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

    logger.info("broker_scan: FastPeopleSearch returned %d profiles", len(profiles))
    return profiles


TPS_BASE = "https://www.truepeoplesearch.com/results"


def _run_truepeoplesearch(inp: BrokerScanInput) -> list[BrokerProfile]:
    """Scrape TruePeopleSearch via Scrapfly.

    URL: /results?name=John+Smith&citystatezip=New+York%2C+NY
    Returns relatives, address history, age — all free, no account required.
    """
    try:
        scrapfly_key = config.get("SCRAPFLY_API_KEY")
    except RuntimeError:
        scrapfly_key = ""
    if not scrapfly_key:
        logger.info("broker_scan: SCRAPFLY_API_KEY not set, skipping TruePeopleSearch")
        return []

    # Build location param: prefer "City, ST" or zip or state alone
    location_parts = []
    if inp.city:
        location_parts.append(inp.city)
    if inp.state:
        location_parts.append(_state_to_abbrev(inp.state).upper())
    location = ", ".join(location_parts) if location_parts else inp.zip_code or ""

    qs_params: dict = {"name": inp.value}
    if location:
        qs_params["citystatezip"] = location

    # Embed query params directly in the URL — Scrapfly passes the url verbatim
    # to the target site; a separate "query_string" param is not supported.
    target_url = f"{TPS_BASE}?{urllib.parse.urlencode(qs_params)}"

    logger.info(
        "broker_scan: scraping TruePeopleSearch url=%s",
        target_url,
    )
    try:
        resp = requests.get(
            "https://api.scrapfly.io/scrape",
            params={
                "key": scrapfly_key,
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
        logger.info(
            "broker_scan: TruePeopleSearch scrapfly status=%s html_len=%d",
            sc,
            len(html),
        )
        if sc and sc != 200:
            logger.warning(
                "broker_scan: TruePeopleSearch non-200 from target site: %s", sc
            )
            return []
    except Exception as exc:
        logger.warning("broker_scan: TruePeopleSearch scrape failed: %s", exc)
        return []

    # TruePeopleSearch result cards: div.card-block.shadow-form.card-block-detail
    profiles: list[BrokerProfile] = []
    cards = re.findall(
        r'<div[^>]*class="[^"]*card-block[^"]*shadow-form[^"]*"[^>]*>'
        r"(.*?)</div>\s*</div>\s*</div>",
        html,
        re.DOTALL,
    )

    for card in cards[:10]:
        # Name — inside <span class="h4"> or <div class="h4">
        name_m = re.search(
            r'class="h4[^"]*"[^>]*>(.*?)</(?:span|div)>', card, re.DOTALL
        )
        if not name_m:
            continue
        name = re.sub(r"<[^>]+>", "", name_m.group(1)).strip()

        # Age
        age_m = re.search(r"Age[:\s]+(\d+)", card)
        age = age_m.group(1) if age_m else ""

        # Current location (City, ST pattern)
        loc_m = re.search(r"([\w\s]+,\s+[A-Z]{2})", card)
        current_loc = loc_m.group(1).strip() if loc_m else ""

        # Past addresses
        past_addresses = re.findall(
            r"(?:lived in|previous address)[^<]*?([A-Z][^<]{5,40},\s+[A-Z]{2})",
            card,
            re.IGNORECASE,
        )

        # Relatives — "Also known as" or "Relatives:" section
        relatives = re.findall(
            r"(?:Relatives|Associated)[^<]*?<[^>]+>([A-Z][a-z]+ [A-Z][a-z]+)",
            card,
        )

        # Profile URL
        href_m = re.search(r'href="(/find/[^"]+)"', card)
        profile_url = (
            f"https://www.truepeoplesearch.com{href_m.group(1)}" if href_m else TPS_BASE
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

    logger.info("broker_scan: TruePeopleSearch returned %d profiles", len(profiles))
    return profiles


BAZZELL_DB_PATH = Path(__file__).parent.parent / "data" / "bazzell_brokers.json"


def _cross_reference_bazzell(profiles: list[BrokerProfile]) -> dict:
    """Cross-reference found broker profiles against Bazzell's removal database.

    Returns:
        dict with keys:
          bazzell_tier1_found       - names of tier-1 brokers detected in scan
          manual_removal_required   - broker names found that EasyOptOuts does NOT cover
          easyoptouts_would_cover   - count of found brokers that EasyOptOuts covers
    """
    try:
        db: list[dict] = json.loads(BAZZELL_DB_PATH.read_text())
    except Exception as exc:
        logger.warning("bazzell cross-reference: failed to load DB — %s", exc)
        return {
            "bazzell_tier1_found": [],
            "manual_removal_required": [],
            "easyoptouts_would_cover": 0,
        }

    # Build a domain -> record map
    domain_map: dict[str, dict] = {entry["domain"]: entry for entry in db}

    tier1_found: list[str] = []
    manual_required: list[str] = []
    easyoptouts_count = 0

    for profile in profiles:
        domain = (profile.broker_domain or "").lower().removeprefix("www.")
        entry = domain_map.get(domain)
        if not entry:
            continue

        if entry.get("tier") == 1:
            tier1_found.append(entry["name"])

        if entry.get("easyoptouts_covered"):
            easyoptouts_count += 1
        else:
            manual_required.append(entry["name"])

    return {
        "bazzell_tier1_found": tier1_found,
        "manual_removal_required": manual_required,
        "easyoptouts_would_cover": easyoptouts_count,
    }


def _calculate_exposure_score(profiles: list[BrokerProfile]) -> int:
    score = 0
    depth_weights = {
        "email": 15,
        "phone": 15,
        "address": 10,
        "relatives": 20,
        "name": 5,
        "age": 5,
    }
    for p in profiles:
        score += 5
        if p.confidence == "high":
            score += 10
        elif p.confidence == "medium":
            score += 5
        for field in p.data_found:
            score += depth_weights.get(field, 3)
    return min(score, 100)


def run(inp: BrokerScanInput) -> ToolResult:
    logger.info("broker_scan: scanning input_type=%s", inp.input_type)

    if config.is_test_mode():
        return _load_fixture()

    # Broker scan only meaningful for name inputs — brokers list by name/address
    if inp.input_type not in ("name",):
        logger.info(
            "broker_scan: skipping for input_type=%s (name required)", inp.input_type
        )
        output = BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=0,
            brokers_found=[],
            exposure_score=0,
            priority_optouts=[],
        )
        return ToolResult(
            success=True,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    try:
        apify_profiles = _run_apify(inp)
        fps_profiles = _run_fastpeoplesearch(inp)
        tps_profiles = _run_truepeoplesearch(inp)
        all_profiles = apify_profiles + fps_profiles + tps_profiles

        seen: set[str] = set()
        deduped: list[BrokerProfile] = []
        for p in all_profiles:
            if p.broker_domain not in seen:
                seen.add(p.broker_domain)
                deduped.append(p)
        all_profiles = deduped

        exposure_score = _calculate_exposure_score(all_profiles)
        sorted_by_depth = sorted(
            all_profiles, key=lambda p: len(p.data_found), reverse=True
        )
        priority_optouts = [p.broker_domain for p in sorted_by_depth[:5]]

        bazzell = _cross_reference_bazzell(all_profiles)

        output = BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=len(all_profiles),
            brokers_found=all_profiles,
            exposure_score=exposure_score,
            priority_optouts=priority_optouts,
            bazzell_tier1_found=bazzell["bazzell_tier1_found"],
            manual_removal_required=bazzell["manual_removal_required"],
            easyoptouts_covers=bazzell["easyoptouts_would_cover"],
        )
        return ToolResult(
            success=True,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )

    except Exception as exc:
        logger.error("broker_scan: FAILED — %s", exc, exc_info=True)
        return ToolResult(
            success=False,
            tool="broker_scan",
            input_type=inp.input_type,
            input_value=inp.value,
            timestamp=datetime.now(timezone.utc),
            data={},
            error=f"broker_scan error: {exc}",
        )
