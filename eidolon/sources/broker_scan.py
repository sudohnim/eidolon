"""Data broker aggregation.

Three independent vendor tools find a person on broker sites:
  - apify             (TruePeopleSearch Contact Finder actor)
  - fastpeoplesearch  (Scrapfly scrape)
  - truepeoplesearch  (Scrapfly scrape)

``BrokerScan`` (the Tool) runs all three, de-duplicates by domain, scores
exposure, and cross-references the Bazzell removal database — the source-level
aggregation for this multi-vendor source. ``scan`` is a backward-compatible
wrapper returning the ToolResult envelope. The shared input/profile schemas
live here so the vendor modules can import them without a cycle (vendors are
imported lazily).
"""

import logging
import re
from typing import Literal, cast

import structlog
from pydantic import BaseModel

from eidolon.core.findings import (
    BrokerExposure,
    Confidence,
    Finding,
    RemovalHint,
    Severity,
)
from eidolon.core.logging import get_logger
from eidolon.core.state import ToolResult
from eidolon.sources.base import Tool, run_to_result
from eidolon.utils import load_data

logger = logging.getLogger(__name__)


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


class BrokerProfilesOutput(BaseModel):
    """A single vendor's profiles."""

    profiles: list[BrokerProfile] = []
    count: int = 0


class BrokerScanOutput(BaseModel):
    query_value: str = ""
    brokers_found_count: int = 0
    brokers_found: list[BrokerProfile] = []
    exposure_score: int = 0
    easyoptouts_url: str = "https://easyoptouts.com/dashboard"
    priority_optouts: list[str] = []
    bazzell_tier1_found: list[str] = []
    manual_removal_required: list[str] = []
    easyoptouts_covers: int = 0


# Maps full state names to 2-letter abbreviations for broker URL slugs
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


def state_to_abbrev(state: str) -> str:
    """Convert full state name or abbreviation to 2-letter lowercase slug."""
    s = state.strip().lower()
    if len(re.sub(r"[^a-z]", "", s)) == 2:
        return re.sub(r"[^a-z]", "", s)
    return _STATE_ABBREVS.get(s, s[:2])


def _cross_reference_bazzell(profiles: list[BrokerProfile]) -> dict:
    """Cross-reference found brokers against Bazzell's removal database."""
    try:
        db = cast(list, load_data("bazzell_brokers.json"))
    except Exception as exc:
        logger.warning("bazzell cross-reference: failed to load DB — %s", exc)
        return {
            "bazzell_tier1_found": [],
            "manual_removal_required": [],
            "easyoptouts_would_cover": 0,
        }

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


class BrokerScan(Tool[BrokerScanInput, BrokerScanOutput]):
    """Composite source: fan out across broker vendors, dedupe, score."""

    name = "broker_scan"
    input_schema = BrokerScanInput
    output_schema = BrokerScanOutput
    input_type = "name"
    #: multi-vendor composite (apify + scrapfly scrapes) — no single host
    vendor = ""

    def run(self, inp: BrokerScanInput) -> BrokerScanOutput:
        # Composite: no single fixture to load in TEST_MODE — each vendor tool
        # loads its own, so always run the real aggregation path.
        log = get_logger(f"eidolon.sources.{self.name}").bind(tool=self.name)
        return self._run(inp, log)

    def _input_type(
        self, inp: BrokerScanInput
    ) -> Literal["email", "phone", "name", "org"]:
        return inp.input_type

    def _input_value(self, inp: BrokerScanInput) -> str:
        return inp.value

    def _run(
        self, inp: BrokerScanInput, log: structlog.stdlib.BoundLogger
    ) -> BrokerScanOutput:
        # Broker scanning is only meaningful for name inputs (brokers list by
        # name + address), so non-name inputs return an empty result.
        if inp.input_type != "name":
            return BrokerScanOutput(query_value=inp.value)

        # Lazy import keeps the vendor ↔ shared-models dependency acyclic.
        from eidolon.sources.apify import Apify
        from eidolon.sources.fastpeoplesearch import FastPeopleSearch
        from eidolon.sources.truepeoplesearch import TruePeopleSearch

        all_profiles: list[BrokerProfile] = []
        for vendor in (Apify(), FastPeopleSearch(), TruePeopleSearch()):
            try:
                out = vendor.run(inp)  # typed output — no envelope re-parsing
                all_profiles.extend(out.profiles)
            except Exception as exc:
                log.warning(
                    "broker vendor failed — degrading independently",
                    vendor=vendor.name,
                    error=str(exc),
                )

        # De-duplicate by broker domain
        seen: set[str] = set()
        deduped: list[BrokerProfile] = []
        for p in all_profiles:
            if p.broker_domain not in seen:
                seen.add(p.broker_domain)
                deduped.append(p)

        bazzell = _cross_reference_bazzell(deduped)
        priority = sorted(deduped, key=lambda p: len(p.data_found), reverse=True)
        return BrokerScanOutput(
            query_value=inp.value,
            brokers_found_count=len(deduped),
            brokers_found=deduped,
            exposure_score=_calculate_exposure_score(deduped),
            priority_optouts=[p.broker_domain for p in priority[:5]],
            bazzell_tier1_found=bazzell["bazzell_tier1_found"],
            manual_removal_required=bazzell["manual_removal_required"],
            easyoptouts_covers=bazzell["easyoptouts_would_cover"],
        )

    def to_findings(self, out: BrokerScanOutput) -> list[Finding]:
        """One BrokerExposure per broker holding a profile — removable by
        construction, carrying the deterministic opt-out path."""
        severity_by_confidence = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        findings: list[Finding] = []
        for p in out.brokers_found:
            findings.append(
                BrokerExposure(
                    dedup_key=f"broker:{p.broker_domain}",
                    title=p.broker_name or p.broker_domain,
                    severity=severity_by_confidence.get(p.confidence, Severity.MEDIUM),
                    removable=True,
                    removal=RemovalHint(mechanism="optout", url=p.optout_url),
                    broker=p.broker_name,
                    domain=p.broker_domain,
                    opt_out_url=p.optout_url,
                    data_points=list(p.data_found),
                    match_strength=p.confidence,
                    # name + location match: plausible, identity not verified
                    confidence=Confidence.POSSIBLE,
                )
            )
        return findings

    def run_summary(self, out: BrokerScanOutput) -> str:
        return (
            f"{out.brokers_found_count} brokers, "
            f"exposure score {out.exposure_score}/100"
        )


def scan(inp: BrokerScanInput) -> ToolResult:
    """Backward-compatible envelope wrapper over ``BrokerScan``."""
    return run_to_result(BrokerScan(), inp)
