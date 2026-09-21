"""The source registry (REFACTOR.5): every source the scan can run.

One ``SourceSpec`` per source: the Tool factory, its wave (concurrency group -
wave N runs after wave N-1, its members in parallel), the input kinds it
consumes, and the ``input_for`` builder that derives the tool's input from the
scan state (None = not applicable to this scan, so the source is absent from
coverage).

Adding a source = one SourceSpec here + the tool (with ``to_findings`` /
``run_summary``). No consumer (analysis, report, state) changes — pinned by
the decoupling test.

The input builders are pure functions of the scan state; they may read wave
N-1 findings (that is what waves are for). Sources needing custom run logic
beyond collect-once (e.g. Shodan's per-IP aggregation) register a node
override in ``eidolon.pipeline.collect`` instead.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Literal, cast

from pydantic import BaseModel

from eidolon.core.state import InputClassification, ScanState
from eidolon.sources.ai_audit import AiAudit, AiAuditInput
from eidolon.sources.base import Tool
from eidolon.sources.blackbird import Blackbird, BlackbirdInput
from eidolon.sources.broker_scan import BrokerScan, BrokerScanInput
from eidolon.sources.commoncrawl import CommonCrawl, CommonCrawlInput
from eidolon.sources.dehashed import Dehashed, DehashedInput
from eidolon.sources.ghunt import Ghunt, GHuntInput
from eidolon.sources.hibp import Hibp, HibpInput
from eidolon.sources.holehe import Holehe, HoleheInput
from eidolon.sources.maigret import Maigret, MaigretInput
from eidolon.sources.paste import Paste, PasteInput
from eidolon.sources.phone import PhoneInput, PhoneLookup
from eidolon.sources.public_records import PublicRecords, PublicRecordsInput
from eidolon.sources.shodan import Shodan
from eidolon.sources.spiderfoot import Spiderfoot, SpiderfootInput
from eidolon.sources.stealer import Stealer, StealerInput
from eidolon.sources.whoxy import Whoxy, WhoxyInput
from eidolon.sources.xposedornot import XposedOrNot, XposedOrNotInput
from eidolon.utils import clean_url

logger = logging.getLogger(__name__)

InputBuilder = Callable[["ScanState"], "BaseModel | None"]


@dataclass(frozen=True)
class SourceSpec:
    """One source: how to build it, when it runs, what it consumes."""

    name: str
    factory: Callable[[], Tool]
    wave: int
    input_kinds: tuple[str, ...]
    #: derives the tool input from the scan state; None = not applicable
    input_for: InputBuilder | None = None


# ── Input builders (pure functions of the scan state) ─────────────────────────


def _classification(state: "ScanState", kind: str) -> "InputClassification | None":
    return next((c for c in state.classifications if c.type == kind), None)


def _email(state: "ScanState") -> str | None:
    c = _classification(state, "email")
    return c.value if c else None


def xposedornot_input(state: "ScanState") -> XposedOrNotInput | None:
    email = _email(state)
    return XposedOrNotInput(email=email) if email else None


def hibp_input(state: "ScanState") -> HibpInput | None:
    primary = next(
        (c for c in state.classifications if c.type in ("email", "phone")),
        state.classifications[0] if state.classifications else None,
    )
    if not primary or primary.type not in ("email", "phone"):
        return None
    return HibpInput(input_type=primary.type, value=primary.value)


def email_input(state: "ScanState") -> DehashedInput | None:
    email = _email(state)
    return DehashedInput(email=email) if email else None


def whoxy_input(state: "ScanState") -> WhoxyInput | None:
    email = _email(state)
    return WhoxyInput(email=email) if email else None


def paste_input(state: "ScanState") -> PasteInput | None:
    email = _email(state)
    return PasteInput(email=email) if email else None


def stealer_input(state: "ScanState") -> StealerInput | None:
    email = _email(state)
    return StealerInput(email=email) if email else None


def holehe_input(state: "ScanState") -> HoleheInput | None:
    email = _email(state)
    return HoleheInput(email=email) if email else None


def blackbird_input(state: "ScanState") -> BlackbirdInput | None:
    email = _email(state)
    return BlackbirdInput(email=email) if email else None


def ghunt_input(state: "ScanState") -> GHuntInput | None:
    email = _email(state)
    return GHuntInput(email=email) if email else None


def phone_lookup_input(state: "ScanState") -> PhoneInput | None:
    c = _classification(state, "phone")
    return PhoneInput(phone=c.value) if c else None


SPIDERFOOT_TARGET_TYPE = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}


def spiderfoot_input(state: "ScanState") -> SpiderfootInput | None:
    primary = state.classifications[0] if state.classifications else None
    if not primary:
        return None
    target_type = cast(
        "Literal['emailaddr', 'phone', 'human_name', 'company_name']",
        SPIDERFOOT_TARGET_TYPE.get(primary.type, "human_name"),
    )
    return SpiderfootInput(target=primary.value, target_type=target_type)


def maigret_input(state: "ScanState") -> MaigretInput | None:
    primary = state.classifications[0] if state.classifications else None
    if not primary:
        return None
    if primary.type == "email":
        username = primary.value.split("@")[0]
    elif primary.type == "name":
        username = primary.value.replace(" ", "").lower()
    else:
        return None
    return MaigretInput(username=username)


def resolve_name(state: "ScanState") -> str | None:
    """Find the best available name for name-based sources.

    Priority:
    1. Explicit --name input from the user
    2. GHunt display name (most reliable — pulled from Google account)
    3. SpiderFoot human_name elements
    """
    name_classification = _classification(state, "name")
    if name_classification:
        return name_classification.value

    from eidolon.core.findings import GoogleFootprint

    for g in state.findings_of(GoogleFootprint):
        if g.account_name:
            logger.info("resolve_name: using GHunt name: %s", g.account_name)
            return g.account_name

    for f in state.generic_findings("footprint_element"):
        if f.payload.get("element_type") == "HUMAN_NAME":
            name = str(f.payload.get("value") or "").strip()
            if name:
                logger.info("resolve_name: using SpiderFoot name: %s", name)
                return name

    return None


def broker_scan_input(state: "ScanState") -> BrokerScanInput | None:
    name = resolve_name(state)
    if not name:
        return None
    return BrokerScanInput(
        input_type="name",
        value=name,
        city=state.location_city,
        state=state.location_state,
        zip_code=state.location_zip,
    )


def public_records_input(state: "ScanState") -> PublicRecordsInput | None:
    name = resolve_name(state)
    if not name:
        return None
    return PublicRecordsInput(name=name, state=state.location_state)


def ai_audit_input(state: "ScanState") -> AiAuditInput | None:
    """Platforms the target uses, from account findings + SOCIAL_MEDIA
    footprint elements."""
    from eidolon.core.findings import Account

    platforms: set[str] = set()
    for a in state.findings_of(Account):
        if a.platform:
            platforms.add(a.platform.lower().replace(" ", "_"))
    for f in state.generic_findings("footprint_element"):
        if f.payload.get("element_type") == "SOCIAL_MEDIA":
            # value is typically "Platform: username" or a URL
            raw = str(f.payload.get("value") or "")
            platform = raw.split(":")[0].strip().lower().replace(" ", "_")
            if platform:
                platforms.add(platform)
    if not platforms:
        return None
    return AiAuditInput(platforms=sorted(platforms))


def commoncrawl_input(state: "ScanState") -> CommonCrawlInput | None:
    """The person's web properties worth checking against Common Crawl.

    Priority (most clearly "their content" first):
      1. Personal domains the person registered (reverse-WHOIS findings).
      2. Profile/account URLs from account findings (probe URLs filtered out).
      3. Profile/site URLs from SpiderFoot footprint elements.

    Deduped (case-insensitive) and capped at 5 — the CDX index is rate-limited
    and we only need a representative sample of the person's footprint.
    """
    from eidolon.core.findings import Account

    targets: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        v = (value or "").strip()
        if not v or v.lower() in seen:
            return
        seen.add(v.lower())
        targets.append(v)

    for f in state.generic_findings("registered_domain"):
        if f.payload.get("domain"):
            add(str(f.payload["domain"]))
    for a in state.findings_of(Account):
        add(clean_url(a.url))
    for f in state.generic_findings("footprint_element"):
        data = str(f.payload.get("value") or "").strip()
        if data.startswith("http"):
            add(clean_url(data))

    if not targets:
        return None
    return CommonCrawlInput(targets=targets[:5])


#: The complete source registry. Wave 1 = input-only sources; wave 2 = sources
#: that derive their input from wave-1 findings.
REGISTRY: tuple[SourceSpec, ...] = (
    SourceSpec("hibp", Hibp, 1, ("email", "phone"), hibp_input),
    SourceSpec("xposedornot", XposedOrNot, 1, ("email",), xposedornot_input),
    SourceSpec("dehashed", Dehashed, 1, ("email",), email_input),
    SourceSpec("whoxy", Whoxy, 1, ("email",), whoxy_input),
    SourceSpec("paste", Paste, 1, ("email",), paste_input),
    SourceSpec("stealer", Stealer, 1, ("email",), stealer_input),
    SourceSpec("phone_lookup", PhoneLookup, 1, ("phone",), phone_lookup_input),
    SourceSpec(
        "spiderfoot", Spiderfoot, 1, ("email", "phone", "name", "org"), spiderfoot_input
    ),
    SourceSpec("holehe", Holehe, 1, ("email",), holehe_input),
    SourceSpec("blackbird", Blackbird, 1, ("email",), blackbird_input),
    SourceSpec("maigret", Maigret, 1, ("email", "name"), maigret_input),
    SourceSpec("ghunt", Ghunt, 1, ("email",), ghunt_input),
    # wave 2: derive their input from wave-1 findings
    SourceSpec(
        "broker_scan",
        BrokerScan,
        2,
        ("email", "phone", "name", "org"),
        broker_scan_input,
    ),
    SourceSpec("shodan", Shodan, 2, ("email", "phone", "name", "org"), None),
    SourceSpec(
        "public_records",
        PublicRecords,
        2,
        ("email", "phone", "name", "org"),
        public_records_input,
    ),
    SourceSpec(
        "ai_audit", AiAudit, 2, ("email", "phone", "name", "org"), ai_audit_input
    ),
    SourceSpec(
        "commoncrawl",
        CommonCrawl,
        2,
        ("email", "phone", "name", "org"),
        commoncrawl_input,
    ),
)


def waves() -> list[int]:
    """The distinct wave numbers present in the registry, in run order."""
    return sorted({spec.wave for spec in REGISTRY})
