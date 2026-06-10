import json
import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, cast

from eidolon import config
from eidolon.agent.prompts import ANALYSIS_PROMPT, CORRELATION_PROMPT
from eidolon.core.logging import bind_run_context, redact
from eidolon.core.models import (
    AnalysisResult,
    InputClassification,
    PipelineState,
    ToolResult,
)
from eidolon.tools.ai_audit import AiAuditInput
from eidolon.tools.base import run_to_result
from eidolon.tools.blackbird import BlackbirdInput
from eidolon.tools.broker_scan import BrokerScanInput, BrokerScanOutput
from eidolon.tools.ghunt import GHuntInput
from eidolon.tools.hibp import HibpInput
from eidolon.tools.holehe import HoleheInput
from eidolon.tools.maigret import MaigretInput
from eidolon.tools.spiderfoot import SpiderfootInput

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _parse_json_tolerant(text: str) -> dict | list:
    """Parse JSON with progressive repair for common LLM output quirks.

    Attempts in order:
    1. Plain json.loads (fast path)
    2. Strip trailing commas before ] or } (most common LLM mistake)
    3. Extract the first {...} or [...] block (handles surrounding prose)
    Raises json.JSONDecodeError if all attempts fail.
    """
    # Fast path
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Repair trailing commas: ,  } or ,  ]
    repaired = re.sub(r",\s*([\]}])", r"\1", text)
    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    # Extract outermost JSON object or array
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        end = text.rfind(end_char)
        if start != -1 and end > start:
            candidate = text[start : end + 1]
            # Also repair trailing commas in extracted fragment
            candidate = re.sub(r",\s*([\]}])", r"\1", candidate)
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    # All attempts failed — raise original error for the caller to log
    raise json.JSONDecodeError("could not repair JSON", text, 0)


PHONE_RE = re.compile(r"^[\d\s\-\(\)\+\.]{7,}$")

SPIDERFOOT_TARGET_TYPE = {
    "email": "emailaddr",
    "phone": "phone",
    "name": "human_name",
    "org": "company_name",
}


def _classify_input(raw: str) -> InputClassification:
    raw = raw.strip()
    if EMAIL_RE.match(raw):
        return InputClassification(type="email", value=raw.lower(), raw=raw)
    if PHONE_RE.match(raw):
        digits = re.sub(r"\D", "", raw)
        normalized = f"+1{digits}" if len(digits) == 10 else raw
        return InputClassification(type="phone", value=normalized, raw=raw)
    words = raw.split()
    if 2 <= len(words) <= 4 and all(w[0].isupper() for w in words if w):
        return InputClassification(type="name", value=raw, raw=raw)
    return InputClassification(type="org", value=raw, raw=raw)


def intake_node(state: PipelineState) -> PipelineState:
    logger.info("intake_node: classifying inputs")
    classifications = []
    location: dict = {}
    for line in state.raw_input.splitlines():
        line = line.strip()
        if not line:
            continue
        # Structured format from main.py argparse: "type:value"
        if line.startswith(("email:", "phone:", "name:")):
            kind, _, value = line.partition(":")
            type_map: dict[str, Literal["email", "phone", "name", "org"]] = {
                "email": "email",
                "phone": "phone",
                "name": "name",
            }
            classifications.append(
                InputClassification(
                    type=type_map[kind], value=value.strip(), raw=value.strip()
                )
            )
        elif line.startswith(("city:", "state:", "zip:")):
            kind, _, value = line.partition(":")
            location[kind] = value.strip()
            logger.info("  location: %s=%s", kind, value.strip())
        else:
            # Fallback: regex-based classification for bare strings
            classifications.append(_classify_input(line))

    for c in classifications:
        logger.info("  classified: type=%s value=%s", c.type, c.value)

    # Bind run context for every subsequent log line: run_id, scan type, and a
    # REDACTED target (never the full PII this tool exists to protect).
    run_id = uuid.uuid4().hex[:8]
    primary = classifications[0] if classifications else None
    if primary:
        bind_run_context(
            run_id=run_id,
            scan_type=primary.type,
            target=redact(primary.value, primary.type),
        )
    else:
        bind_run_context(run_id=run_id)

    updates: dict = {"classifications": classifications, "run_id": run_id}
    if location.get("city"):
        updates["location_city"] = location["city"]
    if location.get("state"):
        updates["location_state"] = location["state"]
    if location.get("zip"):
        updates["location_zip"] = location["zip"]
    return state.model_copy(update=updates)


def breach_check_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.hibp import Hibp

    primary = next(
        (c for c in state.classifications if c.type in ("email", "phone")),
        state.classifications[0] if state.classifications else None,
    )
    if not primary or primary.type not in ("email", "phone"):
        logger.info("breach_check_node: no email/phone input, skipping HIBP")
        return state

    inp = HibpInput(input_type=primary.type, value=primary.value)
    result = run_to_result(Hibp(), inp)
    if result.success:
        logger.info(
            "breach_check_node: OK — breach_count=%s",
            result.data.get("breach_count", 0),
        )
    else:
        logger.error("breach_check_node: FAILED — %s", result.error)
    return state.model_copy(update={"hibp_result": result})


def _resolve_name(state: PipelineState) -> str | None:
    """Find the best available name for broker search.

    Priority:
    1. Explicit --name input from the user
    2. GHunt display name (most reliable — pulled from Google account)
    3. SpiderFoot human_name elements
    Returns None if no name found anywhere.
    """
    # 1. Explicit name from intake
    name_classification = next(
        (c for c in state.classifications if c.type == "name"), None
    )
    if name_classification:
        return name_classification.value

    # 2. GHunt display name
    if state.ghunt_result and state.ghunt_result.success:
        ghunt_name = state.ghunt_result.data.get("name", "")
        if ghunt_name:
            logger.info("broker_scan_node: using GHunt name: %s", ghunt_name)
            return ghunt_name

    # 3. SpiderFoot HUMAN_NAME elements
    if state.spiderfoot_result and state.spiderfoot_result.success:
        elements = state.spiderfoot_result.data.get("elements", [])
        for el in elements:
            if el.get("type") == "HUMAN_NAME" and el.get("data"):
                name = el["data"].strip()
                if name:
                    logger.info("broker_scan_node: using SpiderFoot name: %s", name)
                    return name

    return None


def broker_scan_node(state: PipelineState) -> PipelineState:
    from eidolon.tools import broker_scan as broker_tool

    name = _resolve_name(state)

    if not name:
        logger.info(
            "broker_scan_node: no name available from input or prior tools — skipping"
        )
        output = BrokerScanOutput(
            query_value="",
            brokers_found_count=0,
            brokers_found=[],
            exposure_score=0,
            priority_optouts=[],
        )
        result = ToolResult(
            success=True,
            tool="broker_scan",
            input_type="name",
            input_value="",
            timestamp=datetime.now(timezone.utc),
            data=output.model_dump(),
        )
        return state.model_copy(update={"broker_result": result})

    logger.info(
        "broker_scan_node: searching brokers for name=%s city=%s state=%s zip=%s",
        name,
        state.location_city,
        state.location_state,
        state.location_zip,
    )
    inp = BrokerScanInput(
        input_type="name",
        value=name,
        city=state.location_city,
        state=state.location_state,
        zip_code=state.location_zip,
    )
    result = broker_tool.scan(inp)
    if result.success:
        logger.info(
            "broker_scan_node: OK — brokers_found=%s exposure_score=%s",
            result.data.get("brokers_found_count", 0),
            result.data.get("exposure_score", 0),
        )
    else:
        logger.error("broker_scan_node: FAILED — %s", result.error)
    return state.model_copy(update={"broker_result": result})


def surface_map_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.spiderfoot import Spiderfoot

    primary = state.classifications[0] if state.classifications else None
    if not primary:
        logger.info("surface_map_node: no input, skipping SpiderFoot")
        return state

    target_type = cast(
        Literal["emailaddr", "phone", "human_name", "company_name"],
        SPIDERFOOT_TARGET_TYPE.get(primary.type, "human_name"),
    )
    inp = SpiderfootInput(target=primary.value, target_type=target_type)
    result = run_to_result(Spiderfoot(), inp)
    if result.success:
        logger.info(
            "surface_map_node: OK — elements=%s", result.data.get("element_count", 0)
        )
    else:
        logger.error("surface_map_node: FAILED — %s", result.error)
    return state.model_copy(update={"spiderfoot_result": result})


def holehe_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.holehe import Holehe

    primary = next(
        (c for c in state.classifications if c.type == "email"),
        None,
    )
    if not primary:
        logger.info("holehe_node: no email input, skipping")
        return state

    inp = HoleheInput(email=primary.value)
    result = run_to_result(Holehe(), inp)
    if result.success:
        logger.info(
            "holehe_node: OK — found=%s checked=%s",
            result.data.get("found_count", 0),
            result.data.get("platforms_checked", 0),
        )
    else:
        logger.error("holehe_node: FAILED — %s", result.error)
    return state.model_copy(update={"holehe_result": result})


def blackbird_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.blackbird import Blackbird

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("blackbird_node: no email input, skipping")
        return state

    inp = BlackbirdInput(email=primary.value)
    result = run_to_result(Blackbird(), inp)
    if result.success:
        logger.info("blackbird_node: OK — found=%s", result.data.get("found_count", 0))
    else:
        logger.error("blackbird_node: FAILED — %s", result.error)
    return state.model_copy(update={"blackbird_result": result})


def maigret_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.maigret import Maigret

    primary = state.classifications[0] if state.classifications else None
    if not primary:
        logger.info("maigret_node: no input, skipping")
        return state

    if primary.type == "email":
        username = primary.value.split("@")[0]
    elif primary.type == "name":
        username = primary.value.replace(" ", "").lower()
    else:
        logger.info("maigret_node: skipping for input_type=%s", primary.type)
        return state

    inp = MaigretInput(username=username)
    result = run_to_result(Maigret(), inp)
    if result.success:
        logger.info(
            "maigret_node: OK — found=%s checked=%s",
            result.data.get("found_count", 0),
            result.data.get("platforms_checked", 0),
        )
    else:
        logger.error("maigret_node: FAILED — %s", result.error)
    return state.model_copy(update={"sherlock_result": result})


def ghunt_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.ghunt import Ghunt

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("ghunt_node: no email input, skipping")
        return state

    inp = GHuntInput(email=primary.value)
    result = run_to_result(Ghunt(), inp)
    if result.success:
        logger.info(
            "ghunt_node: OK — found=%s services=%s",
            result.data.get("found", False),
            result.data.get("google_services", []),
        )
    else:
        logger.error("ghunt_node: FAILED — %s", result.error)
    return state.model_copy(update={"ghunt_result": result})


def shodan_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.shodan import Shodan, ShodanInput, ShodanOutput

    if not state.spiderfoot_result or not state.spiderfoot_result.success:
        logger.info("shodan_node: no spiderfoot_result, skipping")
        return state

    elements = state.spiderfoot_result.data.get("elements", [])
    ips = [
        el["data"]
        for el in elements
        if el.get("type") == "IP_ADDRESS" and el.get("data")
    ][
        :5
    ]  # cap at 5 IPs

    if not ips:
        logger.info(
            "shodan_node: no IP_ADDRESS elements in spiderfoot_result, skipping"
        )
        return state

    logger.info("shodan_node: scanning %d IPs: %s", len(ips), ips)

    all_hosts = []
    for ip in ips:
        inp = ShodanInput(ip=ip)
        result = run_to_result(Shodan(), inp)
        if result.success:
            all_hosts.extend(result.data.get("hosts", []))
        else:
            logger.warning("shodan_node: failed for ip=%s — %s", ip, result.error)

    total_open_ports = sum(len(h.get("ports", [])) for h in all_hosts)
    total_vulns = sum(len(h.get("vulns", [])) for h in all_hosts)
    high_risk_ips = [h["ip"] for h in all_hosts if h.get("vulns")]

    output = ShodanOutput(
        ips_checked=len(ips),
        hosts=[],
        total_open_ports=total_open_ports,
        total_vulns=total_vulns,
        high_risk_ips=high_risk_ips,
    )
    aggregated_data = output.model_dump()
    aggregated_data["hosts"] = all_hosts

    primary = state.classifications[0] if state.classifications else None
    aggregated = ToolResult(
        success=True,
        tool="shodan",
        input_type=primary.type if primary else "org",
        input_value=primary.value if primary else "",
        timestamp=datetime.now(timezone.utc),
        data=aggregated_data,
    )

    logger.info(
        "shodan_node: OK — ips_checked=%d open_ports=%d vulns=%d",
        len(ips),
        total_open_ports,
        total_vulns,
    )
    return state.model_copy(update={"shodan_result": aggregated})


def ai_audit_node(state: PipelineState) -> PipelineState:
    from eidolon.tools.ai_audit import AiAudit

    # Derive platforms from Blackbird + Holehe + SpiderFoot social media elements
    platforms: set[str] = set()

    if state.blackbird_result and state.blackbird_result.success:
        for account in state.blackbird_result.data.get("accounts_found", []):
            platforms.add(account["platform"].lower().replace(" ", "_"))

    if state.holehe_result and state.holehe_result.success:
        for match in state.holehe_result.data.get("platforms_found", []):
            platforms.add(match["platform"].lower())

    if state.spiderfoot_result and state.spiderfoot_result.success:
        for el in state.spiderfoot_result.data.get("elements", []):
            if el.get("type") == "SOCIAL_MEDIA":
                # data field is typically "Platform: username" or a URL
                raw = el.get("data", "")
                platform = raw.split(":")[0].strip().lower().replace(" ", "_")
                if platform:
                    platforms.add(platform)

    if not platforms:
        logger.info("ai_audit_node: no platforms detected, skipping")
        return state

    logger.info("ai_audit_node: detected platforms=%s", sorted(platforms))
    inp = AiAuditInput(platforms=sorted(platforms))
    result = run_to_result(AiAudit(), inp)
    if result.success:
        logger.info(
            "ai_audit_node: OK — high_risk=%s overall=%s",
            result.data.get("high_risk_count", 0),
            result.data.get("overall_risk", "?"),
        )
    else:
        logger.error("ai_audit_node: FAILED — %s", result.error)
    return state.model_copy(update={"ai_audit_result": result})


def dehashed_node(state: PipelineState) -> PipelineState:
    """Search DeHashed for breach records containing plaintext passwords,
    hashed passwords, usernames, phone numbers, and physical addresses.

    Complements HIBP: where HIBP shows breach metadata, DeHashed surfaces
    the actual record contents — filling the physical data gap when broker
    scanning returns nothing.

    Skips gracefully if DEHASHED_EMAIL or DEHASHED_API_KEY are not set.
    """
    from eidolon.tools.dehashed import Dehashed, DehashedInput

    primary = next(
        (c for c in state.classifications if c.type == "email"),
        None,
    )
    if not primary:
        logger.info("dehashed_node: no email input, skipping")
        return state

    result = run_to_result(Dehashed(), DehashedInput(email=primary.value))
    if result.success:
        d = result.data
        logger.info(
            "dehashed_node: OK — total=%d plaintext=%d hashed=%d addresses=%d usernames=%d",
            d.get("total", 0),
            d.get("plaintext_password_count", 0),
            d.get("hashed_password_count", 0),
            len(d.get("unique_addresses") or []),
            len(d.get("unique_usernames") or []),
        )
    else:
        logger.error("dehashed_node: FAILED — %s", result.error)
    return state.model_copy(update={"dehashed_result": result})


def paste_node(state: PipelineState) -> PipelineState:
    """Search psbdmp paste archives for credential dumps containing this email.

    Surfaces email:password pairs posted to Pastebin and related sites —
    often appears before HIBP ingests the breach (psbdmp indexes in near
    real-time). No API key required.
    """
    from eidolon.tools.paste import Paste, PasteInput

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("paste_node: no email input, skipping")
        return state

    result = run_to_result(Paste(), PasteInput(email=primary.value))
    if result.success:
        d = result.data
        logger.info(
            "paste_node: OK — pastes=%d credential_pastes=%d recent=%d plaintext=%d",
            d.get("paste_count", 0),
            d.get("credential_paste_count", 0),
            d.get("recent_paste_count", 0),
            d.get("plaintext_passwords_found", 0),
        )
    else:
        logger.error("paste_node: FAILED — %s", result.error)
    return state.model_copy(update={"paste_result": result})


def stealer_node(state: PipelineState) -> PipelineState:
    """Check Hudson Rock Cavalier for infostealer log hits.

    Infostealer logs (RedLine, Vidar, Raccoon, etc.) are categorically more
    severe than breach records: malware ran on the victim's machine and
    exfiltrated ALL saved browser credentials, cookies, and session tokens —
    not just one service's database. A hit here means an attacker may have
    had live authenticated access to every service the victim was logged into.

    Free, no API key required.
    """
    from eidolon.tools.stealer import Stealer, StealerInput

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("stealer_node: no email input, skipping")
        return state

    result = run_to_result(Stealer(), StealerInput(email=primary.value))
    if result.success:
        d = result.data
        if d.get("found"):
            logger.info(
                "stealer_node: OK — FOUND hits=%d families=%s earliest=%s latest=%s",
                d.get("stealer_count", 0),
                d.get("malware_families", []),
                d.get("earliest_compromise", "?"),
                d.get("latest_compromise", "?"),
            )
        else:
            logger.info("stealer_node: OK — no infostealer hits")
    else:
        logger.error("stealer_node: FAILED — %s", result.error)
    return state.model_copy(update={"stealer_result": result})


def whoxy_node(state: PipelineState) -> PipelineState:
    """Reverse WHOIS lookup — find all domains registered to this email.

    Surfaces business activity, old projects, company names (pivot to
    OpenCorporates), and physical addresses embedded in WHOIS registrant data.
    Expired domains are flagged as a risk finding (impersonation risk).

    Email inputs only. Skips gracefully if WHOXY_API_KEY is not set.
    """
    from eidolon.tools.whoxy import Whoxy, WhoxyInput

    primary = next((c for c in state.classifications if c.type == "email"), None)
    if not primary:
        logger.info("whoxy_node: no email input, skipping")
        return state

    result = run_to_result(Whoxy(), WhoxyInput(email=primary.value))
    if result.success:
        d = result.data
        logger.info(
            "whoxy_node: OK — total=%d active=%d expired=%d companies=%d",
            d.get("total_results", 0),
            d.get("active_domain_count", 0),
            d.get("expired_domain_count", 0),
            len(d.get("unique_company_names") or []),
        )
    else:
        logger.error("whoxy_node: FAILED — %s", result.error)
    return state.model_copy(update={"whoxy_result": result})


def phone_pivot_node(state: PipelineState) -> PipelineState:
    """Resolve carrier, line type, and location for phone number inputs.

    No-op for email/name/org inputs — runs only when a phone classification exists.
    Skips gracefully if NUMVERIFY_API_KEY is not set.
    """
    from eidolon.tools import phone as phone_tool

    primary = next((c for c in state.classifications if c.type == "phone"), None)
    if not primary:
        logger.info("phone_pivot_node: no phone input, skipping")
        return state

    result = phone_tool.lookup(primary.value)
    if result.success:
        logger.info(
            "phone_pivot_node: OK — valid=%s line_type=%s carrier=%s location=%s",
            result.data.get("valid"),
            result.data.get("line_type"),
            (result.data.get("carrier") or {}).get("name", "unknown"),
            result.data.get("location"),
        )
    else:
        logger.error("phone_pivot_node: FAILED — %s", result.error)
    return state.model_copy(update={"phone_result": result})


def public_records_node(state: PipelineState) -> PipelineState:
    """Search CourtListener (federal cases) and OpenCorporates (corporate roles).

    Requires a resolved name — uses the same priority chain as broker_scan_node.
    Passes state location to narrow court results when available.
    Both APIs are free with no API key required for basic search.
    """
    from eidolon.tools import public_records as pr_tool

    name = _resolve_name(state)
    if not name:
        logger.info("public_records_node: no name resolved, skipping")
        return state

    result = pr_tool.lookup(name, state=state.location_state)
    if result.success:
        logger.info(
            "public_records_node: OK — court_cases=%d corporate_records=%d",
            result.data.get("court_case_count", 0),
            result.data.get("corporate_record_count", 0),
        )
    else:
        logger.error("public_records_node: FAILED — %s", result.error)
    return state.model_copy(update={"public_records_result": result})


def _build_analysis_digest(state: PipelineState) -> str:
    """Build a compact text digest of scan results to send to the LLM.

    The full state dump can be 50-100KB with hundreds of raw tool records.
    A local 8B model given that much context is extremely slow and often
    produces garbled output. Instead we extract the signal: counts, names,
    severities, and a capped list of the most important findings.
    """
    lines: list[str] = []

    # ── Target ────────────────────────────────────────────────────────────────
    primary = state.classifications[0] if state.classifications else None
    if primary:
        lines.append(f"TARGET: {primary.value} (type={primary.type})")
    lines.append("")

    # ── HIBP breaches ─────────────────────────────────────────────────────────
    if state.hibp_result and state.hibp_result.success:
        d = state.hibp_result.data
        lines.append(f"HIBP BREACHES: {d.get('breach_count', 0)} total")
        for b in d.get("breaches") or []:
            name = b.get("name", "?")
            year = str(b.get("breach_date", ""))[:4]
            classes = (
                ", ".join((b.get("data_classes") or [])[:6]) or "unknown data types"
            )
            spam = " [spam list]" if b.get("is_spam_list") else ""
            lines.append(f"  - {name} ({year}): {classes}{spam}")
        lines.append("")

    # ── DeHashed breach records ───────────────────────────────────────────────
    if state.dehashed_result and state.dehashed_result.success:
        d = state.dehashed_result.data
        total = d.get("total", 0)
        if total:
            lines.append(
                f"DEHASHED: {total} breach records — "
                f"{d.get('plaintext_password_count', 0)} plaintext passwords, "
                f"{d.get('hashed_password_count', 0)} hashed passwords"
            )
            dbs = d.get("unique_databases") or []
            if dbs:
                lines.append(f"  Sources: {', '.join(dbs[:10])}")
            usernames = _clean_handles(d.get("unique_usernames") or [])
            if usernames:
                lines.append(f"  Usernames exposed: {', '.join(usernames[:10])}")
            addresses = _clean_addresses(d.get("unique_addresses") or [])
            if addresses:
                lines.append(f"  Physical addresses: {', '.join(addresses[:5])}")
            phones = d.get("unique_phones") or []
            if phones:
                lines.append(f"  Phones in breach data: {', '.join(phones[:5])}")
            lines.append("")

    # ── Paste site credential dumps ───────────────────────────────────────────
    if state.paste_result and state.paste_result.success:
        d = state.paste_result.data
        total = d.get("paste_count", 0)
        if total:
            lines.append(
                f"PASTE SITES (HIBP): {total} paste(s) found — "
                f"{d.get('recent_paste_count', 0)} posted within 90 days"
            )
            for entry in (d.get("pastes") or [])[:5]:
                count_note = (
                    f" — {entry.get('credential_count', 0)} addresses in paste"
                    if entry.get("credential_count")
                    else ""
                )
                lines.append(
                    f"  - {entry.get('url')} ({entry.get('date')}){count_note}"
                )
            lines.append("")

    # ── Infostealer logs (Hudson Rock) ────────────────────────────────────────
    if state.stealer_result and state.stealer_result.success:
        d = state.stealer_result.data
        if d.get("found"):
            lines.append(
                f"INFOSTEALER LOGS (Hudson Rock): {d.get('stealer_count', 0)} hit(s) — "
                f"CRITICAL: malware exfiltrated ALL browser credentials + session tokens"
            )
            lines.append(
                f"  Malware families: {', '.join(d.get('malware_families') or [])}"
            )
            lines.append(
                f"  Compromise window: {d.get('earliest_compromise', '?')} → {d.get('latest_compromise', '?')}"
            )
            for log in (d.get("logs") or [])[:3]:
                lines.append(
                    f"  - {log.get('malware_family')} on {log.get('computer_name')} "
                    f"({log.get('date_compromised')}) — "
                    f"{log.get('credential_count', 0)} credentials stolen"
                )
            lines.append("")
        else:
            lines.append("INFOSTEALER LOGS: no hits")
            lines.append("")

    # ── Whoxy reverse WHOIS ───────────────────────────────────────────────────
    if state.whoxy_result and state.whoxy_result.success:
        d = state.whoxy_result.data
        total = d.get("total_results", 0)
        if total:
            active = d.get("active_domain_count", 0)
            expired = d.get("expired_domain_count", 0)
            lines.append(
                f"WHOXY REVERSE WHOIS: {total} domains registered — "
                f"{active} active, {expired} expired"
            )
            domains = d.get("domains") or []
            for dom in domains[:10]:
                expiry = dom.get("expiry_date", "")
                status = (
                    "active"
                    if expiry >= datetime.now(timezone.utc).date().isoformat()
                    else "EXPIRED"
                )
                company = (
                    f" [{dom['registrant_company']}]"
                    if dom.get("registrant_company")
                    else ""
                )
                lines.append(
                    f"  - {dom['domain_name']} ({status}, expires {expiry}){company}"
                )
            companies = d.get("unique_company_names") or []
            if companies:
                lines.append(
                    f"  Company names in registrant data: {', '.join(companies[:5])}"
                )
            addresses = _clean_addresses(d.get("unique_addresses") or [])
            if addresses:
                lines.append(f"  Physical addresses: {', '.join(addresses[:3])}")
            if expired > 0:
                lines.append(
                    f"  ⚠ {expired} expired domain(s) — impersonation/typosquat risk"
                )
            lines.append("")

    # ── Holehe registrations ──────────────────────────────────────────────────
    if state.holehe_result and state.holehe_result.success:
        d = state.holehe_result.data
        found = [p.get("platform") for p in (d.get("platforms_found") or [])]
        lines.append(
            f"HOLEHE: {d.get('found_count', 0)} registrations found across {d.get('platforms_checked', 0)} platforms"
        )
        if found:
            lines.append(f"  Platforms: {', '.join(found[:20])}")
        lines.append("")

    # ── Blackbird accounts ────────────────────────────────────────────────────
    if state.blackbird_result and state.blackbird_result.success:
        d = state.blackbird_result.data
        accts = [
            (a.get("platform"), a.get("url")) for a in (d.get("accounts_found") or [])
        ]
        lines.append(f"BLACKBIRD: {d.get('found_count', 0)} accounts found")
        for platform, url in accts[:15]:
            lines.append(f"  - {platform}: {url}")
        lines.append("")

    # ── Maigret username profiles ─────────────────────────────────────────────
    if state.sherlock_result and state.sherlock_result.success:
        d = state.sherlock_result.data
        profiles = [
            (p.get("platform"), p.get("url")) for p in (d.get("profiles_found") or [])
        ]
        lines.append(
            f"MAIGRET: {d.get('found_count', 0)} profiles across {d.get('platforms_checked', 0)} platforms"
        )
        for platform, url in profiles[:20]:
            lines.append(f"  - {platform}: {url}")
        lines.append("")

    # ── GHunt ─────────────────────────────────────────────────────────────────
    if state.ghunt_result and state.ghunt_result.success:
        d = state.ghunt_result.data
        if d.get("found"):
            lines.append("GHUNT: Google account found")
            lines.append(f"  Name: {d.get('name', 'unknown')}")
            lines.append(f"  Services: {', '.join(d.get('google_services', []))}")
            if d.get("maps_reviews_count"):
                lines.append(
                    f"  Google Maps reviews: {d['maps_reviews_count']} (public activity trail)"
                )
            if d.get("youtube_channel"):
                lines.append(f"  YouTube channel: {d['youtube_channel']}")
        else:
            lines.append("GHUNT: not run (no credentials)")
        lines.append("")

    # ── Broker scan ───────────────────────────────────────────────────────────
    if state.broker_result and state.broker_result.success:
        d = state.broker_result.data
        lines.append(
            f"DATA BROKERS: {d.get('brokers_found_count', 0)} brokers, exposure score {d.get('exposure_score', 0)}/100"
        )
        for b in (d.get("brokers_found") or [])[:8]:
            lines.append(
                f"  - {b.get('broker_name')}: {b.get('data_types_exposed', [])}"
            )
        lines.append("")

    # ── SpiderFoot ────────────────────────────────────────────────────────────
    if state.spiderfoot_result and state.spiderfoot_result.success:
        d = state.spiderfoot_result.data
        elements = d.get("elements") or []
        by_type: dict = defaultdict(list)
        for el in elements:
            val = (el.get("data") or "").strip()
            if val:
                by_type[el.get("type", "UNKNOWN")].append(val)

        # Exclude noisy/low-signal types that the LLM misreads as physical addresses
        SKIP_TYPES = {
            "RAW_RIR_DATA",
            "GEOINFO",
            "COUNTRY_NAME",
            "PROVIDER_TELCO",
            "PHONE_PREFIX_OWNED",
            "NETBLOCK_OWNER",
            "BGP_AS_OWNER",
        }
        lines.append(f"SPIDERFOOT: {d.get('element_count', 0)} elements")
        for etype, vals in list(by_type.items())[:10]:
            if etype in SKIP_TYPES:
                continue
            # Skip values that are just short codes (e.g. "us", "md", "511")
            clean = [v for v in vals if len(v) > 4]
            if clean:
                lines.append(f"  {etype}: {', '.join(clean[:5])}")
        lines.append("")

    # ── AI audit ─────────────────────────────────────────────────────────────
    if state.ai_audit_result and state.ai_audit_result.success:
        d = state.ai_audit_result.data
        lines.append(
            f"AI PLATFORM EXPOSURE: {d.get('high_risk_count', 0)} high-risk, overall={d.get('overall_risk', 'unknown')}"
        )
        for p in d.get("platforms_found") or []:
            lines.append(
                f"  - {p.get('platform')}: risk={p.get('risk_level')} data_known={p.get('data_known', [])}"
            )
        lines.append("")

    # ── Shodan infrastructure ─────────────────────────────────────────────────
    if state.shodan_result and state.shodan_result.success:
        d = state.shodan_result.data
        lines.append(
            f"SHODAN: {d.get('ips_checked', 0)} IPs checked, "
            f"{d.get('total_open_ports', 0)} open ports, "
            f"{d.get('total_vulns', 0)} CVEs"
        )
        for h in (d.get("hosts") or [])[:5]:
            vulns = h.get("vulns", [])
            ports = h.get("ports", [])
            lines.append(f"  - {h['ip']}: ports={ports} vulns={vulns}")
        lines.append("")

    # ── Phone pivot ───────────────────────────────────────────────────────────
    if state.phone_result and state.phone_result.success:
        d = state.phone_result.data
        if d.get("valid"):
            carrier = (d.get("carrier") or {}).get("name", "unknown")
            voip_flag = " ⚠ VoIP/anonymous number" if d.get("is_voip") else ""
            geocode = d.get("geocode") or d.get("location") or "unknown"
            tz = ", ".join(d.get("timezone") or []) or "unknown"
            lines.append(
                f"PHONE: valid=true line_type={d.get('line_type','unknown')}{voip_flag} "
                f"carrier={carrier} location={geocode} timezone={tz} "
                f"country={d.get('country_code','')}"
            )
            lines.append("")

    # ── Public records ────────────────────────────────────────────────────────
    if state.public_records_result and state.public_records_result.success:
        d = state.public_records_result.data
        n_cases = d.get("court_case_count", 0)
        n_corp = d.get("corporate_record_count", 0)
        if n_cases or n_corp:
            lines.append(
                f"PUBLIC RECORDS: {n_cases} court cases, {n_corp} corporate records"
            )
            for case in (d.get("court_cases") or [])[:5]:
                lines.append(
                    f"  COURT: {case.get('case_name')} | {case.get('court')} | "
                    f"filed={case.get('date_filed')} | {case.get('nature_of_suit')}"
                )
            for rec in (d.get("corporate_records") or [])[:5]:
                lines.append(
                    f"  CORP: {rec.get('company_name')} | role={rec.get('role')} | "
                    f"jurisdiction={rec.get('jurisdiction')} | status={rec.get('status')}"
                )
            lines.append("")

    # ── Correlation follow-up results ─────────────────────────────────────────
    if state.correlation_results:
        lines.append(
            f"CORRELATION PIVOTS: {len(state.correlation_results)} follow-up results"
        )
        for r in state.correlation_results:
            if not r.success:
                continue
            if r.tool == "maigret":
                found = r.data.get("found_count", 0)
                lines.append(
                    f"  USERNAME PIVOT ({r.input_value}): {found} accounts found"
                )
                for site in (r.data.get("sites_found") or [])[:5]:
                    lines.append(f"    - {site.get('name')}: {site.get('url','')}")
            elif r.tool == "public_records":
                lines.append(
                    f"  NAME PIVOT ({r.input_value}): "
                    f"{r.data.get('court_case_count',0)} court cases, "
                    f"{r.data.get('corporate_record_count',0)} corporate records"
                )
            elif r.tool == "shodan_scan":
                lines.append(
                    f"  IP PIVOT ({r.input_value}): "
                    f"{r.data.get('total_open_ports',0)} open ports, "
                    f"{r.data.get('total_vulns',0)} CVEs"
                )
            elif r.tool == "phone_lookup":
                carrier = (r.data.get("carrier") or {}).get("name", "unknown")
                voip_tag = " [VoIP]" if r.data.get("is_voip") else ""
                geocode = r.data.get("geocode") or r.data.get("location") or "?"
                lines.append(
                    f"  PHONE PIVOT ({r.input_value}): "
                    f"{r.data.get('line_type','?')}{voip_tag} via {carrier}, "
                    f"location={geocode}"
                )
            elif r.tool == "hibp":
                lines.append(
                    f"  EMAIL PIVOT/HIBP ({r.input_value}): "
                    f"{r.data.get('breach_count',0)} breaches"
                )
            elif r.tool == "holehe":
                lines.append(
                    f"  EMAIL PIVOT/HOLEHE ({r.input_value}): "
                    f"{r.data.get('found_count',0)} accounts"
                )
        lines.append("")

    return "\n".join(lines)


def _run_concurrent(
    state: PipelineState,
    fns: list,
) -> PipelineState:
    """Run node functions concurrently and merge their state updates.

    Each function receives the *same* input state (safe because Wave 1 functions
    are fully independent).  Results are diff'd against the original state and
    merged — if two functions somehow touch the same field the last one wins,
    but in practice each tool writes to its own dedicated result field.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    updates: dict = {}
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = {
            pool.submit(fn, state): getattr(fn, "__name__", str(fn)) for fn in fns
        }
        for future in as_completed(futures):
            fn_name = futures[future]
            try:
                result_state = future.result()
                # Extract only the fields that changed
                for field in PipelineState.model_fields:
                    new_val = getattr(result_state, field)
                    old_val = getattr(state, field)
                    if new_val is not old_val and new_val != old_val:
                        updates[field] = new_val
                        logger.debug(
                            "_run_concurrent: %s updated field=%s", fn_name, field
                        )
            except Exception as exc:
                logger.error("_run_concurrent: %s raised — %s", fn_name, exc)

    return state.model_copy(update=updates) if updates else state


def wave1_scan_node(state: PipelineState) -> PipelineState:
    """Run all input-only tools concurrently.

    These tools only need state.classifications — they have no dependencies on
    each other.  Running them in parallel reduces elapsed time from the sum of
    their runtimes to roughly the slowest single tool (usually SpiderFoot).

    Wave 1: breach_check, dehashed, whoxy, paste, stealer, phone_pivot,
            surface_map, holehe, blackbird, maigret, ghunt
    """
    logger.info("wave1_scan_node: starting 11 tools in parallel")
    result = _run_concurrent(
        state,
        [
            breach_check_node,
            dehashed_node,
            whoxy_node,
            paste_node,
            stealer_node,
            phone_pivot_node,
            surface_map_node,
            holehe_node,
            blackbird_node,
            maigret_node,
            ghunt_node,
        ],
    )
    logger.info("wave1_scan_node: all tools complete")
    return result


def wave2_scan_node(state: PipelineState) -> PipelineState:
    """Run tools that depend on Wave 1 results, concurrently.

    These tools need at least one Wave 1 result (GHunt name, SpiderFoot IPs,
    Holehe/Blackbird platform lists) but are independent of each other.

    Wave 2: broker_scan, shodan, public_records, ai_audit
    """
    logger.info("wave2_scan_node: starting 4 tools in parallel")
    result = _run_concurrent(
        state,
        [
            broker_scan_node,
            shodan_node,
            public_records_node,
            ai_audit_node,
        ],
    )
    logger.info("wave2_scan_node: all tools complete")
    return result


def _extract_deterministic_pivots(state: PipelineState) -> list[dict]:
    """Extract high-confidence pivots that don't need LLM judgment.

    Current rules:
    1. DeHashed alternate emails — any email co-appearing in a breach record that
       is NOT the original target:
         - Gmail +alias variants (user+amazon@gmail.com) → HIBP for service-specific
           breach exposure that the base-email search misses
         - Different-domain alternates (user@comcast.net alongside user@gmail.com)
           → full HIBP + Holehe footprint check

    GHunt name → public records and broker scan are already handled deterministically
    by Wave 2 via _resolve_name(); no need to re-add them here.
    """
    pivots: list[dict] = []
    already_seen: set[str] = {c.value.lower() for c in state.classifications}

    primary_email = next(
        (c.value for c in state.classifications if c.type == "email"), None
    )

    if state.dehashed_result and state.dehashed_result.success and primary_email:
        entries = state.dehashed_result.data.get("entries") or []
        # Normalize base local-part: strip dots (Gmail treats them as equivalent)
        base_local = primary_email.split("@")[0].lower().replace(".", "")

        for entry in entries:
            alt = (entry.get("email") or "").strip().lower()
            if not alt or alt in already_seen:
                continue
            already_seen.add(alt)

            alt_local = alt.split("@")[0].lower()
            is_plus_variant = (
                "+" in alt_local
                and alt_local.split("+")[0].replace(".", "") == base_local
            )

            if is_plus_variant:
                pivots.append(
                    {
                        "type": "email",
                        "value": alt,
                        "source": "dehashed",
                        "reason": (
                            f"Gmail +alias '{alt}' found in breach data — "
                            "HIBP treats these as distinct; may surface additional service breaches"
                        ),
                    }
                )
            else:
                # Different account co-appearing in the same breach record
                pivots.append(
                    {
                        "type": "email",
                        "value": alt,
                        "source": "dehashed",
                        "reason": (
                            f"Alternate email '{alt}' co-appeared in breach record — "
                            "check full breach history and active account footprint"
                        ),
                    }
                )

    return pivots[:3]  # cap at 3 to leave room for LLM pivots


def correlation_planner_node(state: PipelineState) -> PipelineState:
    """Ask Ollama to identify follow-up pivots based on current scan findings.

    First seeds the plan with deterministic high-value pivots (alternate emails
    from DeHashed), then asks Ollama to fill the remaining slots (up to 5 total).
    Each pivot has: type (name/ip/username/phone/email), value, source, reason.
    Skips gracefully in TEST_MODE and on any LLM/parse failure.
    """
    logger.info("correlation_planner_node: asking Ollama to plan follow-up pivots")

    # Always extract deterministic pivots regardless of mode
    deterministic = _extract_deterministic_pivots(state)
    if deterministic:
        logger.info(
            "correlation_planner_node: %d deterministic pivot(s): %s",
            len(deterministic),
            [(p["type"], p["value"]) for p in deterministic],
        )

    if config.is_test_mode():
        # In test mode inject one deterministic pivot so the execute node is exercised
        plan = deterministic + [
            {
                "type": "username",
                "value": "jdoe92",
                "source": "holehe_result",
                "reason": "Username found on multiple platforms — check full account footprint",
            }
        ]
        return state.model_copy(update={"correlation_plan": plan[:5]})

    digest = _build_analysis_digest(state)
    if not digest.strip():
        logger.info("correlation_planner_node: empty digest, skipping correlation")
        return state

    try:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(  # type: ignore[call-arg]
            model="llama3.1:8b",
            base_url=config.get("OLLAMA_HOST"),
            temperature=0,
            request_timeout=120,
            num_ctx=4096,  # CORRELATION_PROMPT + digest fits comfortably
            num_predict=512,  # small JSON array of ≤5 pivots
        )
        response = llm.invoke([("system", CORRELATION_PROMPT), ("human", digest)])
        raw = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )

        # Strip markdown fences
        stripped = raw.strip()
        if stripped.startswith("```"):
            stripped = stripped.split("\n", 1)[-1].rsplit("```", 1)[0]
        stripped = stripped.strip()

        # Attempt JSON parse with progressive repair for common LLM quirks
        data = _parse_json_tolerant(stripped)
        # _parse_json_tolerant may return a bare list; pivots live under a dict key
        pivots: list[dict] = (
            data.get("pivots") if isinstance(data, dict) else []
        ) or []

        # Validate type and value presence
        valid_types = {"name", "ip", "username", "phone", "email"}
        pivots = [
            p
            for p in pivots
            if isinstance(p, dict) and p.get("type") in valid_types and p.get("value")
        ]

        # Reject hallucinated placeholder values the LLM invents even when told not to
        def _is_real_value(pivot: dict) -> bool:
            v = (pivot.get("value") or "").strip()
            t = pivot.get("type", "")
            if not v:
                return False
            # Phone: reject obvious fakes — sequential digits, all same digit, too short
            if t == "phone":
                digits = re.sub(r"\D", "", v)
                if len(digits) < 10:
                    return False
                if re.match(r"^(\d)\1+$", digits):  # all same digit: 1111111111
                    return False
                if re.match(r"^1?234567890?$", digits):  # 1234567890 placeholder
                    return False
            # IP: reject private/loopback/unspecified ranges
            if t == "ip":
                private = (
                    v.startswith("192.168.")
                    or v.startswith("10.")
                    or v.startswith("172.")
                    or v in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "localhost")
                    or re.match(r"^0\.0\.", v)
                )
                if private:
                    return False
            # Name: reject obvious placeholders
            if t == "name":
                if v.lower() in ("<name>", "unknown", "n/a", "target", "person"):
                    return False
            return True

        # Remove LLM suggestions that duplicate deterministic pivots
        det_keys = {(p["type"], p["value"].lower()) for p in deterministic}
        llm_pivots = [
            p
            for p in pivots
            if _is_real_value(p) and (p["type"], p["value"].lower()) not in det_keys
        ]

        # Deterministic first, LLM fills remaining slots up to 5 total
        remaining_slots = max(0, 5 - len(deterministic))
        combined = deterministic + llm_pivots[:remaining_slots]

        logger.info(
            "correlation_planner_node: planned %d pivot(s) (%d deterministic, %d llm): %s",
            len(combined),
            len(deterministic),
            len(llm_pivots[:remaining_slots]),
            [(p["type"], p["value"]) for p in combined],
        )
        return state.model_copy(update={"correlation_plan": combined})

    except Exception as exc:
        logger.warning(
            "correlation_planner_node: failed (%s) — using deterministic pivots only",
            exc,
        )
        # LLM failed but deterministic pivots are still valid
        return state.model_copy(update={"correlation_plan": deterministic})


def correlation_execute_node(state: PipelineState) -> PipelineState:
    """Execute each planned pivot sequentially and collect results.

    Deduplicates against already-completed work so we never re-query
    a value the initial scan already covered (e.g. the original email).
    Results are stored in state.correlation_results and included in the
    analysis digest so the LLM's final risk score reflects them.
    """
    if not state.correlation_plan:
        logger.info("correlation_execute_node: no pivots planned, skipping")
        return state

    logger.info(
        "correlation_execute_node: executing %d pivots", len(state.correlation_plan)
    )

    # Build a set of (type, value) pairs already covered by the initial scan
    already_done: set[tuple[str, str]] = set()
    for c in state.classifications:
        already_done.add((c.type, c.value.lower()))

    results: list[ToolResult] = []

    for pivot in state.correlation_plan:
        ptype = pivot.get("type", "")
        pvalue = (pivot.get("value") or "").strip()
        if not pvalue:
            continue

        key = (ptype, pvalue.lower())
        if key in already_done:
            logger.info("correlation: skipping %s=%s (already covered)", ptype, pvalue)
            continue
        already_done.add(key)

        logger.info(
            "correlation: running pivot type=%s value=%s reason=%s",
            ptype,
            pvalue,
            pivot.get("reason", ""),
        )

        try:
            if ptype == "username":
                from eidolon.tools.maigret import Maigret, MaigretInput

                result = run_to_result(Maigret(), MaigretInput(username=pvalue))
                results.append(result)

            elif ptype == "name":
                from eidolon.tools import public_records as pr_tool

                result = pr_tool.lookup(pvalue, state=state.location_state)
                results.append(result)

            elif ptype == "ip":
                from eidolon.tools.shodan import Shodan, ShodanInput

                result = run_to_result(Shodan(), ShodanInput(ip=pvalue))
                results.append(result)

            elif ptype == "phone":
                from eidolon.tools import phone as phone_tool

                result = phone_tool.lookup(pvalue)
                results.append(result)

            elif ptype == "email":
                from eidolon.tools.hibp import Hibp, HibpInput
                from eidolon.tools.holehe import Holehe, HoleheInput

                hibp_result = run_to_result(
                    Hibp(), HibpInput(input_type="email", value=pvalue)
                )
                results.append(hibp_result)
                holehe_result = run_to_result(Holehe(), HoleheInput(email=pvalue))
                results.append(holehe_result)

            else:
                logger.warning("correlation: unknown pivot type %s, skipping", ptype)
                continue

        except Exception as exc:
            logger.error(
                "correlation: pivot type=%s value=%s FAILED — %s", ptype, pvalue, exc
            )

    logger.info("correlation_execute_node: collected %d results", len(results))
    return state.model_copy(update={"correlation_results": results})


# ── Analysis post-processing ──────────────────────────────────────────────────
# The local 8B model is unreliable at two things: emitting the full, deeply
# nested remediation JSON (it silently drops sections), and honouring the
# "items must be strings" contract (it returns objects instead). It also parrots
# the few-shot example breach names. Everything below repairs the model's output
# deterministically so the report is always complete and grounded in scan state.


def _stringify(v: object) -> str:
    """Best-effort coerce any JSON value the model returns into a flat string."""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return ", ".join(_stringify(x) for x in v if x not in (None, "", []))
    if isinstance(v, dict):
        return ", ".join(f"{k}: {_stringify(val)}" for k, val in v.items() if val)
    return str(v) if v is not None else ""


_HANDLE_NOISE = {
    "1",
    "na",
    "n/a",
    "none",
    "null",
    "unknown",
    "true",
    "false",
    "target",
    "person",
    "user",
    "username",
    "email",
}


# 16+ hex chars = a hash or DB id (e.g. Mongo ObjectId), not a username.
_HASH_LIKE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)


def _clean_handles(handles: list) -> list[str]:
    """Drop junk usernames and dedupe.

    DeHashed's v2 normalizer packs multiple values into one comma-joined string
    (e.g. ``"rmilo12648, 1"``), so each entry is first split on commas before
    filtering. Rejects: too-short, all-digits, hash/DB-id-like hex blobs, and
    placeholder noise words.
    """
    seen: set[str] = set()
    out: list[str] = []
    for h in handles or []:
        for token in _stringify(h).split(","):
            s = token.strip()
            if len(s) < 3 or s.isdigit() or s.lower() in _HANDLE_NOISE:
                continue
            if _HASH_LIKE.match(s):
                continue
            if s.lower() in seen:
                continue
            seen.add(s.lower())
            out.append(s)
    return out


def _looks_like_street_address(s: str) -> bool:
    """True only for real street addresses — rejects raw GEOINFO fragments like
    'US, san diego ca us 92115' that have no street number."""
    s = (s or "").strip()
    if not s:
        return False
    if re.search(r"\b\d{1,6}\s+[A-Za-z]", s):  # street number followed by a word
        return True
    return "po box" in s.lower()


def _clean_addresses(addrs: list) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for a in addrs or []:
        s = _stringify(a).strip()
        if not _looks_like_street_address(s) or s.lower() in seen:
            continue
        seen.add(s.lower())
        out.append(s)
    return out


_BOGUS_URL_MARKERS = ("api.", "/api/", "email_available", "/lookup", "/users/lookup")


def _clean_url(url: str) -> str:
    """Drop internal probe endpoints (Holehe/Blackbird API URLs) — they are not
    a user-facing profile and are misleading in a report."""
    u = (url or "").strip()
    if not u or any(m in u.lower() for m in _BOGUS_URL_MARKERS):
        return ""
    return u


def _known_platform_item(item: object) -> str:
    if isinstance(item, dict):
        name = (
            item.get("PlatformName") or item.get("platform") or item.get("name") or ""
        )
        url = _clean_url(item.get("url") or item.get("URL") or "")
        return f"{name}: {url}" if (name and url) else (name or _stringify(item))
    return _stringify(item)


def _known_credential_item(item: object) -> str:
    if isinstance(item, dict):
        name = (
            item.get("BreachName") or item.get("name") or item.get("ServiceName") or ""
        )
        year = str(
            item.get("YYYY") or item.get("year") or item.get("breach_date") or ""
        )[:4]
        types = item.get("data_types") or item.get("data_classes") or []
        types_s = ", ".join(types) if isinstance(types, list) else _stringify(types)
        head = f"{name} ({year})" if year else name
        return f"{head} — {types_s}" if types_s else head
    return _stringify(item)


def _known_breach_item(item: object) -> str:
    if isinstance(item, dict):
        name = (
            item.get("ServiceName") or item.get("BreachName") or item.get("name") or ""
        )
        year = str(
            item.get("YYYY") or item.get("year") or item.get("breach_date") or ""
        )[:4]
        return f"{name} ({year})" if year else name
    return _stringify(item)


def _known_google_item(item: object) -> str:
    if isinstance(item, dict):
        svc = (
            item.get("Google service") or item.get("service") or item.get("name") or ""
        )
        url = _clean_url(item.get("url") or "")
        return f"{svc}: {url}" if (svc and url) else (svc or _stringify(item))
    return _stringify(item)


def _normalize_what_is_known(known: dict) -> dict:
    """Coerce every what_is_known item to a clean string and strip noise."""
    known = dict(known or {})
    known["handles_and_usernames"] = _clean_handles(
        known.get("handles_and_usernames") or []
    )
    known["physical_data"] = _clean_addresses(known.get("physical_data") or [])
    for key, fn in (
        ("platforms_with_accounts", _known_platform_item),
        ("credentials_exposed", _known_credential_item),
        ("breach_history", _known_breach_item),
        ("google_footprint", _known_google_item),
    ):
        known[key] = [s for s in (fn(i) for i in (known.get(key) or [])) if s.strip()]
    return known


# Verbatim brand names that only ever appear in the prompt's few-shot examples.
# If the model emits one of these and the breach isn't actually in scan state,
# it's a hallucinated parroting of the example — drop it.
_EXAMPLE_LEAK_TOKENS = ("parkmobile", "luminpdf", "lumin pdf", "pdl breach")


def _real_breach_names(state: PipelineState) -> set[str]:
    names: set[str] = set()
    if state.hibp_result and state.hibp_result.success:
        for b in state.hibp_result.data.get("breaches") or []:
            n = (b.get("name") or "").lower()
            if n:
                names.add(n)
    if state.dehashed_result and state.dehashed_result.success:
        for db in state.dehashed_result.data.get("unique_databases") or []:
            if db:
                names.add(str(db).lower())
    return names


def _filter_top_risks(risks: list, state: PipelineState) -> list[str]:
    real = _real_breach_names(state)
    out: list[str] = []
    for r in risks or []:
        s = _stringify(r).strip()
        if not s:
            continue
        low = s.lower()
        leaked = any(tok in low for tok in _EXAMPLE_LEAK_TOKENS)
        grounded = any(name in low for name in real)
        if leaked and not grounded:
            logger.info("analysis: dropping hallucinated top_risk: %s", s[:80])
            continue
        out.append(s)
    return out[:5]


def _active_accounts(state: PipelineState) -> list[str]:
    """Confirmed active accounts — only platforms found by Holehe or Blackbird."""
    seen: set[str] = set()
    names: list[str] = []

    def add(n: str) -> None:
        n = (n or "").strip()
        if n and n.lower() not in seen:
            seen.add(n.lower())
            names.append(n)

    if state.holehe_result and state.holehe_result.success:
        for p in state.holehe_result.data.get("platforms_found") or []:
            add(p.get("platform", ""))
    if state.blackbird_result and state.blackbird_result.success:
        for a in state.blackbird_result.data.get("accounts_found") or []:
            add(a.get("platform", ""))
    return names


def _password_breaches(state: PipelineState) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if state.hibp_result and state.hibp_result.success:
        for b in state.hibp_result.data.get("breaches") or []:
            classes = [str(c).lower() for c in (b.get("data_classes") or [])]
            if any("password" in c for c in classes):
                name = b.get("name", "")
                year = str(b.get("breach_date") or "")[:4]
                label = f"{name} ({year})" if year else name
                if label and label.lower() not in seen:
                    seen.add(label.lower())
                    out.append(label)
    return out


def _has_address(state: PipelineState) -> bool:
    for res in (state.dehashed_result, state.whoxy_result):
        if res and res.success and res.data.get("unique_addresses"):
            return True
    return False


_REMEDIATION_KEYS = [
    "change_passwords",
    "enable_2fa",
    "account_hygiene",
    "credit_freeze",
    "identity_fraud_prevention",
    "sim_swap_hardening",
    "account_reviews",
    "gdpr_removals",
    "ccpa_removals",
    "broker_optouts",
    "monitoring",
    "no_action_available",
]


def _build_deterministic_remediation(state: PipelineState) -> dict[str, list[str]]:
    """Generate action items directly from scan state.

    These are rule-based, not reasoning — so we compute them in Python rather
    than trusting the 8B model, which drops sections and hallucinates. This is
    what guarantees the report is never sparse.
    """
    rem: dict[str, list[str]] = {}

    pw_breaches = _password_breaches(state)
    dh = (
        state.dehashed_result.data
        if (state.dehashed_result and state.dehashed_result.success)
        else {}
    )
    dh_pw = (dh.get("plaintext_password_count") or 0) + (
        dh.get("hashed_password_count") or 0
    )
    if pw_breaches:
        rem["change_passwords"] = [
            f"Passwords were exposed in: {', '.join(pw_breaches[:15])}. Change them "
            "everywhere — and on any other site where you reused the same password."
        ]
    elif dh_pw:
        rem["change_passwords"] = [
            f"{dh_pw} password(s) tied to your accounts appear in breach dumps — "
            "change them and any site where you reused the same password."
        ]

    accounts = _active_accounts(state)
    if accounts:
        rem["enable_2fa"] = [
            "Enable 2FA (prefer an authenticator app over SMS) on: "
            + ", ".join(accounts[:25])
        ]
        rem["account_reviews"] = [
            "Review privacy/visibility settings on: "
            + ", ".join(accounts[:25])
            + " — set profiles to private, remove any public phone number, and "
            "disable 'allow search engines to index my profile'."
        ]

    stealer_found = bool(
        state.stealer_result
        and state.stealer_result.success
        and state.stealer_result.data.get("found")
    )

    hygiene = [
        "Revoke unused OAuth app access: Google (myaccount.google.com/permissions), "
        "Facebook, Twitter/X, GitHub — remove any app you no longer use.",
        "Audit active sessions for unrecognized devices: Google "
        "(myaccount.google.com/device-activity), Apple ID, and Microsoft.",
    ]
    if stealer_found:
        hygiene.insert(
            0,
            "Infostealer malware exfiltrated your entire browser credential store — "
            "change ALL saved passwords now, move to a password manager "
            "(Bitwarden/1Password) with unique passwords, and sign out of every "
            "session everywhere (the attacker may hold live session cookies).",
        )
    rem["account_hygiene"] = hygiene

    breach_count = (
        state.hibp_result.data.get("breach_count", 0)
        if (state.hibp_result and state.hibp_result.success)
        else 0
    )
    broker_count = (
        state.broker_result.data.get("brokers_found_count", 0)
        if (state.broker_result and state.broker_result.success)
        else 0
    )
    has_addr = _has_address(state)

    if breach_count or broker_count or has_addr:
        rem["credit_freeze"] = [
            "Freeze your credit at all bureaus to block unauthorized credit/loan "
            "applications: Equifax (equifax.com/freeze), Experian "
            "(experian.com/freeze), TransUnion (transunion.com/freeze), Innovis "
            "(innovis.com/freeze). Also freeze ChexSystems (chexsystems.com, "
            "protects bank accounts) and LexisNexis (optout.lexisnexis.com)."
        ]

    if has_addr or stealer_found or breach_count:
        rem["identity_fraud_prevention"] = [
            "Get an IRS Identity Protection PIN at "
            "irs.gov/identity-theft-fraud-scams/get-an-identity-protection-pin — "
            "blocks fraudulent tax filings in your name. Free, renews annually.",
            "Lock your SSN in E-Verify at myeverify.uscis.gov — stops your SSN "
            "being used to pass employment eligibility checks. Free.",
            "Enroll in USPS Informed Delivery at informeddelivery.usps.com — "
            "preview incoming mail and catch mail-redirect fraud early.",
        ]

    phone_valid = bool(
        state.phone_result
        and state.phone_result.success
        and state.phone_result.data.get("valid")
    )
    if phone_valid or stealer_found:
        rem["sim_swap_hardening"] = [
            "Add a verbal passcode / port-freeze with your mobile carrier (AT&T, "
            "Verizon, and T-Mobile all support this) to block SIM-swap attacks.",
            "Remove your phone number from account recovery on Facebook, Twitter/X, "
            "and Google — replace SMS 2FA with an authenticator app.",
        ]

    if broker_count or has_addr:
        rem["broker_optouts"] = [
            "Use EasyOptOuts (easyoptouts.com, ~$20/year) to automate removal from "
            "Spokeo, Whitepages, BeenVerified, Radaris, and 100+ brokers. Profiles "
            "re-populate every ~90 days, so keep the subscription active."
        ]

    # Always applicable — this is the section the model most often dropped.
    rem["monitoring"] = [
        "Sign up for free breach monitoring at haveibeenpwned.com to be alerted to "
        "future breaches immediately.",
        "Set Google Alerts (google.com/alerts) for your full name, phone number, and "
        "home address to catch new public appearances.",
        "Re-run data-broker opt-outs every 90 days — profiles re-populate "
        "automatically from public records (voter rolls, property, court filings).",
        "Review active OAuth app permissions quarterly: Google, Facebook, Twitter/X, "
        "and GitHub.",
    ]

    return rem


def _stringify_rem_item(item: object) -> str:
    """Coerce a remediation item the model returned as an object into a string."""
    if isinstance(item, dict):
        if item.get("action"):
            plats = _stringify(item.get("platforms"))
            return f"{item['action']}: {plats}" if plats else str(item["action"])
        service = item.get("service") or item.get("name") or ""
        how = item.get("how_to_remove") or item.get("url") or ""
        if service and how:
            return f"{service}: {how}"
        return service or _stringify(item)
    return _stringify(item)


def _finalize_remediation(state: PipelineState, llm_rem: dict) -> dict:
    """Deterministic sections win when present; otherwise fall back to the
    (normalized) model output. Guarantees no empty/object items reach the report."""
    llm_rem = dict(llm_rem or {})
    deterministic = _build_deterministic_remediation(state)
    final: dict[str, list[str]] = {}
    for key in _REMEDIATION_KEYS:
        if deterministic.get(key):
            final[key] = deterministic[key]
        else:
            items = llm_rem.get(key) or []
            final[key] = [
                s for s in (_stringify_rem_item(i) for i in items) if s.strip()
            ]
    return final


def _postprocess_analysis(state: PipelineState, analysis: dict) -> dict:
    """Repair and complete the model's analysis before it reaches the report."""
    analysis = dict(analysis)
    analysis["what_is_known"] = _normalize_what_is_known(
        analysis.get("what_is_known") or {}
    )
    analysis["top_risks"] = _filter_top_risks(analysis.get("top_risks") or [], state)
    analysis["remediation"] = _finalize_remediation(
        state, analysis.get("remediation") or {}
    )
    return analysis


def _validate_analysis(analysis: dict) -> None:
    """Hard schema contract for the post-processed analysis.

    `_postprocess_analysis` already normalizes every shape and builds remediation
    deterministically, so a failure here means the model omitted a core narrative
    field it alone is responsible for (overall_risk_score / overall_risk_level /
    identity_summary / top_risks). We fail loudly rather than emit a degraded
    report. Raises ``pydantic.ValidationError``.
    """
    try:
        AnalysisResult(**analysis)
    except Exception as exc:
        logger.error("analysis_node: analysis failed schema validation — %s", exc)
        raise


def analysis_node(state: PipelineState) -> PipelineState:
    logger.info("analysis_node: synthesizing results with Ollama")

    if config.is_test_mode():
        fixture_path = (
            Path(__file__).parent.parent.parent
            / "tests"
            / "fixtures"
            / "analysis_response.json"
        )
        analysis = json.loads(fixture_path.read_text())
        return state.model_copy(update={"analysis_result": analysis})

    # Build a compact digest — sending the full state dump (50-100KB) to a local
    # 8B model makes inference extremely slow. Instead we extract only the signal.
    digest = _build_analysis_digest(state)

    try:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(  # type: ignore[call-arg]
            model="llama3.1:8b",
            base_url=config.get("OLLAMA_HOST"),
            temperature=0,
            request_timeout=300,  # 5 min hard cap
            num_ctx=8192,  # ANALYSIS_PROMPT alone is ~2300 tokens; default 2048 truncates the prompt
            num_predict=4096,  # full remediation + findings_context JSON needs ~2000-3000 tokens
        )
        messages = [
            ("system", ANALYSIS_PROMPT),
            ("human", digest),
        ]
        response = llm.invoke(messages)
        raw_text = (
            response.content
            if isinstance(response.content, str)
            else str(response.content)
        )
        logger.debug("analysis_node: raw response length=%d", len(raw_text))

        # Strip markdown code fences if the model wrapped the JSON
        stripped = raw_text.strip()
        if stripped.startswith("```"):
            stripped = stripped.split("\n", 1)[-1]
            stripped = stripped.rsplit("```", 1)[0]
        stripped = stripped.strip()

        if not stripped:
            raise json.JSONDecodeError("empty response from model", "", 0)

        analysis = json.loads(stripped)

    except json.JSONDecodeError as exc:
        logger.error("analysis_node: failed to parse Ollama JSON response: %s", exc)
        error_result: dict = {
            "overall_risk_score": 0,
            "overall_risk_level": "low",
            "summary": "Analysis failed — could not parse model response.",
            "top_findings": [],
            "immediate_actions": [],
            "longer_term_actions": [],
            "breach_severity": "none",
            "broker_exposure_severity": "none",
            "ai_exposure_severity": "none",
            "error": str(exc),
        }
        return state.model_copy(update={"analysis_result": error_result})
    except Exception as exc:
        logger.error("analysis_node: unexpected error: %s", exc)
        error_result = {
            "overall_risk_score": 0,
            "overall_risk_level": "low",
            "summary": f"Analysis failed: {exc}",
            "top_findings": [],
            "immediate_actions": [],
            "longer_term_actions": [],
            "breach_severity": "none",
            "broker_exposure_severity": "none",
            "ai_exposure_severity": "none",
            "error": str(exc),
        }
        return state.model_copy(update={"analysis_result": error_result})

    # ── Hard contract (runs only on a successfully parsed response) ────────────
    # LLM/network/JSON failures above degrade gracefully; from here on the output
    # is OUR responsibility. Repair shapes + build remediation deterministically,
    # then enforce the schema as a hard contract — a violation means the model
    # dropped a core narrative field, and we fail loudly rather than ship a broken
    # report. These steps are intentionally outside the soft-fallback try.
    analysis = _postprocess_analysis(state, analysis)
    _validate_analysis(analysis)

    # Enrich findings_context with real URLs from the static privacy DB. The LLM
    # is instructed to set how_to_remove=null; we inject verified deletion URLs +
    # correct legal frameworks here.
    findings = analysis.get("findings_context")
    if isinstance(findings, list):
        from eidolon.tools.privacy_url_lookup import enrich_findings_context

        analysis["findings_context"] = enrich_findings_context(findings)
    return state.model_copy(update={"analysis_result": analysis})


def report_node(state: PipelineState) -> PipelineState:
    from eidolon.agent.report import write_report

    report_path = write_report(state)
    return state.model_copy(update={"report_path": report_path})
