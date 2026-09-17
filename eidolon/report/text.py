"""Display cleaning + static framing strings for the report (REFACTOR.6).

The credential cleaners make raw (sometimes DeHashed-packed) values renderable;
the framing constants are the exact strings and row orders every renderer
shares. ``_rem_item`` normalizes remediation items defensively.
"""

from __future__ import annotations

import re


def _clean_cred_username(u: str) -> str:
    """DeHashed packs multiple values into one field; keep the first real one."""
    u = (u or "").split(",")[0].strip()
    return "" if len(u) < 3 or u.isdigit() else u


def _clean_cred_address(a: str) -> str:
    """Show only real addresses (street number present)."""
    a = (a or "").strip()
    return a if (len(a) >= 6 and re.search(r"\d", a)) else ""


def _clean_cred_hash(h: str) -> tuple[str, str]:
    """DeHashed formats hashes as 'hash:salt||ALGO' — split out hash + algo."""
    from eidolon.sources.dehashed import _hash_type

    raw = (h or "").split("||")[0].split(":")[0].strip()
    if "||" in (h or ""):
        algo = h.rsplit("||", 1)[-1].strip().strip("|").strip()
    else:
        algo = _hash_type(raw)
    return raw, algo


# ── Static framing (identical strings in every renderer) ─────────────────────

TRAINING_PILE_INTRO = (
    "Common Crawl is a free, openly published archive of the public web — "
    "the raw corpus that most AI training sets (like Google's C4) are "
    "filtered and built FROM. Your pages showing up here means your public "
    "content is in that upstream pile. It does **not** mean any specific AI "
    "model memorized you or was trained on you — only that your content is in "
    "the corpus training data is sourced from."
)

TRAINING_PILE_OPT_OUT_STEPS = [
    "Register your content with Spawning's **Do Not Train** registry at "
    "<https://haveibeentrained.com> (spawning.ai) so participating AI "
    "trainers skip it.",
    "Add an **ai.txt** file to your site (and robots rules) to signal that "
    "AI crawlers should not collect your pages going forward.",
]

TRAINING_PILE_OPT_OUT_NOTE = (
    "_Opting out only affects future crawls. It cannot remove content "
    "already in existing archives or datasets._"
)

THREAT_INTRO = (
    "{count} thing(s) a stranger could realistically try with what's already "
    "exposed. (These map to MITRE ATT&CK, a standard catalog of real-world "
    "attacker behaviour — the codes are just for reference.)"
)

# Fixed order + titles of the remediation groups (identical in every renderer).
_REMEDIATION_GROUPS: list[tuple[str, str]] = [
    ("identity_fraud_prevention", "Identity Fraud Prevention (Do These First)"),
    ("credit_freeze", "Freeze Your Credit"),
    ("sim_swap_hardening", "SIM Swap Hardening"),
    ("change_passwords", "Change Passwords"),
    ("enable_2fa", "Enable 2FA"),
    ("account_hygiene", "Account Hygiene"),
    ("account_reviews", "Review Privacy Settings"),
    ("ccpa_removals", "US Data Deletion Requests (CCPA)"),
    ("gdpr_removals", "EU/UK Erasure Requests (GDPR)"),
    ("broker_optouts", "Data Broker Opt-Outs"),
    ("monitoring", "Ongoing Monitoring"),
]

# what_is_known key → rendered subsection title (identical in every renderer).
_KNOWN_GROUPS: list[tuple[str, str]] = [
    ("handles_and_usernames", "Usernames & Handles"),
    ("platforms_with_accounts", "Accounts Found"),
    ("physical_data", "Physical Data Exposed"),
    ("credentials_exposed", "Passwords That Have Leaked"),
    ("google_footprint", "Google Footprint"),
    ("breach_history", "Where Your Data Has Shown Up"),
]

# Source name → coverage row label (identical in every renderer).
_SOURCE_LABELS: dict[str, str] = {
    "hibp": "HIBP",
    "dehashed": "DeHashed",
    "whoxy": "Whoxy",
    "paste": "Paste sites",
    "stealer": "Infostealer logs",
    "holehe": "Holehe",
    "blackbird": "Blackbird",
    "maigret": "Maigret",
    "ghunt": "GHunt",
    "spiderfoot": "SpiderFoot",
    "broker_scan": "Broker scan",
    "shodan": "Shodan",
    "ai_audit": "AI Audit",
    "phone_lookup": "Phone",
    "public_records": "Public Records",
    "commoncrawl": "Common Crawl",
}

#: canonical row order (the legacy markdown order); unknown sources append.
_SOURCE_ORDER: list[str] = [
    "hibp",
    "dehashed",
    "whoxy",
    "paste",
    "stealer",
    "blackbird",
    "maigret",
    "ghunt",
    "holehe",
    "broker_scan",
    "spiderfoot",
    "shodan",
    "ai_audit",
    "phone_lookup",
    "public_records",
    "commoncrawl",
]

_MECH_LABELS = {
    "gdpr": "GDPR erasure (EU/UK)",
    "ccpa": "CCPA deletion (US)",
    "optout": "Opt-out",
    "account_deletion": "Delete account",
}


def _rem_item(item: object) -> str:
    """Normalize a remediation item (defensive against dict shapes)."""
    if isinstance(item, dict):
        if item.get("action"):
            plats = item.get("platforms")
            if isinstance(plats, list):
                plats = ", ".join(str(p) for p in plats if p)
            return f"{item['action']}: {plats}" if plats else str(item["action"])
        service = item.get("service") or item.get("name") or ""
        how = item.get("how_to_remove") or item.get("url") or ""
        if service and how:
            return f"{service}: {how}"
        return service or ""
    return str(item)
