"""Deterministic risk analysis: what-is-known, risk floor, identity summary."""

import re

from eidolon.core.findings import (
    Account,
    Breach,
    BrokerExposure,
    Credential,
    ExposedHost,
    GoogleFootprint,
    InfostealerLog,
    PhoneIntel,
)
from eidolon.core.state import ScanState

# --- Constants ---

_HANDLE_NOISE = {
    "me",
    "user",
    "admin",
    "test",
    "demo",
    "info",
    "support",
    "contact",
    "help",
    "sales",
    "noreply",
    "no-reply",
    "root",
    "postmaster",
    "webmaster",
    "hostmaster",
    "abuse",
    "security",
    "privacy",
    "legal",
    "compliance",
    "marketing",
    "newsletter",
    "blog",
    "www",
    "mail",
    "email",
    "api",
    "app",
    "dev",
    "staging",
    "prod",
    "production",
}

_HASH_LIKE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)

_BOOGUS_URL_MARKERS = ("api.", "/api/", "email_available", "/lookup", "/users/lookup")

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

_EXAMPLE_LEAK_TOKENS = ("parkmobile", "luminpdf", "lumin pdf", "pdl breach")


# --- Helpers ---


def _stringify(v: object) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float, bool)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return ", ".join(_stringify(x) for x in v)
    if isinstance(v, dict):
        return ", ".join(f"{k}: {_stringify(v2)}" for k, v2 in v.items())
    return str(v)


def _clean_handles(handles: list) -> list[str]:
    """Drop junk usernames and dedupe.

    DeHashed's v2 normalizer packs multiple values into one comma-joined string
    (e.g. ``"rmilo12648, 1"``), so each entry is first split on commas before
    filtering. Rejects: too-short, all-digits, hash/DB-id-like hex blobs, and
    placeholder noise words.
    """
    out: list[str] = []
    seen = set()
    for h in handles:
        if not isinstance(h, str):
            continue
        # Split comma-packed values (DeHashed v2)
        for part in h.split(","):
            u = part.strip().lower()
            if not u:
                continue
            if u in _HANDLE_NOISE:
                continue
            if _HASH_LIKE.match(u):
                continue
            if len(u) < 3:
                continue
            if u.isdigit():
                continue
            if u not in seen:
                seen.add(u)
                out.append(part.strip())
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


def _clean_addresses(addresses: list) -> list[str]:
    """Extract unique street-like addresses from a list of strings."""
    out: list[str] = []
    seen = set()
    for addr in addresses:
        if isinstance(addr, str) and _looks_like_street_address(addr):
            key = addr.lower().strip()
            if key not in seen:
                seen.add(key)
                out.append(addr.strip())
    return out


def _real_breach_names(state: ScanState) -> set[str]:
    """Return the set of real breach names from Breach findings."""
    names = set()
    for f in state.findings or []:
        if isinstance(f, Breach):
            if f.title:
                names.add(f.title.lower())
    for f in state.findings or []:
        if isinstance(f, Credential):
            if f.source_breach:
                names.add(f.source_breach.lower())
    return names


def _filter_top_risks(risks: list, state: ScanState) -> list[str]:
    """Filter and order the top risks, preferring real breaches + infostealers.
    Drops hallucinated example tokens (parkmobile, luminpdf, pdl breach) unless
    grounded in actual findings.
    """
    real_breaches = _real_breach_names(state)
    scored: list[tuple[int, str]] = []
    for r in risks or []:
        s = _stringify(r).strip()
        if not s:
            continue
        low = s.lower()
        leaked = any(tok in low for tok in _EXAMPLE_LEAK_TOKENS)
        grounded = any(name in low for name in real_breaches)
        if leaked and not grounded:
            continue  # drop hallucinated example
        score = 0
        if any(b.lower() in low for b in real_breaches):
            score += 10
        if "infostealer" in low or "malware" in low:
            score += 15
        if "password" in low and "leak" in low:
            score += 8
        if "address" in low and ("home" in low or "street" in low):
            score += 7
        if "phone" in low and ("sim" in low or "swap" in low):
            score += 6
        scored.append((score, s))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for _, r in scored[:5]]


def _active_accounts(state: ScanState) -> list[str]:
    """Active accounts from Holehe/Blackbird/Maigret confirmations."""
    out = []
    for f in state.findings or []:
        if isinstance(f, Account) and f.active:
            platform = f.platform or f.payload.get("platform", "?")
            user = f.payload.get("username", "?")
            out.append(f"{platform}:{user}" if user != "?" else platform)
    return out


def _password_breaches(state: ScanState) -> list[str]:
    """Breaches that exposed passwords (hashed or plaintext)."""
    out = []
    for f in state.findings or []:
        if isinstance(f, Breach):
            data = f.data_classes
            if any("password" in d.lower() for d in data):
                out.append(f.title or f.payload.get("breach_name", "?"))
    return out


def _has_address(state: ScanState) -> bool:
    """Whether any broker exposure contains a street address."""
    return bool(
        _clean_addresses(
            [f for f in state.findings or [] if isinstance(f, BrokerExposure)]
        )
    )


# --- Remediation ---


def _build_deterministic_remediation(state: ScanState) -> dict[str, list[str]]:
    """Build the deterministic remediation dict from findings."""
    rem: dict[str, list[str]] = {k: [] for k in _REMEDIATION_KEYS}

    # Change passwords - only for breaches with password class
    for f in state.findings or []:
        if isinstance(f, Breach):
            data = f.data_classes
            if any("password" in d.lower() for d in data):
                year = f.breach_date.year if f.breach_date else ""
                name = f.title or f.payload.get("breach_name", "?")
                suffix = f" ({year})" if year else ""
                rem["change_passwords"].append(f"Change password for {name}{suffix}")

    # Enable 2FA
    active = _active_accounts(state)
    if active:
        platforms = ", ".join(a.split(":")[0] for a in active)
        rem["enable_2fa"].append(
            "Enable 2FA on active accounts: "
            f"{platforms} (prefer authenticator app over SMS)"
        )

    # Account hygiene
    if active:
        rem["account_hygiene"].append("Review and remove unused linked accounts")

    # Credit freeze
    if _has_address(state) or any(
        isinstance(f, BrokerExposure) for f in state.findings or []
    ):
        rem["credit_freeze"].append(
            "Freeze credit with Equifax, Experian, and TransUnion"
        )

    # Identity fraud prevention
    if _has_address(state):
        rem["identity_fraud_prevention"].append(
            "Monitor for identity fraud; address found in broker data"
        )

    # SIM swap hardening
    phones = [f for f in state.findings or [] if isinstance(f, PhoneIntel)]
    stealer = any(isinstance(f, InfostealerLog) for f in state.findings or [])
    if phones or stealer:
        rem["sim_swap_hardening"].append("Add SIM PIN / port freeze with carrier")

    # Account hygiene - infostealer triggers priority hygiene
    if stealer:
        rem["account_hygiene"].append(
            "Infostealer detected: treat all saved passwords as "
            "compromised, rotate immediately"
        )

    # Account reviews
    if active:
        rem["account_reviews"].append("Review active accounts for unauthorized changes")

    # GDPR removals
    if _has_address(state):
        rem["gdpr_removals"].append(
            "Submit GDPR deletion requests for broker-held addresses"
        )

    # CCPA removals
    if _has_address(state):
        rem["ccpa_removals"].append(
            "Submit CCPA deletion requests for broker-held addresses"
        )

    # Broker opt-outs
    brokers = set()
    for f in state.findings or []:
        if isinstance(f, BrokerExposure):
            brokers.add(f.broker or f.payload.get("broker", "?"))
    if brokers:
        rem["broker_optouts"].append(
            "Opt out from data brokers: "
            f"{', '.join(sorted(brokers)[:5])} (use EasyOptOuts for bulk)"
        )

    # Monitoring - always present
    rem["monitoring"].append("Set up breach monitoring alerts for email and phone")

    # No action available
    if not any(rem.values()):
        rem["no_action_available"].append(
            "No specific actions required based on current findings"
        )

    # Remove empty keys
    return {k: v for k, v in rem.items() if v}


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


def _finalize_remediation(
    state: ScanState, llm_rem: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Merge LLM remediation with deterministic remediation (deterministic wins)."""
    det = _build_deterministic_remediation(state)
    # Deterministic takes precedence; LLM fills gaps
    for k in set(list(det.keys()) + list(llm_rem.keys())):
        if k not in det:
            # Coerce LLM items to strings
            det[k] = [
                s
                for s in (_stringify_rem_item(i) for i in (llm_rem.get(k) or []))
                if s.strip()
            ]
    return det


# --- What Is Known ---


def _state_what_is_known(state: ScanState) -> dict[str, list[str]]:
    """Build the 'what is known' dict from findings."""
    known: dict[str, list[str]] = {}

    # Breaches
    breaches = []
    for f in state.findings or []:
        if isinstance(f, Breach):
            name = f.title or f.payload.get("breach_name", "?")
            date = (
                str(f.breach_date.year)
                if f.breach_date
                else f.payload.get("breach_date", "?")
            )
            breaches.append(f"{name} ({date})")
    if breaches:
        known["breach_history"] = breaches[:15]

    # Accounts
    accounts = []
    for f in state.findings or []:
        if isinstance(f, Account) and f.payload.get("confirmed"):
            p = f.payload
            accounts.append(f"{p.get('platform', '?')}: {p.get('username', '?')}")
    if accounts:
        known["accounts"] = accounts

    # Credentials
    creds = []
    for f in state.findings or []:
        if isinstance(f, Credential):
            breach = f.source_breach or f.payload.get("source_breach", "?")
            user = (
                f.username
                or f.email
                or f.payload.get("username")
                or f.payload.get("email", "?")
            )
            creds.append(f"{breach}: {user}")
    if creds:
        known["credentials_exposed"] = creds[:10]

    # Brokers
    brokers = []
    for f in state.findings or []:
        if isinstance(f, BrokerExposure):
            p = f.payload
            brokers.append(
                f"{p.get('broker', '?')}: {', '.join(p.get('exposed_fields', []))}"
            )
    if brokers:
        known["brokers"] = brokers[:10]

    # Infostealers
    stealers = []
    for f in state.findings or []:
        if isinstance(f, InfostealerLog):
            p = f.payload
            stealers.append(f"{p.get('family', '?')} on {p.get('host', '?')}")
    if stealers:
        known["infostealers"] = stealers

    # Phone
    phones = []
    for f in state.findings or []:
        if isinstance(f, PhoneIntel):
            p = f.payload
            phones.append(f"{p.get('number', '?')} — {p.get('carrier', '?')}")
    if phones:
        known["phone"] = phones

    # Google
    googles = []
    for f in state.findings or []:
        if isinstance(f, GoogleFootprint):
            p = f.payload
            googles.append(p.get("query", "?"))
    if googles:
        known["google_footprints"] = googles

    # Hosts
    hosts = []
    for f in state.findings or []:
        if isinstance(f, ExposedHost):
            p = f.payload
            hosts.append(
                f"{p.get('ip', '?')}: {', '.join(str(x) for x in p.get('ports', []))}"
            )
    if hosts:
        known["exposed_hosts"] = hosts

    # Footprints (base Finding with kind="footprint")
    footprints = state.generic_findings("footprint")
    if footprints:
        known["footprints"] = [f.payload.get("name", "?") for f in footprints[:10]]

    # Domains (base Finding with kind="registered_domain")
    domains = state.generic_findings("registered_domain")
    if domains:
        known["domains"] = [f.payload.get("domain", "?") for f in domains[:10]]

    # Web presence (base Finding with kind="web_presence")
    web = state.generic_findings("web_presence")
    if web:
        known["web_presence"] = [f.payload.get("url", "?") for f in web[:10]]

    return known


def _state_risk_floor(state: ScanState) -> int:
    """A minimum risk score derived from scan findings, so a failed LLM
    analysis never reports 0/low for a heavily-exposed target."""
    score = 0
    findings = state.findings or []

    # Breaches: +2 each, max 30
    breaches = [f for f in findings if isinstance(f, Breach)]
    score += min(len(breaches) * 2, 30)

    # Credentials: plaintext +5 each (max 30), hashed +1 each (max 10)
    creds = [f for f in findings if isinstance(f, Credential)]
    plain = [c for c in creds if c.password is not None]
    hashed = [c for c in creds if c.password_hash and c.password is None]
    score += min(len(plain) * 5, 30)
    score += min(len(hashed), 10)

    # Infostealer: +40
    if any(isinstance(f, InfostealerLog) for f in findings):
        score += 40

    # Broker exposures: +3 each, max 15
    brokers = [f for f in findings if isinstance(f, BrokerExposure)]
    score += min(len(brokers) * 3, 15)

    # Address: +10
    if _has_address(state):
        score += 10

    # Phone: +5
    if any(isinstance(f, PhoneIntel) for f in findings):
        score += 5

    return min(score, 100)


def _state_identity_summary(state: ScanState) -> str:
    """Factual one-paragraph summary from scan findings — used when the LLM's
    narrative is unavailable, so the report is never blank."""
    parts = []
    findings = state.findings or []

    # Breaches - count all
    breaches = [f for f in findings if isinstance(f, Breach)]
    if breaches:
        parts.append(f"your email appears in {len(breaches)} known data breach(es)")

    # Credentials - plaintext vs hashed
    creds = [f for f in findings if isinstance(f, Credential)]
    plain = [c for c in creds if c.password is not None]
    hashed = [c for c in creds if c.password_hash and c.password is None]
    bits = []
    if plain:
        bits.append(f"{len(plain)} in plaintext")
    if hashed:
        bits.append(f"{len(hashed)} hashed")
    if bits:
        parts.append(f"breach dumps expose {' and '.join(bits)} password(s)")

    # Infostealer
    if any(isinstance(f, InfostealerLog) for f in findings):
        parts.append("infostealer malware logs hold your full saved-credential store")

    # Active accounts
    active = _active_accounts(state)
    if active:
        parts.append(f"active accounts were found on {len(active)} platform(s)")

    if not parts:
        return "No significant exposure detected."

    return (
        "Automated summary (the AI narrative step was unavailable): "
        + "; ".join(parts)
        + "."
    )


# --- LLM output normalization helpers (used by narrative) ---


def _known_platform_item(item: object) -> str:
    from eidolon.utils import clean_url

    if isinstance(item, dict):
        name = (
            item.get("PlatformName") or item.get("platform") or item.get("name") or ""
        )
        url = clean_url(item.get("url") or item.get("URL") or "")
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
    from eidolon.utils import clean_url

    if isinstance(item, dict):
        svc = (
            item.get("Google service") or item.get("service") or item.get("name") or ""
        )
        url = clean_url(item.get("url") or "")
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
