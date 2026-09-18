"""Deterministic facts derived from scan findings: what-is-known, risk floor,
identity summary, top-risk filtering, account/breach/address markers.

No LLM involvement — these functions translate ``state.findings`` into the
human-readable facts the narrative step and the deterministic fallback both
consume. The LLM writes narrative only; this module writes the floor.
"""

from __future__ import annotations

from eidolon.analysis.normalize import _clean_addresses, _stringify
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

#: Breach names that appear verbatim in prompts' few-shot examples; treated as
#: hallucinations unless grounded in real findings.
_EXAMPLE_LEAK_TOKENS = ("parkmobile", "luminpdf", "lumin pdf", "pdl breach")


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


def _has_category(state: ScanState, category: str) -> bool:
    """Whether the scan actually produced findings of a claim-category. Used to
    reject narrative that asserts a category the scan never found (an 8B model
    parrots prompt examples / hallucinates breaches when breach tools return
    nothing — see the dogfood finding)."""
    f = state.findings or []
    if category == "breach":
        return any(isinstance(x, (Breach, Credential)) for x in f)
    if category == "infostealer":
        return any(isinstance(x, InfostealerLog) for x in f)
    if category == "address":
        return _has_address(state)
    if category == "broker":
        return any(isinstance(x, BrokerExposure) for x in f)
    return True  # unknown category: don't second-guess


#: claim tokens → the finding-category that must exist for the claim to be grounded
_CLAIM_CATEGORIES: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        (
            "breach",
            "leak",
            "leaked",
            "hacked",
            "data dump",
            "password",
            "credential",
            "hashed",
            "plaintext",
        ),
        "breach",
    ),
    (
        ("infostealer", "info-stealer", "malware", "stealer log", "redline", "vidar"),
        "infostealer",
    ),
    (
        (
            "home address",
            "street address",
            "license plate",
            "where you live",
            "front door",
            "physical address",
        ),
        "address",
    ),
    (("data broker", "people-finder", "people finder", "broker site"), "broker"),
)


def _claim_is_ungrounded(text: str, state: ScanState) -> bool:
    """True if the text asserts a finding-category the scan has zero findings for."""
    low = _stringify(text).lower()
    for tokens, category in _CLAIM_CATEGORIES:
        if any(t in low for t in tokens) and not _has_category(state, category):
            return True
    return False


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
            continue  # drop hallucinated example breach name
        if not grounded and _claim_is_ungrounded(s, state):
            # drop a risk asserting a category the scan never found — unless it's
            # grounded in a real breach (whose data classes may name an address,
            # license plate, etc. that has no separate finding of its own)
            continue
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

    # Linked accounts: identity-correlation risk. A large cross-platform footprint
    # is real exposure even with no breach — but capped modest so it can't alone
    # reach "high" (breach/credential/infostealer are the severe categories).
    accounts = [f for f in findings if isinstance(f, Account) and f.active]
    score += min(len(accounts), 20)
    if any(isinstance(f, GoogleFootprint) for f in findings):
        score += 2

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
