"""String normalization helpers for analysis content.

Filtering, cleaning and coercion of raw text (handles, addresses, LLM
``what_is_known`` items) into display strings. Deterministic, no LLM
involvement; shared by ``facts`` (state-derived content), ``narrative``
(LLM output) and ``digest`` (prompt digest).
"""

from __future__ import annotations

import re

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
