"""
privacy_url_lookup.py — static lookup table for privacy/deletion URLs.

The LLM is unreliable at knowing exact deletion URLs and often confuses GDPR
(EU-only) with CCPA (US companies).  This module provides ground truth.

Usage:
    entry = lookup_platform("Betterment")
    # {"display_name": "Betterment", "framework": "ccpa",
    #  "deletion_url": "https://...", "notes": "..."}

    enriched = enrich_findings_context(findings_context_list)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TypedDict

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent.parent / "data" / "privacy_urls.json"


class PrivacyEntry(TypedDict, total=False):
    display_name: str
    domain: str
    hq_country: str
    framework: str  # gdpr | ccpa | optout | voluntary | none
    deletion_url: str | None
    request_email: str | None
    notes: str


# ── Module-level index (loaded once) ─────────────────────────────────────────


def _build_index() -> dict[str, PrivacyEntry]:
    """Return a mapping of normalised name → entry."""
    try:
        entries: list[dict] = json.loads(_DB_PATH.read_text())
    except Exception as exc:
        logger.warning("privacy_url_lookup: could not load %s: %s", _DB_PATH, exc)
        return {}

    index: dict[str, PrivacyEntry] = {}
    for entry in entries:
        for name in entry.get("names", []):
            index[_norm(name)] = entry  # type: ignore[assignment]
        # Also index by domain root (e.g. "betterment" from "betterment.com")
        domain = entry.get("domain", "")
        if domain:
            root = domain.split(".")[0]
            key = _norm(root)
            if key not in index:
                index[key] = entry  # type: ignore[assignment]
    return index


def _norm(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    s = s.lower()
    s = re.sub(r"[^\w\s]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


_INDEX: dict[str, PrivacyEntry] = {}


def _get_index() -> dict[str, PrivacyEntry]:
    global _INDEX
    if not _INDEX:
        _INDEX = _build_index()
    return _INDEX


# ── Public API ────────────────────────────────────────────────────────────────


def lookup_platform(name: str) -> PrivacyEntry | None:
    """
    Look up a platform by display name, returning its PrivacyEntry or None.

    Tries:
      1. Exact normalised match (e.g. "betterment" → entry)
      2. Prefix match on normalised name tokens (e.g. "betterment financial" → "betterment")
      3. Substring match (e.g. "adobe 2013 breach" → "adobe")
    """
    idx = _get_index()
    key = _norm(name)

    # 1. Exact
    if key in idx:
        return idx[key]

    # 2. Token-prefix: every word in the lookup key is a prefix of a key in the index
    words = key.split()
    for ikey, entry in idx.items():
        iwords = ikey.split()
        if words and iwords[: len(words)] == words:
            return entry

    # 3. Substring: the normalised name contains an index key (handles "Adobe (2013)")
    for ikey, entry in idx.items():
        if len(ikey) >= 4 and ikey in key:
            return entry

    return None


def enrich_findings_context(findings: list[dict]) -> list[dict]:
    """
    Post-process LLM findings_context to inject real URLs and correct frameworks.

    For each finding:
    - Look up the platform name in the static DB
    - If found: override removal_mechanism with the correct framework
    - If found and has a deletion_url: override how_to_remove with the real URL
    - If found and has notes: append notes to the finding

    The LLM's output is only used as a fallback when the platform isn't in the DB.
    """
    enriched = []
    for f in findings:
        f = dict(f)  # shallow copy — don't mutate the original
        name = f.get("name", "")
        entry = lookup_platform(name)

        if entry:
            framework = entry.get("framework", "")
            deletion_url = entry.get("deletion_url")
            request_email = entry.get("request_email")
            notes = entry.get("notes", "")
            # domain=None signals a non-service (threat intel datasets, aggregators)
            is_real_service = entry.get("domain") is not None

            # Override the LLM's (often wrong) removal_mechanism
            if framework and framework != "none":
                f["removal_mechanism"] = framework
                f["removable"] = True
            else:
                # framework == "none" — shut-down or non-removable
                f["removal_mechanism"] = "none"
                f["removable"] = False
                f["service_is_live"] = False
                f["account_is_active"] = False

            # Non-service datasets (SynthientCredentialStuffing, SOCRadar, etc.)
            if not is_real_service:
                f["removable"] = False
                f["service_is_live"] = False
                f["account_is_active"] = False

            # Build a clean how_to_remove from verified data
            parts: list[str] = []
            if deletion_url:
                parts.append(deletion_url)
            if request_email:
                parts.append(f"or email {request_email}")
            if notes:
                parts.append(f"— {notes}")

            if parts:
                f["how_to_remove"] = " ".join(parts)
            else:
                # Explicitly null out LLM-hallucinated URLs for non-removable items
                f["how_to_remove"] = None

        enriched.append(f)
    return enriched
