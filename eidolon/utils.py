"""Common paths, fixture/data loading, and small shared helpers.

Single source of truth for where data and test fixtures live, so tools don't
each recompute ``Path(__file__).parent...`` chains.
"""

from __future__ import annotations

import json
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent  # eidolon/
PROJECT_ROOT = PACKAGE_DIR.parent  # repo root
DATA_DIR = PACKAGE_DIR / "data"  # eidolon/data/
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"  # repo/tests/fixtures/


def load_fixture(name: str) -> dict:
    """Load tests/fixtures/<name>_response.json as a dict (TEST_MODE payloads)."""
    return json.loads((FIXTURES_DIR / f"{name}_response.json").read_text())


def load_data(filename: str) -> object:
    """Load a JSON file from eidolon/data/ (e.g. ai_policies.json)."""
    return json.loads((DATA_DIR / filename).read_text())


def dedupe(values: list[str]) -> list[str]:
    """Order-preserving, case-insensitive de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        key = v.lower()
        if v and key not in seen:
            seen.add(key)
            out.append(v)
    return out


#: URL markers that identify internal probe endpoints (Holehe/Blackbird API
#: URLs) — not user-facing profiles; misleading if rendered in a report.
BOGUS_URL_MARKERS = ("api.", "/api/", "email_available", "/lookup", "/users/lookup")


def clean_url(url: str) -> str:
    """Drop internal probe endpoints: they are not a user-facing profile and
    are misleading in a report."""
    u = (url or "").strip()
    if not u or any(m in u.lower() for m in BOGUS_URL_MARKERS):
        return ""
    return u
