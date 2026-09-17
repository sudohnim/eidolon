"""Deterministic risk analysis — re-export façade (REFACTOR.6).

The old god module here (611 LOC) split by responsibility:

- ``facts`` — state → facts (what-is-known, risk floor, identity summary)
- ``remediation`` — deterministic remediation checklist
- ``normalize`` — string/normalization helpers

This module re-exports every name the old ``risk.py`` exposed so existing
consumers (``narrative``, ``digest``, tests) keep working unchanged.
"""

from __future__ import annotations

from eidolon.analysis.facts import (  # noqa: F401
    _EXAMPLE_LEAK_TOKENS,
    _active_accounts,
    _filter_top_risks,
    _has_address,
    _password_breaches,
    _real_breach_names,
    _state_identity_summary,
    _state_risk_floor,
    _state_what_is_known,
)
from eidolon.analysis.normalize import (  # noqa: F401
    _BOOGUS_URL_MARKERS,
    _HANDLE_NOISE,
    _HASH_LIKE,
    _clean_addresses,
    _clean_handles,
    _known_breach_item,
    _known_credential_item,
    _known_google_item,
    _known_platform_item,
    _looks_like_street_address,
    _normalize_what_is_known,
    _stringify,
)
from eidolon.analysis.remediation import (  # noqa: F401
    _REMEDIATION_KEYS,
    _build_deterministic_remediation,
    _finalize_remediation,
    _stringify_rem_item,
)
