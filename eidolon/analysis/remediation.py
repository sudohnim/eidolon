"""Deterministic remediation: what-to-do items derived from findings.

The LLM writes narrative only; the remediation checklist is built entirely
from scan state here (deterministic sections win). ``_finalize_remediation``
merges any LLM-provided items into the gaps the rules don't cover.
"""

from __future__ import annotations

from eidolon.analysis.facts import _active_accounts, _has_address
from eidolon.analysis.normalize import _stringify
from eidolon.core.findings import Breach, BrokerExposure, InfostealerLog, PhoneIntel
from eidolon.core.state import ScanState

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
