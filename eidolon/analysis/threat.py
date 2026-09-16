"""Threat mapping: attack signals and MITRE techniques."""

import logging

from eidolon.core.findings import Breach, Credential, InfostealerLog
from eidolon.core.state import ScanState
from eidolon.sources.mitre import MitreAttack, MitreInput, MitreSignal

logger = logging.getLogger(__name__)


def _extract_attack_signals(state: ScanState) -> list[MitreSignal]:
    """Map findings to MITRE ATT&CK signals for the correlation planner."""
    findings = state.findings or []
    signals: list[MitreSignal] = []

    # Deduplicate InfostealerLog by malware family
    seen_families = set()
    for f in findings:
        if isinstance(f, InfostealerLog):
            family = f.malware_family or "unknown"
            if family in seen_families:
                continue
            seen_families.add(family)
            signals.append(
                MitreSignal(
                    signal="infostealer_log",
                    evidence=family,
                    severity="critical",
                )
            )
        elif isinstance(f, Breach):
            # Check if breach has password data
            data = f.data_classes
            has_password = any("password" in d.lower() for d in data)
            signals.append(
                MitreSignal(
                    signal=(
                        "password_in_breach" if has_password else "breach_no_password"
                    ),
                    evidence=f.title or f.payload.get("breach_name", "unknown"),
                    severity="critical" if has_password else "medium",
                )
            )
        elif isinstance(f, Credential):
            signals.append(
                MitreSignal(
                    signal="password_in_breach",
                    evidence=f.source_breach or "unknown",
                    severity="critical",
                )
            )

    logger.debug("attack_signals: %d", len(signals))
    return signals


def mitre_node(state: ScanState) -> ScanState:
    """Map findings to MITRE ATT&CK techniques using the MitreAttack tool."""
    signals = _extract_attack_signals(state)
    if not signals:
        logger.info("mitre: no signals")
        return state

    out = MitreAttack().run(MitreInput(signals=signals))
    logger.info("mitre: %d techniques", len(out.techniques))
    return state.model_copy(update={"mitre_techniques": out.techniques})
