"""Dogfood bug — the LLM narrative must not fabricate breach content or drive
the risk score when the scan found none (an 8B model parrots prompt examples
when the breach tools return nothing).

A scan with only account findings (no breach/credential/broker) must:
  - score deterministically (accounts don't reach HIGH), never the LLM's number;
  - drop top-risks that assert breaches/leaks/addresses the scan never found;
  - fall back to the grounded identity summary when the LLM's asserts breaches.
"""

import os
from datetime import datetime, timezone

os.environ.setdefault("TEST_MODE", "true")

from eidolon.analysis.facts import _claim_is_ungrounded  # noqa: E402
from eidolon.analysis.narrative import _postprocess_analysis  # noqa: E402
from eidolon.core.findings import Account, Provenance, Severity  # noqa: E402
from eidolon.core.state import ScanState  # noqa: E402


def _accounts_only_state(n: int = 5) -> ScanState:
    prov = Provenance(
        source="maigret", retrieved_at=datetime.now(timezone.utc), status="ok"
    )
    findings = [
        Account(
            dedup_key=f"account:plat{i}",
            title=f"plat{i}",
            severity=Severity.LOW,
            provenance=prov,
            platform=f"plat{i}",
            active=True,
        )
        for i in range(n)
    ]
    return ScanState(raw_input="email:a@b.com", findings=findings)


# a fabricated LLM analysis like the one the 8B model produced on the real scan
_HALLUCINATED = {
    "overall_risk_score": 85,
    "identity_summary": "Your home address showed up in two leaks and jdoe92 "
    "appears in a breach with 100 hashed passwords.",
    "top_risks": [
        "A parking app leaked your license plate and phone number together.",
        "Your email was exposed in a data breach along with 100 hashed passwords.",
        "Your name is searchable on people-finder sites.",
    ],
    "what_is_known": {},
    "remediation": {},
}


def test_score_is_deterministic_not_the_llm_number():
    out = _postprocess_analysis(_accounts_only_state(5), dict(_HALLUCINATED))
    assert out["overall_risk_score"] != 85  # the fabricated number does not win
    assert out["overall_risk_level"] != "high"  # accounts alone can't be HIGH


def test_ungrounded_top_risks_are_dropped():
    out = _postprocess_analysis(_accounts_only_state(5), dict(_HALLUCINATED))
    joined = " ".join(out["top_risks"]).lower()
    assert "breach" not in joined and "license plate" not in joined
    assert "100 hashed" not in joined


def test_identity_summary_falls_back_when_ungrounded():
    out = _postprocess_analysis(_accounts_only_state(5), dict(_HALLUCINATED))
    assert "jdoe92" not in out["identity_summary"]
    assert "two leaks" not in out["identity_summary"]


def test_claim_grounding_predicate():
    st = _accounts_only_state(1)
    assert _claim_is_ungrounded("exposed in a data breach", st) is True
    assert _claim_is_ungrounded("your home address is on brokers", st) is True
    assert _claim_is_ungrounded("you have accounts on 5 platforms", st) is False
