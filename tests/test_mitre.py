"""Tests for the MITRE ATT&CK mapping node.

These call the mapping logic directly (bypassing TEST_MODE fixtures) so they
exercise the real attack_map.json → technique mapping, and the signal-extraction
that reads scan state.
"""

import os

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("SCRAPFLY_API_KEY", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

import structlog  # noqa: E402

from eidolon.analysis.threat import _extract_attack_signals  # noqa: E402
from eidolon.core.findings import InfostealerLog  # noqa: E402
from eidolon.core.state import PipelineState  # noqa: E402
from eidolon.sources.mitre import (  # noqa: E402
    MitreAttack,
    MitreInput,
    MitreOutput,
    MitreSignal,
)

_LOG = structlog.get_logger()


def _stealer_state(found: bool = True) -> PipelineState:
    state = PipelineState(raw_input="x@example.com")
    if found:
        state.findings = [
            InfostealerLog(
                dedup_key=f"stealer:PC{i}:2024:RedLine",
                malware_family="RedLine",
                computer_name=f"PC{i}",
                date_compromised="2024-11-02",
            )
            for i in range(2)
        ]
    return state


def test_infostealer_signal_maps_to_three_techniques():
    out: MitreOutput = MitreAttack()._run(
        MitreInput(
            signals=[
                MitreSignal(
                    signal="infostealer_log",
                    evidence="2 infostealer log(s) (RedLine)",
                    severity="critical",
                )
            ]
        ),
        _LOG,
    )
    ids = {t.technique_id for t in out.techniques}
    assert ids == {"T1555", "T1539", "T1078"}
    assert out.technique_count == 3
    assert out.highest_severity == "critical"
    assert set(out.tactics_covered) == {"Credential Access", "Initial Access"}


def test_techniques_carry_teaching_fields():
    out = MitreAttack()._run(
        MitreInput(signals=[MitreSignal(signal="infostealer_log", evidence="x")]),
        _LOG,
    )
    t1555 = next(t for t in out.techniques if t.technique_id == "T1555")
    assert t1555.what_it_is and t1555.why_this_finding
    assert t1555.url.startswith("https://attack.mitre.org/")
    assert "x" in t1555.evidence


def test_unknown_signal_maps_to_nothing():
    out = MitreAttack()._run(
        MitreInput(signals=[MitreSignal(signal="not_a_real_signal", evidence="x")]),
        _LOG,
    )
    assert out.technique_count == 0


def test_extract_signals_from_stealer_state():
    signals = _extract_attack_signals(_stealer_state(found=True))
    assert len(signals) == 1
    assert signals[0].signal == "infostealer_log"
    assert signals[0].severity == "critical"
    assert "RedLine" in signals[0].evidence


def test_no_signal_when_no_infostealer():
    assert _extract_attack_signals(_stealer_state(found=False)) == []
    assert _extract_attack_signals(PipelineState(raw_input="x@example.com")) == []
