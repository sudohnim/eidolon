"""Confidence model + pivot lineage.

Confidence answers the identity question ("is this fact tied to THIS target?"),
kept separate from severity ("how bad if true"). It is what lets the report and
the risk score treat a password-reset-confirmed account differently from a bare
username claim, without per-source hacks.
"""

import os
from datetime import datetime, timezone

os.environ.setdefault("TEST_MODE", "true")

from eidolon.analysis.facts import _state_risk_floor  # noqa: E402
from eidolon.core.findings import (  # noqa: E402
    Account,
    Breach,
    Confidence,
    Provenance,
    Severity,
    confidence_rank,
    merge_findings,
)
from eidolon.core.state import ScanState  # noqa: E402


def _prov(source: str) -> Provenance:
    return Provenance(
        source=source, retrieved_at=datetime.now(timezone.utc), status="ok"
    )


def _account(platform: str, conf: Confidence, source: str, active: bool = False):
    return Account(
        dedup_key=f"account:{platform}",
        title=platform,
        severity=Severity.MEDIUM,
        confidence=conf,
        provenance=_prov(source),
        platform=platform,
        active=active,
    )


class TestConfidenceRank:
    def test_accepts_enum_and_raw_value(self):
        # str(Confidence.POSSIBLE) is "Confidence.POSSIBLE" on a str-Enum — the
        # rank lookup must go through .value or everything silently ranks 0
        assert confidence_rank(Confidence.POSSIBLE) == 1
        assert confidence_rank("possible") == 1
        assert confidence_rank(Confidence.CONFIRMED) > confidence_rank(
            Confidence.UNVERIFIED
        )

    def test_unknown_value_is_lowest(self):
        assert confidence_rank("nonsense") == 0


class TestScoringGate:
    def test_unverified_findings_never_move_the_score(self):
        """A bare username claim (maigret) must not inflate the number."""
        unverified = ScanState(
            raw_input="email:a@b.com",
            findings=[
                _account(f"plat{i}", Confidence.UNVERIFIED, "maigret")
                for i in range(30)
            ],
        )
        assert _state_risk_floor(unverified) == 0

    def test_confirmed_accounts_do_score(self):
        confirmed = ScanState(
            raw_input="email:a@b.com",
            findings=[
                _account(f"plat{i}", Confidence.CONFIRMED, "holehe", active=True)
                for i in range(5)
            ],
        )
        assert _state_risk_floor(confirmed) == 10  # 5 x +2

    def test_unverified_cannot_dilute_confirmed(self):
        mixed = ScanState(
            raw_input="email:a@b.com",
            findings=[
                _account("a", Confidence.CONFIRMED, "holehe", active=True),
                *[
                    _account(f"n{i}", Confidence.UNVERIFIED, "maigret")
                    for i in range(40)
                ],
            ],
        )
        assert _state_risk_floor(mixed) == 2  # only the confirmed one counts


class TestCorroboration:
    def test_two_independent_sources_upgrade_possible_to_probable(self):
        a = Breach(
            dedup_key="breach:X",
            title="X",
            confidence=Confidence.POSSIBLE,
            provenance=_prov("hibp"),
        )
        b = Breach(
            dedup_key="breach:X",
            title="X",
            confidence=Confidence.POSSIBLE,
            provenance=_prov("xposedornot"),
        )
        merged = merge_findings([a], [b])[0]
        assert merged.confidence == Confidence.PROBABLE
        assert set(merged.sources) == {"hibp", "xposedornot"}

    def test_confirmation_is_never_invented(self):
        """Corroboration upgrades POSSIBLE, but never fabricates CONFIRMED."""
        a = _account("gh", Confidence.UNVERIFIED, "maigret")
        b = _account("gh", Confidence.UNVERIFIED, "someother")
        assert merge_findings([a], [b])[0].confidence == Confidence.UNVERIFIED

    def test_higher_confidence_wins_the_merge(self):
        claim = _account("gh", Confidence.UNVERIFIED, "maigret")
        proved = _account("gh", Confidence.CONFIRMED, "holehe", active=True)
        # order-independent: the confirmed representation always survives
        assert merge_findings([claim], [proved])[0].confidence == Confidence.CONFIRMED
        assert merge_findings([proved], [claim])[0].confidence == Confidence.CONFIRMED


class TestLineage:
    def test_collect_stamps_selector_and_source(self):
        from eidolon.sources.base import collect
        from eidolon.sources.xposedornot import XposedOrNot, XposedOrNotInput

        sr = collect(XposedOrNot(), XposedOrNotInput(email="target@example.com"))
        assert sr.findings, "fixture should yield findings"
        for f in sr.findings:
            assert f.selector == "target@example.com"  # how we got here
            assert "xposedornot" in f.sources  # who asserted it


class TestSelectorEntityResolution:
    """A finding is never more confident than the selector that produced it."""

    def test_derived_selector_caps_its_findings(self):
        from eidolon.core.state import Selector
        from eidolon.pipeline.collect import _apply_selector_confidence

        state = ScanState(
            raw_input="email:a@b.com",
            selectors=[
                Selector(
                    kind="email",
                    value="a@b.com",
                    origin="input",
                    confidence=Confidence.CONFIRMED,
                )
            ],
        )
        # a source reports CONFIRMED, but it searched a guessed handle
        via_guess = _account("gh", Confidence.CONFIRMED, "somesrc")
        via_guess.selector = "a"  # derived from the email local-part
        via_input = _account("hib", Confidence.CONFIRMED, "hibp")
        via_input.selector = "a@b.com"

        findings, derived = _apply_selector_confidence(state, [via_guess, via_input])
        assert findings[0].confidence == Confidence.UNVERIFIED  # capped by selector
        assert findings[1].confidence == Confidence.CONFIRMED  # input selector intact
        assert [d.value for d in derived] == ["a"]
        assert derived[0].origin == "derived"
        assert derived[0].derived_from == "a@b.com"

    def test_input_selectors_are_confirmed_at_intake(self):
        from eidolon.pipeline.classify import intake_node

        out = intake_node(ScanState(raw_input="email:a@b.com"))
        assert [s.origin for s in out.selectors] == ["input"]
        assert out.selectors[0].confidence == Confidence.CONFIRMED
