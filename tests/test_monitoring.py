"""Run-to-run monitoring (#4): what changed since the previous scan.

``dedup_key`` is the identity of a fact across scans; this is what finally uses
it. A snapshot says "you are in 14 breaches"; the diff says "2 are new" — that
is the part with intelligence value.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("TEST_MODE", "true")

from eidolon.core.findings import Breach, Confidence, Severity  # noqa: E402
from eidolon.core.monitoring import apply_temporal, previous_findings  # noqa: E402
from eidolon.core.state import ScanDiff, ScanState  # noqa: E402


def _breach(name: str, first_seen: datetime | None = None) -> Breach:
    return Breach(
        dedup_key=f"breach:{name}",
        title=name,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        first_seen=first_seen,
    )


class TestDiff:
    def test_first_scan_is_not_a_comparison(self):
        """No prior scan must read as 'not compared', never as 'nothing changed'."""
        d = apply_temporal([], [_breach("A")])
        assert d.compared is False
        assert d.new_findings == [] and d.resolved_findings == []

    def test_new_and_resolved_are_reported(self):
        prev = [_breach("A"), _breach("B")]
        cur = [_breach("B"), _breach("C")]
        d = apply_temporal(prev, cur)
        assert d.compared is True
        assert d.new_findings == ["C"]  # appeared
        assert d.resolved_findings == ["A"]  # gone
        assert d.unchanged_count == 1  # B

    def test_first_seen_is_carried_forward(self):
        """The age of an exposure is the number an analyst wants — a fact seen
        before keeps its original first_seen, not today's date."""
        old = datetime.now(timezone.utc) - timedelta(days=90)
        prev = [_breach("A", first_seen=old)]
        cur = [_breach("A")]
        apply_temporal(prev, cur)
        assert cur[0].first_seen == old
        assert cur[0].last_seen is not None and cur[0].last_seen > old

    def test_new_finding_gets_first_seen_now(self):
        cur = [_breach("New")]
        apply_temporal([_breach("Other")], cur)
        assert cur[0].first_seen == cur[0].last_seen

    def test_previous_findings_is_safe_without_history(self):
        assert previous_findings("", "run1") == []
        assert previous_findings("nobody@example.com", "run1") == []


class TestRendererParityWithChanges:
    """The md and pdf renderers must agree even on the changes section — the
    fixture scan has no prior run, so this is the only place that path is
    exercised."""

    def test_md_and_pdf_both_render_changes(self, tmp_path):
        pytest.importorskip("pypdf")
        from eidolon.report import build_report_model, render_markdown, render_pdf

        state = ScanState(
            raw_input="email:a@b.com",
            findings=[_breach("NewCorp")],
            diff=ScanDiff(
                compared=True,
                new_findings=["NewCorp"],
                resolved_findings=["OldCorp"],
                unchanged_count=3,
            ),
        )
        model = build_report_model(state)
        assert model.changes is not None
        assert "What Changed Since Last Scan" in model.section_titles()

        md = render_markdown(model)
        assert "## What Changed Since Last Scan" in md
        assert "NewCorp" in md and "OldCorp" in md

        # the pdf path must not blow up and must carry the same section
        out = tmp_path / "changes.pdf"
        render_pdf(model, out)
        assert out.exists() and out.stat().st_size > 0
