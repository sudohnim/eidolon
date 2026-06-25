"""A skipped (unconfigured) source must render 'not checked', never '0 found'."""

from datetime import datetime, timezone


def _skipped(tool: str, reason: str):
    from eidolon.core.models import ToolResult

    return ToolResult(
        success=True,
        status="skipped",
        tool=tool,
        input_type="email",
        input_value="a@b.com",
        timestamp=datetime.now(timezone.utc),
        data={},
        error=reason,
    )


def test_skipped_source_shows_not_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path) + "/")
    from eidolon.agent.report import write_report
    from eidolon.core.models import InputClassification, PipelineState

    state = PipelineState(
        raw_input="a@b.com",
        classifications=[
            InputClassification(type="email", value="a@b.com", raw="a@b.com")
        ],
        hibp_result=_skipped("hibp", "not checked — set HIBP_API_KEY"),
    )
    md_path = write_report(state)
    md = open(md_path).read()

    assert "Not checked" in md
    assert "HIBP_API_KEY" in md
    assert "0 breaches" not in md  # the bug: skipped must NOT read as "found none"
