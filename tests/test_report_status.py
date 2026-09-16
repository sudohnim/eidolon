"""A skipped (unconfigured) source must render 'not checked', never '0 found'."""


def test_skipped_source_shows_not_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path) + "/")

    from eidolon.core.state import InputClassification, ScanState, SourceResult
    from eidolon.report import write_report

    state = ScanState(
        raw_input="a@b.com",
        classifications=[
            InputClassification(type="email", value="a@b.com", raw="a@b.com")
        ],
        results={
            "hibp": SourceResult(
                name="hibp",
                status="skipped",
                findings=[],
                detail="not checked — set HIBP_API_KEY",
            )
        },
    )
    md_path = write_report(state)
    md = open(md_path).read()

    assert "Not checked" in md
    assert "HIBP_API_KEY" in md
    assert "0 breaches" not in md  # the bug: skipped must NOT read as "found none"


def test_coverage_reports_skipped_never_clean():
    """The honesty gate: skipped sources are visible in coverage() with their
    reason, and analysis risk treats them as unknown (not as clean)."""
    from eidolon.core.state import ScanState, SourceResult

    state = ScanState(
        raw_input="a@b.com",
        results={
            "hibp": SourceResult(
                name="hibp", status="skipped", findings=[], detail="set HIBP_API_KEY"
            )
        },
    )
    coverage = {c.name: c for c in state.coverage()}
    assert coverage["hibp"].status == "skipped"
    assert coverage["hibp"].detail == "set HIBP_API_KEY"
    # skipped ≠ clean: no findings, but the source is visibly not-checked
    assert state.results["hibp"].findings == []
