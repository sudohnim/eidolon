"""Tests for the run_scan core and the report repository (Phase 1 MCP work)."""

import os
import shutil
from pathlib import Path

import pytest

os.environ["TEST_MODE"] = "true"
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["RESULTS_OUTPUT_PATH"] = "/tmp/eidolon_runner_test/"

from eidolon.core import repository, runner  # noqa: E402


@pytest.fixture(autouse=True)
def cleanup_output():
    yield
    out = Path("/tmp/eidolon_runner_test")
    if out.exists():
        shutil.rmtree(out)


# ── input normalization (single source of truth) ──────────────────────────────


def test_normalize_phone_adds_us_country_code():
    assert runner.normalize_phone("2143354529") == "+12143354529"


def test_normalize_email_rejects_garbage():
    with pytest.raises(ValueError):
        runner.normalize_email("not-an-email")


def test_build_raw_input_requires_an_identifier():
    with pytest.raises(ValueError):
        runner.build_raw_input(state="CA")  # location only, no id


def test_build_raw_input_formats_type_value_lines():
    raw = runner.build_raw_input(email="A@B.com", name="John  Smith", state="CA")
    assert "email:a@b.com" in raw
    assert "name:John Smith" in raw
    assert "state:CA" in raw


# ── run_scan + repository round-trip ──────────────────────────────────────────


def test_run_scan_returns_result_and_writes_reports():
    res = runner.run_scan(email="test@example.com")
    assert res.scan_id  # run_id minted by intake
    assert res.identifier == "test@example.com"
    assert res.report_md and Path(res.report_md).exists()
    assert res.report_json and Path(res.report_json).exists()


def test_repository_get_report_and_list():
    res = runner.run_scan(email="test@example.com")
    md = repository.get_report(res.scan_id, "md")
    assert "# Privacy OSINT Report" in md

    scans = repository.list_scans()
    assert any(s.scan_id == res.scan_id for s in scans)


def test_repository_missing_scan_raises():
    with pytest.raises(FileNotFoundError):
        repository.get_report("deadbeef", "md")
