"""Tests for the MCP server tools (Phase 1 — stateless)."""

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
os.environ["RESULTS_OUTPUT_PATH"] = "/tmp/eidolon_mcp_test/"

from eidolon.core import runner  # noqa: E402
from eidolon.mcp import server  # noqa: E402


@pytest.fixture(autouse=True)
def cleanup_output():
    yield
    out = Path("/tmp/eidolon_mcp_test")
    if out.exists():
        shutil.rmtree(out)


def test_all_four_tools_registered():
    import asyncio

    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert names == {"scan_target", "list_scans", "get_report", "reveal_credentials"}


def test_strip_dossier_removes_section_and_keeps_neighbors():
    md = (
        "# Privacy OSINT Report\n\n## What\n\nx\n\n---\n\n"
        "## Leaked Credentials\n\n### SomeDB\n- password: hunter2\n\n---\n\n"
        "## Top Risks\n\n- y\n"
    )
    out = server._strip_dossier(md)
    assert "## Leaked Credentials" not in out
    assert "hunter2" not in out  # the actual secret is gone
    assert "## What" in out and "## Top Risks" in out  # neighbors intact
    assert "reveal_credentials" in out  # points the user at the gate


def test_get_report_redacts_dossier_but_reveal_exposes_it():
    res = runner.run_scan(email="test@example.com")

    md = server.get_report(res.scan_id, "md")
    assert "# Privacy OSINT Report" in md
    assert "## Leaked Credentials" not in md  # redacted by default

    creds = server.reveal_credentials(res.scan_id)
    assert isinstance(creds, str)  # dossier or a "none on record" message


def test_list_scans_includes_the_new_scan():
    res = runner.run_scan(email="test@example.com")
    scans = server.list_scans()
    assert any(s["scan_id"] == res.scan_id for s in scans)
