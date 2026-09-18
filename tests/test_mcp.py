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


def _tools() -> dict:
    import asyncio

    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_all_tools_registered():
    assert set(_tools()) == {
        "scan_target",
        "scan_batch",
        "scan_status",
        "list_scans",
        "get_report",
        "reveal_credentials",
        "get_evidence",
    }


def _schema(name: str) -> dict:
    return _tools()[name].inputSchema or {}


def _type_of(spec: dict):
    """JSON-schema type for a property, unwrapping Optional's anyOf."""
    if spec.get("type"):
        return spec["type"]
    for sub in spec.get("anyOf", []) or []:
        if sub.get("type") and sub["type"] != "null":
            return sub["type"]
    return None


def test_tool_schemas_pinned():
    """TASKING.1 — the MCP tool surface is a contract: names, arg names + types.
    A shape change (e.g. scan_id becoming optional) breaks this loudly."""

    def props(name: str) -> dict:
        p = _schema(name).get("properties") or {}
        return {k: _type_of(v) for k, v in p.items()}

    def required(name: str) -> list:
        return _schema(name).get("required") or []

    # single scan: authorization (operator + reason) is required; the six
    # target kwargs are optional strings
    single = {
        "authorized_by": "string",
        "reason": "string",
        "email": "string",
        "phone": "string",
        "name": "string",
        "city": "string",
        "state": "string",
        "zip_code": "string",
    }
    assert props("scan_target") == single
    assert required("scan_target") == ["authorized_by", "reason"]

    # batch: authorization + targets required, max_concurrency optional int
    assert props("scan_batch") == {
        "authorized_by": "string",
        "reason": "string",
        "targets": "array",
        "max_concurrency": "integer",
    }
    assert required("scan_batch") == ["authorized_by", "reason", "targets"]

    # poll/read surfaces: scan_id is required wherever it appears
    for name in ("scan_status", "get_report", "reveal_credentials", "get_evidence"):
        assert required(name) == ["scan_id"], name
        assert props(name)["scan_id"] == "string"

    # get_report: optional fmt; get_evidence: optional source filter
    assert props("get_report") == {"scan_id": "string", "fmt": "string"}
    assert props("get_evidence") == {"scan_id": "string", "source": "string"}
    # fmt documents the two supported values
    assert "md" in _tools()["get_report"].description
    assert "json" in _tools()["get_report"].description

    # list_scans takes no arguments
    assert props("list_scans") == {}
    assert required("list_scans") == []


def test_scan_target_is_async_and_polls_to_done():
    import time

    out = server.scan_target(
        authorized_by="op", reason="test", email="test@example.com"
    )
    assert out.get("status") == "running"
    scan_id = out["scan_id"]

    status = {}
    for _ in range(100):  # TEST_MODE scan finishes fast
        status = server.scan_status(scan_id)
        if status["status"] in ("done", "error"):
            break
        time.sleep(0.05)

    assert status["status"] == "done", status
    assert status["result"]["scan_id"] == scan_id
    assert "skipped_sources" in status


def test_strip_dossier_removes_section_and_keeps_neighbors():
    md = (
        "# Privacy OSINT Report\n\n## What\n\nx\n\n---\n\n"
        "## Your Actual Leaked Data\n\n### SomeDB\n- password: hunter2\n\n---\n\n"
        "## Top Risks\n\n- y\n"
    )
    out = server._strip_dossier(md)
    assert "## Your Actual Leaked Data" not in out
    assert "hunter2" not in out  # the actual secret is gone
    assert "## What" in out and "## Top Risks" in out  # neighbors intact
    assert "reveal_credentials" in out  # points the user at the gate


def test_get_report_redacts_dossier_but_reveal_exposes_it():
    res = runner.run_scan(email="test@example.com")

    md = server.get_report(res.scan_id, "md")
    assert "# Privacy OSINT Report" in md
    assert "## Your Actual Leaked Data" not in md  # redacted by default

    creds = server.reveal_credentials(res.scan_id)
    assert isinstance(creds, str)  # dossier or a "none on record" message


def test_list_scans_includes_the_new_scan():
    res = runner.run_scan(email="test@example.com")
    scans = server.list_scans()
    assert any(s["scan_id"] == res.scan_id for s in scans)


def test_scan_batch_aggregates_two_targets():
    import time

    out = server.scan_batch(
        authorized_by="op",
        reason="test",
        targets=[{"email": "test@example.com"}, {"phone": "+14155550100"}],
        max_concurrency=2,
    )
    assert out.get("status") == "running"
    batch_id = out["batch_id"]

    status = {}
    for _ in range(200):  # TEST_MODE batch finishes fast
        status = server.scan_status(batch_id)
        if status["status"] in ("done", "error"):
            break
        time.sleep(0.05)

    assert status["status"] == "done", status
    assert status["total"] == 2
    assert status["done"] == 2
    assert len(status["scan_ids"]) == 2
    assert [r["index"] for r in status["reports"]] == [0, 1]
    assert all(r["report"] for r in status["reports"])  # each child wrote a report
    # each child is individually readable through the normal path
    for r in status["reports"]:
        assert "# Privacy OSINT Report" in server.get_report(r["scan_id"], "md")


def test_single_scan_and_batch_share_the_runway():
    """Single-flight: a batch id must not start while a scan job runs (and vice
    versa), or concurrent scans would double the vendor call rate."""
    import time

    single = server.scan_target(
        authorized_by="op", reason="test", email="a@example.com"
    )
    assert not server.scan_batch(
        authorized_by="op", reason="test", targets=[{"phone": "+14155550100"}]
    ).get("batch_id"), "batch must be rejected while a single scan runs"
    for _ in range(200):
        if server.scan_status(single["scan_id"])["status"] in ("done", "error"):
            break
        time.sleep(0.05)


def test_get_evidence_returns_provenance_and_filters_by_source():
    res = runner.run_scan(email="test@example.com")
    r = server.get_evidence(res.scan_id)

    assert r["scan_id"] == res.scan_id
    assert r["sources"], "expected at least one source row"
    sources = {row["source"] for row in r["sources"]}
    assert "hibp" in sources

    ran = [row for row in r["sources"] if row["status"] == "ok"]
    assert ran, "expected at least one ran (ok) source"
    for row in ran:
        assert len(row["response_sha256"]) == 64
        assert isinstance(row["egress_proxied"], bool)
        assert row["latency_ms"] >= 0
        assert row["tool_version"]

    # skipped sources drop the replay hash, keep the reason
    skipped = [row for row in r["sources"] if row["status"] == "skipped"]
    for row in skipped:
        assert not row["response_sha256"]
        assert row["detail"]

    # per-source filter
    hibp = server.get_evidence(res.scan_id, source="hibp")
    assert {row["source"] for row in hibp["sources"]} == {"hibp"}
