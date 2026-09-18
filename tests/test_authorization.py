"""Blindspot #1 — authorization / rules-of-engagement gate.

A scan targets a real person: the human surfaces require an operator + reason,
and every scan is written to an append-only audit log.
"""

import json
import os

import pytest

os.environ.setdefault("HIBP_API_KEY", "test")

from eidolon.core.authorization import (  # noqa: E402
    AUDIT_LOG_NAME,
    Authorization,
    record_authorization,
)
from eidolon.mcp import server  # noqa: E402


def test_authorization_requires_operator_and_reason():
    with pytest.raises(ValueError):
        Authorization(operator="", reason="x")
    with pytest.raises(ValueError):
        Authorization(operator="op", reason="  ")
    a = Authorization(operator="analyst", reason="IR case 42")
    assert a.is_attested and a.authorized_at is not None


def test_unattested_is_recorded_not_blocked():
    a = Authorization.unattested()
    assert a.operator == "unattested"
    assert a.is_attested is False


def test_record_writes_append_only_audit_without_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path))
    monkeypatch.setenv("TEST_MODE", "false")  # exercise the real write path
    auth = Authorization(operator="analyst", reason="authorized IR")
    record_authorization(auth, scan_id="abcd1234", target="a@b.com")
    record_authorization(auth, scan_id="efef5656", target="c@d.com")

    log = tmp_path / AUDIT_LOG_NAME
    rows = [json.loads(ln) for ln in log.read_text().splitlines()]
    assert [r["scan_id"] for r in rows] == ["abcd1234", "efef5656"]  # append-only
    assert rows[0]["operator"] == "analyst" and rows[0]["attested"] is True
    # audit never carries scan results / secrets — only the attestation + target
    assert set(rows[0]) == {
        "scan_id",
        "target",
        "operator",
        "reason",
        "attested",
        "authorized_at",
        "recorded_at",
    }


def test_mcp_scan_target_refuses_without_authorization():
    out = server.scan_target(authorized_by="", reason="", email="test@example.com")
    assert out["status"] == "error"
    assert "authorization required" in out["error"]


def test_mcp_scan_batch_refuses_without_authorization():
    out = server.scan_batch(
        authorized_by="op", reason="   ", targets=[{"email": "test@example.com"}]
    )
    assert out["status"] == "error"
    assert "authorization required" in out["error"]
