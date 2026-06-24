"""Unconfigured tools must report 'skipped', never a false 'found nothing'."""

from eidolon.tools.base import run_to_result
from eidolon.tools.hibp import Hibp, HibpInput


def test_unconfigured_tool_is_skipped_not_empty(monkeypatch):
    # Real mode (not TEST_MODE) + missing key -> skipped, with a helpful reason.
    monkeypatch.setenv("TEST_MODE", "false")
    monkeypatch.delenv("HIBP_API_KEY", raising=False)

    r = run_to_result(Hibp(), HibpInput(input_type="email", value="a@b.com"))

    assert r.status == "skipped"
    assert r.success is True  # not an error — just not run
    assert r.data == {}
    assert "HIBP_API_KEY" in (r.error or "")  # tells the user which key to set


def test_skip_reason_names_missing_key(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    assert Hibp().available() is False
    assert "HIBP_API_KEY" in Hibp().skip_reason()

    monkeypatch.setenv("HIBP_API_KEY", "x")
    assert Hibp().available() is True


def test_configured_tool_runs_ok(monkeypatch):
    monkeypatch.setenv("TEST_MODE", "true")  # fixture path
    r = run_to_result(Hibp(), HibpInput(input_type="email", value="a@b.com"))
    assert r.status == "ok"
    assert r.success is True
