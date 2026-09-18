"""RESILIENCE — partial-failure isolation.

RESILIENCE.1: a wedged tool must not stall the whole wave; its slot holds a
visible timeout error.
RESILIENCE.2: a node that raises writes an error result into its slots — the
result renders as failed, never as absent.
RESILIENCE.3: a slow transport surfaces as a tool timeout (status="error"), not
an indefinite hang.
"""

import os
import threading
import time

import pytest
from pydantic import BaseModel

os.environ.setdefault("TEST_MODE", "true")

from eidolon.core.registry import SourceSpec  # noqa: E402
from eidolon.core.state import InputClassification, ScanState  # noqa: E402
from eidolon.pipeline import collect as collect_mod  # noqa: E402
from eidolon.sources.base import Tool  # noqa: E402


class _FakeInput(BaseModel):
    value: str = "a@b.com"


class _FakeOutput(BaseModel):
    ok: bool = True


#: lets a sleeping fake tool out of its block so pool threads drain fast
_WAKE = threading.Event()


class _SleeperTool(Tool[_FakeInput, _FakeOutput]):
    """A tool whose run blocks until the test releases it (a hung vendor)."""

    name = "sleeper"
    input_schema = _FakeInput
    output_schema = _FakeOutput

    def _run(self, inp, log):  # type: ignore[override]
        _WAKE.wait(timeout=60)  # blocks far past the wave's per-tool cap
        return _FakeOutput()

    def run(self, inp: _FakeInput) -> _FakeOutput:  # type: ignore[override]
        # real path: never touch fixtures, exercise _run for real
        return self._run(inp, None)


class _BoomTool(Tool[_FakeInput, _FakeOutput]):
    """A tool whose run always raises (the rare pre-collect failure path)."""

    name = "boomer"
    input_schema = _FakeInput
    output_schema = _FakeOutput

    def _run(self, inp, log):  # type: ignore[override]
        raise RuntimeError("kaboom")

    def run(self, inp: _FakeInput) -> _FakeOutput:  # type: ignore[override]
        return self._run(inp, None)


def _base_state() -> ScanState:
    return ScanState(
        raw_input="a@b.com",
        classifications=[
            InputClassification(type="email", value="a@b.com", raw="a@b.com")
        ],
    )


class TestPerToolTimeout:
    def test_slow_tool_does_not_block_the_wave(self, monkeypatch):
        monkeypatch.setenv("TEST_MODE", "false")
        monkeypatch.setenv("PER_TOOL_TIMEOUT_S", "0.3")
        _WAKE.clear()
        monkeypatch.setattr(
            collect_mod,
            "REGISTRY",
            (
                SourceSpec(
                    "sleeper", _SleeperTool, 1, ("email",), lambda s: _FakeInput()
                ),
            ),
        )

        t0 = time.monotonic()
        out = collect_mod.wave_scan_node(_base_state(), 1)
        elapsed = time.monotonic() - t0
        _WAKE.set()  # release the orphan so the worker thread drains

        # the wave returned long before the 60s sleep ended
        assert elapsed < 2.0, f"wave blocked for {elapsed:.1f}s"
        # the slow tool's slot holds a visible error, not a silent hole
        assert out.results["sleeper"].status == "error"
        assert "timed out" in (out.results["sleeper"].detail or "").lower()
        coverage = {c.name: c.status for c in out.coverage()}
        assert coverage["sleeper"] == "error"

    def test_fast_tool_returns_ok_within_its_wave(self, monkeypatch):
        monkeypatch.setenv("TEST_MODE", "false")
        monkeypatch.setenv("PER_TOOL_TIMEOUT_S", "5")
        _WAKE.set()

        class _QuickTool(_SleeperTool):
            name = "quick"

            def _run(self, inp, log):  # type: ignore[override]
                return _FakeOutput()

        monkeypatch.setattr(
            collect_mod,
            "REGISTRY",
            (SourceSpec("quick", _QuickTool, 1, ("email",), lambda s: _FakeInput()),),
        )
        out = collect_mod.wave_scan_node(_base_state(), 1)
        assert out.results["quick"].status == "ok"


class TestNodeRaiseIsVisible:
    def test_run_concurrent_records_error_for_raising_node(self):
        def bad_node(state):  # type: ignore[no-untyped-def]
            raise RuntimeError("node kaboom")

        bad_node.__name__ = "hibp_node"
        out = collect_mod._run_concurrent(
            _base_state(), [(bad_node, ["hibp"])], per_tool_timeout_s=5.0
        )
        sr = out.results["hibp"]
        assert sr.status == "error"
        assert "node kaboom" in (sr.detail or "")
        # digest/report see it as failed, not absent
        assert {c.name for c in out.coverage()} == {"hibp"}

    def test_raising_tool_results_in_error_slot(self, monkeypatch):
        """The tool-level raise (pre-collect) still lands an error slot."""
        monkeypatch.setenv("TEST_MODE", "false")
        monkeypatch.setenv("PER_TOOL_TIMEOUT_S", "5")
        monkeypatch.setattr(
            collect_mod,
            "REGISTRY",
            (SourceSpec("boomer", _BoomTool, 1, ("email",), lambda s: _FakeInput()),),
        )
        out = collect_mod.wave_scan_node(_base_state(), 1)
        assert out.results["boomer"].status == "error"
        assert "kaboom" in (out.results["boomer"].detail or "")


class TestHttpToolTimeout:
    def test_slow_transport_surfaces_as_tool_error(self, monkeypatch):
        """RESILIENCE.3 — a black-holed vendor raises inside the tool and the
        envelope reports status='error' instead of hanging indefinitely."""
        import httpx as real_httpx

        monkeypatch.setenv("TEST_MODE", "false")
        monkeypatch.setenv("HIBP_API_KEY", "test")

        from eidolon.sources import _http as http_mod

        class _FakeClient:
            def __init__(self, **kwargs):  # noqa: ANN001 - constructor stub
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):  # type: ignore[no-untyped-def]
                return None

            def get(self, *a, **k):  # type: ignore[no-untyped-def]
                raise real_httpx.TimeoutException("read timeout after 30s")

        class _Stub:
            Timeout = real_httpx.Timeout
            Client = _FakeClient  # type: ignore[assignment]
            AsyncClient = _FakeClient  # type: ignore[assignment]
            # client() builds a (real) transport before handing it to Client;
            # the stub Client ignores it and raises on .get().
            HTTPTransport = real_httpx.HTTPTransport
            AsyncHTTPTransport = real_httpx.AsyncHTTPTransport

        monkeypatch.setattr(http_mod, "httpx", _Stub())

        from eidolon.sources.base import collect
        from eidolon.sources.hibp import Hibp, HibpInput

        sr = collect(Hibp(), HibpInput(input_type="email", value="a@b.com"))
        assert sr.status == "error"
        assert sr.findings == []
        assert "timeout" in (sr.detail or "").lower()
