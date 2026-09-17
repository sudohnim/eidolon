"""SCALE.1/.2/.3 — bounded concurrent multi-target scans.

run_batch runs N targets under a max_concurrency cap, each getting its own
run_id + report path (no shared mutable state). SCALE.3: the per-vendor OPSEC
pacing map is process-global, so two concurrent targets hitting the same vendor
are paced together, not independently.
"""

import os
import threading
import time
from pathlib import Path

import pytest
from pydantic import BaseModel

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["AI_PLATFORMS"] = "claude,chatgpt,gemini,grok"

import tempfile  # noqa: E402

from eidolon.core import batch  # noqa: E402
from eidolon.core import egress  # noqa: E402
from eidolon.core.registry import SourceSpec  # noqa: E402
from eidolon.pipeline import collect as collect_mod  # noqa: E402
from eidolon.sources.base import Tool  # noqa: E402

OUT = tempfile.mkdtemp(prefix="eidolon-batch-")
os.environ["RESULTS_OUTPUT_PATH"] = OUT


class _FakeInput(BaseModel):
    value: str = "a@b.com"


class _FakeOutput(BaseModel):
    ok: bool = True


class _PacedTool(Tool[_FakeInput, _FakeOutput]):
    """Records every call timestamp globally — used to prove cross-target pacing."""

    name = "paced"
    input_schema = _FakeInput
    output_schema = _FakeOutput
    timestamps: list[float] = []
    lock: threading.Lock = threading.Lock()

    @classmethod
    def _record(cls) -> None:
        with cls.lock:
            cls.timestamps.append(time.monotonic())

    def _run(self, inp, log):  # type: ignore[override]
        self._record()
        return _FakeOutput()

    def run(self, inp: _FakeInput) -> _FakeOutput:  # type: ignore[override]
        return self._run(inp, None)


class TestParseTargetLine:
    def test_simple_email(self):
        assert batch.parse_target_line("email:test@example.com") == {
            "email": "test@example.com"
        }

    def test_name_with_spaces_and_state(self):
        assert batch.parse_target_line("name:John Smith;state:CA") == {
            "name": "John Smith",
            "state": "CA",
        }

    def test_zip_alias_maps_to_zip_code(self):
        assert batch.parse_target_line("zip:94110") == {"zip_code": "94110"}

    def test_unknown_key_dropped(self):
        assert batch.parse_target_line("email:a@b.com;frobnicate:yes") == {
            "email": "a@b.com"
        }

    def test_empty_and_garbage_lines(self):
        assert batch.parse_target_line("") == {}
        assert batch.parse_target_line("   ") == {}
        assert batch.parse_target_line(";;;") == {}


class TestRunBatch:
    @pytest.fixture(autouse=True)
    def _tmp_output(self):
        os.environ["RESULTS_OUTPUT_PATH"] = OUT
        yield

    def test_three_targets_under_concurrency_2(self):
        from eidolon.core.repository import report_paths

        states = batch.run_batch(
            [
                {"email": "test@example.com"},
                {"phone": "+14155550100"},
                {"name": "John Smith", "state": "CA"},
            ],
            max_concurrency=2,
        )
        # 3 independent states, input order preserved
        assert len(states) == 3
        run_ids = [s.run_id for s in states]
        assert len(set(run_ids)) == 3, "targets must not share a run_id"

        # each target has its own report artifact
        for state in states:
            if not state.run_id:
                raise AssertionError("batch state missing run_id")
            paths = report_paths(state.run_id)
            assert paths.get("md") or paths.get("json"), f"no report for {state.run_id}"

    def test_batch_rejects_bad_concurrency(self):
        with pytest.raises(ValueError):
            batch.run_batch([{"email": "a@b.com"}], max_concurrency=0)

    def test_empty_targets(self):
        assert batch.run_batch([]) == []


class TestBatchPacingSharedAcrossTargets:
    """SCALE.3 — two concurrent targets call a paced vendor no faster than
    min_interval_s as ONE stream (process-global pacing map)."""

    @pytest.fixture(autouse=True)
    def _paced_registry(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PACING_PACED", "0.4,0.0")
        _PacedTool.timestamps = []
        monkeypatch.setattr(
            collect_mod,
            "REGISTRY",
            (SourceSpec("paced", _PacedTool, 1, ("email",), lambda s: _FakeInput()),),
        )
        monkeypatch.setenv("RESULTS_OUTPUT_PATH", OUT)
        yield
        # leave the pacing map clean for other tests
        egress._last_call_ts.clear()

    def test_cross_target_calls_are_spaced_together(self, monkeypatch):
        states = batch.run_batch(
            [{"email": "a@b.com"}, {"email": "c@d.com"}], max_concurrency=2
        )
        stamps = sorted(_PacedTool.timestamps)
        assert len(stamps) == 2, f"expected one call per target, got {stamps}"
        # both targets completed
        assert len(states) == 2
        assert all(s.results.get("paced") for s in states)
        # calls from DIFFERENT targets land in the same paced stream
        assert len(stamps) >= 2
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        assert all(g >= 0.30 for g in gaps), f"cross-target pacing violated: {gaps}"
