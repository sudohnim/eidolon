"""REFACTOR.4 — findings are the only read path (decoupling proof + grep gate).

Decoupling proof: a throwaway source registered at RUNTIME (one SourceSpec
appended to the registry, with its adapter Tool) surfaces in state.findings
AND in the rendered report with ZERO lines changed in report/analysis/state
— the consumers are generic over kinds and sources, so a new source needs no
consumer edits. That is the whole point of the Finding domain: coupling
dropped from O(sources x consumers) to O(sources).

Grep gate: no live consumer reads ``ToolResult.data[`` / ``.data.get(``.
"""

import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["AI_PLATFORMS"] = "claude,chatgpt,gemini,grok"

import structlog  # noqa: E402
from pydantic import BaseModel  # noqa: E402

import eidolon.analysis.risk as risk  # noqa: E402
import eidolon.pipeline.collect as nodes  # noqa: E402
from eidolon.core.findings import (  # noqa: E402
    Breach,
    Finding,
    Severity,
    merge_findings,
)
from eidolon.core.registry import REGISTRY, SourceSpec  # noqa: E402
from eidolon.core.state import ScanState  # noqa: E402
from eidolon.sources.base import Tool  # noqa: E402


class FakeCorpInput(BaseModel):
    value: str = "test@example.com"


class FakeCorpOutput(BaseModel):
    found: bool = True


class FakeCorpTool(Tool[FakeCorpInput, FakeCorpOutput]):
    """A throwaway source no consumer has ever heard of."""

    name = "fakecorp"
    input_schema = FakeCorpInput
    output_schema = FakeCorpOutput
    vendor = "fakecorp.example"

    def _run(self, inp, log) -> FakeCorpOutput:
        return FakeCorpOutput()

    def run(self, inp: FakeCorpInput) -> FakeCorpOutput:
        # no fixture — this source always runs its real (trivial) path
        return self._run(inp, structlog.get_logger(f"eidolon.sources.{self.name}"))

    def to_findings(self, out: FakeCorpOutput) -> list[Finding]:
        return [
            Breach(
                dedup_key="breach:FakeCorp",
                title="FakeCorp",
                severity=Severity.HIGH,
                data_classes=["Email addresses", "Passwords"],
            )
        ]

    def run_summary(self, out: FakeCorpOutput) -> str:
        return "1 breaches"


class TestDecouplingProof:
    @pytest.fixture()
    def report_dir(self, tmp_path, monkeypatch):
        out = tmp_path / "reports"
        monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(out))
        yield out

    def _run_scan_with_throwaway_source(self, monkeypatch):
        """Register the throwaway source at runtime: ONE SourceSpec appended to
        the registry. The wave runner, state, analysis and report pick it up
        generically — no consumer code is touched. This is the literal
        "adding a source = one SourceSpec + one adapter + one to_findings"
        gate from the plan."""

        def fakecorp_input(state: ScanState):
            return FakeCorpInput(value="test@example.com")

        monkeypatch.setattr(
            nodes,
            "REGISTRY",
            REGISTRY
            + (SourceSpec("fakecorp", FakeCorpTool, 1, ("email",), fakecorp_input),),
        )

        from eidolon.pipeline.graph import build_graph

        graph = build_graph()
        final = graph.invoke(
            ScanState(raw_input="email:test@example.com\nname:John Doe\nstate:CA")
        )
        return (
            final if isinstance(final, ScanState) else ScanState.model_validate(final)
        )

    def test_throwaway_source_surfaces_in_findings_and_report(
        self, monkeypatch, report_dir, capsys
    ):
        state = self._run_scan_with_throwaway_source(monkeypatch)

        # 1. surfaced in state.findings, provenance stamped
        fake = [f for f in state.findings if f.dedup_key == "breach:FakeCorp"]
        assert len(fake) == 1
        assert fake[0].provenance.source == "fakecorp"
        assert fake[0].provenance.source_host == "fakecorp.example"

        # 2. surfaced in the coverage envelope
        assert "fakecorp" in state.results
        assert state.results["fakecorp"].status == "ok"

        # 3. surfaced in the RENDERED report — zero lines changed in
        #    report/analysis/state to make this true. (In TEST_MODE the analysis
        #    narrative comes from the fixture, so the coverage row is the
        #    report surface here; the analysis surface is asserted below.)
        from eidolon.report import write_report

        md_path = write_report(state)
        md = Path(md_path).read_text()
        assert "**fakecorp:** 1 breaches" in md  # coverage row, generic over sources

        # 4. the ANALYSIS consumer is generic over kinds too: what_is_known
        #    (the breach-history section of every report) derives from findings
        known = risk._state_what_is_known(state)
        assert any("FakeCorp" in entry for entry in known["breach_history"])


class TestNoRawDictConsumers:
    LIVE_CONSUMERS = [
        "eidolon/agent/graph.py",
        "eidolon/report/model.py",
        "eidolon/report/markdown.py",
        "eidolon/report/pdf.py",
        "eidolon/report/json.py",
        "eidolon/report/__init__.py",
        "eidolon/mcp/server.py",
        "eidolon/core/runner.py",
        "eidolon/core/jobs.py",
        "eidolon/core/repository.py",
        "eidolon/main.py",
    ]

    def test_no_consumer_reparses_toolresult_data(self):
        root = Path(__file__).resolve().parents[1]
        patterns = re.compile(r"\.data\.get\(|\.data\[")
        offenders: list[str] = []
        for rel in self.LIVE_CONSUMERS:
            path = root / rel
            assert path.exists(), rel
            for i, line in enumerate(path.read_text().splitlines(), 1):
                if patterns.search(line):
                    offenders.append(f"{rel}:{i}: {line.strip()}")
        assert (
            not offenders
        ), "raw ToolResult.data reads in live consumers:\n" + "\n".join(offenders)

    def test_no_package_file_reparses_toolresult_data(self):
        """Sweep the whole package (not just the listed consumers)."""
        root = Path(__file__).resolve().parents[1]
        patterns = re.compile(r"\.data\.get\(|\.data\[")
        dirty = []
        for path in (root / "eidolon").rglob("*.py"):
            rel = str(path.relative_to(root))
            if "__pycache__" in rel:
                continue
            if patterns.search(path.read_text()):
                dirty.append(rel)
        assert not dirty, f"files still reading raw dicts: {dirty}"
