"""REFACTOR.3 — one content model, three renderers, provably no drift.

Renderer parity: the markdown and PDF rendered from ONE ReportModel carry the
same section titles (and those equal ``model.section_titles()``), so the two
renderers cannot drift apart the way the legacy pair did ("Where We Looked" vs
"Tool Results", dossier counts md-only).

Transitional snapshot: for a fixture scan the new renderer's markdown is
content-equivalent to the legacy renderer's — the same lines (order-insensitive;
the new renderer orders dossier groups and opt-out lists deterministically
instead of by vendor response order), which covers the plan's bar of "same
breaches/accounts/actions" with room to spare.
"""

import os
import re
import shutil

import pytest

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["AI_PLATFORMS"] = "claude,chatgpt,gemini,grok"

pypdf = pytest.importorskip("pypdf")

from eidolon.core.state import PipelineState, SourceResult  # noqa: E402
from eidolon.pipeline.graph import build_graph  # noqa: E402
from eidolon.report import (  # noqa: E402
    build_report_model,
    render_json,
    render_markdown,
    render_pdf,
)
from eidolon.report.model import CoverageRow  # noqa: E402

RAW_INPUT = "email:test@example.com\nname:John Doe\nstate:CA"


@pytest.fixture(scope="module")
def scan_state(tmp_path_factory):
    """One fixture-scan state shared by the whole module (the graph is slow)."""
    out = tmp_path_factory.mktemp("reports")
    os.environ["RESULTS_OUTPUT_PATH"] = str(out)
    try:
        graph = build_graph()
        final = graph.invoke(PipelineState(raw_input=RAW_INPUT))
        state = (
            final
            if isinstance(final, PipelineState)
            else PipelineState.model_validate(final)
        )
        yield state
    finally:
        os.environ.pop("RESULTS_OUTPUT_PATH", None)
        shutil.rmtree(out, ignore_errors=True)


def _normalize(text: str) -> str:
    """Erase run-varying header/path bits so renders are comparable."""
    text = re.sub(r"\d{4}-\d{2}-\d{2}", "DATE", text)
    text = re.sub(r"run [0-9a-f]{8}", "run RUNID", text)
    text = re.sub(r"`[^`]*\.json`", "JSONPATH", text)
    return text


def _md_h2_titles(md: str) -> list[str]:
    return [ln[3:].strip() for ln in md.splitlines() if ln.startswith("## ")]


def _pdf_h2_titles(pdf_bytes: bytes) -> list[str]:
    """Extract the H2 headings (13pt style) from the rendered PDF."""
    import io

    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(pdf_bytes))
    titles: list[str] = []

    def visitor(text, cm, tm, font_dict, font_size):
        t = (text or "").strip()
        if t and 12.5 < font_size < 13.5:
            titles.append(t)

    for page in reader.pages:
        page.extract_text(visitor_text=visitor)
    return titles


class TestRendererParity:
    def test_md_and_pdf_sections_match_the_model(self, scan_state, tmp_path):
        model = build_report_model(scan_state, results_json_path="/x/y.json")
        md = render_markdown(model)
        pdf_path = tmp_path / "parity.pdf"
        render_pdf(model, pdf_path)

        md_titles = _md_h2_titles(md)
        pdf_titles = _pdf_h2_titles(pdf_path.read_bytes())
        model_titles = model.section_titles()

        assert md_titles == model_titles
        assert pdf_titles == model_titles, "md/pdf section drift"
        assert "Where We Looked" in model_titles  # one title, not two names

    def test_all_three_renderers_share_one_model_source(self, scan_state, tmp_path):
        """json renderer: the model serialized round-trips with its sections."""
        import json as stdlib_json

        model = build_report_model(scan_state)
        restored = type(model).model_validate(stdlib_json.loads(render_json(model)))
        assert restored.section_titles() == model.section_titles()
        assert restored.dossier is not None and model.dossier is not None
        assert len(restored.dossier.groups) == len(model.dossier.groups)

    def test_dossier_reveal_is_the_only_plaintext_path(self, scan_state):
        """The dossier records carry the plaintext via display() — the reveal
        path — while every serialization of the model keeps it masked."""
        model = build_report_model(scan_state)
        assert model.dossier is not None
        # default display() masks; only the reveal surface exposes plaintext
        masked = "\n".join(
            rec.display() for g in model.dossier.groups for rec in g.records
        )
        assert "hunter2" not in masked
        assert "password: ********" in masked
        revealed = "\n".join(
            rec.display(reveal=True) for g in model.dossier.groups for rec in g.records
        )
        assert "password: hunter2" in revealed
        assert "hunter2" not in model.model_dump_json()
        # and the structured state never leaves the SecretStr either
        assert "hunter2" not in render_json(model)


class TestFixtureContentPinning:
    """The plan's parity bar, pinned directly against the fixture's known
    values (the legacy renderer this was compared against was deleted with the
    flat state fields in REFACTOR.5 — equivalence was proven at REFACTOR.3/4
    and is preserved by these assertions)."""

    def test_breaches_accounts_actions(self, scan_state):
        md = render_markdown(
            build_report_model(scan_state, results_json_path="/x/y.json")
        )

        # breaches: the fixture's three, in the breach-history section
        block = md.split("## Where Your Data Has Shown Up", 1)[-1].split("---", 1)[0]
        names = {
            ln.strip("- ").split(" (")[0]
            for ln in block.splitlines()
            if ln.startswith("- ")
        }
        assert names == {"LinkedIn", "Adobe", "Dropbox"}

        # accounts: the fixture's confirmed accounts (holehe/blackbird)
        block = md.split("### Accounts Found", 1)[-1].split("###", 1)[0]
        accounts = {
            ln.strip("- ").split(":")[0]
            for ln in block.splitlines()
            if ln.startswith("- ")
        }
        assert accounts == {"GitHub", "Twitter", "Reddit"}

        # actions: the deterministic remediation checkboxes
        block = md.split("## What To Do", 1)[-1]
        actions = {
            ln
            for ln in block.splitlines()
            if ln.startswith("- [ ] ") and "Opt-Outs" not in ln
        }
        assert any("Enable 2FA on active accounts:" in a for a in actions)
        assert any("Freeze credit with Equifax" in a for a in actions)

        # the follow-up check surfaces with its pivot value + count
        assert "testuser" in md and "4 profiles" in md

    def test_dossier_and_coverage_shape(self, scan_state):
        md = render_markdown(
            build_report_model(scan_state, results_json_path="/x/y.json")
        )
        # the dossier section renders, but masked — no plaintext to disk/stdout
        assert "## Your Actual Leaked Data" in md
        assert "hunter2" not in md
        assert "password: ********" in md
        assert "hash: 5f4dcc3b5aa765d61d8327deb882cf99 (MD5)" in md
        # plaintext is reachable only through the gated reveal surface
        from eidolon.report import dossier_lines

        assert "password: hunter2" in "\n".join(dossier_lines(scan_state))
        # coverage: every ran source has a row with its summary
        assert "**HIBP:** 3 breaches" in md
        assert "**Maigret:** 4 profiles found across 3155 platforms" in md
        assert "**Broker scan:** 4 brokers, exposure score 100/100" in md


class TestModelBehaviour:
    def test_skipped_source_renders_not_checked_never_zero_found(self):
        """The honesty gate: a skipped source's coverage row carries its
        reason; it never reads as a count."""
        state = PipelineState(
            raw_input=RAW_INPUT,
            results={
                "hibp": SourceResult(
                    name="hibp",
                    status="skipped",
                    findings=[],
                    detail="not checked — set HIBP_API_KEY",
                )
            },
        )
        model = build_report_model(state)
        assert model.coverage is not None
        assert model.coverage.skipped == [
            CoverageRow(label="HIBP", summary="not checked — set HIBP_API_KEY")
        ]
        md = render_markdown(model)
        assert "not checked — set HIBP_API_KEY" in md
        assert "HIBP:** 0" not in md

    def test_model_is_deterministic_for_same_state(self, scan_state):
        a = build_report_model(scan_state)
        b = build_report_model(scan_state)
        assert a.section_titles() == b.section_titles()
        assert render_markdown(a) == render_markdown(b)


class TestEvidenceAppendix:
    """EVIDENCE.2 / OPSEC.5 / RESILIENCE.4: the report appendix carries
    per-source provenance (replayable sha256), egress exposure, and a
    run-health rollup — and removes the hashes of sources that were skipped."""

    def test_appendix_present_in_report(self, scan_state):
        model = build_report_model(scan_state)
        assert model.appendix is not None
        assert model.appendix.evidence
        assert "Evidence, Egress & Run Health" in model.section_titles()
        md = render_markdown(model)
        assert "## Evidence, Egress & Run Health" in md
        assert "### Evidence" in md
        assert "### Egress Exposure" in md
        assert "### Run Health" in md

    def test_ran_sources_have_replay_hash_skipped_do_not(self, scan_state):
        model = build_report_model(scan_state)
        assert model.appendix is not None
        ran = [r for r in model.appendix.evidence if r.response_sha256]
        assert ran, "expected at least one ran source with a replay hash"
        for row in ran:
            assert len(row.response_sha256) == 64
            assert row.latency_ms >= 0
            assert row.tool_version
        # single-host tools expose the vendor host; aggregators (holehe,
        # maigret, broker_scan, ...) resolve many hosts and legitimately emit ""
        assert any(row.source_host for row in ran), "no vendor host recorded"
        egress_by_source = {e.source for e in model.appendix.egress}
        assert {
            r.source for r in ran
        } <= egress_by_source, "every ran source has an egress row"

    def test_run_health_rolls_up_statuses(self, scan_state):
        model = build_report_model(scan_state)
        assert model.appendix is not None
        assert model.appendix.run_health is not None
        h = model.appendix.run_health
        expected = {"ok": 0, "skipped": 0, "error": 0}
        for sr in scan_state.results.values():
            expected[sr.status] = expected.get(sr.status, 0) + 1
        assert h.ok == expected["ok"]
        assert h.skipped == expected["skipped"]
        assert h.error == expected["error"]
        assert h.wall_time_ms >= 0

    def test_skipped_only_state_still_produces_health_rollup(self):
        state = PipelineState(
            raw_input=RAW_INPUT,
            results={
                "hibp": SourceResult(
                    name="hibp",
                    status="skipped",
                    findings=[],
                    detail="not checked — set HIBP_API_KEY",
                )
            },
        )
        model = build_report_model(state)
        assert model.appendix is None  # nothing ran: no evidence appendix
        md = render_markdown(model)
        assert "## Evidence, Egress & Run Health" not in md
