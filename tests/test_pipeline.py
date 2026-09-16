import os
import shutil
from pathlib import Path

import pytest

os.environ["TEST_MODE"] = "true"
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("GOOGLE_CSE_API_KEY", "test")
os.environ.setdefault("GOOGLE_CSE_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["RESULTS_OUTPUT_PATH"] = "/tmp/osint_test_output/"
os.environ["AI_PLATFORMS"] = "claude,chatgpt,gemini,grok"

from eidolon.core.state import AnalysisResult, PipelineState
from eidolon.pipeline.graph import build_graph


@pytest.fixture(autouse=True)
def cleanup_output():
    yield
    out = Path("/tmp/osint_test_output")
    if out.exists():
        shutil.rmtree(out)


class TestFullPipeline:
    def test_email_input_completes(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        assert result is not None

    def test_classifications_populated(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        classifications = result["classifications"]
        assert len(classifications) == 1
        c = classifications[0]
        c_type = c.type if hasattr(c, "type") else c["type"]
        assert c_type == "email"

    def test_results_envelope_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        results = result["results"]
        assert results is not None
        # every email-applicable source ran and recorded its envelope
        for name in (
            "hibp",
            "dehashed",
            "whoxy",
            "paste",
            "stealer",
            "spiderfoot",
            "holehe",
            "blackbird",
            "maigret",
            "ghunt",
            "commoncrawl",
        ):
            assert name in results, f"{name} missing from results"
            status = (
                results[name].status
                if hasattr(results[name], "status")
                else results[name]["status"]
            )
            assert status == "ok"

    def test_findings_populated(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        findings = result["findings"]
        assert findings
        kinds = {f.kind for f in findings}
        assert "breach" in kinds and "credential" in kinds

    def test_mitre_techniques_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        techniques = result["mitre_techniques"]
        assert techniques  # the fixture scan has infostealer + password signals
        assert all(t.technique_id.startswith("T") for t in techniques)

    def test_analysis_result_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        assert result["analysis_result"] is not None

    def test_analysis_result_validates(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        analysis = AnalysisResult(**result["analysis_result"])
        assert 0 <= analysis.overall_risk_score <= 100
        assert analysis.overall_risk_level in ("high", "medium", "low")

    def test_report_path_written(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        assert result["report_path"] is not None
        assert Path(result["report_path"]).exists()

    def test_name_input_classifies_correctly(self):
        graph = build_graph()
        state = PipelineState(raw_input="John Doe")
        result = graph.invoke(state)
        c = result["classifications"][0]
        c_type = c.type if hasattr(c, "type") else c["type"]
        assert c_type == "name"

    def test_multiple_inputs_all_classified(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com\nJohn Doe\n555-123-4567")
        result = graph.invoke(state)
        assert len(result["classifications"]) == 3
        types = {
            (c.type if hasattr(c, "type") else c["type"])
            for c in result["classifications"]
        }
        assert "email" in types
        assert "name" in types
        assert "phone" in types

    def test_no_tool_raises_exception(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        try:
            result = graph.invoke(state)
            assert True
        except Exception as exc:
            pytest.fail(f"Pipeline raised an unexpected exception: {exc}")
