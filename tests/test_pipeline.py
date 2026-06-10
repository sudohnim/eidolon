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

from eidolon.agent.graph import build_graph
from eidolon.core.models import AnalysisResult, PipelineState


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

    def test_hibp_result_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        hibp = result["hibp_result"]
        assert hibp is not None
        success = hibp.success if hasattr(hibp, "success") else hibp["success"]
        assert success is True

    def test_broker_result_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        broker = result["broker_result"]
        assert broker is not None
        success = broker.success if hasattr(broker, "success") else broker["success"]
        assert success is True

    def test_spiderfoot_result_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        sf = result["spiderfoot_result"]
        assert sf is not None
        success = sf.success if hasattr(sf, "success") else sf["success"]
        assert success is True

    def test_ai_audit_result_present(self):
        graph = build_graph()
        state = PipelineState(raw_input="test@example.com")
        result = graph.invoke(state)
        ai = result["ai_audit_result"]
        assert ai is not None
        success = ai.success if hasattr(ai, "success") else ai["success"]
        assert success is True

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
