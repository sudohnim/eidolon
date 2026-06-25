"""Scan must finish even if the local LLM (Ollama) is unreachable."""


def test_analysis_completes_without_ollama(monkeypatch):
    import langchain_ollama

    class _Boom:
        def __init__(self, *a, **k):
            pass

        def invoke(self, *a, **k):
            raise ConnectionError("ollama is down")

    monkeypatch.setattr(langchain_ollama, "ChatOllama", _Boom)

    from eidolon.agent.nodes import analysis_node
    from eidolon.core.models import InputClassification, PipelineState

    state = PipelineState(
        raw_input="a@b.com",
        classifications=[
            InputClassification(type="email", value="a@b.com", raw="a@b.com")
        ],
    )
    out = analysis_node(state)

    assert out.analysis_result is not None  # not blank despite no LLM
    assert "overall_risk_score" in out.analysis_result  # deterministic content built
