import os
from datetime import datetime, timezone

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

from eidolon.agent.nodes import _commoncrawl_targets, commoncrawl_node
from eidolon.core.models import PipelineState, ToolResult
from eidolon.tools.base import run_to_result
from eidolon.tools.commoncrawl import (
    CommonCrawl,
    CommonCrawlInput,
    CommonCrawlOutput,
    MatchedProperty,
    _query_target,
)


def _result(tool: str, data: dict, success: bool = True) -> ToolResult:
    return ToolResult(
        success=success,
        tool=tool,
        input_type="email",
        input_value="test@example.com",
        timestamp=datetime.now(timezone.utc),
        data=data,
    )


class TestCommonCrawlTool:
    def test_returns_tool_result(self):
        result = run_to_result(CommonCrawl(), CommonCrawlInput(targets=["janedoe.com"]))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = run_to_result(CommonCrawl(), CommonCrawlInput(targets=["janedoe.com"]))
        assert result.success is True

    def test_tool_name(self):
        result = run_to_result(CommonCrawl(), CommonCrawlInput(targets=["janedoe.com"]))
        assert result.tool == "commoncrawl"

    def test_available_no_key(self):
        # No API key required — always available.
        assert CommonCrawl().available() is True

    def test_output_schema(self):
        result = run_to_result(CommonCrawl(), CommonCrawlInput(targets=["janedoe.com"]))
        output = CommonCrawlOutput(**result.data)
        assert output.present is True
        assert output.total_captures == 31
        assert output.index_id == "CC-MAIN-2026-22"
        assert len(output.matched) == 2

    def test_matched_property_fields(self):
        result = run_to_result(CommonCrawl(), CommonCrawlInput(targets=["janedoe.com"]))
        output = CommonCrawlOutput(**result.data)
        first = output.matched[0]
        assert first.target == "janedoe.com"
        assert first.capture_count == 27
        assert first.sample_url == "https://janedoe.com/about"
        assert first.sample_timestamp == "20260518094233"

    def test_input_value_joins_targets(self):
        tool = CommonCrawl()
        value = tool._input_value(CommonCrawlInput(targets=["a.com", "b.com"]))
        assert value == "a.com, b.com"

    def test_empty_output_default(self):
        # The empty output models the "nothing found / skipped" shape.
        out = CommonCrawlOutput()
        assert out.present is False
        assert out.matched == []
        assert out.total_captures == 0


class _Resp:
    """Minimal stand-in for a requests.Response for _query_target tests."""

    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class TestQueryTarget:
    def test_parses_jsonlines_captures(self, monkeypatch):
        import eidolon.tools.commoncrawl as cc

        body = (
            '{"url": "https://janedoe.com/", "timestamp": "20260101000000"}\n'
            '{"url": "https://janedoe.com/about", "timestamp": "20260102000000"}\n'
        )
        monkeypatch.setattr(cc.requests, "get", lambda *a, **k: _Resp(200, body))
        log = __import__("structlog").get_logger()
        prop = _query_target("https://index.example/cdx", "janedoe.com", log)
        assert prop is not None
        assert prop.capture_count == 2
        assert prop.sample_url == "https://janedoe.com/"
        assert prop.sample_timestamp == "20260101000000"

    def test_404_returns_none(self, monkeypatch):
        import eidolon.tools.commoncrawl as cc

        monkeypatch.setattr(cc.requests, "get", lambda *a, **k: _Resp(404, ""))
        log = __import__("structlog").get_logger()
        assert _query_target("https://index.example/cdx", "nope.com", log) is None

    def test_empty_body_returns_none(self, monkeypatch):
        import eidolon.tools.commoncrawl as cc

        monkeypatch.setattr(cc.requests, "get", lambda *a, **k: _Resp(200, "   "))
        log = __import__("structlog").get_logger()
        assert _query_target("https://index.example/cdx", "nope.com", log) is None

    def test_network_error_returns_none(self, monkeypatch):
        import eidolon.tools.commoncrawl as cc

        def _raise(*a, **k):
            raise cc.requests.RequestException("boom")

        monkeypatch.setattr(cc.requests, "get", _raise)
        log = __import__("structlog").get_logger()
        assert _query_target("https://index.example/cdx", "x.com", log) is None


class TestTargetDerivation:
    def test_no_candidates_returns_empty(self):
        state = PipelineState(raw_input="test@example.com")
        assert _commoncrawl_targets(state) == []

    def test_whoxy_domains_first(self):
        state = PipelineState(
            raw_input="test@example.com",
            whoxy_result=_result(
                "whoxy",
                {"domains": [{"domain_name": "janedoe.com"}, {"domain_name": "jd.io"}]},
            ),
        )
        targets = _commoncrawl_targets(state)
        assert targets[:2] == ["janedoe.com", "jd.io"]

    def test_maigret_profile_urls_included(self):
        state = PipelineState(
            raw_input="test@example.com",
            sherlock_result=_result(
                "maigret",
                {
                    "profiles_found": [
                        {"platform": "GitHub", "url": "https://github.com/jdoe"},
                    ]
                },
            ),
        )
        assert "https://github.com/jdoe" in _commoncrawl_targets(state)

    def test_blackbird_probe_urls_filtered(self):
        # Internal API probe URLs (api., /lookup, ?email=) are dropped by _clean_url.
        state = PipelineState(
            raw_input="test@example.com",
            blackbird_result=_result(
                "blackbird",
                {
                    "accounts_found": [
                        {
                            "platform": "Adobe",
                            "url": "https://auth.services.adobe.com/api/users/lookup",
                        },
                        {"platform": "Real", "url": "https://realprofile.example/jdoe"},
                    ]
                },
            ),
        )
        targets = _commoncrawl_targets(state)
        assert "https://realprofile.example/jdoe" in targets
        assert all("lookup" not in t for t in targets)

    def test_dedupe_and_cap_at_five(self):
        state = PipelineState(
            raw_input="test@example.com",
            whoxy_result=_result(
                "whoxy",
                {
                    "domains": [{"domain_name": f"site{i}.com"} for i in range(8)]
                    + [{"domain_name": "SITE0.com"}]  # case-insensitive dup
                },
            ),
        )
        targets = _commoncrawl_targets(state)
        assert len(targets) == 5
        # case-insensitive dedupe kept only the first "site0.com"
        assert sum(t.lower() == "site0.com" for t in targets) == 1


class TestCommonCrawlNode:
    def test_skips_when_no_targets(self):
        state = PipelineState(raw_input="test@example.com")
        out = commoncrawl_node(state)
        assert out.commoncrawl_result is None

    def test_runs_and_stores_result_in_test_mode(self):
        # With a candidate target, the node runs the tool (TEST_MODE fixture) and
        # stores a successful ToolResult.
        state = PipelineState(
            raw_input="test@example.com",
            whoxy_result=_result(
                "whoxy", {"domains": [{"domain_name": "janedoe.com"}]}
            ),
        )
        out = commoncrawl_node(state)
        assert out.commoncrawl_result is not None
        assert out.commoncrawl_result.success is True
        assert out.commoncrawl_result.tool == "commoncrawl"
        assert out.commoncrawl_result.data["present"] is True


def test_matched_property_model_defaults():
    m = MatchedProperty(target="x.com")
    assert m.capture_count == 0
    assert m.sample_url == ""
