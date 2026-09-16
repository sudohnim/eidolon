import os
from datetime import datetime, timezone

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

from eidolon.core.findings import Account, Finding
from eidolon.core.registry import commoncrawl_input
from eidolon.core.state import PipelineState, ToolResult
from eidolon.sources.base import run_to_result
from eidolon.sources.commoncrawl import (
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
    """Minimal stand-in for an httpx.Response for _query_target tests."""

    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _MockClient:
    def __init__(self, get_fn):
        self._get = get_fn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None

    def get(self, *a, **k):
        return self._get(*a, **k)


class TestQueryTarget:
    def test_parses_jsonlines_captures(self, monkeypatch):
        import eidolon.sources.commoncrawl as cc

        body = (
            '{"url": "https://janedoe.com/", "timestamp": "20260101000000"}\n'
            '{"url": "https://janedoe.com/about", "timestamp": "20260102000000"}\n'
        )

        def mock_get(*a, **k):
            return _Resp(200, body)

        monkeypatch.setattr(cc, "client", lambda *a, **k: _MockClient(mock_get))
        log = __import__("structlog").get_logger()
        status, prop = _query_target("https://index.example/cdx", "janedoe.com", log)
        assert status == "matched"
        assert prop is not None
        assert prop.capture_count == 2
        assert prop.sample_url == "https://janedoe.com/"
        assert prop.sample_timestamp == "20260101000000"

    def test_404_is_absent(self, monkeypatch):
        import eidolon.sources.commoncrawl as cc

        def mock_get(*a, **k):
            return _Resp(404, "")

        monkeypatch.setattr(cc, "client", lambda *a, **k: _MockClient(mock_get))
        log = __import__("structlog").get_logger()
        assert _query_target("https://index.example/cdx", "nope.com", log) == (
            "absent",
            None,
        )

    def test_empty_body_is_absent(self, monkeypatch):
        import eidolon.sources.commoncrawl as cc

        def mock_get(*a, **k):
            return _Resp(200, "   ")

        monkeypatch.setattr(cc, "client", lambda *a, **k: _MockClient(mock_get))
        log = __import__("structlog").get_logger()
        assert _query_target("https://index.example/cdx", "nope.com", log) == (
            "absent",
            None,
        )

    def test_network_error_is_error_not_absent(self, monkeypatch):
        import eidolon.sources.commoncrawl as cc

        monkeypatch.setattr(cc.time, "sleep", lambda *a, **k: None)

        def _raise(*a, **k):
            raise cc.httpx.RequestError("boom")

        monkeypatch.setattr(cc, "client", lambda *a, **k: _MockClient(_raise))
        log = __import__("structlog").get_logger()
        # A network failure is "error" (could-not-check), never "absent".
        assert _query_target("https://index.example/cdx", "x.com", log) == (
            "error",
            None,
        )

    def test_transient_504_retries_then_errors(self, monkeypatch):
        import eidolon.sources.commoncrawl as cc

        monkeypatch.setattr(cc.time, "sleep", lambda *a, **k: None)
        calls = {"n": 0}

        def _504(*a, **k):
            calls["n"] += 1
            return _Resp(504, "")

        monkeypatch.setattr(cc, "client", lambda *a, **k: _MockClient(_504))
        log = __import__("structlog").get_logger()
        status, prop = _query_target("https://index.example/cdx", "x.com", log)
        assert status == "error" and prop is None
        assert calls["n"] == cc._MAX_ATTEMPTS  # retried, not given up on first 504


class TestTargetDerivation:
    def _targets(self, state):
        inp = commoncrawl_input(state)
        return list(inp.targets) if inp is not None else []

    def test_no_candidates_returns_empty(self):
        state = PipelineState(raw_input="test@example.com")
        assert self._targets(state) == []

    def _domain_finding(self, domain: str) -> Finding:
        return Finding(
            kind="registered_domain",
            dedup_key=f"domain:{domain}",
            title=domain,
            payload={"domain": domain},
        )

    def test_whoxy_domains_first(self):
        state = PipelineState(
            raw_input="test@example.com",
            findings=[
                self._domain_finding("janedoe.com"),
                self._domain_finding("jd.io"),
            ],
        )
        targets = self._targets(state)
        assert targets[:2] == ["janedoe.com", "jd.io"]

    def test_maigret_profile_urls_included(self):
        state = PipelineState(
            raw_input="test@example.com",
            findings=[
                Account(
                    dedup_key="account:github",
                    platform="GitHub",
                    url="https://github.com/jdoe",
                )
            ],
        )
        assert "https://github.com/jdoe" in self._targets(state)

    def test_blackbird_probe_urls_filtered(self):
        # Internal API probe URLs (api., /lookup, ?email=) are dropped by _clean_url.
        state = PipelineState(
            raw_input="test@example.com",
            findings=[
                Account(
                    dedup_key="account:adobe",
                    platform="Adobe",
                    url="https://auth.services.adobe.com/api/users/lookup",
                ),
                Account(
                    dedup_key="account:real",
                    platform="Real",
                    url="https://realprofile.example/jdoe",
                ),
            ],
        )
        targets = self._targets(state)
        assert "https://realprofile.example/jdoe" in targets
        assert all("lookup" not in x for x in targets)

    def test_dedupe_and_cap_at_five(self):
        state = PipelineState(
            raw_input="test@example.com",
            findings=[self._domain_finding(f"site{i}.com") for i in range(8)]
            + [self._domain_finding("SITE0.com")],  # case-insensitive dup
        )
        targets = self._targets(state)
        assert len(targets) == 5
        # case-insensitive dedupe kept only the first "site0.com"
        assert sum(x.lower() == "site0.com" for x in targets) == 1


class TestCommonCrawlNode:
    def test_skips_when_no_targets(self):
        state = PipelineState(raw_input="test@example.com")
        inp = commoncrawl_input(state)
        assert inp is None  # not applicable -> absent from coverage

    def test_runs_and_stores_result_in_test_mode(self):
        # With a candidate target, the node runs the tool (TEST_MODE fixture) and
        # stores a successful ToolResult.
        state = PipelineState(
            raw_input="test@example.com",
            findings=[
                Finding(
                    kind="registered_domain",
                    dedup_key="domain:janedoe.com",
                    title="janedoe.com",
                    payload={"domain": "janedoe.com"},
                )
            ],
        )
        from eidolon.core.registry import REGISTRY
        from eidolon.pipeline.collect import _default_source_node

        spec = next(s for s in REGISTRY if s.name == "commoncrawl")
        out = _default_source_node(spec)(state)
        assert "commoncrawl" in out.results
        assert out.results["commoncrawl"].status == "ok"
        assert out.results["commoncrawl"].summary.startswith(
            "present in the public web archive"
        )


def test_matched_property_model_defaults():
    m = MatchedProperty(target="x.com")
    assert m.capture_count == 0
    assert m.sample_url == ""
