"""Tests for OPSEC.1 — egress policy resolution and pacing."""

import os
import time

import pytest

from eidolon.core.egress import (
    EgressPolicy,
    _parse_pacing,
    bind_policy,
    enforce_pacing_for_run,
    get_active_policy,
    resolve_policy,
    unbind_policy,
)


class TestParsePacing:
    def test_empty_string_returns_zeros(self):
        assert _parse_pacing("") == (0.0, 0.0)
        assert _parse_pacing("  ") == (0.0, 0.0)

    def test_single_value(self):
        assert _parse_pacing("1.5") == (1.5, 0.0)
        assert _parse_pacing("0.2") == (0.2, 0.0)

    def test_two_values(self):
        assert _parse_pacing("1.5,0.3") == (1.5, 0.3)
        assert _parse_pacing("0.1,0.05") == (0.1, 0.05)

    def test_whitespace_handling(self):
        assert _parse_pacing(" 1.5 , 0.3 ") == (1.5, 0.3)

    def test_invalid_first_value_defaults_to_zero(self):
        assert _parse_pacing("invalid") == (0.0, 0.0)
        assert _parse_pacing("invalid,0.3") == (0.0, 0.3)

    def test_invalid_second_value_defaults_to_zero(self):
        assert _parse_pacing("1.5,invalid") == (1.5, 0.0)


class TestResolvePolicy:
    def test_defaults_when_no_env(self, monkeypatch):
        # Clear all relevant env vars
        for k in list(os.environ.keys()):
            if k.startswith("EIDOLON_"):
                monkeypatch.delenv(k, raising=False)

        policy = resolve_policy("hibp")
        assert policy.proxy is None
        assert policy.min_interval_s == 0.0
        assert policy.jitter_s == 0.0
        assert policy.user_agent.startswith("eidolon/")
        assert policy.dns_via_proxy is False
        assert policy.require_proxy is False

    def test_global_proxy(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PROXY", "http://proxy:8080")
        policy = resolve_policy("hibp")
        assert policy.proxy == "http://proxy:8080"

    def test_per_tool_proxy_overrides_global(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PROXY", "http://global:8080")
        monkeypatch.setenv("EIDOLON_PROXY_HIBP", "http://tool:8080")
        policy = resolve_policy("hibp")
        assert policy.proxy == "http://tool:8080"

    def test_global_pacing(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PACING", "0.5,0.1")
        policy = resolve_policy("shodan")
        assert policy.min_interval_s == 0.5
        assert policy.jitter_s == 0.1

    def test_per_tool_pacing_overrides_global(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PACING", "0.5,0.1")
        monkeypatch.setenv("EIDOLON_PACING_SHODAN", "1.0,0.2")
        policy = resolve_policy("shodan")
        assert policy.min_interval_s == 1.0
        assert policy.jitter_s == 0.2

    def test_custom_user_agent(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_USER_AGENT", "custom-agent/1.0")
        policy = resolve_policy("hibp")
        assert policy.user_agent == "custom-agent/1.0"

    def test_dns_via_proxy_true_values(self, monkeypatch):
        for val in ("1", "true", "yes", "on", "True", "YES"):
            monkeypatch.setenv("EIDOLON_DNS_PROXY", val)
            policy = resolve_policy("hibp")
            assert policy.dns_via_proxy is True

    def test_dns_via_proxy_false_values(self, monkeypatch):
        for val in ("0", "false", "no", "off", "", "maybe"):
            monkeypatch.setenv("EIDOLON_DNS_PROXY", val)
            policy = resolve_policy("hibp")
            assert policy.dns_via_proxy is False

    def test_require_proxy_true_values(self, monkeypatch):
        for val in ("1", "true", "yes", "on", "True", "YES"):
            monkeypatch.setenv("EIDOLON_REQUIRE_PROXY", val)
            policy = resolve_policy("hibp")
            assert policy.require_proxy is True

    def test_require_proxy_false_values(self, monkeypatch):
        for val in ("0", "false", "no", "off", "", "maybe"):
            monkeypatch.setenv("EIDOLON_REQUIRE_PROXY", val)
            policy = resolve_policy("hibp")
            assert policy.require_proxy is False

    def test_tool_name_normalization(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PROXY_FAST_PEOPLE_SEARCH", "http://fps:8080")
        policy = resolve_policy("fast-people-search")
        assert policy.proxy == "http://fps:8080"


class TestContextVarBinding:
    def test_get_active_policy_returns_none_by_default(self):
        assert get_active_policy() is None

    def test_bind_and_unbind(self):
        policy = EgressPolicy(proxy="http://test:8080")
        token = bind_policy(policy)
        try:
            assert get_active_policy() == policy
        finally:
            unbind_policy(token)
        assert get_active_policy() is None

    def test_nested_binding_restores_previous(self):
        policy1 = EgressPolicy(proxy="http://proxy1:8080")
        policy2 = EgressPolicy(proxy="http://proxy2:8080")

        token1 = bind_policy(policy1)
        assert get_active_policy() == policy1

        token2 = bind_policy(policy2)
        assert get_active_policy() == policy2

        unbind_policy(token2)
        assert get_active_policy() == policy1

        unbind_policy(token1)
        assert get_active_policy() is None


class TestPacingEnforcement:
    def test_no_pacing_no_delay(self, monkeypatch):
        monkeypatch.delenv("EIDOLON_PACING", raising=False)
        monkeypatch.delenv("EIDOLON_PACING_HIBP", raising=False)

        policy = EgressPolicy()
        token = bind_policy(policy)
        try:
            start = time.monotonic()
            enforce_pacing_for_run("hibp")
            enforce_pacing_for_run("hibp")
            elapsed = time.monotonic() - start
            assert elapsed < 0.1  # Should be nearly instant
        finally:
            unbind_policy(token)

    def test_pacing_enforces_minimum_interval(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PACING_HIBP", "0.15,0.0")

        policy = resolve_policy("hibp")
        token = bind_policy(policy)
        try:
            start = time.monotonic()
            enforce_pacing_for_run("hibp")
            enforce_pacing_for_run("hibp")
            elapsed = time.monotonic() - start
            # Two calls with 0.15 min_interval should take at least 0.15s
            assert elapsed >= 0.13  # Allow small margin
        finally:
            unbind_policy(token)

    def test_pacing_is_per_tool(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PACING_HIBP", "0.15,0.0")
        monkeypatch.delenv("EIDOLON_PACING_SHODAN", raising=False)

        policy_hibp = resolve_policy("hibp")
        policy_shodan = resolve_policy("shodan")

        # Test hibp with pacing
        token = bind_policy(policy_hibp)
        try:
            start = time.monotonic()
            enforce_pacing_for_run("hibp")
            enforce_pacing_for_run("hibp")
            hibp_elapsed = time.monotonic() - start
            assert hibp_elapsed >= 0.13
        finally:
            unbind_policy(token)

        # Test shodan without pacing (reset pacing map)
        from eidolon.core import egress

        egress._last_call_ts.clear()

        token = bind_policy(policy_shodan)
        try:
            start = time.monotonic()
            enforce_pacing_for_run("shodan")
            enforce_pacing_for_run("shodan")
            shodan_elapsed = time.monotonic() - start
            assert shodan_elapsed < 0.1
        finally:
            unbind_policy(token)

    def test_pacing_shared_across_threads_process_global(self, monkeypatch):
        """Pacing map is process-global, keyed by tool name."""
        monkeypatch.setenv("EIDOLON_PACING_HIBP", "0.1,0.0")

        import threading

        results = []

        def worker():
            policy = resolve_policy("hibp")
            token = bind_policy(policy)
            try:
                start = time.monotonic()
                enforce_pacing_for_run("hibp")
                enforce_pacing_for_run("hibp")
                results.append(time.monotonic() - start)
            finally:
                unbind_policy(token)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Both threads share the same pacing map, so at least one should wait
        # Actually both will wait because the last_call_ts is shared
        assert any(r >= 0.08 for r in results)


class TestPolicyEquality:
    def test_same_inputs_produce_equal_policy(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PROXY", "http://proxy:8080")
        monkeypatch.setenv("EIDOLON_PACING", "1.0,0.5")

        p1 = resolve_policy("hibp")
        p2 = resolve_policy("hibp")
        assert p1 == p2

    def test_different_tool_names_produce_different_policies_when_per_tool_env(
        self, monkeypatch
    ):
        monkeypatch.setenv("EIDOLON_PROXY_HIBP", "http://hibp:8080")
        monkeypatch.setenv("EIDOLON_PROXY_SHODAN", "http://shodan:8080")

        p1 = resolve_policy("hibp")
        p2 = resolve_policy("shodan")
        assert p1.proxy != p2.proxy


class TestHttpClientHonorsPolicy:
    """OPSEC.3 — every HTTP tool builds its client through the shared helper,
    which reads the ContextVar policy (proxy + UA + trust_env=False)."""

    def _setenv(self, monkeypatch):
        for k in list(os.environ.keys()):
            if k.startswith("EIDOLON_"):
                monkeypatch.delenv(k, raising=False)

    @pytest.fixture
    def _record_httpx(self, monkeypatch):
        """Stub httpx.Client with a recorder so tests can assert constructor args
        (httpx 0.27 doesn't expose the resolved proxy as a public attribute)."""
        calls = []

        class _FakeClient:
            def __init__(self, **kwargs):
                calls.append(kwargs)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return None

        import eidolon.sources._http as http_mod

        monkeypatch.setattr(http_mod, "httpx", _Stub(calls))
        return calls

    def test_client_uses_contextvar_proxy(self, monkeypatch, _record_httpx):
        from eidolon.core.egress import bind_policy, unbind_policy
        from eidolon.sources._http import client

        self._setenv(monkeypatch)
        token = bind_policy(
            EgressPolicy(proxy="http://socks5-host:1080", user_agent="ua/1")
        )
        try:
            client()
        finally:
            unbind_policy(token)
        kwargs = _record_httpx[0]
        assert kwargs.get("proxy") == "http://socks5-host:1080"
        assert kwargs.get("headers") == {"User-Agent": "ua/1"}
        assert kwargs.get("trust_env") is False  # ambient env can't redirect

    def test_client_direct_when_no_active_policy(self, monkeypatch, _record_httpx):
        from eidolon.sources._http import client

        self._setenv(monkeypatch)
        client()
        kwargs = _record_httpx[0]
        assert kwargs.get("proxy") is None
        assert kwargs.get("trust_env") is False

    def test_explicit_policy_overrides_context(self, monkeypatch, _record_httpx):
        from eidolon.core.egress import bind_policy, unbind_policy
        from eidolon.sources._http import client

        self._setenv(monkeypatch)
        token = bind_policy(EgressPolicy(proxy="http://ctx:8080"))
        try:
            client(policy=EgressPolicy(proxy="http://explicit:8080"))
        finally:
            unbind_policy(token)
        assert _record_httpx[0]["proxy"] == "http://explicit:8080"

    def test_http_tools_import_the_shared_client_not_bare_httpx(self):
        """Locks the boundary: HTTP tools route through `_http.client`, and the
        async ones through `_http.async_client` — never a bare httpx client."""
        from pathlib import Path

        from eidolon import sources as sources_pkg

        banned = ("httpx.Client(", "httpx.AsyncClient(")
        http_tools = [
            "hibp.py",
            "dehashed.py",
            "whoxy.py",
            "shodan.py",
            "numverify.py",
            "courtlistener.py",
            "opencorporates.py",
            "spiderfoot.py",
            "stealer.py",
            "paste.py",
            "commoncrawl.py",
            "fastpeoplesearch.py",
            "truepeoplesearch.py",
            "holehe.py",
        ]
        for name in http_tools:
            src = (Path(sources_pkg.__file__).resolve().parent / name).read_text()
            assert (
                "from eidolon.sources._http import" in src
            ), f"{name} does not use the shared _http client"
            for banned_frag in banned:
                assert (
                    banned_frag not in src
                ), f"{name} constructs a bare httpx client ({banned_frag})"

    def test_default_timeout_is_bounded(self, monkeypatch, _record_httpx):
        """RESILIENCE.3 — the shared client default can't hang past a read cap."""
        from eidolon.sources._http import client

        self._setenv(monkeypatch)
        client()
        kwargs = _record_httpx[0]
        timeout = kwargs["timeout"]
        assert timeout.connect < 10
        assert timeout.read <= 60
        assert timeout.pool < 20


class _Stub:
    """Minimal httpx-module stand-in exposing Client + AsyncClient (both route
    to the shared recorder) and Timeout (real) for the _http helper."""

    Timeout = pytest.importorskip("httpx").Timeout

    def __init__(self, calls):
        self._calls = calls

    def Client(self, **kwargs):
        return _FakeClient(kwargs, self._calls)

    def AsyncClient(self, **kwargs):
        return _FakeClient(kwargs, self._calls)


class _FakeClient:
    def __init__(self, kwargs, calls):
        calls.append(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None


class TestCollectBoundaryPacing:
    """OPSEC.2 — pacing is enforced at the collect boundary, so back-to-back
    runs of one tool respect min_interval_s, and zero pacing adds no latency."""

    def _clear(self):
        from eidolon.core import egress

        egress._last_call_ts.clear()

    def test_pacing_enforced_at_collect_boundary(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_PACING_HIBP", "0.2,0.0")
        monkeypatch.delenv("HIBP_API_KEY", raising=False)

        from eidolon.sources.base import collect
        from eidolon.sources.hibp import Hibp, HibpInput

        self._clear()
        t0 = time.monotonic()
        collect(Hibp(), HibpInput(input_type="email", value="a@b.com"))
        collect(Hibp(), HibpInput(input_type="email", value="a@b.com"))
        elapsed = time.monotonic() - t0
        self._clear()
        # the second collect paces itself: at least the 0.2s minimum interval
        assert elapsed >= 0.16, f"pacing not enforced at boundary: {elapsed:.3f}s"

    def test_zero_pacing_adds_no_latency(self, monkeypatch):
        for k in list(os.environ.keys()):
            if k.startswith("EIDOLON_PACING"):
                monkeypatch.delenv(k, raising=False)
        monkeypatch.delenv("HIBP_API_KEY", raising=False)

        from eidolon.sources.base import collect
        from eidolon.sources.hibp import Hibp, HibpInput

        self._clear()
        t0 = time.monotonic()
        collect(Hibp(), HibpInput(input_type="email", value="a@b.com"))
        collect(Hibp(), HibpInput(input_type="email", value="a@b.com"))
        elapsed = time.monotonic() - t0
        self._clear()
        assert elapsed < 0.5, f"zero pacing still added latency: {elapsed:.3f}s"


class TestSubprocessEgress:
    """OPSEC.4 — subprocess tools inherit the policy proxy/env and a
    require_proxy-without-proxy policy skips them without spawning."""

    def test_subprocess_env_injects_proxy(self, monkeypatch):
        from eidolon.core.egress import bind_policy, subprocess_env, unbind_policy

        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        token = bind_policy(EgressPolicy(proxy="http://proxy:8080"))
        try:
            env = subprocess_env("ghunt", {"PATH": "/bin"})
            assert env["HTTPS_PROXY"] == "http://proxy:8080"
            assert env["HTTP_PROXY"] == "http://proxy:8080"
            assert env["ALL_PROXY"] == "http://proxy:8080"
            assert env["PATH"] == "/bin"  # base env preserved
        finally:
            unbind_policy(token)

    def test_subprocess_env_without_policy_is_clean(self, monkeypatch):
        from eidolon.core.egress import subprocess_env

        monkeypatch.delenv("EIDOLON_PROXY", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        env = subprocess_env("ghunt", {"PATH": "/bin"})
        assert "HTTPS_PROXY" not in env

    def test_require_proxy_without_proxy_skips(self, monkeypatch):
        """Boundary returns 'skipped' — never egresses in the clear, and never
        masquerades as a successful empty run."""
        monkeypatch.setenv("EIDOLON_REQUIRE_PROXY", "true")
        monkeypatch.delenv("EIDOLON_PROXY", raising=False)

        from eidolon.sources.base import collect
        from eidolon.sources.ghunt import Ghunt, GHuntInput

        monkeypatch.setattr("subprocess.run", _boom)  # must not be called
        sr = collect(Ghunt(), GHuntInput(email="a@b.com"))
        assert sr.status == "skipped"
        assert "requires a proxy" in (sr.detail or "").lower()
        assert sr.findings == []

    def test_require_proxy_with_proxy_allows(self, monkeypatch):
        monkeypatch.setenv("EIDOLON_REQUIRE_PROXY", "true")
        monkeypatch.setenv("EIDOLON_PROXY", "http://proxy:8080")

        from eidolon.sources.base import collect
        from eidolon.sources.hibp import Hibp, HibpInput

        sr = collect(Hibp(), HibpInput(input_type="email", value="a@b.com"))
        assert sr.status == "ok"


def _boom(*args, **kwargs):  # pragma: no cover - sentinel that must never fire
    raise AssertionError("subprocess ran despite require_proxy without a proxy")
