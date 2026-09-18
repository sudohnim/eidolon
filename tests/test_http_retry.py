"""Blindspot #3 — the shared HTTP client retries transient failures with
backoff and honors Retry-After, but never retries a caller error (4xx≠429)."""

import httpx
import pytest

from eidolon.sources import _http


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(_http.time, "sleep", lambda _s: None)


def _client_over(handler) -> httpx.Client:
    """A client whose innermost transport is a MockTransport, wrapped by the
    real _RetryTransport under test."""
    return httpx.Client(transport=_http._RetryTransport(httpx.MockTransport(handler)))


def test_retries_transient_then_succeeds():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503 if calls["n"] < 3 else 200)

    with _client_over(handler) as c:
        assert c.get("https://x.test").status_code == 200
    assert calls["n"] == 3  # two 503s retried, third ok


def test_gives_up_after_max_retries():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503)

    with _client_over(handler) as c:
        assert c.get("https://x.test").status_code == 503
    assert calls["n"] == _http._MAX_RETRIES + 1  # initial + retries


def test_does_not_retry_client_error():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(404)

    with _client_over(handler) as c:
        assert c.get("https://x.test").status_code == 404
    assert calls["n"] == 1  # 404 is the caller's fault, never retried


def test_retry_after_seconds_and_http_date():
    r = httpx.Response(429, headers={"Retry-After": "5"})
    assert _http._retry_after_seconds(r) == 5.0
    assert _http._retry_after_seconds(httpx.Response(429)) is None
