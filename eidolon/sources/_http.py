"""Shared HTTP client that respects the active egress policy (OPSEC.3) and
retries transient failures with backoff (blindspot #3).

Every HTTP tool should use `client()` / `async_client()` instead of building an
`httpx.Client` directly. The client:
  - reads the active `EgressPolicy` from the ContextVar (proxy, UA);
  - sets `trust_env=False` so ambient env can't silently redirect egress;
  - applies explicit connect/read timeouts (also the hard cap behind the wave
    timeout — RESILIENCE.3);
  - retries 429 / 502 / 503 / 504 with exponential backoff + jitter, honoring a
    ``Retry-After`` header, so a throttling or briefly-flapping vendor doesn't
    surface as a hard failure or get hammered.
"""

from __future__ import annotations

import email.utils
import random
import time

import httpx

from eidolon.core.egress import EgressPolicy, get_active_policy

# Transient statuses worth retrying. 4xx other than 429 are the caller's fault
# and never retried; 429/5xx-ish are transient.
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES = 3
_BACKOFF_BASE = 0.5  # seconds
_BACKOFF_CAP = 8.0
_JITTER = 0.3


def _default_timeout() -> httpx.Timeout:
    # connect=5s, read=30s, write=30s, pool=10s
    return httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse a Retry-After header (delta-seconds or an HTTP date)."""
    raw = response.headers.get("retry-after")
    if not raw:
        return None
    raw = raw.strip()
    if raw.isdigit():
        return float(raw)
    dt = email.utils.parsedate_to_datetime(raw)
    if dt is None:
        return None
    import datetime as _dt

    delta = (dt - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    return max(0.0, delta)


def _backoff_delay(attempt: int, response: httpx.Response | None) -> float:
    """Retry-After wins; else exponential backoff (base·2^attempt) + jitter, capped."""
    if response is not None:
        ra = _retry_after_seconds(response)
        if ra is not None:
            return min(ra, _BACKOFF_CAP)
    delay = min(_BACKOFF_BASE * (2**attempt), _BACKOFF_CAP)
    return delay + random.uniform(0, _JITTER)


class _RetryTransport(httpx.BaseTransport):
    """Sync transport that retries transient responses with backoff.

    ``proxy`` is stored for introspection (httpx doesn't expose the resolved
    proxy publicly, and it now lives on the transport rather than the Client)."""

    def __init__(
        self,
        inner: httpx.BaseTransport,
        max_retries: int = _MAX_RETRIES,
        proxy: str | None = None,
    ):
        self._inner = inner
        self._max_retries = max_retries
        self.proxy = proxy

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._inner.handle_request(request)
        for attempt in range(self._max_retries):
            if response.status_code not in _RETRY_STATUS:
                return response
            # Drain the discarded response before retrying (httpx contract).
            response.read()
            response.close()
            time.sleep(_backoff_delay(attempt, response))
            response = self._inner.handle_request(request)
        return response


class _AsyncRetryTransport(httpx.AsyncBaseTransport):
    """Async variant of `_RetryTransport`."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        max_retries: int = _MAX_RETRIES,
        proxy: str | None = None,
    ):
        self._inner = inner
        self._max_retries = max_retries
        self.proxy = proxy

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        import asyncio

        response = await self._inner.handle_async_request(request)
        for attempt in range(self._max_retries):
            if response.status_code not in _RETRY_STATUS:
                return response
            await response.aread()
            await response.aclose()
            await asyncio.sleep(_backoff_delay(attempt, response))
            response = await self._inner.handle_async_request(request)
        return response


def _resolve(policy: EgressPolicy | None) -> tuple[str | None, str]:
    active = policy or get_active_policy()
    proxy = active.proxy if active else None
    ua = active.user_agent if active else "eidolon"
    return proxy, ua


def client(
    policy: EgressPolicy | None = None,
    *,
    timeout: httpx.Timeout | None = None,
    follow_redirects: bool = True,
) -> httpx.Client:
    """A configured httpx.Client: egress policy (proxy/UA), explicit timeouts,
    and transient-failure retries. Reads the active policy from the ContextVar
    when ``policy`` is None."""
    proxy, ua = _resolve(policy)
    transport = _RetryTransport(
        httpx.HTTPTransport(proxy=proxy, retries=0), proxy=proxy
    )
    return httpx.Client(
        transport=transport,
        timeout=timeout or _default_timeout(),
        follow_redirects=follow_redirects,
        headers={"User-Agent": ua},
        trust_env=False,
    )


def async_client(
    policy: EgressPolicy | None = None,
    *,
    timeout: httpx.Timeout | None = None,
    follow_redirects: bool = True,
) -> httpx.AsyncClient:
    """Async variant of `client()`."""
    proxy, ua = _resolve(policy)
    transport = _AsyncRetryTransport(
        httpx.AsyncHTTPTransport(proxy=proxy, retries=0), proxy=proxy
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout or _default_timeout(),
        follow_redirects=follow_redirects,
        headers={"User-Agent": ua},
        trust_env=False,
    )
