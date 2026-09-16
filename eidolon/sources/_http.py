"""Shared HTTP client that respects the active egress policy (OPSEC.3).

Every HTTP tool should use `client()` instead of constructing `httpx.Client`
directly. The client reads the active `EgressPolicy` from the ContextVar,
ensuring proxy, UA, and DNS settings are applied consistently.
"""

import httpx

from eidolon.core.egress import EgressPolicy, get_active_policy


def _default_timeout() -> httpx.Timeout:
    # connect=5s, read=30s, write=30s, pool=10s
    return httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=10.0)


def client(
    policy: EgressPolicy | None = None,
    *,
    timeout: httpx.Timeout | None = None,
    follow_redirects: bool = True,
) -> httpx.Client:
    """Return a configured httpx.Client that obeys the egress policy.

    Args:
        policy: Explicit policy override. If None, reads from ContextVar.
        timeout: Per-tool timeout. Default: connect=5, read=30, write=30, pool=10.
        follow_redirects: Whether to follow redirects.

    The client is configured with:
    - proxy from policy (or None for direct)
    - user-agent from policy
    - trust_env=False so ambient env vars can't silently redirect egress
    """
    active = policy or get_active_policy()
    proxy = active.proxy if active else None
    ua = active.user_agent if active else "eidolon"

    proxies = proxy if proxy else None

    if timeout is None:
        timeout = _default_timeout()

    return httpx.Client(
        proxy=proxies,
        timeout=timeout,
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
    active = policy or get_active_policy()
    proxy = active.proxy if active else None
    ua = active.user_agent if active else "eidolon"

    proxies = proxy if proxy else None

    if timeout is None:
        timeout = _default_timeout()

    return httpx.AsyncClient(
        proxy=proxies,
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers={"User-Agent": ua},
        trust_env=False,
    )
