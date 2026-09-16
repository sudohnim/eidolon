"""Egress policy — how tools reach the network (OPSEC.1).

A frozen `EgressPolicy` describes proxy, pacing, UA, and DNS behavior.
`resolve_policy(tool_name)` overlays per-tool env over a global default.
The resolved policy is exposed via a `ContextVar` so the collect boundary
and HTTP/subprocess helpers all read the same object without threading it
through every call signature.
"""

import contextvars
import os
from dataclasses import dataclass

from eidolon import __version__


@dataclass(frozen=True)
class EgressPolicy:
    """Network egress policy for a single tool/vendor."""

    proxy: str | None = None
    min_interval_s: float = 0.0
    jitter_s: float = 0.0
    user_agent: str = f"eidolon/{__version__}"
    dns_via_proxy: bool = False
    require_proxy: bool = False


# ContextVar carrying the active policy for the current tool invocation.
_active_policy: contextvars.ContextVar[EgressPolicy | None] = contextvars.ContextVar(
    "eidolon_active_egress_policy", default=None
)


# Module-level lock and last-call map for per-vendor pacing (process-global).
import threading  # noqa: E402

_pacing_lock = threading.Lock()
_last_call_ts: dict[str, float] = {}


def _parse_pacing(value: str) -> tuple[float, float]:
    """Parse pacing string like '1.5' or '1.5,0.3' -> (min_interval_s, jitter_s)."""
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if not parts:
        return (0.0, 0.0)
    try:
        min_interval = float(parts[0])
    except ValueError:
        min_interval = 0.0
    try:
        jitter = float(parts[1]) if len(parts) > 1 else 0.0
    except ValueError:
        jitter = 0.0
    return (min_interval, jitter)


def resolve_policy(tool_name: str) -> EgressPolicy:
    """Resolve the egress policy for a tool.

    Env overlay (highest priority first):
      - EIDOLON_PROXY_<TOOL> / EIDOLON_PACING_<TOOL> (per-tool)
      - EIDOLON_PROXY / EIDOLON_PACING (global)
      - defaults
    """
    upper = tool_name.upper().replace("-", "_")

    # Proxy
    proxy = os.environ.get(f"EIDOLON_PROXY_{upper}") or os.environ.get("EIDOLON_PROXY")

    # Pacing: "min_interval" or "min_interval,jitter"
    pacing_str = os.environ.get(f"EIDOLON_PACING_{upper}") or os.environ.get(
        "EIDOLON_PACING"
    )
    min_interval, jitter = _parse_pacing(pacing_str) if pacing_str else (0.0, 0.0)

    # User agent
    ua = os.environ.get("EIDOLON_USER_AGENT") or f"eidolon/{__version__}"

    # DNS via proxy
    dns_proxy = os.environ.get(f"EIDOLON_DNS_PROXY_{upper}") or os.environ.get(
        "EIDOLON_DNS_PROXY"
    )
    dns_via_proxy = bool(dns_proxy and dns_proxy.lower() in ("1", "true", "yes", "on"))

    # Require proxy
    req_proxy = os.environ.get(f"EIDOLON_REQUIRE_PROXY_{upper}") or os.environ.get(
        "EIDOLON_REQUIRE_PROXY"
    )
    require_proxy = bool(req_proxy and req_proxy.lower() in ("1", "true", "yes", "on"))

    return EgressPolicy(
        proxy=proxy,
        min_interval_s=min_interval,
        jitter_s=jitter,
        user_agent=ua,
        dns_via_proxy=dns_via_proxy,
        require_proxy=require_proxy,
    )


def get_active_policy() -> EgressPolicy | None:
    """Get the currently bound policy (for HTTP/subprocess helpers)."""
    return _active_policy.get()


def bind_policy(policy: EgressPolicy) -> contextvars.Token:
    """Bind a policy for the current context (used by collect boundary)."""
    return _active_policy.set(policy)


def unbind_policy(token: contextvars.Token) -> None:
    """Restore previous policy."""
    _active_policy.reset(token)


def _enforce_pacing(tool_name: str, policy: EgressPolicy) -> None:
    """Enforce per-vendor pacing (process-global, thread-safe)."""
    if policy.min_interval_s <= 0 and policy.jitter_s <= 0:
        return

    import random
    import time

    key = tool_name.upper()
    now = time.monotonic()

    with _pacing_lock:
        last = _last_call_ts.get(key)
        if last is not None:
            elapsed = now - last
            wait = policy.min_interval_s + random.uniform(0, policy.jitter_s)
            if elapsed < wait:
                time.sleep(wait - elapsed)
        _last_call_ts[key] = time.monotonic()


def enforce_pacing_for_run(tool_name: str) -> None:
    """Call at the start of a tool run to enforce pacing against the active policy."""
    policy = get_active_policy()
    if policy:
        _enforce_pacing(tool_name, policy)
