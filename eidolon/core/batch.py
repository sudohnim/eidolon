"""run_batch — bounded concurrent multi-target scans (SCALE.1).

The single-target path (``run_scan``, one identity per invocation) is unchanged;
``run_batch`` runs the same compiled graph per target under a bounded pool and
returns one ``ScanState`` per target. Escaping a single identity via concurrency
on top of the per-target path — never by changing it.

Chosen design (per PLAN.md §0 — simplicity + robustness over cleverness): a
bounded ``ThreadPoolExecutor`` running the compiled graph directly per target.
A worker/greenlet pool with per-target backpressure would add a job-queue layer
with no payoff at this stage — the graph invoke is the expensive, bounded step,
and ``ThreadPoolExecutor(max_workers=...)`` caps it cleanly. Order of targets is
preserved (``pool.map``) so batch output lines up with the input.

Isolation: each target mints its own ``run_id`` in intake and writes its own
report artifact; nothing mutable is shared between targets. The ONE thing that
_is_ shared, deliberately, is the OPSEC per-vendor pacing map (SCALE.3) — two
targets hitting the same vendor are paced as one, so concurrent scans cannot
blow a quota or raise attribution signal by doubling call rate.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from eidolon.core.authorization import Authorization
from eidolon.core.runner import build_raw_input
from eidolon.core.state import ScanState

logger = logging.getLogger(__name__)

#: target dict keys run_batch understands (mirrors run_scan kwargs)
TARGET_KEYS = ("email", "phone", "name", "city", "state", "zip_code", "zip")


def parse_target_line(line: str) -> dict[str, str]:
    """Parse one --targets-file line into a target dict.

    Grammar: ``key:value`` tokens separated by ``;`` (a semicolon, not a space,
    so values may contain spaces). Unknown keys are dropped with a warning
    — a typo must not silently produce a broken target.

    Examples:
      ``email:target@example.com``
      ``name:John Smith;state:CA``
    """
    target: dict[str, str] = {}
    for token in line.split(";"):
        token = token.strip()
        if not token:
            continue
        key, _, value = token.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not key or not value:
            logger.warning("targets-file: dropping malformed token %r", token)
            continue
        if key == "zip":
            key = "zip_code"
        if key not in TARGET_KEYS:
            logger.warning("targets-file: dropping unknown key %r", key)
            continue
        target[key] = value
    return target


def run_batch(
    targets: list[dict[str, str]],
    max_concurrency: int = 3,
    authorization: Authorization | None = None,
) -> list[ScanState]:
    """Scan ``targets`` concurrently under a ``max_concurrency`` pool cap.

    Each dict holds run_scan kwargs (``email`` / ``phone`` / ``name`` /
    ``city`` / ``state`` / ``zip_code``). Returns one independent ``ScanState``
    per target (own run_id, own report path), in input order. A target that
    fails hard raises; per-source failures stay isolated inside its state.

    ``authorization`` covers the whole batch (one operator attestation); each
    target's scan is stamped and audit-logged individually, so the audit trail
    has one entry per identity scanned.
    """
    if not targets:
        return []
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be >= 1")

    from eidolon.core.authorization import record_authorization
    from eidolon.pipeline.graph import build_graph

    graph = build_graph()
    auth = authorization or Authorization.unattested()
    if not auth.is_attested:
        logger.warning(
            "batch running WITHOUT an authorization attestation (recorded as "
            "'unattested' per target)"
        )

    def _one(target: dict[str, Any]) -> ScanState:
        raw_input = build_raw_input(**{k: v for k, v in target.items() if v})
        final = graph.invoke(ScanState(raw_input=raw_input, authorization=auth))
        state = (
            final if isinstance(final, ScanState) else ScanState.model_validate(final)
        )
        record_authorization(
            auth,
            scan_id=state.run_id,
            target=next((c.value for c in state.classifications), ""),
        )
        return state

    logger.info(
        "batch: %d targets, max_concurrency=%d (pacing shared process-wide)",
        len(targets),
        max_concurrency,
    )
    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        return list(pool.map(_one, targets))
