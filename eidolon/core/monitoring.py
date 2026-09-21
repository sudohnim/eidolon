"""Run-to-run monitoring: what changed since the last scan of this target.

OSINT value compounds over time — "you are in 14 breaches" is a snapshot, "2 of
those are new since March" is intelligence. ``dedup_key`` was designed as the
stable identity of a fact across scans, and this module is what finally uses it:
match the current findings against the previous scan's by key, carry ``first_seen``
forward, and report what appeared and what disappeared.

Reading the prior scan goes through the repository (files today, a database
later), so nothing here knows how scans are stored.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from eidolon.core.findings import Finding
from eidolon.core.state import ScanDiff

logger = logging.getLogger(__name__)


def previous_findings(identifier: str, exclude_run_id: str) -> list[Finding]:
    """Findings from the most recent earlier scan of the same target.

    Returns [] when this is the first scan of the target, when the prior
    artifact is unreadable, or when anything else goes wrong — monitoring is
    additive and must never sink a scan.
    """
    if not identifier:
        return []
    try:
        from eidolon.core import repository

        prior = [
            ref
            for ref in repository.list_scans()
            if ref.identifier == identifier and ref.scan_id != exclude_run_id
        ]
        if not prior:
            return []
        # list_scans is newest-first, so the first match is the previous scan
        data = repository.load_scan_state(prior[0].scan_id)
        raw = data.get("findings") or []
        out: list[Finding] = []
        for item in raw:
            try:
                out.append(Finding.model_validate(item))
            except Exception:  # a single malformed finding must not sink the diff
                continue
        logger.info(
            "monitoring: previous scan %s had %d findings", prior[0].scan_id, len(out)
        )
        return out
    except Exception as exc:
        logger.warning("monitoring: could not load previous scan — %s", exc)
        return []


def apply_temporal(
    previous: list[Finding], current: list[Finding], now: datetime | None = None
) -> ScanDiff:
    """Stamp ``first_seen``/``last_seen`` on ``current`` (in place) and diff.

    A fact seen before keeps its original ``first_seen`` — that is the age of
    the exposure, the number an analyst actually wants. A fact present last time
    and absent now is reported as resolved, not silently dropped.
    """
    ts = now or datetime.now(timezone.utc)
    if not previous:
        # First scan of this target: stamp the baseline, but report no changes —
        # "everything is new" is noise, and compared=False already says why.
        for f in current:
            f.first_seen = f.first_seen or ts
            f.last_seen = ts
        return ScanDiff(compared=False, unchanged_count=len(current))
    prev_by_key = {f.dedup_key: f for f in previous if f.dedup_key}

    new_keys: list[str] = []
    for f in current:
        prior = prev_by_key.get(f.dedup_key)
        f.first_seen = (prior.first_seen if prior and prior.first_seen else None) or ts
        f.last_seen = ts
        if prior is None:
            new_keys.append(f.dedup_key)

    current_keys = {f.dedup_key for f in current}
    resolved = [
        f.title or f.dedup_key
        for f in previous
        if f.dedup_key and f.dedup_key not in current_keys
    ]
    new_titles = [
        f.title or f.dedup_key for f in current if f.dedup_key in set(new_keys)
    ]
    return ScanDiff(
        compared=bool(previous),
        new_findings=new_titles,
        resolved_findings=resolved,
        unchanged_count=len(current) - len(new_titles),
    )
