"""Authorization / rules-of-engagement gate (blindspot #1).

An OSINT scan targets a real person. Before one runs, the operator must attest
*who* authorized it and *why*, and that attestation is written to an append-only
audit log. This is the difference between a tool and an operation: every scan is
attributable and nothing runs unlogged.

- The human-facing surfaces (CLI, MCP) REQUIRE an operator + reason and refuse
  without them (see ``main.py`` / ``mcp/server.py``).
- ``run_scan`` (the library primitive) accepts an optional ``Authorization`` so
  internal/test callers still work; when absent it records an ``unattested``
  entry with a warning rather than running silently.
- The audit log never contains scan results or secrets — only the target
  identifier (the same value the operator typed) plus operator/reason/timestamps.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from eidolon import config

logger = logging.getLogger(__name__)

AUDIT_LOG_NAME = "audit.log.jsonl"


class Authorization(BaseModel):
    """An operator's attestation that a scan is authorized."""

    operator: str
    reason: str
    authorized_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("operator", "reason")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("authorization requires a non-empty operator and reason")
        return v

    @classmethod
    def unattested(cls) -> "Authorization":
        """A recorded-but-unattested authorization (library/test callers that
        supplied none). Bypasses the non-empty validator on purpose so the scan
        is still logged rather than running silently off the books."""
        return cls.model_construct(
            operator="unattested",
            reason="no authorization supplied",
            authorized_at=datetime.now(timezone.utc),
        )

    @property
    def is_attested(self) -> bool:
        return self.operator != "unattested"


def record_authorization(auth: Authorization, *, scan_id: str, target: str) -> None:
    """Append one authorization to the append-only audit log.

    Never writes scan results or secrets. No-op in TEST_MODE so the suite does
    not accrete audit files. Best-effort: an audit-write failure is logged, it
    does not sink the scan.
    """
    if config.is_test_mode():
        return
    try:
        out = Path(config.get("RESULTS_OUTPUT_PATH"))
        out.mkdir(parents=True, exist_ok=True)
        entry = {
            "scan_id": scan_id,
            "target": target,
            "operator": auth.operator,
            "reason": auth.reason,
            "attested": auth.is_attested,
            "authorized_at": auth.authorized_at.isoformat(),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        with (out / AUDIT_LOG_NAME).open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:  # audit is best-effort; never sink a scan on it
        logger.warning("could not write authorization audit entry: %s", exc)
