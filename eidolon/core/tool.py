"""BaseTool — the common execution + logging envelope for every tool.

Subclasses implement only ``_execute`` (the actual work, returning the output
data dict). The ``run`` template method — marked ``@final`` so it cannot be
overridden — uniformly handles:

  * TEST_MODE fixture loading
  * the ToolResult envelope (success/error, tool name, input, timestamp)
  * never raising — failures come back as ``ToolResult(success=False, ...)``
  * structured logging bound to the tool name (the run-level context — run_id,
    scan_type, redacted target — is already bound at intake)

This is what makes "log the query, never the results" and the no-raise contract
structural rather than a per-tool convention.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar, Generic, TypeVar, final

import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.core.logging import get_logger
from eidolon.core.models import InputType, ToolResult

TInput = TypeVar("TInput", bound=BaseModel)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"

# Input-model attributes that may hold the primary value, in priority order.
_VALUE_FIELDS = ("value", "email", "phone", "ip", "username", "target", "name", "query")


class BaseTool(ABC, Generic[TInput]):
    #: tool name — also the fixture stem (tests/fixtures/<name>_response.json)
    name: ClassVar[str]
    #: default ToolResult.input_type; override _input_type() for dynamic cases
    input_type: ClassVar[InputType] = "email"

    @final
    def run(self, inp: TInput) -> ToolResult:
        value = self._input_value(inp)
        itype = self._input_type(inp)
        log = get_logger(f"eidolon.tools.{self.name}").bind(tool=self.name)

        if config.is_test_mode():
            return self._load_fixture()

        try:
            data = self._execute(inp, log)
            return ToolResult(
                success=True,
                tool=self.name,
                input_type=itype,
                input_value=value,
                timestamp=datetime.now(timezone.utc),
                data=data,
            )
        except Exception as exc:
            log.error("tool failed", error=str(exc))
            return ToolResult(
                success=False,
                tool=self.name,
                input_type=itype,
                input_value=value,
                timestamp=datetime.now(timezone.utc),
                data={},
                error=f"{self.name} error: {exc}",
            )

    @abstractmethod
    def _execute(self, inp: TInput, log: structlog.stdlib.BoundLogger) -> dict:
        """Do the actual work and return the output data dict (never raise for
        expected failures — return an empty/typed output; raising is caught and
        turned into ToolResult(success=False) by ``run``)."""

    # ── overridable hooks ─────────────────────────────────────────────────────

    def _input_value(self, inp: TInput) -> str:
        for attr in _VALUE_FIELDS:
            v = getattr(inp, attr, None)
            if v:
                return str(v)
        return ""

    def _input_type(self, inp: TInput) -> InputType:
        return self.input_type

    def _load_fixture(self) -> ToolResult:
        raw = json.loads((FIXTURES_DIR / f"{self.name}_response.json").read_text())
        return ToolResult(**raw)
