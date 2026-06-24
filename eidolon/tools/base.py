"""The Tool base class — a typed pydantic-in / pydantic-out contract.

Every tool declares:
  * ``name``           — also the fixture stem (tests/fixtures/<name>_response.json)
  * ``input_schema``   — pydantic model validating the input
  * ``output_schema``  — pydantic model the result is validated against
  * ``_run()``         — the actual work, returning an ``output_schema`` instance

``run(inp) -> output_schema`` is the clean public contract: import the class and
call it. It handles TEST_MODE fixtures and short-circuits to an empty output when
the tool isn't configured (``available()`` is False).

The pipeline wants an execution envelope (success/error/metadata), so nodes call
``run_to_result(tool, inp) -> ToolResult`` — the single boundary adapter that
turns the typed output into a ToolResult and never raises.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import ClassVar, Generic, TypeVar

import structlog
from pydantic import BaseModel

from eidolon import config
from eidolon.core.logging import get_logger
from eidolon.core.models import InputType, ToolResult
from eidolon.utils import load_fixture

TIn = TypeVar("TIn", bound=BaseModel)
TOut = TypeVar("TOut", bound=BaseModel)

# Input-schema attributes that may hold the primary value, in priority order.
_VALUE_FIELDS = ("value", "email", "phone", "ip", "username", "target", "name", "query")


class Tool(ABC, Generic[TIn, TOut]):
    #: tool name — also the fixture stem (tests/fixtures/<name>_response.json)
    name: ClassVar[str]
    #: pydantic schema for the input
    input_schema: ClassVar[type[BaseModel]]
    #: pydantic schema the output is validated against
    output_schema: ClassVar[type[BaseModel]]
    #: default ToolResult.input_type; override _input_type() for dynamic cases
    input_type: ClassVar[InputType] = "email"
    #: env vars this tool needs to run (e.g. ["HIBP_API_KEY"]). Drives both the
    #: default availability check and the user-facing "skipped" message.
    requires: ClassVar[list[str]] = []

    def available(self) -> bool:
        """Whether the tool is configured to run. Default: every var in
        ``requires`` is set. Override for custom logic (e.g. multiple keys)."""
        return all(config.get(k) for k in self.requires)

    def skip_reason(self) -> str:
        """Human-readable reason the tool was skipped (which keys are missing)."""
        missing = [k for k in self.requires if not config.get(k)]
        if missing:
            return "not checked — set " + ", ".join(missing)
        return "not checked — not configured"

    @abstractmethod
    def _run(self, inp: TIn, log: structlog.stdlib.BoundLogger) -> TOut:
        """Do the work and return an ``output_schema`` instance. Raise on failure;
        ``run_to_result`` turns the exception into ToolResult(success=False)."""
        raise NotImplementedError

    def run(self, inp: TIn) -> TOut:
        log = get_logger(f"eidolon.tools.{self.name}").bind(tool=self.name)
        if config.is_test_mode():
            out = self.output_schema.model_validate(load_fixture(self.name))
            return out  # type: ignore[return-value]
        if not self.available():
            log.info("skipped — not configured")
            return self.output_schema()  # type: ignore[return-value]
        return self._run(inp, log)

    # ── overridable hooks (used by run_to_result for the envelope) ────────────

    def _input_type(self, inp: TIn) -> InputType:
        return self.input_type

    def _input_value(self, inp: TIn) -> str:
        for attr in _VALUE_FIELDS:
            v = getattr(inp, attr, None)
            if v:
                return str(v)
        return ""


def run_to_result(tool: Tool[TIn, TOut], inp: TIn) -> ToolResult:
    """Run a tool and wrap its typed output in the pipeline's ToolResult envelope.
    Never raises — failures come back as ToolResult(success=False, ...)."""
    ts = datetime.now(timezone.utc)
    itype = tool._input_type(inp)
    ivalue = tool._input_value(inp)
    # "not configured" is a distinct, visible state — never let a missing key
    # masquerade as "ran and found nothing". (TEST_MODE always runs via fixtures.)
    if not config.is_test_mode() and not tool.available():
        return ToolResult(
            success=True,
            status="skipped",
            tool=tool.name,
            input_type=itype,
            input_value=ivalue,
            timestamp=ts,
            data={},
            error=tool.skip_reason(),
        )
    try:
        out = tool.run(inp)
        return ToolResult(
            success=True,
            status="ok",
            tool=tool.name,
            input_type=itype,
            input_value=ivalue,
            timestamp=ts,
            data=out.model_dump(),
        )
    except Exception as exc:
        get_logger(f"eidolon.tools.{tool.name}").error("tool failed", error=str(exc))
        return ToolResult(
            success=False,
            status="error",
            tool=tool.name,
            input_type=itype,
            input_value=ivalue,
            timestamp=ts,
            data={},
            error=f"{tool.name} error: {exc}",
        )
