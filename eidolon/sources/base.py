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

import hashlib
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import ClassVar, Generic, TypeVar, cast

import structlog
from pydantic import BaseModel

from eidolon import __version__, config
from eidolon.core.egress import (
    bind_policy,
    enforce_pacing_for_run,
    resolve_policy,
    unbind_policy,
)
from eidolon.core.findings import Finding, Provenance
from eidolon.core.logging import get_logger
from eidolon.core.state import InputType, SourceResult, ToolResult
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
    #: vendor host for provenance (evidence chain). Single-vendor HTTP tools
    #: set it; "" for offline tools, subprocess tools, and composites that fan
    #: out across many vendors. Host only — never the full URL, so no target
    #: value ever leaks into evidence.
    vendor: ClassVar[str] = ""

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
        log = get_logger(f"eidolon.sources.{self.name}").bind(tool=self.name)
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

    def to_findings(self, out: TOut) -> list[Finding]:
        """Map a typed output to findings about the target. Default: none.

        Override per source. Findings constructed here leave provenance at its
        default — ``collect()`` stamps it once at the boundary so every
        downstream consumer trusts a single provenance home.
        """
        return []

    def run_summary(self, out: TOut) -> str:
        """One-line account of this run, e.g. "3 breaches" or
        "4 profiles / 3155 platforms".

        Facts about the CHECK (how many platforms were probed, the exposure
        score) are not facts about the target, so they ride the SourceResult
        envelope instead of becoming findings. Rendered by the report's
        coverage section verbatim. Empty string = nothing worth a row.
        """
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
        get_logger(f"eidolon.sources.{tool.name}").error("tool failed", error=str(exc))
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


def collect(tool: Tool[TIn, TOut], inp: TIn) -> SourceResult:
    """Run one source and map it into the Finding domain. Never raises.

    THE boundary where a tool run becomes findings (REFACTOR.2): runs the tool
    via ``run_to_result``, re-validates its typed output, maps it with
    ``to_findings``, and stamps ``Provenance`` on every finding — source,
    retrieved_at, status incl. skip reason, tool_version, source_host,
    latency_ms, response_sha256 (sha256 of the typed output, replayable), and
    egress_proxied (from the resolved OPSEC policy).

    A skipped or failed source emits no findings — the SourceResult carries
    the status and reason.
    """
    log = get_logger(f"eidolon.sources.{tool.name}").bind(tool=tool.name)

    # OPSEC.2: resolve and bind egress policy for this tool
    policy = resolve_policy(tool.name)
    policy_token = bind_policy(policy)

    # OPSEC.4: a policy that REQUIRES a proxy and has none means the tool cannot
    # egress compliantly. Return an honest "skipped" — never run it in the clear
    # and never let it read as a successful empty result.
    if policy.require_proxy and not policy.proxy:
        unbind_policy(policy_token)
        return SourceResult(
            name=tool.name,
            status="skipped",
            findings=[],
            detail="egress policy requires a proxy; none configured — skipped",
        )

    # OPSEC.2: enforce per-vendor pacing before the run
    enforce_pacing_for_run(tool.name)

    t0 = time.monotonic()
    result = run_to_result(tool, inp)
    latency_ms = int((time.monotonic() - t0) * 1000)

    # Restore previous policy context
    unbind_policy(policy_token)

    findings: list[Finding] = []
    response_sha256 = ""
    summary = ""
    if result.status == "ok":
        try:
            out = cast(TOut, tool.output_schema.model_validate(result.data))
            response_sha256 = hashlib.sha256(
                out.model_dump_json().encode("utf-8")
            ).hexdigest()
            findings = tool.to_findings(out)
            summary = tool.run_summary(out)
        except Exception as exc:  # mapping must never sink the envelope
            log.error("finding mapping failed", error=str(exc))
            result = result.model_copy(
                update={
                    "success": False,
                    "status": "error",
                    "data": {},
                    "error": f"{tool.name} mapping error: {exc}",
                }
            )
            findings = []

    # egress_proxied is True only when a proxy was configured for this tool
    egress_proxied = bool(policy.proxy)

    provenance = Provenance(
        source=tool.name,
        retrieved_at=result.timestamp,
        status=result.status,
        detail=result.error,
        tool_version=__version__,
        source_host=tool.vendor,
        latency_ms=latency_ms,
        response_sha256=response_sha256,
        egress_proxied=egress_proxied,
    )
    for f in findings:
        f.provenance = provenance.model_copy()

    return SourceResult(
        name=tool.name,
        status=result.status,
        findings=findings,
        detail=result.error,
        summary=summary,
        evidence=provenance,
    )
