"""Structured logging for the OSINT pipeline.

structlog is configured to render both structlog and stdlib `logging` records
through one pipeline, so existing ``logging.getLogger(__name__)`` calls keep
working and automatically pick up the bound run context.

Run context (run_id, scan_type, redacted target) is bound once at intake via
``bind_run_context`` and then appears on every subsequent log line for the run.

Privacy: the target identifier is NEVER bound in full. ``redact`` reduces it to
a non-identifying hint (``r***@gmail.com``, ``***4567``) so logs stay traceable
without spilling the PII the tool exists to protect.
"""

from __future__ import annotations

import logging
import sys

import structlog


def redact(value: str, kind: str = "") -> str:
    """Reduce a target identifier to a non-identifying hint for logs."""
    v = str(value or "").strip()
    if not v:
        return ""
    if kind == "phone":
        digits = "".join(c for c in v if c.isdigit())
        return f"***{digits[-4:]}" if len(digits) >= 4 else "***"
    if "@" in v and kind in ("email", ""):
        local, _, domain = v.partition("@")
        head = local[0] if local else ""
        return f"{head}***@{domain}"
    # name / org / fallback — keep only the first character
    return f"{v[0]}***"


# Processors shared by structlog-native and stdlib-routed records.
_SHARED_PROCESSORS: list = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),  # interpolate %s-style calls
    structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
]


def configure_logging(level: int = logging.INFO) -> None:
    """Configure structlog + stdlib so all log records share one renderer and
    pick up the bound run context. Idempotent — safe to call once at startup."""
    structlog.configure(
        processors=_SHARED_PROCESSORS
        + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=_SHARED_PROCESSORS,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
    )
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)


def bind_run_context(**kwargs: object) -> None:
    """Bind key/values onto the context for every subsequent log line this run."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_run_context() -> None:
    structlog.contextvars.clear_contextvars()
