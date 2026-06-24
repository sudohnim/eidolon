"""Eidolon MCP server (Phase 1 — stateless).

Exposes a *small* high-level surface over the same `run_scan` core the CLI uses,
so any MCP client (Claude Desktop / Code, or a local-model agent) can drive a
scan and read results. No database: reads go through the report repository, which
today is files and tomorrow is Postgres — the tool contract won't change.

Privacy posture — redact by default:
  - ``scan_target`` / ``get_report`` never include the plaintext-password dossier.
  - ``reveal_credentials`` is the explicit, separate gate that returns it.
So the sensitive data only crosses to the LLM client when deliberately requested.

Transport: stdio (``python -m eidolon.mcp``). The same image can later serve
HTTP for the managed/background tier without changing these tools.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from eidolon.core import repository, runner

mcp = FastMCP("eidolon")


@mcp.tool()
def scan_target(
    email: str | None = None,
    phone: str | None = None,
    name: str | None = None,
    city: str | None = None,
    state: str | None = None,
    zip_code: str | None = None,
) -> dict:
    """Run a full privacy-OSINT scan on a target and return its headline result.

    Provide at least one of email / phone / name (name works best with a
    location). Returns scan_id, risk score/level, an identity summary, top risks,
    and report paths. Does NOT include leaked credentials — use
    reveal_credentials(scan_id) for those. Blocks for several minutes while the
    scan runs.
    """
    result = runner.run_scan(
        email=email,
        phone=phone,
        name=name,
        city=city,
        state=state,
        zip_code=zip_code,
    )
    return result.model_dump()


@mcp.tool()
def list_scans() -> list[dict]:
    """List previously run scans (newest first): scan_id, identifier, date, paths."""
    return [ref.model_dump() for ref in repository.list_scans()]


@mcp.tool()
def get_report(scan_id: str, fmt: str = "md") -> str:
    """Return a scan's report. ``fmt`` is 'md' (default) or 'json'.

    The markdown is returned with the leaked-credentials section removed; call
    reveal_credentials(scan_id) to see those.
    """
    content = repository.get_report(scan_id, fmt)
    if fmt == "md":
        return _strip_dossier(content)
    return content


@mcp.tool()
def reveal_credentials(scan_id: str) -> str:
    """Return the leaked-credentials dossier for a scan (plaintext passwords).

    This is the explicit gate for the most sensitive output — only call it when
    the user has clearly asked to see the actual leaked credentials.
    """
    from eidolon.agent.report import _dossier_lines
    from eidolon.core.models import PipelineState

    state = PipelineState.model_validate(repository.load_scan_state(scan_id))
    lines = _dossier_lines(state)
    if not lines:
        return f"No leaked credentials on record for scan {scan_id}."
    return "\n".join(lines)


def _strip_dossier(md: str) -> str:
    """Remove the leaked-data dossier section from a rendered markdown report.

    Keep this heading in sync with report.py's dossier heading.
    """
    lines = md.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.strip() == "## Your Actual Leaked Data"),
        None,
    )
    if start is None:
        return md
    # absorb the '---' separator that precedes the heading
    cut = start
    j = start - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j >= 0 and lines[j].strip() == "---":
        cut = j
    # the section runs until the next H2
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    notice = [
        "",
        "_Leaked credentials hidden. Call reveal_credentials(scan_id) to view._",
        "",
    ]
    return "\n".join(lines[:cut] + notice + lines[end:])
