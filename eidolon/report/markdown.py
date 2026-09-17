"""Markdown layout for a ReportModel (REFACTOR.3).

Dumb renderer: every string of content comes from the model; this module
only decides markdown structure (headings, bullets, checkboxes, rules).

HARDEN.3 — every model string crosses the sanitizer (``report.sanitize``)
before layout, so hostile LLM content can't forge sections, inject control
bytes, or open code fences mid-report.
"""

from __future__ import annotations

from eidolon.report.model import ActionItem, OptOutItem, ReportModel
from eidolon.report.sanitize import sanitize_inline, sanitize_text, sanitize_url

_t = sanitize_text  # paragraph slots (keep newlines)
_i = sanitize_inline  # single-line slots (titles, bullets, items)
_u = sanitize_url  # link targets


def render_markdown(model: ReportModel) -> str:
    lines: list[str] = []
    h = model.header

    # ── Header ────────────────────────────────────────────────────────────
    risk = (
        f"{h.risk_score}/100 — {_i(h.risk_level)}"
        if h.risk_score is not None
        else "N/A"
    )
    lines += [
        "# Privacy OSINT Report",
        "",
        f"**Generated:** {_i(h.generated)} (run {_i(h.run_id)})",
        f"**Target:** {_i(h.target)}",
        f"**Risk Score:** {risk}",
        "",
    ]

    # ── What the internet knows ───────────────────────────────────────────
    if model.summary_narrative or model.known_groups:
        lines += ["---", "", "## What the Internet Knows About You", ""]
        if model.summary_narrative:
            lines += [_t(model.summary_narrative), ""]
        for group in model.known_groups:
            lines += [f"### {_i(group.title)}", ""]
            for item in group.items:
                lines.append(f"- {_i(item)}")
            lines.append("")

    # ── Leaked credentials dossier ────────────────────────────────────────
    if model.dossier and model.dossier.groups:
        lines += [
            "---",
            "",
            "## Your Actual Leaked Data",
            "",
            _t(model.dossier.intro),
            "",
        ]
        for dgroup in model.dossier.groups:
            lines += (
                [f"### {_i(dgroup.source)}", ""]
                + [f"- {_i(rec.display())}" for rec in dgroup.records]
                + [""]
            )

    # ── Top risks ─────────────────────────────────────────────────────────
    if model.top_risks:
        lines += ["---", "", "## Top Risks", ""]
        for risk_item in model.top_risks:
            lines.append(f"- {_i(risk_item)}")
        lines.append("")

    # ── Threat model (MITRE ATT&CK) ───────────────────────────────────────
    if model.threat and model.threat.techniques:
        t = model.threat
        lines += ["---", "", "## What Someone Could Do With This", "", _t(t.intro), ""]
        for tech in t.techniques:
            title = _i(tech.headline) + (
                f"  ·  {_i(tech.severity)}" if tech.severity else ""
            )
            lines += [f"### {_i(title)}", ""]
            if tech.what_it_is:
                lines.append(f"**What this means:** {_i(tech.what_it_is)}  ")
            if tech.why_this_finding:
                lines.append(
                    f"**Why it applies to you:** {_i(tech.why_this_finding)}  "
                )
            if tech.evidence:
                lines.append(
                    f"**Based on:** {'; '.join(_i(e) for e in tech.evidence)}  "
                )
            ref_line = f"_MITRE reference: {_i(tech.reference)}_"
            url = _u(tech.url)
            lines.append(f"{ref_line} · [details]({url})" if url else f"{ref_line}  ")
            lines.append("")

    # ── AI training pile ──────────────────────────────────────────────────
    if model.training_pile and model.training_pile.properties:
        tp = model.training_pile
        lines += [
            "---",
            "",
            "## Your Content in the AI Training Pile",
            "",
            f"_{_t(tp.intro)}_",
            "",
        ]
        lines += [_t(tp.headline), ""]
        for prop in tp.properties:
            line = (
                f"- **{_i(prop.target)}** — "
                f"{_i(str(prop.capture_count))} page capture(s)"
            )
            url = _u(prop.sample_url)
            if url:
                line += f" (e.g. {url})"
            lines.append(line)
        lines += ["", f"### {_i(tp.opt_out_title)}", ""]
        for step in tp.opt_out_steps:
            lines.append(f"- {_i(step)}")
        lines += [f"- {_i(tp.opt_out_note)}", ""]

    # ── Actions (findings context) ────────────────────────────────────────
    if model.actions:
        a = model.actions
        if a.active:
            lines += ["---", "", "## Active Accounts — Take Action", ""]
            lines += [f"_{_t(a.active_intro)}_", ""]
            lines += _action_items(a.active)
        if a.breach_only:
            lines += ["---", "", "## Breach Records — Request Data Deletion", ""]
            lines += [f"_{_t(a.breach_intro)}_", ""]
            lines += _action_items(a.breach_only)
        if a.no_action:
            lines += ["---", "", "## No Action Available", ""]
            lines += [f"_{_t(a.no_action_intro)}_", ""]
            for nitem in a.no_action:
                lines += [f"### {_i(nitem.name)}", ""]
                if nitem.why_it_matters:
                    lines.append(_t(nitem.why_it_matters))
                lines.append("")

    # ── What to do (remediation) ──────────────────────────────────────────
    if model.remediation_groups or model.bazzell or model.no_action_items:
        lines += ["---", "", "## What To Do", ""]
        for rgroup in model.remediation_groups:
            lines += [f"### {_i(rgroup.title)}", ""]
            for ritem in rgroup.items:
                lines.append(f"- [ ] {_i(ritem)}")
            lines.append("")

        if model.bazzell and (model.bazzell.tier1 or model.bazzell.manual):
            lines += ["### Priority Manual Opt-Outs (Bazzell Tier 1)", ""]
            if model.bazzell.easyoptouts_covers:
                lines.append(
                    f"_EasyOptOuts.com can automate "
                    f"{_i(model.bazzell.easyoptouts_covers)} of these — visit "
                    "<https://easyoptouts.com> first._"
                )
                lines.append("")
            for oitem in model.bazzell.tier1:
                lines.append(_optout_line(oitem))
            lines.append("")
            if model.bazzell.manual:
                lines += [
                    "### Additional Manual Opt-Outs (Not Covered by EasyOptOuts)",
                    "",
                ]
                for oitem in model.bazzell.manual:
                    lines.append(_optout_line(oitem, with_notes=True))
                lines.append("")

        if model.no_action_items:
            lines += ["### No Action Available", ""]
            for na_item in model.no_action_items:
                lines.append(f"- ℹ️ {_i(na_item)}")
            lines.append("")

    # ── Where we looked ───────────────────────────────────────────────────
    if model.coverage and (
        model.coverage.rows or model.coverage.skipped or model.coverage.follow_ups
    ):
        lines += ["---", "", "## Where We Looked", ""]
        for row in model.coverage.rows:
            lines.append(f"- **{_i(row.label)}:** {_i(row.summary)}")
            for sub in row.subitems:
                lines.append(f"  - {_i(sub)}")
        if model.coverage.skipped:
            lines += ["", f"_{_t(model.coverage.skipped_intro)}_", ""]
            for row in model.coverage.skipped:
                lines.append(f"- **{_i(row.label)}:** {_i(row.summary)}")
        if model.coverage.follow_ups:
            lines += ["", f"### {_i(model.coverage.follow_ups_title)}"]
            for line in model.coverage.follow_ups:
                lines.append(f"- {_i(line)}")

    # ── Tail ──────────────────────────────────────────────────────────────
    if model.header.results_json_path:
        lines += ["", f"Full results: `{_i(model.header.results_json_path)}`"]

    # ── Evidence, Egress & Run Health appendix ────────────────────────────
    if model.appendix and (
        model.appendix.evidence or model.appendix.egress or model.appendix.run_health
    ):
        ap = model.appendix
        lines += [
            "",
            "---",
            "",
            "## Evidence, Egress & Run Health",
            "",
            "_Operator reference: what was retrieved, from where, and how "
            "this run reached the network. Latest official copies of the data "
            "below can be pulled via the MCP `get_evidence` tool._",
            "",
        ]
        if ap.evidence:
            lines += ["### Evidence", ""]
            for evrow in ap.evidence:
                sha = _i(evrow.response_sha256 or "(_not run / skipped_)")
                proxied = "proxy on" if evrow.egress_proxied else "direct"
                parts = [
                    f"**{_i(evrow.source)}**",
                    _i(evrow.tool_version or "?"),
                    _i(evrow.source_host or "no third-party host"),
                    f"{_i(str(evrow.latency_ms))}ms",
                    f"`sha256:{sha}`",
                    proxied,
                ]
                lines.append(f"- {' · '.join(parts)}")
            lines.append("")
        if ap.egress:
            lines += ["### Egress Exposure", ""]
            for egrow in ap.egress:
                flags = []
                if egrow.logs_api_key:
                    flags.append("sees API key")
                else:
                    flags.append("no API key")
                if egrow.logs_source_ip:
                    flags.append("logs source IP")
                else:
                    flags.append("no source IP")
                flags.append("third-party" if egrow.third_party else "local-only")
                flags.append("proxied" if egrow.proxied else "direct")
                lines.append(f"- **{_i(egrow.source)}**: {', '.join(flags)}")
            lines.append("")
        if ap.run_health:
            health = ap.run_health
            wall = (
                f"{health.wall_time_ms / 1000:.1f}s" if health.wall_time_ms else "n/a"
            )
            lines += [
                "### Run Health",
                "",
                f"- ok: {health.ok} · skipped: {health.skipped} · "
                f"error: {health.error} · wall time: {wall}",
                "",
            ]

    return "\n".join(lines)


def _action_items(items: list[ActionItem]) -> list[str]:
    out: list[str] = []
    for item in items:
        out += [f"### {_i(item.name)}", ""]
        if item.what_it_is:
            out.append(f"**What it is:** {_i(item.what_it_is)}  ")
        if item.why_it_matters:
            out.append(f"**Why it matters:** {_i(item.why_it_matters)}  ")
        if item.how_to_remove:
            if item.removal_label:
                out.append(f"**{_i(item.removal_label)}:** {_i(item.how_to_remove)}")
            else:
                out.append(f"**Action:** {_i(item.how_to_remove)}")
        out.append("")
    return out


def _optout_line(item: OptOutItem, with_notes: bool = False) -> str:
    url = _u(item.url)
    if url:
        line = f"- [ ] {_i(item.name)}: {url} ({_i(str(item.days))} days)"
        if with_notes and item.notes:
            line += f"  \n  _{_i(item.notes)}_"
        return line
    return f"- [ ] {_i(item.name)}: see broker's website for opt-out"
