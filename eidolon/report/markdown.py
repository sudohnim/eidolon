"""Markdown layout for a ReportModel (REFACTOR.3).

Dumb renderer: every string of content comes from the model; this module
only decides markdown structure (headings, bullets, checkboxes, rules).
"""

from __future__ import annotations

from eidolon.report.model import ActionItem, OptOutItem, ReportModel


def render_markdown(model: ReportModel) -> str:
    lines: list[str] = []
    h = model.header

    # ── Header ────────────────────────────────────────────────────────────
    risk = f"{h.risk_score}/100 — {h.risk_level}" if h.risk_score is not None else "N/A"
    lines += [
        "# Privacy OSINT Report",
        "",
        f"**Generated:** {h.generated} (run {h.run_id})",
        f"**Target:** {h.target}",
        f"**Risk Score:** {risk}",
        "",
    ]

    # ── What the internet knows ───────────────────────────────────────────
    if model.summary_narrative or model.known_groups:
        lines += ["---", "", "## What the Internet Knows About You", ""]
        if model.summary_narrative:
            lines += [model.summary_narrative, ""]
        for group in model.known_groups:
            lines += [f"### {group.title}", ""]
            for item in group.items:
                lines.append(f"- {item}")
            lines.append("")

    # ── Leaked credentials dossier ────────────────────────────────────────
    if model.dossier and model.dossier.groups:
        lines += ["---", "", "## Your Actual Leaked Data", "", model.dossier.intro, ""]
        for dgroup in model.dossier.groups:
            lines += (
                [f"### {dgroup.source}", ""]
                + [f"- {rec.display()}" for rec in dgroup.records]
                + [""]
            )

    # ── Top risks ─────────────────────────────────────────────────────────
    if model.top_risks:
        lines += ["---", "", "## Top Risks", ""]
        for risk_item in model.top_risks:
            lines.append(f"- {risk_item}")
        lines.append("")

    # ── Threat model (MITRE ATT&CK) ───────────────────────────────────────
    if model.threat and model.threat.techniques:
        t = model.threat
        lines += ["---", "", "## What Someone Could Do With This", "", t.intro, ""]
        for tech in t.techniques:
            title = tech.headline + (f"  ·  {tech.severity}" if tech.severity else "")
            lines += [f"### {title}", ""]
            if tech.what_it_is:
                lines.append(f"**What this means:** {tech.what_it_is}  ")
            if tech.why_this_finding:
                lines.append(f"**Why it applies to you:** {tech.why_this_finding}  ")
            if tech.evidence:
                lines.append(f"**Based on:** {'; '.join(tech.evidence)}  ")
            ref_line = f"_MITRE reference: {tech.reference}_"
            lines.append(
                f"{ref_line} · [details]({tech.url})" if tech.url else f"{ref_line}  "
            )
            lines.append("")

    # ── AI training pile ──────────────────────────────────────────────────
    if model.training_pile and model.training_pile.properties:
        tp = model.training_pile
        lines += [
            "---",
            "",
            "## Your Content in the AI Training Pile",
            "",
            f"_{tp.intro}_",
            "",
        ]
        lines += [tp.headline, ""]
        for prop in tp.properties:
            line = f"- **{prop.target}** — {prop.capture_count} page capture(s)"
            if prop.sample_url:
                line += f" (e.g. {prop.sample_url})"
            lines.append(line)
        lines += ["", f"### {tp.opt_out_title}", ""]
        for step in tp.opt_out_steps:
            lines.append(f"- {step}")
        lines += [f"- {tp.opt_out_note}", ""]

    # ── Actions (findings context) ────────────────────────────────────────
    if model.actions:
        a = model.actions
        if a.active:
            lines += ["---", "", "## Active Accounts — Take Action", ""]
            lines += [f"_{a.active_intro}_", ""]
            lines += _action_items(a.active)
        if a.breach_only:
            lines += ["---", "", "## Breach Records — Request Data Deletion", ""]
            lines += [f"_{a.breach_intro}_", ""]
            lines += _action_items(a.breach_only)
        if a.no_action:
            lines += ["---", "", "## No Action Available", ""]
            lines += [f"_{a.no_action_intro}_", ""]
            for nitem in a.no_action:
                lines += [f"### {nitem.name}", ""]
                if nitem.why_it_matters:
                    lines.append(f"{nitem.why_it_matters}")
                lines.append("")

    # ── What to do (remediation) ──────────────────────────────────────────
    if model.remediation_groups or model.bazzell or model.no_action_items:
        lines += ["---", "", "## What To Do", ""]
        for rgroup in model.remediation_groups:
            lines += [f"### {rgroup.title}", ""]
            for ritem in rgroup.items:
                lines.append(f"- [ ] {ritem}")
            lines.append("")

        if model.bazzell and (model.bazzell.tier1 or model.bazzell.manual):
            lines += ["### Priority Manual Opt-Outs (Bazzell Tier 1)", ""]
            if model.bazzell.easyoptouts_covers:
                lines.append(
                    f"_EasyOptOuts.com can automate "
                    f"{model.bazzell.easyoptouts_covers} of these — visit "
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
                lines.append(f"- ℹ️ {na_item}")
            lines.append("")

    # ── Where we looked ───────────────────────────────────────────────────
    if model.coverage and (
        model.coverage.rows or model.coverage.skipped or model.coverage.follow_ups
    ):
        lines += ["---", "", "## Where We Looked", ""]
        for row in model.coverage.rows:
            lines.append(f"- **{row.label}:** {row.summary}")
            for sub in row.subitems:
                lines.append(f"  - {sub}")
        if model.coverage.skipped:
            lines += ["", f"_{model.coverage.skipped_intro}_", ""]
            for row in model.coverage.skipped:
                lines.append(f"- **{row.label}:** {row.summary}")
        if model.coverage.follow_ups:
            lines += ["", f"### {model.coverage.follow_ups_title}"]
            for line in model.coverage.follow_ups:
                lines.append(f"- {line}")

    # ── Tail ──────────────────────────────────────────────────────────────
    if model.header.results_json_path:
        lines += ["", f"Full results: `{model.header.results_json_path}`"]

    return "\n".join(lines)


def _action_items(items: list[ActionItem]) -> list[str]:
    out: list[str] = []
    for item in items:
        out += [f"### {item.name}", ""]
        if item.what_it_is:
            out.append(f"**What it is:** {item.what_it_is}  ")
        if item.why_it_matters:
            out.append(f"**Why it matters:** {item.why_it_matters}  ")
        if item.how_to_remove:
            if item.removal_label:
                out.append(f"**{item.removal_label}:** {item.how_to_remove}")
            else:
                out.append(f"**Action:** {item.how_to_remove}")
        out.append("")
    return out


def _optout_line(item: OptOutItem, with_notes: bool = False) -> str:
    if item.url:
        line = f"- [ ] {item.name}: {item.url} ({item.days} days)"
        if with_notes and item.notes:
            line += f"  \n  _{item.notes}_"
        return line
    return f"- [ ] {item.name}: see broker's website for opt-out"
