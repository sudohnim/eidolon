"""PDF section builders (REFACTOR.6) — one function per report section.

``pdf.py`` is the thin orchestrator (doc setup, page breaks); ``pdf_layout``
holds the shared styles/factories; the response-focused sections (actions,
remediation, coverage) live in ``pdf_sections_actions`` and are re-exported
here so the orchestrator keeps one import surface. Each section function
returns a plain list of reportlab flowables. Nothing here invents or drops
content — every string comes from the model; the renderer-parity test pins
that.
"""

from __future__ import annotations

import logging
from xml.sax.saxutils import escape

from eidolon.report.pdf_layout import (
    _BAND,
    _FONT_BOLD,
    _FONT_MEDIUM,
    _LOGO_PATH,
    _RED,
    PdfLayout,
    _hex,
    _register_fonts,
    _rich,
    _risk_colour,
    build_layout,
)
from eidolon.report.pdf_sections_actions import actions, coverage, footer, remediation
from eidolon.report.sanitize import sanitize_text
from eidolon.report.sections import ReportModel

logger = logging.getLogger(__name__)

__all__ = [
    "PdfLayout",
    "build_layout",
    "_register_fonts",
    "header_band",
    "risk_banner",
    "internet_knows",
    "leaked_dossier",
    "top_risks",
    "threat",
    "training_pile",
    "actions",
    "remediation",
    "coverage",
    "appendices",
    "footer",
]


# ── Per-section flowable builders (each returns a plain list) ─────────────────


def header_band(model: ReportModel, L: PdfLayout) -> list:
    """Logo beside the title, on a gentle tinted panel."""
    from reportlab.platypus import Image, Paragraph, Table, TableStyle

    h = model.header
    ts = h.generated + (f" · run {h.run_id}" if h.run_id else "")
    title_cell = [
        Paragraph("Privacy OSINT Report", L.S["h1"]),
        Paragraph(
            f"Target: <b>{escape(h.target)}</b> &nbsp;·&nbsp; Generated: {ts}",
            L.S["meta"],
        ),
    ]
    logo_cell: object = ""
    if _LOGO_PATH.exists():
        try:
            logo = Image(str(_LOGO_PATH), width=22 * L.mm, height=22 * L.mm)
            logo.hAlign = "CENTER"
            logo_cell = logo
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("logo unavailable: %s", exc)
            logo_cell = ""

    header = Table([[logo_cell, title_cell]], colWidths=[26 * L.mm, L.W - 26 * L.mm])
    header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), L.color.Color(*_BAND)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ROUNDEDCORNERS", [6]),
            ]
        )
    )
    return [header, L.space(5)]


def risk_banner(model: ReportModel, L: PdfLayout) -> list:
    """The top-of-page risk score strip."""
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import Paragraph, Table, TableStyle

    h = model.header
    risk_lvl = h.risk_level or "LOW"
    risk_scr = h.risk_score if h.risk_score is not None else 0
    risk_col = L.color.Color(*_risk_colour(risk_lvl))

    banner = Table(
        [
            [
                Paragraph(
                    "RISK SCORE",
                    L.style(
                        "rs_label",
                        fontName=_FONT_MEDIUM,
                        fontSize=8,
                        leading=11,
                        textColor=L.color.white,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    f"{risk_scr}/100",
                    L.style(
                        "rs_score",
                        fontName=_FONT_BOLD,
                        fontSize=22,
                        leading=26,
                        textColor=L.color.white,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    _rich(risk_lvl),
                    L.style(
                        "rs_level",
                        fontName=_FONT_MEDIUM,
                        fontSize=14,
                        leading=18,
                        textColor=L.color.white,
                        alignment=TA_CENTER,
                    ),
                ),
            ]
        ],
        colWidths=[L.W * 0.25, L.W * 0.35, L.W * 0.40],
    )
    banner.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), risk_col),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ROUNDEDCORNERS", [8]),
            ]
        )
    )
    return [banner, L.space(5)]


def internet_knows(model: ReportModel, L: PdfLayout) -> list:
    """What the internet knows — narrative + known groups."""
    from reportlab.platypus import KeepTogether

    if not (model.summary_narrative or model.known_groups):
        return []
    story = [L.h2("What the Internet Knows About You")]
    if model.summary_narrative:
        story.append(L.body(model.summary_narrative))
    for group in model.known_groups:
        block = [L.h3(group.title)]
        for item in group.items:
            block.append(L.bullet(item))
        block.append(L.space(2))
        story.append(KeepTogether(block))
    return story


def leaked_dossier(model: ReportModel, L: PdfLayout) -> list:
    """The leaked-credentials dossier, grouped by source breach."""
    from reportlab.platypus import KeepTogether

    if not (model.dossier and model.dossier.groups):
        return []
    story = [
        L.hr(),
        L.h2("Your Actual Leaked Data"),
        L.body(model.dossier.intro),
        L.space(2),
    ]
    for dgroup in model.dossier.groups:
        block = [L.h3(dgroup.source)] + [
            L.bullet(rec.display()) for rec in dgroup.records
        ]
        block.append(L.space(2))
        story.append(KeepTogether(block))
    return story


def top_risks(model: ReportModel, L: PdfLayout) -> list:
    from reportlab.platypus import Paragraph

    if not model.top_risks:
        return []
    story = [L.hr(), L.h2("Top Risks")]
    for risk_item in model.top_risks:
        dot = f'<font color="{_hex(_RED)}">•</font>'
        story.append(Paragraph(f"{dot} &nbsp;{_rich(risk_item)}", L.S["bullet"]))
    story.append(L.space(2))
    return story


def threat(model: ReportModel, L: PdfLayout) -> list:
    """Threat model (MITRE ATT&CK)."""
    from reportlab.platypus import KeepTogether, Paragraph

    if not (model.threat and model.threat.techniques):
        return []
    story = [
        L.hr(),
        L.h2("What Someone Could Do With This"),
        L.body(model.threat.intro),
        L.space(2),
    ]
    for tech in model.threat.techniques:
        head = _rich(
            f"{tech.headline}  ·  {tech.severity}" if tech.severity else tech.headline
        )
        block = [L.h3(head)]
        if tech.what_it_is:
            block.append(L.body(f"**What this means:** {tech.what_it_is}"))
        if tech.why_this_finding:
            block.append(L.body(f"**Why it applies to you:** {tech.why_this_finding}"))
        if tech.evidence:
            block.append(L.body(f"**Based on:** {'; '.join(tech.evidence)}"))
        ref = f"_MITRE reference: {tech.reference}_"
        if tech.url:
            block.append(
                Paragraph(
                    f"{_rich(ref)} · "
                    f'<a href="{escape(sanitize_text(tech.url))}"><u>details</u></a>',
                    L.S["body"],
                )
            )
        else:
            block.append(L.body(ref))
        block.append(L.space(2))
        story.append(KeepTogether(block))
    return story


def training_pile(model: ReportModel, L: PdfLayout) -> list:
    """AI training pile section + opt-out steps."""
    from reportlab.platypus import KeepTogether

    if not (model.training_pile and model.training_pile.properties):
        return []
    tp = model.training_pile
    story = [
        L.hr(),
        L.h2("Your Content in the AI Training Pile"),
        L.body(tp.intro),
        L.space(2),
    ]
    block = [L.h3(tp.headline)]
    for prop in tp.properties:
        line = f"**{prop.target}** — {prop.capture_count} page capture(s)"
        if prop.sample_url:
            line += f" (e.g. {prop.sample_url})"
        block.append(L.bullet(line))
    if tp.index_id:
        block.append(L.body(f"_Common Crawl index: {tp.index_id}_"))
    block.append(L.space(2))
    story.append(KeepTogether(block))
    opt_out = [
        L.h3(tp.opt_out_title),
        L.bullet(tp.opt_out_steps[0]) if tp.opt_out_steps else L.space(0),
    ]
    for step in tp.opt_out_steps[1:]:
        opt_out.append(L.bullet(step))
    opt_out.append(L.body(tp.opt_out_note))
    opt_out.append(L.space(2))
    story.append(KeepTogether(opt_out))
    return story


def appendices(model: ReportModel, L: PdfLayout) -> list:
    """Evidence / egress / run-health appendix (operator reference)."""
    from reportlab.platypus import KeepTogether

    ap = model.appendix
    if ap is None or not (ap.evidence or ap.egress or ap.run_health):
        return []
    story = [
        L.hr(),
        L.h2("Evidence, Egress & Run Health"),
        L.body(
            "_Operator reference: what was retrieved, from where, and how this "
            "run reached the network._"
        ),
        L.space(2),
    ]

    if ap.evidence:
        block = [L.h3("Evidence")]
        for evrow in ap.evidence:
            sha = evrow.response_sha256 or "(not run / skipped)"
            proxied = "proxy on" if evrow.egress_proxied else "direct"
            line = (
                f"**{evrow.source}** · {evrow.tool_version or '?'} · "
                f"{evrow.source_host or 'no third-party host'} · "
                f"{evrow.latency_ms}ms · "
                f"sha256:{sha} · {proxied}"
            )
            block.append(L.bullet(line))
        block.append(L.space(2))
        story.append(KeepTogether(block))

    if ap.egress:
        block = [L.h3("Egress Exposure")]
        for egrow in ap.egress:
            flags = []
            flags.append("sees API key" if egrow.logs_api_key else "no API key")
            flags.append("logs source IP" if egrow.logs_source_ip else "no source IP")
            flags.append("third-party" if egrow.third_party else "local-only")
            flags.append("proxied" if egrow.proxied else "direct")
            block.append(L.bullet(f"**{egrow.source}**: {', '.join(flags)}"))
        block.append(L.space(2))
        story.append(KeepTogether(block))

    if ap.run_health:
        health = ap.run_health
        wall = f"{health.wall_time_ms / 1000:.1f}s" if health.wall_time_ms else "n/a"
        story.append(
            L.body(
                f"**Run Health:** ok {health.ok} · skipped {health.skipped} · "
                f"error {health.error} · wall time {wall}"
            )
        )

    return story
