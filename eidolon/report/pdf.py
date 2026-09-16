"""PDF layout for a ReportModel (REFACTOR.3).

Dumb renderer: every string of content comes from the model; this module
only decides PDF structure (styles, flowables, tables, page breaks). The
styling (soft palette, bundled Nunito, gentle banners) is carried over from
the legacy renderer so the artifact keeps its look; the legacy copy is
deleted with the old renderer in REFACTOR.6.

Model strings carry light markdown emphasis (``**bold**``, ``_italic_``,
``<https://url>``); ``_rich`` translates exactly those constructs into
reportlab's mini-HTML after XML-escaping — nothing else is interpreted.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from xml.sax.saxutils import escape

from eidolon.report.model import ActionItem, OptOutItem, ReportModel

logger = logging.getLogger(__name__)


def _hex(rgb: tuple) -> str:
    """An rgb float triple as a reportlab font-color hex string."""
    return f"#{int(rgb[0]*255):02x}{int(rgb[1]*255):02x}{int(rgb[2]*255):02x}"


# ── Colour palette (carried over from the legacy renderer) ────────────────────
# Soft, warm, low-saturation tones — a calm briefing, not a pentest printout.
_RED = (0.70, 0.36, 0.31)  # muted clay / terracotta — high risk
_ORANGE = (0.80, 0.58, 0.34)  # soft amber — medium risk
_GREEN = (0.42, 0.56, 0.45)  # muted sage — low risk
_DARK = (0.22, 0.24, 0.29)  # muted slate ink — body text
_MID = (0.46, 0.48, 0.53)  # soft grey — secondary text
_LIGHT = (0.95, 0.95, 0.96)  # warm off-white — dividers / row tint
_ACCENT = (0.36, 0.45, 0.56)  # dusty slate-blue — headings
_BAND = (0.96, 0.96, 0.97)  # gentle header band fill

# ── Soft typeface (bundled Nunito, Helvetica fallback) ────────────────────────

_ASSETS_DIR_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "assets",  # repo root (source)
    Path(__file__).resolve().parents[1] / "assets",  # packaged alongside pkg
]
_ASSETS_DIR = next(
    (c for c in _ASSETS_DIR_CANDIDATES if c.exists()), _ASSETS_DIR_CANDIDATES[0]
)
_FONT_DIR = _ASSETS_DIR / "fonts"
_LOGO_PATH = _ASSETS_DIR / "logo.png"

_FONT_BODY = "Nunito"
_FONT_MEDIUM = "Nunito-SemiBold"
_FONT_BOLD = "Nunito-Bold"

_FONTS_READY: bool = False


def _register_fonts() -> bool:
    """Register the bundled Nunito weights once; fall back to Helvetica."""
    global _FONTS_READY, _FONT_BODY, _FONT_MEDIUM, _FONT_BOLD
    if _FONTS_READY:
        return _FONT_BODY == "Nunito"
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    faces = {
        "Nunito": _FONT_DIR / "Nunito-Regular.ttf",
        "Nunito-SemiBold": _FONT_DIR / "Nunito-SemiBold.ttf",
        "Nunito-Bold": _FONT_DIR / "Nunito-Bold.ttf",
    }
    try:
        if not all(p.exists() for p in faces.values()):
            raise FileNotFoundError("bundled Nunito fonts not found")
        for name, path in faces.items():
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, str(path)))
        _FONTS_READY = True
        return True
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("soft font unavailable, using Helvetica: %s", exc)
        _FONT_BODY, _FONT_MEDIUM, _FONT_BOLD = (
            "Helvetica",
            "Helvetica-Bold",
            "Helvetica-Bold",
        )
        _FONTS_READY = True
        return False


def _risk_colour(level: str) -> tuple:
    lvl = (level or "").lower()
    if lvl == "high":
        return _RED
    if lvl == "medium":
        return _ORANGE
    return _GREEN


_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_ITALIC_RE = re.compile(r"_([^_\n]+)_")
_URL_RE = re.compile(r"&lt;(https?://[^&\s]+)&gt;")


def _rich(text: str) -> str:
    """Escape model text, then translate its light markdown emphasis into
    reportlab's mini-HTML. Nothing else is interpreted."""
    t = escape(str(text or ""))
    t = _URL_RE.sub(r"\1", t)
    t = _BOLD_RE.sub(r"<b>\1</b>", t)
    t = _ITALIC_RE.sub(r"<i>\1</i>", t)
    return t


def render_pdf(model: ReportModel, pdf_path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _register_fonts()

    h = model.header
    ts = h.generated + (f" · run {h.run_id}" if h.run_id else "")
    risk_lvl = h.risk_level or "LOW"
    risk_scr = h.risk_score if h.risk_score is not None else 0
    risk_col = colors.Color(*_risk_colour(risk_lvl))

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    W = A4[0] - 36 * mm  # usable width

    # ── Styles ────────────────────────────────────────────────────────────
    def style(name: str, **kw: object) -> ParagraphStyle:
        base = dict(
            fontName=_FONT_BODY,
            fontSize=10,
            leading=16,
            textColor=colors.Color(*_DARK),
            spaceAfter=3,
        )
        base.update(kw)
        return ParagraphStyle(name, **base)

    S = {
        "h1": style(
            "h1",
            fontName=_FONT_BOLD,
            fontSize=20,
            leading=25,
            textColor=colors.Color(*_ACCENT),
            spaceAfter=3,
        ),
        "meta": style("meta", fontSize=9, leading=14, textColor=colors.Color(*_MID)),
        "h2": style(
            "h2",
            fontName=_FONT_MEDIUM,
            fontSize=13,
            leading=18,
            textColor=colors.Color(*_ACCENT),
            spaceBefore=12,
            spaceAfter=5,
        ),
        "h3": style(
            "h3",
            fontName=_FONT_MEDIUM,
            fontSize=10.5,
            leading=15,
            textColor=colors.Color(*_DARK),
            spaceBefore=7,
            spaceAfter=3,
        ),
        "body": style("body", leading=16),
        "bullet": style("bullet", leftIndent=12, bulletIndent=0, leading=16),
        "check": style(
            "check",
            fontName=_FONT_BODY,
            fontSize=9.5,
            leading=16,
            leftIndent=12,
            textColor=colors.Color(*_DARK),
        ),
        "small": style("small", fontSize=8, leading=12, textColor=colors.Color(*_MID)),
    }

    def hr():
        return HRFlowable(
            width="100%",
            thickness=0.5,
            color=colors.Color(*_LIGHT),
            spaceAfter=8,
            spaceBefore=4,
        )

    def h2(text):
        return Paragraph(text, S["h2"])

    def h3(text):
        return Paragraph(text, S["h3"])

    def body(text):
        return Paragraph(_rich(text), S["body"])

    def bullet(text):
        return Paragraph(f"• &nbsp;{_rich(text)}", S["bullet"])

    def checkbox(text):
        mark = f'<font name="{_FONT_MEDIUM}">[ ]</font>'
        return Paragraph(f"{mark} &nbsp;{_rich(text)}", S["check"])

    def space(h=4):
        return Spacer(1, h * mm)

    def action_block(item: ActionItem) -> list:
        """One findings-context action item as a flowable block."""
        block = [h3(item.name)]
        if item.what_it_is:
            block.append(body(f"**What it is:** {item.what_it_is}"))
        if item.why_it_matters:
            block.append(body(f"**Why it matters:** {item.why_it_matters}"))
        if item.how_to_remove:
            if item.removal_label:
                block.append(body(f"**{item.removal_label}:** {item.how_to_remove}"))
            else:
                block.append(body(f"**Action:** {item.how_to_remove}"))
        block.append(space(2))
        return block

    def optout_line(item: OptOutItem, with_notes: bool = False) -> str:
        if item.url:
            line = f"{item.name}: {item.url} ({item.days} days)"
            if with_notes and item.notes:
                line += f"  _{item.notes}_"
            return line
        return f"{item.name}: see broker's website for opt-out"

    story: list = []

    # ── Header band — logo beside the title, on a gentle tinted panel ─────
    title_cell = [
        Paragraph("Privacy OSINT Report", S["h1"]),
        Paragraph(
            f"Target: <b>{escape(h.target)}</b> &nbsp;·&nbsp; Generated: {ts}",
            S["meta"],
        ),
    ]
    logo_cell: object = ""
    if _LOGO_PATH.exists():
        try:
            logo = Image(str(_LOGO_PATH), width=22 * mm, height=22 * mm)
            logo.hAlign = "CENTER"
            logo_cell = logo
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("logo unavailable: %s", exc)
            logo_cell = ""

    header = Table([[logo_cell, title_cell]], colWidths=[26 * mm, W - 26 * mm])
    header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.Color(*_BAND)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("ROUNDEDCORNERS", [6]),
            ]
        )
    )
    story += [header, space(5)]

    # ── Risk score banner ─────────────────────────────────────────────────
    banner = Table(
        [
            [
                Paragraph(
                    "RISK SCORE",
                    style(
                        "rs_label",
                        fontName=_FONT_MEDIUM,
                        fontSize=8,
                        leading=11,
                        textColor=colors.white,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    f"{risk_scr}/100",
                    style(
                        "rs_score",
                        fontName=_FONT_BOLD,
                        fontSize=22,
                        leading=26,
                        textColor=colors.white,
                        alignment=TA_CENTER,
                    ),
                ),
                Paragraph(
                    risk_lvl,
                    style(
                        "rs_level",
                        fontName=_FONT_MEDIUM,
                        fontSize=14,
                        leading=18,
                        textColor=colors.white,
                        alignment=TA_CENTER,
                    ),
                ),
            ]
        ],
        colWidths=[W * 0.25, W * 0.35, W * 0.40],
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
    story += [banner, space(5)]

    # ── What the internet knows ───────────────────────────────────────────
    if model.summary_narrative or model.known_groups:
        if model.summary_narrative:
            story += [
                h2("What the Internet Knows About You"),
                body(model.summary_narrative),
                space(2),
            ]
        else:
            story += [h2("What the Internet Knows About You")]
        for group in model.known_groups:
            block = [h3(group.title)]
            for item in group.items:
                block.append(bullet(item))
            block.append(space(2))
            story.append(KeepTogether(block))

    # ── Leaked credentials dossier ────────────────────────────────────────
    if model.dossier and model.dossier.groups:
        story += [
            hr(),
            h2("Your Actual Leaked Data"),
            body(model.dossier.intro),
            space(2),
        ]
        for dgroup in model.dossier.groups:
            block = [h3(dgroup.source)] + [
                bullet(rec.display()) for rec in dgroup.records
            ]
            block.append(space(2))
            story.append(KeepTogether(block))

    # ── Top risks ─────────────────────────────────────────────────────────
    if model.top_risks:
        story += [hr(), h2("Top Risks")]
        for risk_item in model.top_risks:
            dot = f'<font color="{_hex(_RED)}">•</font>'
            story.append(Paragraph(f"{dot} &nbsp;{_rich(risk_item)}", S["bullet"]))
        story.append(space(2))

    # ── Threat model (MITRE ATT&CK) ───────────────────────────────────────
    if model.threat and model.threat.techniques:
        story += [
            hr(),
            h2("What Someone Could Do With This"),
            body(model.threat.intro),
            space(2),
        ]
        for tech in model.threat.techniques:
            head = _rich(tech.headline) + (
                f"  ·  {tech.severity}" if tech.severity else ""
            )
            block = [h3(head)]
            if tech.what_it_is:
                block.append(body(f"**What this means:** {tech.what_it_is}"))
            if tech.why_this_finding:
                block.append(
                    body(f"**Why it applies to you:** {tech.why_this_finding}")
                )
            if tech.evidence:
                block.append(body(f"**Based on:** {'; '.join(tech.evidence)}"))
            ref = f"_MITRE reference: {tech.reference}_"
            if tech.url:
                block.append(
                    Paragraph(
                        f"{_rich(ref)} · "
                        f'<a href="{escape(tech.url)}"><u>details</u></a>',
                        S["body"],
                    )
                )
            else:
                block.append(body(ref))
            block.append(space(2))
            story.append(KeepTogether(block))

    # ── AI training pile ──────────────────────────────────────────────────
    if model.training_pile and model.training_pile.properties:
        tp = model.training_pile
        story += [
            hr(),
            h2("Your Content in the AI Training Pile"),
            body(tp.intro),
            space(2),
        ]
        block = [h3(tp.headline)]
        for prop in tp.properties:
            line = f"**{prop.target}** — {prop.capture_count} page capture(s)"
            if prop.sample_url:
                line += f" (e.g. {prop.sample_url})"
            block.append(bullet(line))
        if tp.index_id:
            block.append(body(f"_Common Crawl index: {tp.index_id}_"))
        block.append(space(2))
        story.append(KeepTogether(block))
        opt_out = [
            h3(tp.opt_out_title),
            bullet(tp.opt_out_steps[0]) if tp.opt_out_steps else space(0),
        ]
        for step in tp.opt_out_steps[1:]:
            opt_out.append(bullet(step))
        opt_out.append(body(tp.opt_out_note))
        opt_out.append(space(2))
        story.append(KeepTogether(opt_out))

    # ── Actions (findings context) ────────────────────────────────────────
    if model.actions:
        a = model.actions
        if a.active:
            story += [
                hr(),
                h2("Active Accounts — Take Action"),
                body(a.active_intro),
                space(2),
            ]
            for aitem in a.active:
                story.append(KeepTogether(action_block(aitem)))
        if a.breach_only:
            story += [
                hr(),
                h2("Breach Records — Request Data Deletion"),
                body(a.breach_intro),
                space(2),
            ]
            for aitem in a.breach_only:
                story.append(KeepTogether(action_block(aitem)))
        if a.no_action:
            story += [
                hr(),
                h2("No Action Available"),
                body(a.no_action_intro),
                space(2),
            ]
            for nitem in a.no_action:
                block = [h3(nitem.name)]
                if nitem.why_it_matters:
                    block.append(body(nitem.why_it_matters))
                block.append(space(2))
                story.append(KeepTogether(block))

    # ── What to do (remediation) ──────────────────────────────────────────
    if model.remediation_groups or model.bazzell or model.no_action_items:
        story += [hr(), h2("What To Do")]
        for rgroup in model.remediation_groups:
            block = [h3(rgroup.title)]
            for ritem in rgroup.items:
                block.append(checkbox(ritem))
            block.append(space(2))
            story.append(KeepTogether(block))

        if model.bazzell and (model.bazzell.tier1 or model.bazzell.manual):
            block = [h3("Priority Manual Opt-Outs (Bazzell Tier 1)")]
            if model.bazzell.easyoptouts_covers:
                block.append(
                    body(
                        f"EasyOptOuts.com can automate "
                        f"**{model.bazzell.easyoptouts_covers} of these** — visit "
                        "easyoptouts.com first."
                    )
                )
            for oitem in model.bazzell.tier1:
                block.append(checkbox(optout_line(oitem)))
            block.append(space(2))
            story.append(KeepTogether(block))
            if model.bazzell.manual:
                block = [h3("Additional Manual Opt-Outs (Not Covered by EasyOptOuts)")]
                for oitem in model.bazzell.manual:
                    block.append(checkbox(optout_line(oitem)))
                    if oitem.notes:
                        block.append(Paragraph(f"_{oitem.notes}_", S["small"]))
                block.append(space(2))
                story.append(KeepTogether(block))

        if model.no_action_items:
            block = [h3("No Action Available")]
            for na_item in model.no_action_items:
                dot = f'<font color="{_hex(_MID)}">•</font>'
                block.append(Paragraph(f"{dot} &nbsp;{_rich(na_item)}", S["check"]))
            block.append(space(2))
            story.append(KeepTogether(block))

    # ── Where we looked ───────────────────────────────────────────────────
    if model.coverage and (
        model.coverage.rows or model.coverage.skipped or model.coverage.follow_ups
    ):
        cov = model.coverage
        story += [hr(), h2("Where We Looked")]
        rows: list[tuple[str, str]] = []
        for row in cov.rows:
            value = _rich(row.summary)
            if row.subitems:
                value += "<br/>" + "<br/>".join(
                    f'<font size="8" color="{_hex(_MID)}">· {_rich(s)}</font>'
                    for s in row.subitems
                )
            rows.append((row.label, value))
        if rows:
            tbl = Table(
                [
                    [
                        Paragraph(
                            lbl,
                            style("tc", fontName=_FONT_MEDIUM, fontSize=9, leading=13),
                        ),
                        Paragraph(val, style("tv", fontSize=9, leading=13)),
                    ]
                    for lbl, val in rows
                ],
                colWidths=[W * 0.30, W * 0.70],
            )
            tbl.setStyle(
                TableStyle(
                    [
                        (
                            "ROWBACKGROUNDS",
                            (0, 0),
                            (-1, -1),
                            [colors.Color(*_LIGHT), colors.white],
                        ),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.Color(*_DARK)),
                        ("FONTNAME", (0, 0), (0, -1), _FONT_MEDIUM),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.Color(*_LIGHT)),
                    ]
                )
            )
            story.append(tbl)
        if cov.skipped:
            story.append(space(2))
            story.append(body(f"_{cov.skipped_intro}_"))
            for row in cov.skipped:
                story.append(bullet(f"**{row.label}:** {row.summary}"))
        if cov.follow_ups:
            block = [h3(cov.follow_ups_title)]
            for line in cov.follow_ups:
                block.append(bullet(line))
            block.append(space(2))
            story.append(KeepTogether(block))

    # ── Footer ────────────────────────────────────────────────────────────
    story += [
        space(4),
        Paragraph(
            "Generated by Eidolon · local processing · no data stored", S["small"]
        ),
    ]

    # Every top-level section on its own page: PageBreak before each h2
    # except the first, dropping dividers/spacers that would dangle.
    paged: list = []
    seen_section = False
    for flowable in story:
        if isinstance(flowable, Paragraph) and flowable.style.name == "h2":
            if seen_section:
                while paged and isinstance(paged[-1], (HRFlowable, Spacer)):
                    paged.pop()
                paged.append(PageBreak())
            seen_section = True
        paged.append(flowable)
    story = paged

    doc.build(story)
