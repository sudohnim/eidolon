"""PDF "action" section builders (REFACTOR.6).

The response-focused report sections — things to do, and where we looked —
in a separate module so no PDF file exceeds ~400 LOC. ``pdf_sections``
re-exports these so the ``pdf`` orchestrator keeps one import surface.
"""

from __future__ import annotations

from eidolon.report.pdf_layout import (
    _DARK,
    _FONT_MEDIUM,
    _LIGHT,
    _MID,
    PdfLayout,
    _hex,
    _rich,
)
from eidolon.report.sections import ReportModel

__all__ = ["actions", "remediation", "coverage", "footer"]


def actions(model: ReportModel, L: PdfLayout) -> list:
    """findings-context action items, split active / breach-only / none."""
    from reportlab.platypus import KeepTogether

    if not model.actions:
        return []
    a = model.actions
    story: list = []
    if a.active:
        story += [
            L.hr(),
            L.h2("Active Accounts — Take Action"),
            L.body(a.active_intro),
            L.space(2),
        ]
        for aitem in a.active:
            story.append(KeepTogether(L.action_block(aitem)))
    if a.breach_only:
        story += [
            L.hr(),
            L.h2("Breach Records — Request Data Deletion"),
            L.body(a.breach_intro),
            L.space(2),
        ]
        for aitem in a.breach_only:
            story.append(KeepTogether(L.action_block(aitem)))
    if a.no_action:
        story += [
            L.hr(),
            L.h2("No Action Available"),
            L.body(a.no_action_intro),
            L.space(2),
        ]
        for nitem in a.no_action:
            block = [L.h3(nitem.name)]
            if nitem.why_it_matters:
                block.append(L.body(nitem.why_it_matters))
            block.append(L.space(2))
            story.append(KeepTogether(block))
    return story


def remediation(model: ReportModel, L: PdfLayout) -> list:
    """What To Do — groups, Bazzell opt-outs, no-action items."""
    from reportlab.platypus import KeepTogether, Paragraph

    if not (model.remediation_groups or model.bazzell or model.no_action_items):
        return []
    story = [L.hr(), L.h2("What To Do")]
    for rgroup in model.remediation_groups:
        block = [L.h3(rgroup.title)]
        for ritem in rgroup.items:
            block.append(L.checkbox(ritem))
        block.append(L.space(2))
        story.append(KeepTogether(block))

    if model.bazzell and (model.bazzell.tier1 or model.bazzell.manual):
        block = [L.h3("Priority Manual Opt-Outs (Bazzell Tier 1)")]
        if model.bazzell.easyoptouts_covers:
            block.append(
                L.body(
                    f"EasyOptOuts.com can automate "
                    f"**{model.bazzell.easyoptouts_covers} of these** — visit "
                    "easyoptouts.com first."
                )
            )
        for oitem in model.bazzell.tier1:
            block.append(L.checkbox(L.optout_line(oitem)))
        block.append(L.space(2))
        story.append(KeepTogether(block))
        if model.bazzell.manual:
            block = [L.h3("Additional Manual Opt-Outs (Not Covered by EasyOptOuts)")]
            for oitem in model.bazzell.manual:
                block.append(L.checkbox(L.optout_line(oitem)))
                if oitem.notes:
                    block.append(Paragraph(f"_{_rich(oitem.notes)}_", L.S["small"]))
            block.append(L.space(2))
            story.append(KeepTogether(block))

    if model.no_action_items:
        block = [L.h3("No Action Available")]
        for na_item in model.no_action_items:
            dot = f'<font color="{_hex(_MID)}">•</font>'
            block.append(Paragraph(f"{dot} &nbsp;{_rich(na_item)}", L.S["check"]))
        block.append(L.space(2))
        story.append(KeepTogether(block))
    return story


def coverage(model: ReportModel, L: PdfLayout) -> list:
    """Where we looked — per-source rows, skipped list, follow-up pivots."""
    from reportlab.platypus import KeepTogether, Paragraph, Table, TableStyle

    if not (
        model.coverage
        and (model.coverage.rows or model.coverage.skipped or model.coverage.follow_ups)
    ):
        return []
    cov = model.coverage
    story = [L.hr(), L.h2("Where We Looked")]
    rows: list[tuple[str, str]] = []
    for row in cov.rows:
        value = _rich(row.summary)
        if row.subitems:
            value += "<br/>" + "<br/>".join(
                f'<font size="8" color="{_hex(_MID)}">· {_rich(s)}</font>'
                for s in row.subitems
            )
        rows.append((_rich(row.label), value))
    if rows:
        tbl = Table(
            [
                [
                    Paragraph(
                        lbl,
                        L.style("tc", fontName=_FONT_MEDIUM, fontSize=9, leading=13),
                    ),
                    Paragraph(val, L.style("tv", fontSize=9, leading=13)),
                ]
                for lbl, val in rows
            ],
            colWidths=[L.W * 0.30, L.W * 0.70],
        )
        tbl.setStyle(
            TableStyle(
                [
                    (
                        "ROWBACKGROUNDS",
                        (0, 0),
                        (-1, -1),
                        [L.color.Color(*_LIGHT), L.color.white],
                    ),
                    ("TEXTCOLOR", (0, 0), (-1, -1), L.color.Color(*_DARK)),
                    ("FONTNAME", (0, 0), (0, -1), _FONT_MEDIUM),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("LINEBELOW", (0, 0), (-1, -2), 0.4, L.color.Color(*_LIGHT)),
                ]
            )
        )
        story.append(tbl)
    if cov.skipped:
        story.append(L.space(2))
        story.append(L.body(f"_{cov.skipped_intro}_"))
        for row in cov.skipped:
            story.append(L.bullet(f"**{row.label}:** {row.summary}"))
    if cov.follow_ups:
        block = [L.h3(cov.follow_ups_title)]
        for line in cov.follow_ups:
            block.append(L.bullet(line))
        block.append(L.space(2))
        story.append(KeepTogether(block))
    return story


def footer(L: PdfLayout) -> list:
    from reportlab.platypus import Paragraph

    return [
        L.space(4),
        Paragraph(
            "Generated by Eidolon · local processing · no data stored",
            L.S["small"],
        ),
    ]
