"""PDF renderer for a ``ReportModel`` (REFACTOR.6) — thin orchestrator.

Dumb renderer: every string of content comes from the model; the per-section
flowable builders live in ``pdf_sections`` (one function per report section,
shared ``PdfLayout``). This module only sets up the document, drives the
sections, and inserts the page breaks between H2 sections. Nothing here
invented or dropped content — the renderer-parity test pins that.
"""

from __future__ import annotations

from pathlib import Path

from eidolon.report import pdf_sections as _sections
from eidolon.report.sections import ReportModel

#: Section builders, in report order. Each returns a plain list of flowables.
_SECTIONS = (
    _sections.internet_knows,
    _sections.leaked_dossier,
    _sections.top_risks,
    _sections.threat,
    _sections.training_pile,
    _sections.actions,
    _sections.remediation,
    _sections.coverage,
    _sections.appendices,
)


def render_pdf(model: ReportModel, pdf_path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
    )

    _sections._register_fonts()

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    W = A4[0] - 36 * mm  # usable width

    layout = _sections.build_layout(W, mm, colors)

    story: list = []
    story += _sections.header_band(model, layout)
    story += _sections.risk_banner(model, layout)
    for section in _SECTIONS:
        story += section(model, layout)
    story += _sections.footer(layout)

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
