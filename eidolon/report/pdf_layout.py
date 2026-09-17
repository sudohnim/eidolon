"""PDF layout infrastructure (REFACTOR.6) — palette, fonts, shared context.

Everything a ``pdf_sections`` builder needs from reportlab and from this
project: the soft colour palette, bundled Nunito font registration, the
markdown-to-mini-HTML ``_rich`` translator, and ``PdfLayout`` / ``build_layout``
(the shared styles + small flowable factories). Section functions themselves
live in ``pdf_sections``; ``pdf.py`` just drives the document.

Model strings carry light markdown emphasis (``**bold**``, ``_italic_``,
``<https://url>``); ``_rich`` translates exactly those constructs into
reportlab's mini-HTML after XML-escaping — nothing else is interpreted.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from xml.sax.saxutils import escape

from eidolon.report.sanitize import sanitize_text
from eidolon.report.sections import ActionItem, OptOutItem

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
    reportlab's mini-HTML. Nothing else is interpreted. (HARDEN.3: control
    bytes are dropped before escaping — a hostile string can't smuggle one
    through the tag pass.)"""
    t = sanitize_text(text)
    t = escape(t)
    t = _URL_RE.sub(r"\1", t)
    t = _BOLD_RE.sub(r"<b>\1</b>", t)
    t = _ITALIC_RE.sub(r"<i>\1</i>", t)
    return t


@dataclass
class PdfLayout:
    """Shared PDF context: usable width, in-mm offset, reportlab colors,
    the style map, and the small flowable factories every section uses."""

    color: Any
    W: float
    mm: float
    S: dict[str, Any]
    style: Callable[..., Any]  # name, **kw -> ParagraphStyle
    hr: Callable[..., Any]
    h2: Callable[..., Any]
    h3: Callable[..., Any]
    body: Callable[..., Any]
    bullet: Callable[..., Any]
    checkbox: Callable[..., Any]
    space: Callable[..., Any]
    action_block: Callable[..., Any]
    optout_line: Callable[..., Any]


def build_layout(W: float, mm: float, color: Any) -> PdfLayout:
    """Build the styles + flowable factories a section function needs."""
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import HRFlowable, Paragraph, Spacer

    def style(name: str, **kw: Any) -> ParagraphStyle:
        base: dict[str, Any] = dict(
            fontName=_FONT_BODY,
            fontSize=10,
            leading=16,
            textColor=color.Color(*_DARK),
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
            textColor=color.Color(*_ACCENT),
            spaceAfter=3,
        ),
        "meta": style("meta", fontSize=9, leading=14, textColor=color.Color(*_MID)),
        "h2": style(
            "h2",
            fontName=_FONT_MEDIUM,
            fontSize=13,
            leading=18,
            textColor=color.Color(*_ACCENT),
            spaceBefore=12,
            spaceAfter=5,
        ),
        "h3": style(
            "h3",
            fontName=_FONT_MEDIUM,
            fontSize=10.5,
            leading=15,
            textColor=color.Color(*_DARK),
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
            textColor=color.Color(*_DARK),
        ),
        "small": style("small", fontSize=8, leading=12, textColor=color.Color(*_MID)),
    }

    def hr():
        return HRFlowable(
            width="100%",
            thickness=0.5,
            color=color.Color(*_LIGHT),
            spaceAfter=8,
            spaceBefore=4,
        )

    def h2(text):
        return Paragraph(_rich(text), S["h2"])

    def h3(text):
        return Paragraph(_rich(text), S["h3"])

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
        block: list[Any] = [h3(item.name)]
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

    return PdfLayout(
        color=color,
        W=W,
        mm=mm,
        S=S,
        style=style,
        hr=hr,
        h2=h2,
        h3=h3,
        body=body,
        bullet=bullet,
        checkbox=checkbox,
        space=space,
        action_block=action_block,
        optout_line=optout_line,
    )
