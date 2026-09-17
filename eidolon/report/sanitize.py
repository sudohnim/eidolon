"""Model->output sanitization shared by the markdown and PDF renderers (HARDEN.3).

The renderers are dumb by design: every inserted string is model (LLM/fixture)
content. This module is the one place that content is made safe to *lay out* —
neutralizing control bytes that could corrupt a stream or a PDF paragraph, and
markdown structure markers that could interrupt the surrounding section (fake
``## `` headings, checkbox bullets, numbered lists, 4-space indented code
fences).

``sanitize_text`` keeps paragraph newlines but neutralizes the leading
structural markers of every line. Use ``sanitize_inline`` for a single-line
slot (titles, bullets, list items). The PDF side additionally runs the same
control-stripping inside its ``_rich`` translator (reportlab mini-HTML), so a
hostile string can neither forge tags after XML-escaping nor smuggle a control
byte through the tag pass.
"""

from __future__ import annotations

import re
from typing import Any

# C0 + C1 control chars, minus the whitespace we mean to keep (\n, \t, \r)
_CONTROL_RX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u0080-\u009f]")
# a line's leading structural marker: heading run, bullet/quote/checkbox char,
# numbered-list marker, or a whitespace indent (defuses 4-space code fences)
_LEADING_MARKER_RX = re.compile(r"^(?:#{1,6}\s*|[->*\s]\s*|\d+[.)]\s*)+")
_INLINE_WS_RX = re.compile(r"[\n\t]+")
_URL_SCHEME_RX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def _strip_control(value: Any) -> str:
    s = str(value) if value is not None else ""
    return _CONTROL_RX.sub("", s)


def sanitize_text(value: Any) -> str:
    """Dynamic text for a paragraph slot: keep newlines, defuse structure."""
    s = _strip_control(value).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(_LEADING_MARKER_RX.sub("", line) for line in s.split("\n"))


def sanitize_inline(value: Any) -> str:
    """Dynamic text for a single-line slot (titles, bullets, list items)."""
    return _INLINE_WS_RX.sub(" ", sanitize_text(value)).strip()


def sanitize_url(value: Any) -> str:
    """A URL for a ``[link](url)`` / ``(url)`` target: no control bytes, no
    whitespace, no non-http(s) scheme. Returns ``""`` for anything that isn't a
    clean http(s) URL. Whitespace is rejected, never glued — joining fragments
    would happily turn ``.../opt-out ) javascript:alert(1)`` into a live link."""
    s = sanitize_text(value or "")
    if re.search(r"\s", s):
        return ""
    s = s.rstrip(".,;])}")
    if not _URL_SCHEME_RX.match(s):
        return ""
    if not s.lower().startswith(("http://", "https://")):
        return ""
    return s
