"""HARDEN.3 — the model->output boundary is sanitized.

A hostile model (LLM content gone wrong, or fixture/source strings) must not:
- forge a new ``## `` section from mid-string content,
- smuggle raw control bytes (nul, ESC) into the md stream or PDF,
- open a 4-space-indented code fence,
- inject a non-http(s) or whitespace-broke URL into a link target.
"""

import os
import re

os.environ.setdefault("TEST_MODE", "true")

import pytest  # noqa: E402

pytest.importorskip("reportlab")

from eidolon.report.markdown import render_markdown  # noqa: E402
from eidolon.report.pdf import render_pdf  # noqa: E402
from eidolon.report.sanitize import (  # noqa: E402
    sanitize_inline,
    sanitize_text,
    sanitize_url,
)
from eidolon.report.sections import (  # noqa: E402
    BazzellOptOuts,
    Coverage,
    CoverageRow,
    KnownGroup,
    OptOutItem,
    ReportHeader,
    ReportModel,
    ThreatSection,
    ThreatTechnique,
)

HOSTILE_ITEM = "normal text\n## FAKE SECTION\nlong content"
HOSTILE_CONTROL = "NUL \x00 ESC \x1b SEQ \x1b]0;"
HOSTILE_INDENT = "    four-space indented\n- fake checkbox\n> quote"


class TestSanitizeCore:
    def test_fake_heading_neutralized(self):
        out = sanitize_text(HOSTILE_ITEM)
        assert "## " not in out
        assert "FAKE SECTION" in out
        assert "normal text" in out

    def test_control_bytes_removed(self):
        out = sanitize_text(HOSTILE_CONTROL)
        assert "\x00" not in out
        assert "\x1b" not in out
        assert "NUL" in out

    def test_indent_and_bullets_neutralized(self):
        out = sanitize_text(HOSTILE_INDENT)
        for line in out.split("\n"):
            assert not line.startswith("    "), repr(line)
            assert not line.startswith("#"), repr(line)
            assert not line.lstrip().startswith(("- ", "[ ] ", "> ")), repr(line)

    def test_inline_collapses_newlines(self):
        out = sanitize_inline(HOSTILE_ITEM)
        assert "\n" not in out
        assert "## " not in out

    def test_inline_strips_leading_marker(self):
        assert sanitize_inline("## Head") == "Head"
        assert sanitize_inline("- [ ] todo") == "[ ] todo"


class TestSanitizeUrl:
    def test_http_kept(self):
        assert sanitize_url("https://example.com/x") == "https://example.com/x"

    def test_bad_scheme_dropped(self):
        assert sanitize_url("ftp://example.com/x") == ""
        assert sanitize_url("javascript:alert(1)") == ""
        assert sanitize_url("file:///etc/passwd") == ""

    def test_whitespace_and_junk_dropped(self):
        assert sanitize_url("https://example.com/a b") == ""
        assert sanitize_url("https://example.com/x ) ]\x00") == ""

    def test_empty_dropped(self):
        assert sanitize_url("") == ""
        assert sanitize_url(None) == ""


class TestHostileMarkdownRender:
    def _model(self) -> ReportModel:
        return ReportModel(
            header=ReportHeader(
                generated="2026-01-01",
                run_id="RUNID",
                target="victim@example.com\x00\x1brun",
                risk_score=42,
                risk_level="MEDIUM\n## INJECT",
                results_json_path="/x/y.json",
            ),
            summary_narrative=HOSTILE_ITEM + "\n" + HOSTILE_INDENT,
            known_groups=[
                KnownGroup(
                    title="### pre-headed group",
                    items=[HOSTILE_ITEM, HOSTILE_CONTROL, HOSTILE_INDENT],
                )
            ],
            top_risks=[HOSTILE_ITEM],
            threat=ThreatSection(
                intro="threat intro",
                techniques=[
                    ThreatTechnique(
                        headline="Phishing\n## PWN",
                        severity="HIGH",
                        what_it_is="no raw control \x1b here",
                        evidence=["src a", "src b & <c>"],
                        reference="T1566",
                        url="https://attack.mitre.org/techniques/T1566/",
                    ),
                ],
            ),
            bazzell=BazzellOptOuts(
                tier1=[
                    OptOutItem(
                        name="Spokeo\n## SPLIT",
                        url="https://spokeo.com/opt-out ) \x00javascript:alert(1)",
                        days="30",
                        notes=HOSTILE_CONTROL,
                    ),
                    OptOutItem(name="Ftp", url="ftp://forbidden.example", days="1"),
                ]
            ),
            coverage=Coverage(
                rows=[
                    CoverageRow(label="### hibp", summary="ok <extra>", subitems=["x"])
                ],
                follow_ups=[HOSTILE_ITEM],
            ),
        )

    def test_no_fake_heading_forged(self):
        md = render_markdown(self._model())
        lines = md.splitlines()
        # forged-section strings must never appear as heading lines
        assert "## FAKE SECTION" not in lines
        assert "## INJECT" not in lines
        assert "## PWN" not in lines
        # renderer heads with hostile content survive as content, not markers
        assert any("Phishing PWN" in l for l in lines), "threat headline lost"
        assert not [l for l in lines if l.startswith("## #")], "forged nested marker"
        # structure survived to legit headings only
        assert "## Top Risks" in lines

    def test_no_raw_control_bytes(self):
        md = render_markdown(self._model())
        assert "\x00" not in md
        assert "\x1b" not in md

    def test_no_four_space_code_fence(self):
        md = render_markdown(self._model())
        for i, ln in enumerate(md.splitlines()):
            assert not ln.startswith("    "), (i, repr(ln))

    def test_only_clean_urls_reach_link_targets(self):
        md = render_markdown(self._model())
        # good url survives intact as a link target
        assert "attack.mitre.org/techniques/T1566" in md
        # the hostile variant (space + ) + nul) is gone — no whitespace/control
        # ever lands inside a link target
        assert "/techniques/T1566/ path" not in md
        # bad-scheme urls are dropped entirely — no ftp:// in the output
        assert "ftp://" not in md
        assert "javascript:" not in md

    def test_hostile_content_still_renders_as_bullets(self):
        md = render_markdown(self._model())
        assert "FAKE SECTION" in md  # content preserved, just defused

    def test_pdf_builds_with_hostile_model(self, tmp_path):
        out = tmp_path / "hostile.pdf"
        render_pdf(self._model(), out)  # must not raise on hostile strings
        assert out.exists() and out.stat().st_size > 0
