import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path

from eidolon import config
from eidolon.core.models import PipelineState


def _rem_item(item: object) -> str:
    """Normalize a remediation list item — LLM sometimes returns dicts instead of strings.

    nodes._postprocess_analysis already coerces these upstream; this is a
    defensive net for the TEST_MODE fixture path and any stray dict shapes.
    """
    if isinstance(item, dict):
        if item.get("action"):
            plats = item.get("platforms")
            if isinstance(plats, list):
                plats = ", ".join(str(p) for p in plats if p)
            return f"{item['action']}: {plats}" if plats else str(item["action"])
        service = item.get("service") or item.get("name") or ""
        how = item.get("how_to_remove") or item.get("url") or ""
        if service and how:
            return f"{service}: {how}"
        return service or ""
    return str(item)


_BAZZELL_DB_PATH = Path(__file__).parent.parent / "data" / "bazzell_brokers.json"


def _load_bazzell_db() -> dict[str, dict]:
    """Return domain -> broker entry map from bazzell_brokers.json."""
    try:
        entries = json.loads(_BAZZELL_DB_PATH.read_text())
        return {e["domain"]: e for e in entries}
    except Exception:
        return {}


def _dossier_records(state: PipelineState) -> list[tuple[str, list[str]]]:
    """[(source_breach, [credential_line, ...])] — the actual DeHashed records for
    the exact mailbox, cleaned. Shared by the Markdown and PDF renderers."""
    dh = (
        state.dehashed_result.data
        if (state.dehashed_result and state.dehashed_result.success)
        else {}
    )
    by_db: dict[str, list[str]] = {}
    for e in dh.get("entries") or []:
        parts = []
        user = _clean_cred_username(e.get("username", ""))
        if user:
            parts.append(f"username: {user}")
        if e.get("password"):
            parts.append(f"password: {e['password']}")
        elif e.get("hashed_password"):
            h, algo = _clean_cred_hash(e["hashed_password"])
            if h:
                parts.append(f"hash: {h}" + (f" ({algo})" if algo else ""))
        addr = _clean_cred_address(e.get("address", ""))
        if addr:
            parts.append(f"address: {addr}")
        if e.get("phone"):
            parts.append(f"phone: {e['phone']}")
        if parts:
            db = e.get("database_name") or "Unknown source"
            by_db.setdefault(db, []).append("  ·  ".join(parts))
    return list(by_db.items())


def _dossier_lines(state: PipelineState) -> list[str]:
    """Markdown for the 'Leaked Credentials' dossier."""
    records = _dossier_records(state)
    if not records:
        return []
    n = sum(len(v) for _, v in records)
    lines = [
        "---",
        "",
        "## Your Actual Leaked Data",
        "",
        "_Actual records found in breach dumps for this exact mailbox — "
        f"{n} record(s) across {len(records)} source(s). "
        "Passwords are shown exactly as they leaked._",
        "",
    ]
    for db, items in records:
        lines += [f"### {db}", ""] + [f"- {it}" for it in items] + [""]
    return lines


def _clean_cred_username(u: str) -> str:
    """DeHashed packs multiple values into one field; keep the first real one."""
    u = (u or "").split(",")[0].strip()
    return "" if len(u) < 3 or u.isdigit() else u


def _clean_cred_address(a: str) -> str:
    """Show only real addresses (street number present) — drop country codes /
    short geo fragments like 'PH' or 'NU'."""
    a = (a or "").strip()
    return a if (len(a) >= 6 and re.search(r"\d", a)) else ""


def _clean_cred_hash(h: str) -> tuple[str, str]:
    """DeHashed formats hashes as 'hash:salt||ALGO' — split out the raw hash + algo."""
    from eidolon.tools.dehashed import _hash_type

    raw = (h or "").split("||")[0].split(":")[0].strip()
    if "||" in (h or ""):
        # rsplit + strip pipes: some salts themselves end in '|', so a plain
        # split("||")[-1] would leave a stray pipe on the algorithm label.
        algo = h.rsplit("||", 1)[-1].strip().strip("|").strip()
    else:
        algo = _hash_type(raw)
    return raw, algo


logger = logging.getLogger(__name__)


# ── Colour palette ────────────────────────────────────────────────────────────
# Soft, warm, low-saturation tones — a calm briefing, not a pentest printout.
# Risk colours read as gentle signals rather than alarms; text is a muted slate
# ink instead of near-black; the accent is a dusty slate-blue.
_RED = (0.70, 0.36, 0.31)  # muted clay / terracotta — high risk
_ORANGE = (0.80, 0.58, 0.34)  # soft amber — medium risk
_GREEN = (0.42, 0.56, 0.45)  # muted sage — low risk
_DARK = (0.22, 0.24, 0.29)  # muted slate ink — body text
_MID = (0.46, 0.48, 0.53)  # soft grey — secondary text
_LIGHT = (0.95, 0.95, 0.96)  # warm off-white — dividers / row tint
_WHITE = (1.00, 1.00, 1.00)
_ACCENT = (0.36, 0.45, 0.56)  # dusty slate-blue — headings
_BAND = (0.96, 0.96, 0.97)  # gentle header band fill

# ── Soft typeface ─────────────────────────────────────────────────────────────
# Nunito (rounded, humanist, OFL) reads warmer than Helvetica. We bundle static
# weights under assets/fonts/ and register them with reportlab. If the fonts are
# unavailable (e.g. a packaged install without assets), fall back to Helvetica so
# the report still renders.


def _find_assets_dir() -> Path:
    """Locate the assets/ folder for both source checkouts and packaged installs.

    Source layout keeps assets/ at the repo root (../../assets relative to this
    file); a wheel build force-includes them next to the package. Return the
    first that exists, defaulting to the repo-root path.
    """
    candidates = [
        Path(__file__).resolve().parents[2] / "assets",  # repo root (source)
        Path(__file__).resolve().parents[1] / "assets",  # packaged alongside pkg
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


_ASSETS_DIR = _find_assets_dir()
_FONT_DIR = _ASSETS_DIR / "fonts"
_LOGO_PATH = _ASSETS_DIR / "logo.png"

# Font face names used in the styles below; rebound to Helvetica on fallback.
_FONT_BODY = "Nunito"
_FONT_MEDIUM = "Nunito-SemiBold"
_FONT_BOLD = "Nunito-Bold"

_FONTS_READY: bool = False


def _register_fonts() -> bool:
    """Register the bundled Nunito weights once; fall back to Helvetica.

    Returns True if Nunito is available, False if we fell back. Idempotent.
    """
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


def _write_pdf(
    pdf_path: Path, state: PipelineState, analysis: dict, run_id: str = ""
) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Image,
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    # Register the soft typeface up front so every style picks it up.
    _register_fonts()

    primary = state.classifications[0] if state.classifications else None
    target = primary.value if primary else "unknown"
    ts = datetime.now().strftime("%Y-%m-%d") + (f" · run {run_id}" if run_id else "")
    risk_lvl = (analysis.get("overall_risk_level") or "low").upper()
    risk_scr = analysis.get("overall_risk_score", 0)
    risk_col = colors.Color(*_risk_colour(risk_lvl))

    known = analysis.get("what_is_known", {}) or {}
    remediation = analysis.get("remediation", {}) or {}

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
    )
    W = A4[0] - 36 * mm  # usable width

    # ── Styles ────────────────────────────────────────────────────────────────
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
        return Paragraph(text, S["body"])

    def bullet(text):
        return Paragraph(f"• &nbsp;{text}", S["bullet"])

    def checkbox(text):
        # Nunito has no checkbox glyph; a bracketed marker reads as a to-do and
        # renders cleanly in the soft face.
        mark = f'<font name="{_FONT_MEDIUM}">[ ]</font>'
        return Paragraph(f"{mark} &nbsp;{_rem_item(text)}", S["check"])

    def space(h=4):
        return Spacer(1, h * mm)

    # ── Build story ───────────────────────────────────────────────────────────
    story = []

    # Header band — logo (left) beside the title, on a gentle tinted panel.
    title_cell = [
        Paragraph("Privacy OSINT Report", S["h1"]),
        Paragraph(f"Target: <b>{target}</b> &nbsp;·&nbsp; Generated: {ts}", S["meta"]),
    ]
    logo_cell: object = ""
    if _LOGO_PATH.exists():
        try:
            # ~22mm (~83px) tall, aspect preserved — a soft, unobtrusive mark.
            logo = Image(str(_LOGO_PATH), width=22 * mm, height=22 * mm)
            logo.hAlign = "CENTER"
            logo_cell = logo
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("logo unavailable: %s", exc)
            logo_cell = ""

    header = Table(
        [[logo_cell, title_cell]],
        colWidths=[26 * mm, W - 26 * mm],
    )
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

    # Risk score banner
    banner_data = [
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
    ]
    banner = Table(banner_data, colWidths=[W * 0.25, W * 0.35, W * 0.40])
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

    # Identity summary
    summary = analysis.get("identity_summary")
    if summary:
        story += [h2("What the Internet Knows About You"), body(summary), space(2)]

    # What is known sub-sections
    sections = [
        ("handles_and_usernames", "Usernames & Handles"),
        ("platforms_with_accounts", "Accounts Found"),
        ("physical_data", "Physical Data Exposed"),
        ("credentials_exposed", "Passwords That Have Leaked"),
        ("google_footprint", "Google Footprint"),
        ("breach_history", "Where Your Data Has Shown Up"),
    ]
    for key, title in sections:
        items = known.get(key) or []
        if items:
            block = [h3(title)]
            for item in items:
                block.append(bullet(item))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Leaked Credentials dossier — escape, since passwords can contain < & etc.
    dossier = _dossier_records(state)
    if dossier:
        from xml.sax.saxutils import escape

        story += [hr(), h2("Your Actual Leaked Data")]
        story.append(
            body(
                "Actual records found in breach dumps for this exact mailbox. "
                "Passwords are shown exactly as they leaked."
            )
        )
        story.append(space(2))
        for db, items in dossier:
            block = [h3(escape(db))] + [bullet(escape(it)) for it in items]
            block.append(space(2))
            story.append(KeepTogether(block))

    # Top risks
    top_risks = analysis.get("top_risks") or []
    if top_risks:
        story += [hr(), h2("Top Risks")]
        for risk in top_risks:
            # A soft coloured dot in the high-risk clay tone — a gentle signal,
            # and one Nunito can render (the warning glyph it cannot).
            story.append(
                bullet(
                    f'<font color="#{int(_RED[0]*255):02x}{int(_RED[1]*255):02x}{int(_RED[2]*255):02x}">•</font> &nbsp;{risk}'
                )
            )
        story.append(space(2))

    # Threat Model (MITRE ATT&CK) — mirrors the markdown section so the PDF
    # deliverable carries the same threat vocabulary. Deterministic.
    mitre = (
        state.mitre_result.data
        if (state.mitre_result and state.mitre_result.success)
        else {}
    )
    techniques = mitre.get("techniques") or []
    if techniques:
        from xml.sax.saxutils import escape

        story += [hr(), h2("What Someone Could Do With This")]
        story.append(
            body(
                f"<i>{mitre.get('technique_count', 0)} thing(s) a stranger could "
                f"realistically try with what's already exposed. (These map to MITRE "
                f"ATT&CK, a standard catalog of real-world attacker behaviour — the "
                f"codes are just for reference.)</i>"
            )
        )
        story.append(space(2))
        for t in techniques:
            sev = (t.get("severity") or "").upper()
            title = t.get("headline") or t.get("name")
            head = escape(str(title)) + (f"  ·  {sev}" if sev else "")
            block = [h3(head)]
            if t.get("what_it_is"):
                block.append(body(f"<b>What this means:</b> {escape(t['what_it_is'])}"))
            if t.get("why_this_finding"):
                block.append(
                    body(
                        f"<b>Why it applies to you:</b> {escape(t['why_this_finding'])}"
                    )
                )
            if t.get("evidence"):
                block.append(
                    body(f"<b>Based on:</b> {escape('; '.join(t['evidence']))}")
                )
            ref = f"{t.get('technique_id')} {t.get('name')} ({t.get('tactic')})"
            block.append(body(f"<i>MITRE reference: {escape(ref)}</i>"))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Your Content in the AI Training Pile (Common Crawl) — honest framing:
    # Common Crawl is the raw web archive training sets are built FROM; a hit
    # does NOT mean any model memorized or trained on the person.
    cc = (
        state.commoncrawl_result.data
        if (state.commoncrawl_result and state.commoncrawl_result.success)
        else {}
    )
    if cc.get("present"):
        from xml.sax.saxutils import escape

        matched = cc.get("matched") or []
        total = cc.get("total_captures", 0)
        index_id = cc.get("index_id", "")
        story += [hr(), h2("Your Content in the AI Training Pile")]
        story.append(
            body(
                "Common Crawl is a free, openly published archive of the public web "
                "&mdash; the raw corpus that most AI training sets (like Google's C4) "
                "are filtered and built FROM. Your pages showing up here means your "
                "public content is in that upstream pile. It does <b>not</b> mean any "
                "specific AI model memorized you or was trained on you &mdash; only "
                "that your content is in the corpus training data is sourced from."
            )
        )
        story.append(space(2))
        block = [
            h3(f"Found in {len(matched)} web property(ies) — {total} page capture(s)")
        ]
        for m in matched:
            target = escape(str(m.get("target", "")))
            count = m.get("capture_count", 0)
            sample = escape(str(m.get("sample_url", "")))
            line = f"<b>{target}</b> — {count} page capture(s)"
            if sample:
                line += f" (e.g. {sample})"
            block.append(bullet(line))
        if index_id:
            block.append(body(f"<i>Common Crawl index: {escape(str(index_id))}</i>"))
        block.append(space(2))
        story.append(KeepTogether(block))
        opt_out = [
            h3("How to opt out of future AI training crawls"),
            bullet(
                "Register your content with Spawning's <b>Do Not Train</b> registry "
                "at haveibeentrained.com (spawning.ai) so participating AI trainers "
                "skip it."
            ),
            bullet(
                "Add an <b>ai.txt</b> file to your site (and robots rules) to signal "
                "that AI crawlers should not collect your pages going forward."
            ),
            body(
                "<i>Note: opting out only affects future crawls. It cannot remove "
                "your content from copies already in existing archives or datasets.</i>"
            ),
            space(2),
        ]
        story.append(KeepTogether(opt_out))

    # Findings context — split into three buckets
    findings = analysis.get("findings_context") or []
    active_removable = [
        f
        for f in findings
        if f.get("removable") is not False and f.get("account_is_active") is True
    ]
    breach_only = [
        f
        for f in findings
        if f.get("removable") is not False and f.get("account_is_active") is not True
    ]
    no_action = [f for f in findings if f.get("removable") is False]

    mech_labels = {
        "gdpr": "GDPR erasure (EU/UK)",
        "ccpa": "CCPA deletion (US)",
        "optout": "Opt-out",
        "account_deletion": "Delete account",
    }

    def _finding_block(f: dict) -> list:
        name = f.get("name", "")
        what = f.get("what_it_is", "")
        why = f.get("why_it_matters", "")
        how = f.get("how_to_remove", "")
        mech = f.get("removal_mechanism", "")
        mech_label = mech_labels.get(mech, "")
        block = [h3(name)]
        if what:
            block.append(body(f"<b>What it is:</b> {what}"))
        if why:
            block.append(body(f"<b>Why it matters:</b> {why}"))
        if how and mech_label:
            block.append(body(f"<b>Action ({mech_label}):</b> {how}"))
        elif how:
            block.append(body(f"<b>Action:</b> {how}"))
        block.append(space(2))
        return block

    if active_removable:
        story += [hr(), h2("Active Accounts — Take Action")]
        story.append(
            body(
                "You have confirmed active accounts on these services. "
                "Delete the account and/or submit a data deletion request."
            )
        )
        story.append(space(2))
        for f in active_removable:
            story.append(KeepTogether(_finding_block(f)))

    if breach_only:
        story += [hr(), h2("Breach Records — Request Data Deletion")]
        story.append(
            body(
                "Your data appeared in breaches from these services. You may not have an "
                "active account, but you can still submit a CCPA or GDPR deletion request "
                "to have your stored data removed. Breach archive copies held by third "
                "parties cannot be removed."
            )
        )
        story.append(space(2))
        for f in breach_only:
            story.append(KeepTogether(_finding_block(f)))

    if no_action:
        story += [hr(), h2("No Action Available")]
        story.append(
            body(
                "These findings are in public archives or threat intelligence datasets. "
                "No removal is possible — monitor for future exposure."
            )
        )
        story.append(space(2))
        for f in no_action:
            name = f.get("name", "")
            why = f.get("why_it_matters", "")
            block = [h3(name)]
            if why:
                block.append(body(why))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Remediation
    story += [hr(), h2("What To Do")]
    rem_sections = [
        ("identity_fraud_prevention", "Identity Fraud Prevention (Do These First)"),
        ("credit_freeze", "Freeze Your Credit"),
        ("sim_swap_hardening", "SIM Swap Hardening"),
        ("change_passwords", "Change Passwords"),
        ("enable_2fa", "Enable 2FA"),
        ("account_hygiene", "Account Hygiene"),
        ("account_reviews", "Review Privacy Settings"),
        ("ccpa_removals", "US Data Deletion Requests (CCPA)"),
        ("gdpr_removals", "EU/UK Erasure Requests (GDPR)"),
        ("broker_optouts", "Data Broker Opt-Outs"),
        ("monitoring", "Ongoing Monitoring"),
    ]
    for key, title in rem_sections:
        items = remediation.get(key) or []
        if items:
            block = [h3(title)]
            for item in items:
                block.append(checkbox(item))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Bazzell cross-reference section
    broker_data = (
        state.broker_result.data
        if state.broker_result and state.broker_result.success
        else {}
    ) or {}
    bazzell_tier1_pdf = broker_data.get("bazzell_tier1_found") or []
    manual_required_pdf = broker_data.get("manual_removal_required") or []
    easyoptouts_covers_pdf = broker_data.get("easyoptouts_covers", 0)

    if bazzell_tier1_pdf or manual_required_pdf:
        bazzell_db_pdf = _load_bazzell_db()
        block = [h3("Priority Manual Opt-Outs (Bazzell Tier 1)")]
        if easyoptouts_covers_pdf:
            block.append(
                body(
                    f"EasyOptOuts.com can automate <b>{easyoptouts_covers_pdf}</b> of these — "
                    f"visit easyoptouts.com first."
                )
            )
        for name in bazzell_tier1_pdf:
            entry = next(
                (e for e in bazzell_db_pdf.values() if e.get("name") == name), None
            )
            if entry and entry.get("optout_url"):
                days = entry.get("estimated_days_to_remove", "?")
                block.append(checkbox(f'{name}: {entry["optout_url"]} ({days} days)'))
            else:
                block.append(checkbox(f"{name}: see broker's website"))
        block.append(space(2))
        story.append(KeepTogether(block))

        if manual_required_pdf:
            block = [h3("Additional Manual Opt-Outs (Not Covered by EasyOptOuts)")]
            for name in manual_required_pdf:
                entry = next(
                    (e for e in bazzell_db_pdf.values() if e.get("name") == name), None
                )
                if entry and entry.get("optout_url"):
                    days = entry.get("estimated_days_to_remove", "?")
                    block.append(
                        checkbox(f'{name}: {entry["optout_url"]} ({days} days)')
                    )
                else:
                    block.append(checkbox(f"{name}: see broker's website"))
            block.append(space(2))
            story.append(KeepTogether(block))

    no_action = remediation.get("no_action_available") or []
    if no_action:
        block = [h3("No Action Available")]
        for item in no_action:
            # Soft grey dot — Nunito has no info glyph; this reads as a note.
            dot = f'<font color="#{int(_MID[0]*255):02x}{int(_MID[1]*255):02x}{int(_MID[2]*255):02x}">•</font>'
            block.append(Paragraph(f"{dot} &nbsp;{item}", S["check"]))
        block.append(space(2))
        story.append(KeepTogether(block))

    # Tool summary table
    story += [hr(), h2("Tool Results")]
    tool_rows = []

    def _tr(label, result_obj, value_fn):
        if result_obj and result_obj.success:
            tool_rows.append([label, value_fn(result_obj.data)])

    _tr("HIBP", state.hibp_result, lambda d: f"{d.get('breach_count',0)} breaches")
    _tr(
        "DeHashed",
        state.dehashed_result,
        lambda d: (
            f"{d.get('total',0)} records — "
            f"{d.get('plaintext_password_count',0)} plaintext, "
            f"{d.get('hashed_password_count',0)} hashed"
        ),
    )
    _tr(
        "Whoxy",
        state.whoxy_result,
        lambda d: (
            f"{d.get('total_results',0)} domains — "
            f"{d.get('active_domain_count',0)} active, "
            f"{d.get('expired_domain_count',0)} expired"
        ),
    )
    _tr(
        "Paste sites",
        state.paste_result,
        lambda d: (
            f"{d.get('paste_count',0)} pastes — "
            f"{d.get('credential_paste_count',0)} with credentials, "
            f"{d.get('recent_paste_count',0)} recent"
        ),
    )
    _tr(
        "Infostealer logs",
        state.stealer_result,
        lambda d: (
            f"{d.get('stealer_count',0)} hit(s) — "
            f"{', '.join(d.get('malware_families') or []) or 'none'}"
            if d.get("found")
            else "no hits"
        ),
    )
    _tr(
        "Blackbird",
        state.blackbird_result,
        lambda d: f"{d.get('found_count',0)} accounts",
    )
    _tr(
        "Maigret",
        state.sherlock_result,
        lambda d: f"{d.get('found_count',0)} profiles / {d.get('platforms_checked',0)} platforms",
    )
    _tr(
        "Holehe",
        state.holehe_result,
        lambda d: f"{d.get('found_count',0)} registrations / {d.get('platforms_checked',0)} platforms",
    )
    _tr(
        "GHunt",
        state.ghunt_result,
        lambda d: "Found" if d.get("found") else "Not found",
    )
    _tr(
        "SpiderFoot",
        state.spiderfoot_result,
        lambda d: f"{d.get('element_count',0)} elements",
    )
    _tr(
        "Broker scan",
        state.broker_result,
        lambda d: f"{d.get('brokers_found_count',0)} brokers, score {d.get('exposure_score',0)}/100",
    )
    _tr(
        "Shodan",
        state.shodan_result,
        lambda d: f"{d.get('ips_checked',0)} IPs, {d.get('total_open_ports',0)} open ports, {d.get('total_vulns',0)} CVEs",
    )
    _tr(
        "AI Audit",
        state.ai_audit_result,
        lambda d: f"{d.get('high_risk_count',0)} high-risk platforms",
    )

    _tr(
        "Phone Lookup",
        state.phone_result,
        lambda d: (
            f"valid={d.get('valid')} {d.get('line_type') or 'unknown'} "
            f"via {(d.get('carrier') or {}).get('name') or 'unknown carrier'}"
            if d.get("valid")
            else "invalid / no key"
        ),
    )
    _tr(
        "Public Records",
        state.public_records_result,
        lambda d: f"{d.get('court_case_count',0)} court cases, {d.get('corporate_record_count',0)} corporate records",
    )
    # Correlation summary row — show count of successful follow-up pivots
    successful_pivots = [r for r in state.correlation_results if r.success]
    if successful_pivots or state.correlation_plan:
        pivot_summary = (
            f"{len(successful_pivots)} pivot(s) executed"
            if successful_pivots
            else "planned but skipped"
        )
        tool_rows.append(("Correlation", pivot_summary))

    if tool_rows:
        tbl = Table(
            [
                [
                    Paragraph(
                        r, style("tc", fontName=_FONT_MEDIUM, fontSize=9, leading=13)
                    ),
                    Paragraph(v, style("tv", fontSize=9, leading=13)),
                ]
                for r, v in tool_rows
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

    story += [
        space(4),
        Paragraph(
            "Generated by osint-agent · local processing · no data stored", S["small"]
        ),
    ]

    doc.build(story)


def _build_identifier(state: PipelineState) -> str:
    """Pick the best identifier for the filename.

    Priority: email > phone > name > org.
    Sanitizes the value so it's safe as a filename component.
    """
    priority = ["email", "phone", "name", "org"]
    classifications_by_type = {c.type: c for c in state.classifications}
    for kind in priority:
        if kind in classifications_by_type:
            value = classifications_by_type[kind].value
            # Sanitize: keep alphanumeric, dots, hyphens, underscores; replace the rest
            safe = re.sub(r"[^\w.\-]", "_", value)
            # Collapse multiple underscores and strip leading/trailing ones
            safe = re.sub(r"_+", "_", safe).strip("_")
            return safe
    return "unknown"


def write_report(state: PipelineState) -> str:
    output_dir = Path(config.get("RESULTS_OUTPUT_PATH"))
    output_dir.mkdir(parents=True, exist_ok=True)

    primary = state.classifications[0] if state.classifications else None
    identifier = _build_identifier(state)
    date_str = datetime.now().strftime("%Y-%m-%d")
    # Reuse the run_id bound at intake so logs and the report filename match.
    run_id = state.run_id or uuid.uuid4().hex[:8]
    base_name = f"{identifier}_{date_str}_{run_id}"

    json_path = output_dir / f"{base_name}.json"
    md_path = output_dir / f"{base_name}.md"
    pdf_path = output_dir / f"{base_name}.pdf"

    json_path.write_text(json.dumps(state.model_dump(), indent=2, default=str))

    analysis = state.analysis_result or {}
    known = analysis.get("what_is_known", {}) or {}
    remediation = analysis.get("remediation", {}) or {}

    # ── Markdown ──────────────────────────────────────────────────────────────
    lines = [
        "# Privacy OSINT Report",
        "",
        f"**Generated:** {date_str} (run {run_id})",
        f"**Target:** {primary.value if primary else 'unknown'}",
        f"**Risk Score:** {analysis.get('overall_risk_score', 'N/A')}/100 — {analysis.get('overall_risk_level', 'N/A').upper()}",
        "",
        "---",
        "",
        "## What the Internet Knows About You",
        "",
        analysis.get("identity_summary", "No analysis available."),
        "",
    ]

    for key, title in [
        ("handles_and_usernames", "Usernames & Handles"),
        ("platforms_with_accounts", "Accounts Found"),
        ("physical_data", "Physical Data Exposed"),
        ("credentials_exposed", "Passwords That Have Leaked"),
        ("google_footprint", "Google Footprint"),
        ("breach_history", "Where Your Data Has Shown Up"),
    ]:
        items = known.get(key) or []
        if items:
            lines += [f"### {title}", ""]
            for item in items:
                lines.append(f"- {item}")
            lines.append("")

    # ── Leaked Credentials dossier — the actual records from DeHashed ──────────
    lines += _dossier_lines(state)

    if analysis.get("top_risks"):
        lines += ["---", "", "## Top Risks", ""]
        for risk in analysis["top_risks"]:
            lines.append(f"- {risk}")
        lines.append("")

    # Threat Model (MITRE ATT&CK) — what an attacker can do with what we found,
    # named in the standard ATT&CK vocabulary. Deterministic; teaches as it goes.
    mitre = (
        state.mitre_result.data
        if (state.mitre_result and state.mitre_result.success)
        else {}
    )
    techniques = mitre.get("techniques") or []
    if techniques:
        lines += ["---", "", "## What Someone Could Do With This", ""]
        lines.append(
            f"_{mitre.get('technique_count', 0)} thing(s) a stranger could "
            f"realistically try with what's already exposed. (These map to MITRE "
            f"ATT&CK, a standard catalog of real-world attacker behaviour — the "
            f"codes are just for reference.)_"
        )
        lines.append("")
        for t in techniques:
            sev = (t.get("severity") or "").upper()
            title = t.get("headline") or t.get("name")
            lines += [f"### {title}" + (f"  ·  {sev}" if sev else ""), ""]
            if t.get("what_it_is"):
                lines.append(f"**What this means:** {t['what_it_is']}  ")
            if t.get("why_this_finding"):
                lines.append(f"**Why it applies to you:** {t['why_this_finding']}  ")
            if t.get("evidence"):
                lines.append(f"**Based on:** {'; '.join(t['evidence'])}  ")
            ref = f"{t.get('technique_id')} {t.get('name')} ({t.get('tactic')})"
            url = t.get("url")
            ref_line = f"_MITRE reference: {ref}_"
            lines.append(f"{ref_line} · [details]({url})" if url else f"{ref_line}  ")
            lines.append("")

    # Your Content in the AI Training Pile (Common Crawl) — honest framing:
    # Common Crawl is the raw web archive training sets are built FROM; a hit
    # does NOT mean any model memorized or trained on the person.
    cc = (
        state.commoncrawl_result.data
        if (state.commoncrawl_result and state.commoncrawl_result.success)
        else {}
    )
    if cc.get("present"):
        matched = cc.get("matched") or []
        total = cc.get("total_captures", 0)
        index_id = cc.get("index_id", "")
        lines += ["---", "", "## Your Content in the AI Training Pile", ""]
        lines.append(
            "_Common Crawl is a free, openly published archive of the public web — "
            "the raw corpus that most AI training sets (like Google's C4) are "
            "filtered and built FROM. Your pages showing up here means your public "
            "content is in that upstream pile. It does **not** mean any specific AI "
            "model memorized you or was trained on you — only that your content is in "
            "the corpus training data is sourced from._"
        )
        lines.append("")
        lines.append(
            f"Found in {len(matched)} web property(ies) — {total} page capture(s)"
            + (f" (index {index_id})" if index_id else "")
            + ":"
        )
        lines.append("")
        for m in matched:
            target = m.get("target", "")
            count = m.get("capture_count", 0)
            sample = m.get("sample_url", "")
            line = f"- **{target}** — {count} page capture(s)"
            if sample:
                line += f" (e.g. {sample})"
            lines.append(line)
        lines.append("")
        lines += ["### How to opt out of future AI training crawls", ""]
        lines.append(
            "- Register your content with Spawning's **Do Not Train** registry at "
            "<https://haveibeentrained.com> (spawning.ai) so participating AI "
            "trainers skip it."
        )
        lines.append(
            "- Add an **ai.txt** file to your site (and robots rules) to signal that "
            "AI crawlers should not collect your pages going forward."
        )
        lines.append(
            "- _Opting out only affects future crawls. It cannot remove content "
            "already in existing archives or datasets._"
        )
        lines.append("")

    mech_labels_md = {
        "gdpr": "GDPR erasure (EU/UK)",
        "ccpa": "CCPA deletion (US)",
        "optout": "Opt-out",
        "account_deletion": "Delete account",
    }

    findings = analysis.get("findings_context") or []
    active_removable_f = [
        f
        for f in findings
        if f.get("removable") is not False and f.get("account_is_active") is True
    ]
    breach_only_f = [
        f
        for f in findings
        if f.get("removable") is not False and f.get("account_is_active") is not True
    ]
    no_action_f = [f for f in findings if f.get("removable") is False]

    def _md_finding(f: dict) -> list[str]:
        name = f.get("name", "")
        what = f.get("what_it_is", "")
        why = f.get("why_it_matters", "")
        how = f.get("how_to_remove", "")
        mech = f.get("removal_mechanism", "")
        mech_label = mech_labels_md.get(mech, "Action")
        out = [f"### {name}", ""]
        if what:
            out.append(f"**What it is:** {what}  ")
        if why:
            out.append(f"**Why it matters:** {why}  ")
        if how:
            out.append(f"**{mech_label}:** {how}")
        out.append("")
        return out

    if active_removable_f:
        lines += ["---", "", "## Active Accounts — Take Action", ""]
        lines.append(
            "_You have confirmed active accounts on these services. "
            "Delete the account and/or submit a data deletion request._"
        )
        lines.append("")
        for f in active_removable_f:
            lines += _md_finding(f)

    if breach_only_f:
        lines += ["---", "", "## Breach Records — Request Data Deletion", ""]
        lines.append(
            "_Your data appeared in breaches from these services. You may not have an "
            "active account, but you can still submit a CCPA or GDPR deletion request. "
            "Breach archive copies held by third parties cannot be removed._"
        )
        lines.append("")
        for f in breach_only_f:
            lines += _md_finding(f)

    if no_action_f:
        lines += ["---", "", "## No Action Available", ""]
        lines.append(
            "_These findings are in public archives or threat intel datasets. "
            "No removal is possible._"
        )
        lines.append("")
        for f in no_action_f:
            name = f.get("name", "")
            why = f.get("why_it_matters", "")
            lines += [f"### {name}", ""]
            if why:
                lines.append(f"{why}")
            lines.append("")

    lines += ["---", "", "## What To Do", ""]
    for key, title in [
        ("identity_fraud_prevention", "Identity Fraud Prevention (Do These First)"),
        ("credit_freeze", "Freeze Your Credit"),
        ("sim_swap_hardening", "SIM Swap Hardening"),
        ("change_passwords", "Change Passwords"),
        ("enable_2fa", "Enable 2FA"),
        ("account_hygiene", "Account Hygiene"),
        ("account_reviews", "Review Privacy Settings"),
        ("ccpa_removals", "US Data Deletion Requests (CCPA)"),
        ("gdpr_removals", "EU/UK Erasure Requests (GDPR)"),
        ("broker_optouts", "Data Broker Opt-Outs"),
        ("monitoring", "Ongoing Monitoring"),
    ]:
        items = remediation.get(key) or []
        if items:
            lines += [f"### {title}", ""]
            for action in items:
                lines.append(f"- [ ] {_rem_item(action)}")
            lines.append("")

    # Bazzell cross-reference block
    broker_data = (
        state.broker_result.data
        if state.broker_result and state.broker_result.success
        else {}
    ) or {}
    bazzell_tier1 = broker_data.get("bazzell_tier1_found") or []
    manual_required = broker_data.get("manual_removal_required") or []
    easyoptouts_covers = broker_data.get("easyoptouts_covers", 0)

    if bazzell_tier1 or manual_required:
        bazzell_db = _load_bazzell_db()
        lines += ["### Priority Manual Opt-Outs (Bazzell Tier 1)", ""]
        if easyoptouts_covers:
            lines.append(
                f"_EasyOptOuts.com can automate {easyoptouts_covers} of these — visit <https://easyoptouts.com> first._"
            )
            lines.append("")
        for name in bazzell_tier1:
            entry = next(
                (e for e in bazzell_db.values() if e.get("name") == name), None
            )
            if entry and entry.get("optout_url"):
                days = entry.get("estimated_days_to_remove", "?")
                lines.append(f"- [ ] {name}: {entry['optout_url']} ({days} days)")
            else:
                lines.append(f"- [ ] {name}: see broker's website for opt-out")
        lines.append("")
        if manual_required:
            lines += ["### Additional Manual Opt-Outs (Not Covered by EasyOptOuts)", ""]
            for name in manual_required:
                entry = next(
                    (e for e in bazzell_db.values() if e.get("name") == name), None
                )
                if entry and entry.get("optout_url"):
                    days = entry.get("estimated_days_to_remove", "?")
                    notes = entry.get("notes", "")
                    line = f"- [ ] {name}: {entry['optout_url']} ({days} days)"
                    if notes:
                        line += f"  \n  _{notes}_"
                    lines.append(line)
                else:
                    lines.append(f"- [ ] {name}: see broker's website for opt-out")
            lines.append("")

    no_action = remediation.get("no_action_available") or []
    if no_action:
        lines += ["### No Action Available", ""]
        for item in no_action:
            lines.append(f"- ℹ️ {item}")
        lines.append("")

    lines += ["---", "", "## Where We Looked", ""]
    if state.hibp_result and state.hibp_result.success:
        lines.append(
            f"- **HIBP:** {state.hibp_result.data.get('breach_count',0)} breaches"
        )
    if state.dehashed_result and state.dehashed_result.success:
        d = state.dehashed_result.data
        if d.get("total", 0):
            lines.append(
                f"- **DeHashed:** {d.get('total',0)} records — "
                f"{d.get('plaintext_password_count',0)} plaintext, "
                f"{d.get('hashed_password_count',0)} hashed passwords"
            )
    if state.whoxy_result and state.whoxy_result.success:
        d = state.whoxy_result.data
        if d.get("total_results", 0):
            lines.append(
                f"- **Whoxy:** {d.get('total_results',0)} domains registered — "
                f"{d.get('active_domain_count',0)} active, "
                f"{d.get('expired_domain_count',0)} expired"
            )
    if state.paste_result and state.paste_result.success:
        d = state.paste_result.data
        if d.get("paste_count", 0):
            lines.append(
                f"- **Paste sites:** {d.get('paste_count',0)} pastes — "
                f"{d.get('recent_paste_count',0)} posted within 90 days"
            )
            for entry in d.get("pastes") or []:
                count_note = (
                    f" — {entry.get('credential_count',0)} addresses"
                    if entry.get("credential_count")
                    else ""
                )
                lines.append(
                    f"  - [{entry.get('paste_id')}]({entry.get('url')}) "
                    f"({entry.get('date')}){count_note}"
                )
    if state.stealer_result and state.stealer_result.success:
        d = state.stealer_result.data
        if d.get("found"):
            families = ", ".join(d.get("malware_families") or [])
            lines.append(
                f"- **Infostealer logs:** {d.get('stealer_count',0)} hit(s) "
                f"— {families} "
                f"({d.get('earliest_compromise','?')} → {d.get('latest_compromise','?')})"
            )
            for log in d.get("logs") or []:
                lines.append(
                    f"  - {log.get('malware_family')} on `{log.get('computer_name')}` "
                    f"({log.get('date_compromised')}) — "
                    f"{log.get('credential_count',0)} credentials stolen"
                )
    if state.blackbird_result and state.blackbird_result.success:
        lines.append(
            f"- **Blackbird:** {state.blackbird_result.data.get('found_count',0)} accounts found"
        )
    if state.sherlock_result and state.sherlock_result.success:
        lines.append(
            f"- **Maigret:** {state.sherlock_result.data.get('found_count',0)} profiles found across {state.sherlock_result.data.get('platforms_checked',0)} platforms"
        )
    if state.ghunt_result and state.ghunt_result.success:
        lines.append(
            f"- **GHunt:** {'Found' if state.ghunt_result.data.get('found') else 'Not found'}"
        )
    if state.holehe_result and state.holehe_result.success:
        lines.append(
            f"- **Holehe:** {state.holehe_result.data.get('found_count',0)} registrations found"
        )
    if state.broker_result and state.broker_result.success:
        lines.append(
            f"- **Broker scan:** {state.broker_result.data.get('brokers_found_count',0)} brokers, exposure score {state.broker_result.data.get('exposure_score',0)}/100"
        )
    if state.spiderfoot_result and state.spiderfoot_result.success:
        lines.append(
            f"- **SpiderFoot:** {state.spiderfoot_result.data.get('element_count',0)} elements"
        )
    if state.ai_audit_result and state.ai_audit_result.success:
        lines.append(
            f"- **AI Audit:** {state.ai_audit_result.data.get('high_risk_count',0)} high-risk platforms"
        )
    if (
        state.phone_result
        and state.phone_result.success
        and state.phone_result.data.get("valid")
    ):
        d = state.phone_result.data
        carrier_name = (d.get("carrier") or {}).get("name") or "unknown carrier"
        location = (
            d.get("geocode") or d.get("location") or d.get("country_code") or "unknown"
        )
        voip_tag = " ⚠ VoIP" if d.get("is_voip") else ""
        lines.append(
            f"- **Phone:** {d.get('line_type','?')}{voip_tag} via {carrier_name}, "
            f"registered in {location}"
        )
    if state.public_records_result and state.public_records_result.success:
        d = state.public_records_result.data
        if d.get("court_case_count") or d.get("corporate_record_count"):
            lines.append(
                f"- **Public Records:** {d.get('court_case_count',0)} court cases, "
                f"{d.get('corporate_record_count',0)} corporate records"
            )
            for case in (d.get("court_cases") or [])[:3]:
                lines.append(
                    f"  - *{case.get('case_name')}* — {case.get('court')}, "
                    f"filed {case.get('date_filed')} [{case.get('nature_of_suit','')}]"
                )
            for rec in (d.get("corporate_records") or [])[:3]:
                lines.append(
                    f"  - {rec.get('role','?').title()} at **{rec.get('company_name')}** "
                    f"({rec.get('jurisdiction','?')}, {rec.get('status','?')})"
                )
    if state.commoncrawl_result and state.commoncrawl_result.success:
        d = state.commoncrawl_result.data
        if d.get("present"):
            lines.append(
                f"- **Common Crawl:** present in the public web archive — "
                f"{len(d.get('matched') or [])} property(ies), "
                f"{d.get('total_captures',0)} page capture(s)"
            )

    if state.correlation_results:
        successful = [r for r in state.correlation_results if r.success]
        if successful:
            lines += ["", "### Follow-Up Checks"]
            for r in successful:
                if r.tool == "maigret":
                    lines.append(
                        f"- **Username `{r.input_value}`** — "
                        f"{r.data.get('found_count', 0)} accounts found"
                    )
                    for site in (r.data.get("sites_found") or [])[:5]:
                        lines.append(f"  - {site.get('name')}: {site.get('url', '')}")
                elif r.tool == "public_records":
                    lines.append(
                        f"- **Name `{r.input_value}`** — "
                        f"{r.data.get('court_case_count', 0)} court cases, "
                        f"{r.data.get('corporate_record_count', 0)} corporate records"
                    )
                elif r.tool == "shodan_scan":
                    lines.append(
                        f"- **IP `{r.input_value}`** — "
                        f"{r.data.get('total_open_ports', 0)} open ports, "
                        f"{r.data.get('total_vulns', 0)} CVEs"
                    )
                elif r.tool == "phone_lookup" and r.data.get("valid"):
                    carrier = (r.data.get("carrier") or {}).get("name") or "unknown"
                    loc = r.data.get("location") or r.data.get("country_code") or ""
                    where = f", registered in {loc}" if loc else ""
                    lines.append(
                        f"- **Phone `{r.input_value}`** — "
                        f"{r.data.get('line_type', '?')} via {carrier}{where}"
                    )
                elif r.tool == "hibp":
                    lines.append(
                        f"- **Email `{r.input_value}` (HIBP)** — "
                        f"{r.data.get('breach_count', 0)} breaches"
                    )
                elif r.tool == "holehe":
                    lines.append(
                        f"- **Email `{r.input_value}` (accounts)** — "
                        f"{r.data.get('found_count', 0)} platforms"
                    )

    lines += ["", f"Full results: `{json_path}`"]

    md_content = "\n".join(lines)
    md_path.write_text(md_content)

    # ── PDF ───────────────────────────────────────────────────────────────────
    try:
        _write_pdf(pdf_path, state, analysis, run_id=run_id)
        logger.info("PDF written to %s", pdf_path)
    except Exception as exc:
        logger.warning("PDF generation failed: %s", exc)
        pdf_path = None

    # ── stdout ────────────────────────────────────────────────────────────────
    print(md_content)
    print(f"\nFull results saved to: {json_path}")
    print(f"Report saved to:       {md_path}")
    if pdf_path:
        print(f"PDF saved to:          {pdf_path}")

    logger.info("report written to %s", md_path)
    return str(md_path)
