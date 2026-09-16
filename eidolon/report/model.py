"""Report content, defined once (REFACTOR.3).

``build_report_model(state)`` derives every section of the report as a typed
``ReportModel`` — facts come from ``state.findings`` (the Finding domain),
narrative and derived guidance from ``state.analysis_result``, the threat
vocabulary from ``state.mitre_result``, and per-run coverage from
``state.results``. The renderers (``markdown``, ``pdf``, ``json``) only lay
the model out; neither may invent or drop content, which is what the
renderer-parity test pins.

The leaked-credentials dossier is the ONE caller of
``Credential.password.get_secret_value()`` — the reveal path. Every other
consumer sees the SecretStr masked by construction.

Transitional note: the credential-cleaning helpers and the static framing
strings are duplicated from the legacy ``eidolon/agent/report.py`` so that
renderer stays byte-stable for the parity snapshot; REFACTOR.6 deletes the
legacy copy along with the old renderer.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import cast

from pydantic import BaseModel, Field, SecretStr

from eidolon.core.findings import (
    BrokerExposure,
    CorporateRecord,
    CourtRecord,
    Credential,
    Finding,
    InfostealerLog,
    Paste,
)
from eidolon.core.state import ScanState
from eidolon.utils import load_data

_BAZZELL_DB = Path(__file__).resolve().parent.parent / "data" / "bazzell_brokers.json"


# ── Section models ────────────────────────────────────────────────────────────


class ReportHeader(BaseModel):
    generated: str = ""
    run_id: str = ""
    target: str = ""
    risk_score: int | None = None
    risk_level: str = ""
    results_json_path: str = ""


class KnownGroup(BaseModel):
    title: str
    items: list[str] = []


class DossierRecord(BaseModel):
    """One leaked credential record, cleaned for display.

    ``password`` stays SecretStr — masked in every serialization of the
    model. The plaintext surfaces only through ``display()``, the dossier
    reveal path (the one caller of ``get_secret_value()``).
    """

    username: str = ""
    password: SecretStr | None = None
    password_hash: str = ""
    hash_algo: str = ""
    address: str = ""
    phone: str = ""

    def display(self, reveal: bool = False) -> str:
        """Render one record. Plaintext password only when ``reveal=True`` — the
        gated reveal surface (``report.dossier_lines`` → MCP
        ``reveal_credentials``). Every default caller (the md/pdf renderers,
        ``model_dump``, ``render_json``) leaves it masked, so no plaintext
        credential is ever written to disk or stdout by the normal report path."""
        parts: list[str] = []
        if self.username:
            parts.append(f"username: {self.username}")
        if self.password is not None and self.password.get_secret_value():
            if reveal:
                parts.append(f"password: {self.password.get_secret_value()}")
            else:
                parts.append("password: ********")
        elif self.password_hash:
            parts.append(
                f"hash: {self.password_hash}"
                + (f" ({self.hash_algo})" if self.hash_algo else "")
            )
        if self.address:
            parts.append(f"address: {self.address}")
        if self.phone:
            parts.append(f"phone: {self.phone}")
        return "  ·  ".join(parts)


class DossierGroup(BaseModel):
    source: str = ""
    records: list[DossierRecord] = Field(default_factory=list)


class Dossier(BaseModel):
    intro: str = ""
    groups: list[DossierGroup] = []


class ThreatTechnique(BaseModel):
    headline: str = ""
    severity: str = ""
    what_it_is: str = ""
    why_this_finding: str = ""
    evidence: list[str] = Field(default_factory=list)
    reference: str = ""
    url: str = ""


class ThreatSection(BaseModel):
    intro: str = ""
    techniques: list[ThreatTechnique] = Field(default_factory=list)


class WebProperty(BaseModel):
    target: str = ""
    capture_count: int = 0
    sample_url: str = ""


class TrainingPile(BaseModel):
    intro: str = ""
    headline: str = ""
    index_id: str = ""
    properties: list[WebProperty] = Field(default_factory=list)
    opt_out_title: str = "How to opt out of future AI training crawls"
    opt_out_steps: list[str] = Field(default_factory=list)
    opt_out_note: str = ""


class ActionItem(BaseModel):
    name: str = ""
    what_it_is: str = ""
    why_it_matters: str = ""
    how_to_remove: str = ""
    removal_label: str = ""


class Actions(BaseModel):
    active_intro: str = ""
    active: list[ActionItem] = Field(default_factory=list)
    breach_intro: str = ""
    breach_only: list[ActionItem] = Field(default_factory=list)
    no_action_intro: str = ""
    no_action: list[ActionItem] = Field(default_factory=list)


class RemediationGroup(BaseModel):
    title: str
    items: list[str] = Field(default_factory=list)


class OptOutItem(BaseModel):
    name: str = ""
    url: str = ""
    days: str = "?"
    notes: str = ""


class BazzellOptOuts(BaseModel):
    easyoptouts_covers: int = 0
    tier1: list[OptOutItem] = Field(default_factory=list)
    manual: list[OptOutItem] = Field(default_factory=list)


class CoverageRow(BaseModel):
    label: str = ""
    summary: str = ""
    subitems: list[str] = Field(default_factory=list)


class Coverage(BaseModel):
    rows: list[CoverageRow] = Field(default_factory=list)
    skipped_intro: str = "Not checked — no API token configured:"
    skipped: list[CoverageRow] = Field(default_factory=list)
    follow_ups_title: str = "Follow-Up Checks"
    follow_ups: list[str] = Field(default_factory=list)


class ReportModel(BaseModel):
    header: ReportHeader = Field(default_factory=ReportHeader)
    summary_narrative: str = ""
    known_groups: list[KnownGroup] = Field(default_factory=list)
    dossier: Dossier | None = None
    top_risks: list[str] = Field(default_factory=list)
    threat: ThreatSection | None = None
    training_pile: TrainingPile | None = None
    actions: Actions | None = None
    remediation_groups: list[RemediationGroup] = Field(default_factory=list)
    bazzell: BazzellOptOuts | None = None
    no_action_items: list[str] = Field(default_factory=list)
    coverage: Coverage | None = None

    def section_titles(self) -> list[str]:
        """The ordered H2 titles of present sections — the one list every
        renderer (and the parity test) must agree on. A section missing from
        here must be missing from every renderer."""
        titles: list[str] = []
        if self.summary_narrative or self.known_groups:
            titles.append("What the Internet Knows About You")
        if self.dossier and self.dossier.groups:
            titles.append("Your Actual Leaked Data")
        if self.top_risks:
            titles.append("Top Risks")
        if self.threat and self.threat.techniques:
            titles.append("What Someone Could Do With This")
        if self.training_pile and self.training_pile.properties:
            titles.append("Your Content in the AI Training Pile")
        if self.actions:
            if self.actions.active:
                titles.append("Active Accounts — Take Action")
            if self.actions.breach_only:
                titles.append("Breach Records — Request Data Deletion")
            if self.actions.no_action:
                titles.append("No Action Available")
        if self.remediation_groups or self.bazzell or self.no_action_items:
            titles.append("What To Do")
        if self.coverage and (
            self.coverage.rows or self.coverage.skipped or self.coverage.follow_ups
        ):
            titles.append("Where We Looked")
        return titles


# ── Credential cleaning (duplicated from the legacy renderer, transitional) ──


def _clean_cred_username(u: str) -> str:
    """DeHashed packs multiple values into one field; keep the first real one."""
    u = (u or "").split(",")[0].strip()
    return "" if len(u) < 3 or u.isdigit() else u


def _clean_cred_address(a: str) -> str:
    """Show only real addresses (street number present)."""
    a = (a or "").strip()
    return a if (len(a) >= 6 and re.search(r"\d", a)) else ""


def _clean_cred_hash(h: str) -> tuple[str, str]:
    """DeHashed formats hashes as 'hash:salt||ALGO' — split out hash + algo."""
    from eidolon.sources.dehashed import _hash_type

    raw = (h or "").split("||")[0].split(":")[0].strip()
    if "||" in (h or ""):
        algo = h.rsplit("||", 1)[-1].strip().strip("|").strip()
    else:
        algo = _hash_type(raw)
    return raw, algo


# ── Static framing (identical strings in every renderer) ─────────────────────

TRAINING_PILE_INTRO = (
    "Common Crawl is a free, openly published archive of the public web — "
    "the raw corpus that most AI training sets (like Google's C4) are "
    "filtered and built FROM. Your pages showing up here means your public "
    "content is in that upstream pile. It does **not** mean any specific AI "
    "model memorized you or was trained on you — only that your content is in "
    "the corpus training data is sourced from."
)

TRAINING_PILE_OPT_OUT_STEPS = [
    "Register your content with Spawning's **Do Not Train** registry at "
    "<https://haveibeentrained.com> (spawning.ai) so participating AI "
    "trainers skip it.",
    "Add an **ai.txt** file to your site (and robots rules) to signal that "
    "AI crawlers should not collect your pages going forward.",
]

TRAINING_PILE_OPT_OUT_NOTE = (
    "_Opting out only affects future crawls. It cannot remove content "
    "already in existing archives or datasets._"
)

THREAT_INTRO = (
    "{count} thing(s) a stranger could realistically try with what's already "
    "exposed. (These map to MITRE ATT&CK, a standard catalog of real-world "
    "attacker behaviour — the codes are just for reference.)"
)

# Fixed order + titles of the remediation groups (identical in every renderer).
_REMEDIATION_GROUPS: list[tuple[str, str]] = [
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

# what_is_known key → rendered subsection title (identical in every renderer).
_KNOWN_GROUPS: list[tuple[str, str]] = [
    ("handles_and_usernames", "Usernames & Handles"),
    ("platforms_with_accounts", "Accounts Found"),
    ("physical_data", "Physical Data Exposed"),
    ("credentials_exposed", "Passwords That Have Leaked"),
    ("google_footprint", "Google Footprint"),
    ("breach_history", "Where Your Data Has Shown Up"),
]

# Source name → coverage row label (identical in every renderer).
_SOURCE_LABELS: dict[str, str] = {
    "hibp": "HIBP",
    "dehashed": "DeHashed",
    "whoxy": "Whoxy",
    "paste": "Paste sites",
    "stealer": "Infostealer logs",
    "holehe": "Holehe",
    "blackbird": "Blackbird",
    "maigret": "Maigret",
    "ghunt": "GHunt",
    "spiderfoot": "SpiderFoot",
    "broker_scan": "Broker scan",
    "shodan": "Shodan",
    "ai_audit": "AI Audit",
    "phone_lookup": "Phone",
    "public_records": "Public Records",
    "commoncrawl": "Common Crawl",
}

#: canonical row order (the legacy markdown order); unknown sources append.
_SOURCE_ORDER: list[str] = [
    "hibp",
    "dehashed",
    "whoxy",
    "paste",
    "stealer",
    "blackbird",
    "maigret",
    "ghunt",
    "holehe",
    "broker_scan",
    "spiderfoot",
    "shodan",
    "ai_audit",
    "phone_lookup",
    "public_records",
    "commoncrawl",
]

_MECH_LABELS = {
    "gdpr": "GDPR erasure (EU/UK)",
    "ccpa": "CCPA deletion (US)",
    "optout": "Opt-out",
    "account_deletion": "Delete account",
}


def _rem_item(item: object) -> str:
    """Normalize a remediation item (defensive against dict shapes)."""
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


# ── Section builders (each returns None when the section has no content) ─────


def _build_dossier(findings: list[Finding]) -> Dossier | None:
    """The leaked-credentials dossier, grouped by source breach.

    The reveal path is ``DossierRecord.display()`` — nothing else reads the
    SecretStr. Values are cleaned at build time (display cleaning is content
    derivation); the plaintext surfaces only at render time.
    """
    by_db: dict[str, list[DossierRecord]] = {}
    for f in findings:
        if not isinstance(f, Credential):
            continue
        raw_hash, algo = (
            _clean_cred_hash(f.password_hash) if f.password_hash else ("", "")
        )
        record = DossierRecord(
            username=_clean_cred_username(f.username),
            password=f.password,
            password_hash=raw_hash,
            hash_algo=algo,
            address=_clean_cred_address(f.address),
            phone=f.phone,
        )
        if record.display():
            db = f.source_breach or "Unknown source"
            by_db.setdefault(db, []).append(record)
    if not by_db:
        return None
    groups = [DossierGroup(source=db, records=items) for db, items in by_db.items()]
    n = sum(len(g.records) for g in groups)
    return Dossier(
        intro=(
            "_Actual records found in breach dumps for this exact mailbox — "
            f"{n} record(s) across {len(groups)} source(s). "
            "Passwords are masked here; use reveal_credentials to view them._"
        ),
        groups=groups,
    )


def _build_threat(state: ScanState) -> ThreatSection | None:
    techniques = state.mitre_techniques
    if not techniques:
        return None
    out = ThreatSection(intro="_" + THREAT_INTRO.format(count=len(techniques)) + "_")
    for t in techniques:
        out.techniques.append(
            ThreatTechnique(
                headline=t.headline or t.name,
                severity=(t.severity or "").upper(),
                what_it_is=t.what_it_is,
                why_this_finding=t.why_this_finding,
                evidence=list(t.evidence),
                reference=f"{t.technique_id} {t.name} ({t.tactic})",
                url=t.url,
            )
        )
    return out


def _build_training_pile(state: ScanState) -> TrainingPile | None:
    props = state.generic_findings("web_presence")
    if not props:
        return None
    total = sum(int(f.payload.get("capture_count", 0) or 0) for f in props)
    index_id = str((props[0].payload.get("index_id") if props[0].payload else "") or "")
    return TrainingPile(
        intro=TRAINING_PILE_INTRO,
        headline=(
            f"Found in {len(props)} web property(ies) — {total} page capture(s)"
            + (f" (index {index_id})" if index_id else "")
            + ":"
        ),
        index_id=index_id,
        properties=[
            WebProperty(
                target=str(f.payload.get("target", "")),
                capture_count=int(f.payload.get("capture_count", 0) or 0),
                sample_url=str(f.payload.get("sample_url", "")),
            )
            for f in props
        ],
        opt_out_steps=TRAINING_PILE_OPT_OUT_STEPS,
        opt_out_note=TRAINING_PILE_OPT_OUT_NOTE,
    )


def _build_actions(analysis: dict) -> Actions | None:
    findings_ctx = analysis.get("findings_context") or []
    active = [
        f
        for f in findings_ctx
        if f.get("removable") is not False and f.get("account_is_active") is True
    ]
    breach_only = [
        f
        for f in findings_ctx
        if f.get("removable") is not False and f.get("account_is_active") is not True
    ]
    no_action = [f for f in findings_ctx if f.get("removable") is False]

    def _item(f: dict) -> ActionItem:
        return ActionItem(
            name=str(f.get("name", "")),
            what_it_is=str(f.get("what_it_is", "")),
            why_it_matters=str(f.get("why_it_matters", "")),
            how_to_remove=str(f.get("how_to_remove") or ""),
            removal_label=_MECH_LABELS.get(str(f.get("removal_mechanism") or ""), ""),
        )

    if not (active or breach_only or no_action):
        return None
    return Actions(
        active_intro=(
            "You have confirmed active accounts on these services. "
            "Delete the account and/or submit a data deletion request."
        ),
        active=[_item(f) for f in active],
        breach_intro=(
            "Your data appeared in breaches from these services. You may not have an "
            "active account, but you can still submit a CCPA or GDPR deletion request. "
            "Breach archive copies held by third parties cannot be removed."
        ),
        breach_only=[_item(f) for f in breach_only],
        no_action_intro=(
            "These findings are in public archives or threat intel datasets. "
            "No removal is possible."
        ),
        no_action=[_item(f) for f in no_action],
    )


def _load_bazzell_db() -> dict[str, dict]:
    """domain -> broker entry map from bazzell_brokers.json."""
    try:
        entries = cast(list, load_data("bazzell_brokers.json"))
        return {e["domain"]: e for e in entries}
    except Exception:
        return {}


def _build_bazzell(findings: list[Finding]) -> BazzellOptOuts | None:
    """Priority opt-outs from the found brokers × the Bazzell removal DB."""
    exposures = [f for f in findings if isinstance(f, BrokerExposure)]
    if not exposures:
        return None
    db = _load_bazzell_db()
    tier1: list[OptOutItem] = []
    manual: list[OptOutItem] = []
    easyoptouts_count = 0
    for f in exposures:
        domain = (f.domain or "").lower().removeprefix("www.")
        entry = db.get(domain)
        if not entry:
            continue
        item = OptOutItem(
            name=str(entry.get("name", f.broker)),
            url=str(entry.get("optout_url", "")),
            days=str(entry.get("estimated_days_to_remove", "?")),
            notes=str(entry.get("notes", "")),
        )
        if entry.get("tier") == 1:
            tier1.append(item)
        if entry.get("easyoptouts_covered"):
            easyoptouts_count += 1
        else:
            manual.append(item)
    if not (tier1 or manual):
        return None
    return BazzellOptOuts(
        easyoptouts_covers=easyoptouts_count, tier1=tier1, manual=manual
    )


def _build_coverage(state: ScanState, findings: list[Finding]) -> Coverage | None:
    """Where we looked: one row per ran source, from the SourceResult envelopes
    plus finding-level detail lines. Skipped sources are listed explicitly so
    a missing key never reads as "checked, nothing found"."""
    rows: list[CoverageRow] = []
    skipped: list[CoverageRow] = []
    order = [n for n in _SOURCE_ORDER if n in state.results]
    order += sorted(n for n in state.results if n not in _SOURCE_ORDER)
    for name in order:
        sr = state.results[name]
        label = _SOURCE_LABELS.get(name, name)
        if sr.status == "skipped":
            skipped.append(
                CoverageRow(label=label, summary=str(sr.detail or "not checked"))
            )
            continue
        if sr.status != "ok" or not sr.summary:
            continue
        row = CoverageRow(label=label, summary=sr.summary)
        row.subitems = _coverage_subitems(name, findings)
        rows.append(row)

    follow_ups = _follow_up_lines(state)

    if not (rows or skipped or follow_ups):
        return None
    return Coverage(rows=rows, skipped=skipped, follow_ups=follow_ups)


def _coverage_subitems(name: str, findings: list[Finding]) -> list[str]:
    """Detail lines under a coverage row, from findings."""
    if name == "paste":
        out: list[str] = []
        for f in findings:
            if not isinstance(f, Paste):
                continue
            count_note = (
                f" — {f.credential_count} addresses" if f.credential_count else ""
            )
            out.append(f"[{f.paste_id}]({f.url}) ({f.date}){count_note}")
        return out
    if name == "stealer":
        return [
            f"{f.malware_family} on `{f.computer_name}` ({f.date_compromised}) — "
            f"{f.credential_count} credentials stolen"
            for f in findings
            if isinstance(f, InfostealerLog)
        ]
    if name == "public_records":
        out = [
            f"*{c.case_name}* — {c.court}, filed {c.date_filed} "
            f"[{c.nature_of_suit}]"
            for c in findings
            if isinstance(c, CourtRecord)
        ][:3]
        out += [
            f"{r.role.title()} at **{r.company_name}** ({r.jurisdiction}, {r.status})"
            for r in findings
            if isinstance(r, CorporateRecord)
        ][:3]
        return out
    return []


def _follow_up_lines(state: ScanState) -> list[str]:
    """Correlation pivot summaries, from the typed CorrelationRun records
    (run-level facts — the pivots' findings already live in state.findings)."""
    kind_labels = {
        "username": "Username",
        "name": "Name",
        "ip": "IP",
        "phone": "Phone",
        "email": "Email",
    }
    out: list[str] = []
    for run in state.correlation_runs:
        if run.status != "ok" or not run.summary:
            continue
        label = kind_labels.get(run.pivot_type, run.pivot_type.title())
        out.append(f"**{label} `{run.value}` ({run.source})** — {run.summary}")
    return out


# ── The model builder ─────────────────────────────────────────────────────────


def build_report_model(state: ScanState, *, results_json_path: str = "") -> ReportModel:
    """Derive the full report content from one scan state."""
    # analysis_result can be AnalysisResult model or dict (backward compat)
    ar = state.analysis_result
    if ar is None:
        analysis = {}
    elif hasattr(ar, "model_dump"):
        analysis = ar.model_dump()
    else:
        analysis = ar
    known: dict[str, list[str]] = analysis.get("what_is_known", {}) or {}
    remediation: dict[str, list[str]] = analysis.get("remediation", {}) or {}
    findings = list(state.findings)

    primary = state.classifications[0] if state.classifications else None
    model = ReportModel(
        header=ReportHeader(
            generated=datetime.now().strftime("%Y-%m-%d"),
            run_id=state.run_id,
            target=primary.value if primary else "unknown",
            risk_score=analysis.get("overall_risk_score"),
            risk_level=str(analysis.get("overall_risk_level", "")).upper(),
            results_json_path=results_json_path,
        ),
        summary_narrative=str(analysis.get("identity_summary", "")),
        known_groups=[
            KnownGroup(title=title, items=[str(i) for i in (known.get(key) or [])])
            for key, title in _KNOWN_GROUPS
            if known.get(key)
        ],
        dossier=_build_dossier(findings),
        top_risks=[str(r) for r in (analysis.get("top_risks") or [])],
        threat=_build_threat(state),
        training_pile=_build_training_pile(state),
        actions=_build_actions(analysis),
        remediation_groups=[
            RemediationGroup(
                title=title, items=[_rem_item(i) for i in (remediation.get(key) or [])]
            )
            for key, title in _REMEDIATION_GROUPS
            if remediation.get(key)
        ],
        bazzell=_build_bazzell(findings),
        no_action_items=[
            _rem_item(i) for i in (remediation.get("no_action_available") or [])
        ],
        coverage=_build_coverage(state, findings),
    )
    return model
