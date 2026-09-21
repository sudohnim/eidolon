"""Report content derivation — one typed ``ReportModel`` per scan (REFACTOR.6).

Facts come from ``state.findings`` (the Finding domain), narrative and
derived guidance from ``state.analysis_result``, the threat vocabulary from
``state.mitre_result``, and per-run coverage from ``state.results``. The
renderers only lay the model out; neither may invent or drop content.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import cast

from eidolon.core.findings import (
    BrokerExposure,
    Confidence,
    CorporateRecord,
    CourtRecord,
    Credential,
    Finding,
    InfostealerLog,
    Paste,
)
from eidolon.core.state import ScanState
from eidolon.report.sections import (
    ActionItem,
    Actions,
    BazzellOptOuts,
    Changes,
    Coverage,
    CoverageRow,
    Dossier,
    DossierGroup,
    DossierRecord,
    EgressRow,
    EvidenceRow,
    KnownGroup,
    OptOutItem,
    RemediationGroup,
    ReportAppendix,
    ReportHeader,
    ReportModel,
    RunHealth,
    SelectorRow,
    ThreatSection,
    ThreatTechnique,
    TrainingPile,
    WebProperty,
)
from eidolon.report.text import (
    _KNOWN_GROUPS,
    _MECH_LABELS,
    _REMEDIATION_GROUPS,
    _SOURCE_LABELS,
    _SOURCE_ORDER,
    THREAT_INTRO,
    TRAINING_PILE_INTRO,
    TRAINING_PILE_OPT_OUT_NOTE,
    TRAINING_PILE_OPT_OUT_STEPS,
    _clean_cred_address,
    _clean_cred_hash,
    _clean_cred_username,
    _rem_item,
)
from eidolon.utils import load_data

_BAZZELL_DB = Path(__file__).resolve().parent.parent / "data" / "bazzell_brokers.json"


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


def _confidence_summary(findings: list[Finding]) -> str:
    """Confidence-qualified basis for the score — what an analyst needs to judge
    how much the number is worth."""
    counts: dict[str, int] = {}
    for f in findings:
        key = getattr(f.confidence, "value", str(f.confidence))
        counts[key] = counts.get(key, 0) + 1
    scored = [
        f"{counts[k]} {k}"
        for k in ("confirmed", "probable", "possible")
        if counts.get(k)
    ]
    basis = ", ".join(scored) or "no verified findings"
    excluded = counts.get("unverified", 0)
    tail = f"; {excluded} unverified excluded" if excluded else ""
    return f"{basis}{tail}"


def _build_selectors(state: ScanState, findings: list[Finding]) -> list[SelectorRow]:
    """Pivot lineage: every selector searched on, how it was obtained, and what
    it produced. A derived selector caps the confidence of its findings, so this
    is where an analyst sees WHY a pile of hits is rated unverified."""
    counts: dict[str, int] = {}
    for f in findings:
        if f.selector:
            counts[f.selector] = counts.get(f.selector, 0) + 1
    rows = [
        SelectorRow(
            value=sel.value,
            origin=sel.origin,
            derivation=sel.derivation,
            confidence=getattr(sel.confidence, "value", str(sel.confidence)),
            finding_count=counts.get(sel.value, 0),
        )
        for sel in state.selectors
    ]
    rows.sort(key=lambda r: (r.origin != "input", -r.finding_count, r.value))
    return rows


def _build_changes(state: ScanState) -> "Changes | None":
    """Temporal section: what appeared / disappeared since the previous scan."""
    d = state.diff
    if not d or not d.compared:
        return None
    if not (d.new_findings or d.resolved_findings):
        return None
    return Changes(
        intro=(
            f"_Compared against the previous scan of this target: "
            f"{len(d.new_findings)} new, {len(d.resolved_findings)} no longer "
            f"present, {d.unchanged_count} unchanged._"
        ),
        new_findings=list(d.new_findings)[:15],
        resolved_findings=list(d.resolved_findings)[:15],
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
        row.subitems = _confidence_note(name, findings) + _coverage_subitems(
            name, findings
        )
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
        courts = [c for c in findings if isinstance(c, CourtRecord)]
        corps = [c for c in findings if isinstance(c, CorporateRecord)]
        out = []
        out += [
            f"*{c.case_name}* — {c.court}, filed {c.date_filed} "
            f"[{c.nature_of_suit}]"
            for c in courts
        ][:3]
        out += [
            f"{r.role.title()} at **{r.company_name}** ({r.jurisdiction}, {r.status})"
            for r in corps
        ][:3]
        return out
    return []


def _confidence_note(name: str, findings: list[Finding]) -> list[str]:
    """Data-driven caveat: if every finding a source produced is UNVERIFIED, say
    so once, here — derived from Finding.confidence rather than hardcoded per
    source, so a new source inherits the honesty automatically."""
    mine = [f for f in findings if f.provenance.source == name]
    if mine and all(f.confidence == Confidence.UNVERIFIED for f in mine):
        return [
            "_unverified — same name/handle is not the same person; "
            "excluded from the risk score_"
        ]
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


def _load_egress_profile() -> dict:
    """Static per-source egress exposure profile (OPSEC.5)."""
    try:
        profile = load_data("egress_profile.json")
        return profile if isinstance(profile, dict) else {}
    except Exception:
        return {}


def _build_appendix(state: ScanState) -> ReportAppendix | None:
    """Evidence + egress + run-health appendix (EVIDENCE.2 / OPSEC.5 /
    RESILIENCE.4). Operator reference only — derived from the stamped
    Provenance on each ran SourceResult, never from raw results."""
    evidence: list[EvidenceRow] = []
    egress_rows: list[EgressRow] = []
    profile = _load_egress_profile()
    counts = {"ok": 0, "skipped": 0, "error": 0}
    times: list[datetime] = []

    order = [n for n in _SOURCE_ORDER if n in state.results]
    order += sorted(n for n in state.results if n not in _SOURCE_ORDER)

    for name in order:
        sr = state.results[name]
        counts[sr.status] = counts.get(sr.status, 0) + 1
        ev = sr.evidence
        if ev is None:
            continue
        if ev.retrieved_at is not None:
            times.append(ev.retrieved_at)
        evidence.append(
            EvidenceRow(
                source=name,
                tool_version=ev.tool_version,
                source_host=ev.source_host,
                latency_ms=ev.latency_ms,
                response_sha256=ev.response_sha256,
                egress_proxied=ev.egress_proxied,
            )
        )
        p = profile.get(name, {})
        egress_rows.append(
            EgressRow(
                source=name,
                logs_api_key=bool(p.get("logs_api_key", True)),
                logs_source_ip=bool(p.get("logs_source_ip", True)),
                third_party=bool(p.get("third_party", True)),
                proxied=ev.egress_proxied,
            )
        )

    if not evidence and not egress_rows:
        return None

    wall_ms = 0
    if len(times) >= 2:
        wall_ms = int((max(times) - min(times)).total_seconds() * 1000)
    health = RunHealth(
        ok=counts["ok"],
        skipped=counts["skipped"],
        error=counts["error"],
        wall_time_ms=wall_ms,
    )
    return ReportAppendix(
        evidence=evidence,
        egress=egress_rows,
        selectors=_build_selectors(state, list(state.findings)),
        run_health=health,
    )


# ── The model builder ─────────────────────────────────────────────────────────


def build_report_model(state: ScanState, *, results_json_path: str = "") -> ReportModel:
    """Derive the full report content from one scan state."""
    # analysis_result can be AnalysisResult model or dict (backward compat)
    ar = state.analysis_result
    if ar is None:
        analysis = {}
    elif isinstance(ar, dict):
        analysis = ar
    else:
        analysis = ar.model_dump()
    known: dict[str, list[str]] = analysis.get("what_is_known", {}) or {}
    remediation: dict[str, list[str]] = analysis.get("remediation", {}) or {}
    findings = list(state.findings)

    primary = state.classifications[0] if state.classifications else None
    model = ReportModel(
        header=ReportHeader(
            generated=datetime.now().strftime("%Y-%m-%d"),
            run_id=state.run_id,
            target=primary.value if primary else "unknown",
            confidence_summary=_confidence_summary(findings),
            authorized_by=state.authorization.operator if state.authorization else "",
            authorization_reason=(
                state.authorization.reason if state.authorization else ""
            ),
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
        changes=_build_changes(state),
        coverage=_build_coverage(state, findings),
        appendix=_build_appendix(state),
    )
    return model
