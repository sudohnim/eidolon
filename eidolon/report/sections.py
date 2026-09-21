"""Report section models (REFACTOR.6).

The typed content of every report section, defined once. ``ReportModel``
(section_titles) is the single source the renderers lay out; nothing in
``markdown`` / ``pdf`` / ``json`` may invent or drop content. ``build_report_model``
lives in ``builders``; this module holds the shapes only.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, SecretStr


class ReportHeader(BaseModel):
    generated: str = ""
    run_id: str = ""
    target: str = ""
    #: confidence-qualified basis for the score, e.g.
    #: "24 confirmed, 1 possible; 55 unverified excluded"
    confidence_summary: str = ""
    authorized_by: str = ""
    authorization_reason: str = ""
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


class Changes(BaseModel):
    """What changed since the previous scan — the temporal view (#4)."""

    intro: str = ""
    new_findings: list[str] = Field(default_factory=list)
    resolved_findings: list[str] = Field(default_factory=list)


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


# ── Evidence / egress / run-health appendix (EVIDENCE.2, OPSEC.5, RESILIENCE.4)


#: operator reference — nothing here is narrative; the report body never quotes it.
class EvidenceRow(BaseModel):
    """One ran source's provenance: what was retrieved, when, and a replay hash."""

    source: str = ""
    tool_version: str = ""
    source_host: str = ""  # vendor host only
    latency_ms: int = 0
    response_sha256: str = ""  # empty on skipped sources (nothing to replay)
    egress_proxied: bool = False


class EgressRow(BaseModel):
    """One ran source's egress exposure profile + whether a proxy was in effect."""

    source: str = ""
    logs_api_key: bool = True
    logs_source_ip: bool = True
    third_party: bool = True
    proxied: bool = False


class SelectorRow(BaseModel):
    """One selector and what it produced — the pivot lineage an analyst reads to
    answer "how did we get here"."""

    value: str = ""
    origin: str = "input"  # "input" or "derived"
    #: how a derived selector was obtained, e.g. "email local-part"
    derivation: str = ""
    #: how strongly this selector belongs to the target — caps its findings
    confidence: str = ""
    finding_count: int = 0


class RunHealth(BaseModel):
    """At-a-glance run rollup: sources by status + total wall time."""

    ok: int = 0
    skipped: int = 0
    error: int = 0
    wall_time_ms: int = 0


class ReportAppendix(BaseModel):
    evidence: list[EvidenceRow] = Field(default_factory=list)
    egress: list[EgressRow] = Field(default_factory=list)
    selectors: list[SelectorRow] = Field(default_factory=list)
    run_health: RunHealth | None = None


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
    changes: Changes | None = None
    coverage: Coverage | None = None
    appendix: ReportAppendix | None = None

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
        if self.changes and (
            self.changes.new_findings or self.changes.resolved_findings
        ):
            titles.append("What Changed Since Last Scan")
        if self.coverage and (
            self.coverage.rows or self.coverage.skipped or self.coverage.follow_ups
        ):
            titles.append("Where We Looked")
        if self.appendix and (
            self.appendix.evidence or self.appendix.egress or self.appendix.run_health
        ):
            titles.append("Evidence, Egress & Run Health")
        return titles
