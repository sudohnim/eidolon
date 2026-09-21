from datetime import datetime
from typing import Literal, TypeVar

from pydantic import BaseModel

from eidolon.core.authorization import Authorization
from eidolon.core.findings import Confidence, Finding, FindingUnion, Provenance

InputType = Literal["email", "phone", "name", "org"]

F = TypeVar("F", bound=Finding)


class ToolResult(BaseModel):
    success: bool
    tool: str
    input_type: InputType
    input_value: str
    timestamp: datetime
    data: dict
    error: str | None = None
    # "ok"      — ran, result in data (may legitimately be empty = nothing found)
    # "skipped" — not configured (no API key); NOT the same as "found nothing"
    # "error"   — ran and failed (error holds the message)
    status: Literal["ok", "skipped", "error"] = "ok"


class InputClassification(BaseModel):
    type: Literal["email", "phone", "name", "org"]
    value: str
    raw: str


class SourceResult(BaseModel):
    """One source's contribution to a scan: the collect() envelope.

    ``findings`` are stamped with ``Provenance`` by ``collect()`` — every
    downstream consumer trusts that stamp. ``summary`` is the source's own
    one-line account of its run ("3 breaches", "4 profiles / 3155 platforms")
    — run facts that are about the check, not facts about the target, so they
    live here rather than as findings.
    """

    name: str = ""
    status: Literal["ok", "skipped", "error"] = "ok"
    findings: list[FindingUnion] = []
    detail: str | None = None
    summary: str = ""
    #: the run's stamped Provenance (EVIDENCE.1) — sha256/source_host/latency,
    #: present on every ran source; None only when a source never ran.
    evidence: Provenance | None = None


class SourceCoverage(BaseModel):
    """One source's run status — the coverage rollup consumers render."""

    name: str = ""
    status: Literal["ok", "skipped", "error"] = "ok"
    detail: str | None = None


class MitreTechnique(BaseModel):
    """One mapped MITRE ATT&CK technique (deterministic analysis output).

    Lives in core (not tools/mitre.py) so the scan state can carry techniques
    as a typed field without an import cycle."""

    technique_id: str = ""  # "T1555"
    name: str = ""  # "Credentials from Password Stores"
    headline: str = ""  # plain-English title for non-technical readers
    tactic: str = ""  # "Credential Access"
    tactic_id: str = ""  # "TA0006"
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    what_it_is: str = ""  # plain-English: what the technique is
    why_this_finding: str = ""  # plain-English: why our finding enables it
    url: str = ""  # official attack.mitre.org page
    evidence: list[str] = []  # findings that map to this technique


class CorrelationRun(BaseModel):
    """One executed correlation pivot, as a consumer-readable record.

    The pivot's findings already merged into ``state.findings``; this carries
    the run-level facts (what value was pivoted on, what the re-run reported)
    so no consumer re-parses the pivot ToolResults.
    """

    pivot_type: str = ""
    value: str = ""
    source: str = ""
    status: Literal["ok", "skipped", "error"] = "ok"
    summary: str = ""


class Selector(BaseModel):
    """One identifier the scan searched on, and how much it belongs to the target.

    Entity resolution starts here: an OPERATOR-SUPPLIED selector is the target by
    definition (CONFIRMED). A DERIVED one — a username guessed from an email
    local-part, a name lifted from a third-party profile — is a hypothesis until
    something verifies it, so it starts UNVERIFIED.

    The load-bearing rule: **a finding is never more confident than the selector
    that produced it.** That is what stops a guessed handle's 49 hits from being
    presented as the target's accounts.
    """

    kind: str = ""  # email / phone / name / username / other
    value: str = ""
    origin: Literal["input", "derived"] = "input"
    #: the selector this one was derived from (empty for inputs)
    derived_from: str = ""
    #: how it was derived, e.g. "email local-part"
    derivation: str = ""
    confidence: Confidence = Confidence.UNVERIFIED


class ScanDiff(BaseModel):
    """What changed since the previous scan of this target.

    ``compared`` is False on a first-ever scan — distinct from "compared and
    nothing changed", which a bare empty diff could not express.
    """

    compared: bool = False
    new_findings: list[str] = []
    resolved_findings: list[str] = []
    unchanged_count: int = 0


class ScanState(BaseModel):
    """The scan's state: classifications in, the Finding domain out.

    ``findings`` is the single source of truth for every consumer;
    ``results`` carries the per-source run envelopes (coverage + summaries);
    ``mitre_techniques`` is the deterministic threat-model analysis.
    """

    raw_input: str
    run_id: str = ""
    authorization: Authorization | None = None
    classifications: list[InputClassification] = []
    #: every identifier searched on, input vs derived (entity resolution)
    selectors: list[Selector] = []
    location_city: str | None = None
    location_state: str | None = None
    location_zip: str | None = None
    correlation_plan: list[dict] = []
    correlation_runs: list[CorrelationRun] = []
    findings: list[FindingUnion] = []
    #: run-to-run monitoring result (what appeared/disappeared since last scan)
    diff: ScanDiff | None = None
    results: dict[str, SourceResult] = {}
    mitre_techniques: list[MitreTechnique] = []
    analysis_result: dict | None = None
    report_path: str | None = None

    # ── Finding-domain read API ──────────────────────────────────────────────
    def findings_of(self, cls: type[F]) -> list[F]:
        """All findings of one subtype."""
        return [f for f in self.findings if isinstance(f, cls)]

    def generic_findings(self, kind: str) -> list[Finding]:
        """Base findings of one generic kind (the payload-carrying concepts:
        footprint_element, registered_domain, web_presence)."""
        # isinstance narrows the discriminated union to the base type (every
        # member IS a Finding; the check is for the type checker).
        return [f for f in self.findings if isinstance(f, Finding) and f.kind == kind]

    def coverage(self) -> list[SourceCoverage]:
        """Per-source run status rollup."""
        return [
            SourceCoverage(name=r.name, status=r.status, detail=r.detail)
            for r in self.results.values()
        ]


#: Backward-compatible alias — the state was renamed to ScanState in
#: REFACTOR.5 when the flat per-tool result fields were removed.
PipelineState = ScanState


class WhatIsKnown(BaseModel):
    handles_and_usernames: list[str] = []
    platforms_with_accounts: list[str] = []
    physical_data: list[str] = []
    credentials_exposed: list[str] = []
    google_footprint: list[str] = []
    breach_history: list[str] = []


class Remediation(BaseModel):
    # Credentials & access
    change_passwords: list[str] = []
    enable_2fa: list[str] = []
    account_hygiene: list[str] = []  # revoke OAuth, audit sessions, delete dormant
    # Identity fraud prevention (non-obvious high-value steps)
    credit_freeze: list[str] = []
    identity_fraud_prevention: list[str] = []  # IRS PIN, SSA lock, USPS
    sim_swap_hardening: list[str] = []
    # Account/data reviews
    account_reviews: list[str] = []
    # Legal removal paths — split by jurisdiction
    gdpr_removals: list[str] = []  # EU/UK-HQ services only
    ccpa_removals: list[str] = []  # US companies (CCPA)
    # Data brokers
    broker_optouts: list[str] = []
    # Ongoing monitoring
    monitoring: list[str] = []
    # No action possible
    no_action_available: list[str] = []


class AnalysisResult(BaseModel):
    overall_risk_score: int
    overall_risk_level: Literal["high", "medium", "low"]
    identity_summary: str
    what_is_known: WhatIsKnown
    top_risks: list[str]
    remediation: Remediation
    breach_severity: Literal["high", "medium", "low", "none"] = "none"
    broker_exposure_severity: Literal["high", "medium", "low", "none"] = "none"
    account_exposure_severity: Literal["high", "medium", "low", "none"] = "none"
