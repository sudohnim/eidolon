"""The Finding domain - the canonical typed fact about the target (REFACTOR.1).

Every source adapter emits ``Finding`` objects; every consumer (analysis digest,
report model, MITRE mapping, and later persistence) reads them. This is the one
type that breaks the O(sources x consumers) coupling: a new source lands by
adding ``to_findings`` on its tool, with zero lines changed in any consumer.

Design rules (docs/PLAN.md, Phase REFACTOR decision record - settled):

* ``SecretStr`` for plaintext passwords - redaction becomes a type property:
  every ``model_dump()`` masks it, and the reveal path (the credentials dossier,
  behind ``reveal_credentials``) is the only caller of ``get_secret_value()``.
* ``dedup_key`` is deterministic and stable across scans - the same fact found
  twice is the same key, which later becomes the DB unique key and the
  monitoring-diff identity.
* ``Provenance`` is stamped once, in ``collect()`` - every downstream consumer
  trusts it. It is the single home for the evidence-chain fields (Phase
  EVIDENCE); there is no competing Provenance on ToolResult.
* Default-constructible throughout: every field carries a default so finding
  schemas can never break the ``output_schema()`` empty-construction contract.
* Do not over-model: a subtype exists only for a concept a consumer actually
  renders; everything else stays a base ``Finding`` with a ``payload`` dict of
  JSON primitives.

Types only in this module - no behavior is wired to the pipeline here.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field, SecretStr, TypeAdapter


class Severity(str, Enum):
    """Severity band; ``str`` enum so it serializes as its value."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """How strongly a finding is tied to *this target* — the identity question,
    kept separate from ``Severity`` (how bad it is if true).

    A source declares this from its own epistemics:

    * ``CONFIRMED``  — the source verified the exact selector (a password-reset
      probe proving this email is registered; the email present in a breach
      corpus; a Google account resolved for this address).
    * ``PROBABLE``   — strong indirect tie, or a POSSIBLE fact corroborated by a
      second independent source.
    * ``POSSIBLE``   — plausible but unverified identity (name + location match).
    * ``UNVERIFIED`` — no identity verification at all (a bare username claim, a
      name-only court record). Same name is not the same person.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNVERIFIED = "unverified"


#: ordering for upgrades/comparisons (higher wins on merge)
_CONFIDENCE_RANK: dict[str, int] = {
    Confidence.UNVERIFIED: 0,
    Confidence.POSSIBLE: 1,
    Confidence.PROBABLE: 2,
    Confidence.CONFIRMED: 3,
}


def confidence_rank(c: "Confidence | str") -> int:
    """Rank of a confidence level. Accepts the enum or its raw value — note
    ``str(Confidence.POSSIBLE)`` is ``"Confidence.POSSIBLE"`` on a str-Enum, so
    the lookup must go through ``.value``, never ``str()``."""
    return _CONFIDENCE_RANK.get(getattr(c, "value", c), 0)


class RemovalHint(BaseModel):
    """Deterministic removal path for a removable finding."""

    #: short label, e.g. "gdpr" / "ccpa" / "optout" / "account_deletion"
    mechanism: str = ""
    #: where to act (empty when the path is procedural, not a URL)
    url: str = ""


class Provenance(BaseModel):
    """Where a finding came from and how it was retrieved.

    Folded into one home: the adapter identity, the run envelope (status /
    skip reason), and the evidence-chain fields a replay needs (Phase
    EVIDENCE). ``retrieved_at`` is ``None`` only on a never-stamped finding -
    ``collect()`` always sets it.
    """

    #: adapter name, e.g. "dehashed"
    source: str = ""
    retrieved_at: datetime | None = None
    status: Literal["ok", "skipped", "error"] = "ok"
    #: skip reason / error message
    detail: str | None = None
    #: eidolon.__version__ at scan time
    tool_version: str = ""
    #: vendor host only (never the full URL - no target value leak)
    source_host: str = ""
    latency_ms: int = 0
    #: sha256 of the source's typed output - replayable
    response_sha256: str = ""
    #: was the OPSEC proxy in effect for the retrieval
    egress_proxied: bool = False


class Finding(BaseModel):
    """One normalized, deduplicated fact about the target.

    ``kind`` discriminates the subtypes (see ``FindingUnion``). ``dedup_key``
    is the stable identity, e.g. ``"breach:Adobe"``. Concepts that do not
    merit a subtype ride their specifics in ``payload`` as JSON primitives.
    """

    #: discriminator; overridden with a Literal by each subtype
    kind: str = ""
    dedup_key: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    #: how strongly this is tied to THIS target (identity), vs severity (impact).
    #: Defaults to POSSIBLE: neither claiming verification nor dismissing.
    confidence: Confidence = Confidence.POSSIBLE
    #: sources that independently asserted this same fact (corroboration).
    #: Populated on merge; two independent sources upgrade POSSIBLE -> PROBABLE.
    sources: list[str] = Field(default_factory=list)
    #: pivot lineage: the selector value this finding was derived from, e.g. the
    #: email queried or the username pivoted to. Stamped at the collect boundary.
    selector: str = ""
    #: temporal: when this fact was FIRST observed across scans of this target,
    #: and when it was last seen. Carried forward on re-scan by dedup_key, which
    #: is exactly what makes run-to-run diffs ("2 new breaches") possible.
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    provenance: Provenance = Field(default_factory=Provenance)
    removable: bool = False
    removal: RemovalHint | None = None
    #: JSON primitives only (str/int/float/bool/None/list/dict) - this model
    #: round-trips through ``model_dump_json()``.
    payload: dict[str, Any] = Field(default_factory=dict)


class Breach(Finding):
    """The target's data appeared in a named breach (HIBP)."""

    kind: Literal["breach"] = "breach"
    breach_date: date | None = None
    data_classes: list[str] = Field(default_factory=list)
    #: spam-list breach (marketing lists, not a security incident)
    is_spam_list: bool = False


class Credential(Finding):
    """An actual leaked credential record (DeHashed).

    ``password`` is ``SecretStr`` - masked in every renderer by construction;
    the dossier reveal is the only caller of ``get_secret_value()``.
    """

    kind: Literal["credential"] = "credential"
    username: str = ""
    #: address on the leaked record (may be a dot/+alias of the target)
    email: str = ""
    password: SecretStr | None = None
    password_hash: str = ""
    hash_algo: str = ""
    #: the breach database the record came from
    source_breach: str = ""
    address: str = ""
    phone: str = ""


class Account(Finding):
    """An account the target holds on a platform (Holehe / Blackbird / Maigret).

    ``active`` marks confirmed-live registrations (Holehe / Blackbird probing);
    a username-claim hit (Maigret) is a found profile, not a confirmed account.
    """

    kind: Literal["account"] = "account"
    platform: str = ""
    url: str = ""
    active: bool = False


class BrokerExposure(Finding):
    """A data broker holding a profile on the target (broker scan)."""

    kind: Literal["broker_exposure"] = "broker_exposure"
    broker: str = ""
    #: broker site domain (the key into the Bazzell opt-out DB)
    domain: str = ""
    opt_out_url: str = ""
    #: what the broker has on the target
    data_points: list[str] = Field(default_factory=list)
    #: the BROKER's own match-strength string ("high"/"medium"/...) — distinct
    #: from Finding.confidence, which rates the identity tie to this target.
    match_strength: str = ""


class Paste(Finding):
    """The target's address appeared in a paste-site dump (HIBP pastes)."""

    kind: Literal["paste"] = "paste"
    paste_id: str = ""
    url: str = ""
    #: ISO date string as pasted ("" when the paste carries none)
    date: str = ""
    #: email:password lines for this address in the paste
    credential_count: int = 0
    has_plaintext_password: bool = False
    #: posted within the 90-day recency window (stamped at collect)
    recent: bool = False


class InfostealerLog(Finding):
    """One infostealer log containing the target (Hudson Rock)."""

    kind: Literal["infostealer_log"] = "infostealer_log"
    malware_family: str = ""
    computer_name: str = ""
    date_compromised: str = ""
    #: saved credentials on the infected machine
    credential_count: int = 0


class CourtRecord(Finding):
    """A court case naming the target (CourtListener)."""

    kind: Literal["court_record"] = "court_record"
    case_name: str = ""
    court: str = ""
    date_filed: str = ""
    nature_of_suit: str = ""


class CorporateRecord(Finding):
    """A corporate record tying the target to a company (OpenCorporates)."""

    kind: Literal["corporate_record"] = "corporate_record"
    company_name: str = ""
    role: str = ""
    jurisdiction: str = ""
    status: str = ""


class PhoneIntel(Finding):
    """What the phone number itself reveals (libphonenumber / Numverify)."""

    kind: Literal["phone_intel"] = "phone_intel"
    phone: str = ""
    valid: bool = False
    #: mobile / landline / voip / prepaid / unknown
    line_type: str = ""
    #: throwaway / anonymous-number risk flag
    is_voip: bool = False
    carrier: str = ""
    location: str = ""
    timezones: list[str] = Field(default_factory=list)
    country_code: str = ""


class ExposedHost(Finding):
    """An internet-exposed host tied to the target (Shodan InternetDB)."""

    kind: Literal["exposed_host"] = "exposed_host"
    ip: str = ""
    ports: list[int] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    #: CVE ids open on the host
    vulns: list[str] = Field(default_factory=list)
    org: str = ""
    country: str = ""


class AiTrainingHit(Finding):
    """A platform that trains on consumer data the target uses (AI audit)."""

    kind: Literal["ai_training_hit"] = "ai_training_hit"
    #: platform id (e.g. "discord")
    platform: str = ""
    #: human-facing name (e.g. "Discord")
    display_name: str = ""
    risk_level: str = ""
    trains_by_default: bool = False
    opt_out_available: bool = False
    opt_out_url: str = ""
    #: data categories the platform is known to hold
    data_known: list[str] = Field(default_factory=list)


class GoogleFootprint(Finding):
    """The target's Google account footprint (GHunt)."""

    kind: Literal["google_footprint"] = "google_footprint"
    account_name: str = ""
    services: list[str] = Field(default_factory=list)
    youtube_channel: str = ""
    maps_reviews_count: int = 0


#: Every Finding subtype, in report-render order. A concept earns a place on
#: this list only when a consumer actually renders it (PLAN.md: do not
#: over-model).
FINDING_TYPES: tuple[type[Finding], ...] = (
    Breach,
    Credential,
    Account,
    BrokerExposure,
    Paste,
    InfostealerLog,
    CourtRecord,
    CorporateRecord,
    PhoneIntel,
    ExposedHost,
    AiTrainingHit,
    GoogleFootprint,
)

#: Discriminated union with a base-class fallback - validate/dump a mixed
#: list of findings without losing the subtype: a known ``kind`` resolves to
#: its subtype; any other kind stays a base ``Finding`` (the payload-carrying
#: generic path). ScanState and the JSON report ride on this.
FindingUnion = Union[
    Annotated[
        Union[FINDING_TYPES],  # type: ignore[valid-type]
        Field(discriminator="kind"),
    ],
    Finding,
]

#: Adapter for (de)serializing collections of findings, e.g.
#: ``FindingAdapter.dump_json(state.findings)``.
FindingAdapter: TypeAdapter = TypeAdapter(list[FindingUnion])


#: severity rank for merge precedence (lower = more severe)
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _corroborate(a: Finding, b: Finding, winner: Finding) -> Finding:
    """Record that two sources asserted the same fact, and rate the result.

    Corroboration is the analyst's lever: the same fact from two INDEPENDENT
    sources is stronger than either alone. The merged finding carries the union
    of asserting sources, and a POSSIBLE fact corroborated independently is
    upgraded to PROBABLE. Confirmation is never invented — the highest declared
    confidence of the two always carries (a CONFIRMED source stays CONFIRMED).
    """
    srcs: list[str] = []
    for f in (a, b):
        for s in [*f.sources, f.provenance.source]:
            if s and s not in srcs:
                srcs.append(s)
    best = (
        a.confidence
        if confidence_rank(a.confidence) >= confidence_rank(b.confidence)
        else b.confidence
    )
    if len(srcs) > 1 and confidence_rank(best) == confidence_rank(Confidence.POSSIBLE):
        best = Confidence.PROBABLE
    return winner.model_copy(update={"sources": srcs, "confidence": best})


def _prefer(a: Finding, b: Finding) -> Finding:
    """Pick the better representation of the same dedup_key.

    Deterministic regardless of arrival order: higher confidence wins first
    (identity beats impact — a confirmed fact outranks a louder unverified one),
    then higher severity, then the alphabetically-lower source; full ties keep
    ``a`` (first seen). The winner carries the corroboration of both.
    """
    ca, cb = confidence_rank(a.confidence), confidence_rank(b.confidence)
    if ca != cb:
        return _corroborate(a, b, a if ca > cb else b)
    ra, rb = _SEVERITY_RANK[a.severity], _SEVERITY_RANK[b.severity]
    if ra != rb:
        return _corroborate(a, b, a if ra < rb else b)
    aa, ab = getattr(a, "active", False), getattr(b, "active", False)
    if aa != ab:
        return _corroborate(a, b, a if aa else b)
    sa, sb = a.provenance.source, b.provenance.source
    if sa != sb:
        return _corroborate(a, b, a if sa <= sb else b)
    return _corroborate(a, b, a)


def merge_findings(existing: list[Finding], incoming: list[Finding]) -> list[Finding]:
    """Merge two finding lists into one deduplicated list.

    The domain's core promise — one normalized fact per ``dedup_key`` — applied
    at every write into ``ScanState.findings`` (wave merges, correlation
    pivots, re-runs). The returned order is first-seen; callers that need a
    canonical order sort the result.
    """
    if not incoming:
        return existing
    by_key: dict[str, Finding] = {}
    order: list[str] = []
    for f in list(existing) + list(incoming):
        cur = by_key.get(f.dedup_key)
        if cur is None:
            by_key[f.dedup_key] = f
            order.append(f.dedup_key)
        else:
            by_key[f.dedup_key] = _prefer(cur, f)
    return [by_key[k] for k in order]
