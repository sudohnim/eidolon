"""REFACTOR.1 - the Finding domain: typed facts, before anything is wired.

Locks the domain invariants the pipeline will lean on:
  * dedup_key is stable - two scans of the same fixture produce identical keys
    (the future DB unique key / monitoring-diff identity);
  * SecretStr redaction is a type property - no serializer ever emits the
    plaintext password, and the reveal path is the only reader;
  * every finding schema is default-constructible (PLAN.md rule: new fields on
    output/finding schemas need defaults);
  * the discriminated union round-trips a mixed list through JSON without
    losing subtypes (what ScanState and the JSON report will ride on).
"""

import os
from datetime import date, datetime, timezone

import pytest

os.environ.setdefault("TEST_MODE", "true")

from eidolon.core.findings import (  # noqa: E402
    FINDING_TYPES,
    Account,
    AiTrainingHit,
    Breach,
    BrokerExposure,
    CorporateRecord,
    CourtRecord,
    Credential,
    ExposedHost,
    Finding,
    FindingAdapter,
    GoogleFootprint,
    InfostealerLog,
    Paste,
    PhoneIntel,
    Provenance,
    Severity,
)
from eidolon.utils import load_fixture  # noqa: E402


def _hibp_findings() -> list[Breach]:
    """Map the HIBP fixture to findings - the shape Hibp.to_findings will take
    in REFACTOR.2 (name → dedup_key, ISO date → date, spam flag)."""
    out: list[Breach] = []
    for b in load_fixture("hibp")["breaches"]:
        raw_date = b.get("breach_date") or ""
        out.append(
            Breach(
                dedup_key=f"breach:{b['name']}",
                title=b.get("title") or b["name"],
                severity=Severity.HIGH,
                breach_date=(date.fromisoformat(raw_date) if raw_date else None),
                data_classes=b.get("data_classes") or [],
                is_spam_list=bool(b.get("is_spam_list")),
            )
        )
    return out


class TestDedupKeyStability:
    def test_identical_keys_across_two_scans_of_same_fixture(self):
        """The monitoring-diff identity: re-scan → same facts → same keys."""
        scan_a = _hibp_findings()
        scan_b = _hibp_findings()
        assert [f.dedup_key for f in scan_a] == [f.dedup_key for f in scan_b]
        assert len(scan_a) > 1
        assert all(f.dedup_key.startswith("breach:") for f in scan_a)

    def test_keys_are_order_independent(self):
        """Dedup identity must not depend on list position."""
        scan_a = {f.dedup_key for f in _hibp_findings()}
        scan_b = {f.dedup_key for f in reversed(_hibp_findings())}
        assert scan_a == scan_b


class TestSecretStrRedaction:
    def _cred(self) -> Credential:
        return Credential(
            dedup_key="credential:dehashed:1",
            title="leaked record",
            severity=Severity.CRITICAL,
            password="hunter2",  # type: ignore[arg-type]
            source_breach="Adobe",
        )

    def test_model_dump_masks_plaintext(self):
        dumped = self._cred().model_dump(mode="json")
        assert dumped["password"] != "hunter2"
        assert dumped["password"] == "**********"

    def test_model_dump_json_masks_plaintext(self):
        assert "hunter2" not in self._cred().model_dump_json()

    def test_reveal_path_is_the_only_reader(self):
        assert self._cred().password is not None
        assert self._cred().password.get_secret_value() == "hunter2"

    def test_default_has_no_password(self):
        assert Credential().password is None


class TestDefaultConstructibility:
    @pytest.mark.parametrize("cls", FINDING_TYPES)
    def test_every_subtype_constructs_empty(self, cls):
        f = cls()
        assert isinstance(f, Finding)
        assert f.title == ""
        assert f.severity == Severity.INFO
        assert f.provenance.status == "ok"

    @pytest.mark.parametrize("cls", FINDING_TYPES)
    def test_every_subtype_constructs_with_only_dedup_key(self, cls):
        """The decoupling-proof ergonomics: adapters build a finding from one
        identity plus whatever fields they have."""
        f = cls(dedup_key="x")
        assert f.dedup_key == "x"


class TestDiscriminatedUnion:
    def _mixed(self) -> list[Finding]:
        provenance = Provenance(
            source="test", retrieved_at=datetime(2026, 9, 1, tzinfo=timezone.utc)
        )
        return [
            Breach(dedup_key="breach:Adobe", provenance=provenance),
            Credential(dedup_key="credential:dh:1", provenance=provenance),
            Account(dedup_key="account:github", platform="github", active=True),
            BrokerExposure(dedup_key="broker:spokeo", broker="Spokeo"),
            Paste(dedup_key="paste:abc123", paste_id="abc123"),
            InfostealerLog(dedup_key="stealer:log1", malware_family="Lumma"),
            CourtRecord(dedup_key="court:1:23", case_name="Doe v. Roe"),
            CorporateRecord(dedup_key="corp:acme", company_name="Acme"),
            PhoneIntel(dedup_key="phone:+15550100", phone="+15550100"),
            ExposedHost(dedup_key="host:1.2.3.4", ip="1.2.3.4"),
            AiTrainingHit(dedup_key="ai:discord", platform="discord"),
            GoogleFootprint(dedup_key="google:acct", account_name="John"),
        ]

    def test_round_trip_preserves_subtypes(self):
        findings = self._mixed()
        as_json = FindingAdapter.dump_json(findings)
        restored = FindingAdapter.validate_json(as_json)
        assert [type(f) for f in restored] == [type(f) for f in findings]
        assert {f.kind for f in restored} == {
            "breach",
            "credential",
            "account",
            "broker_exposure",
            "paste",
            "infostealer_log",
            "court_record",
            "corporate_record",
            "phone_intel",
            "exposed_host",
            "ai_training_hit",
            "google_footprint",
        }

    def test_round_trip_preserves_typed_fields(self):
        findings = self._mixed()
        restored = FindingAdapter.validate_python(FindingAdapter.dump_python(findings))
        assert restored[0].breach_date is None or isinstance(
            restored[0].breach_date, date
        )
        assert restored[2].platform == "github"
        assert restored[9].ip == "1.2.3.4"
        # provenance rides along
        assert restored[0].provenance.source == "test"

    def test_unknown_kind_falls_back_to_base_finding(self):
        """The generic path: a kind with no subtype stays a base Finding
        (payload-carrying), never an error and never a wrong subtype."""
        restored = FindingAdapter.validate_python(
            [{"kind": "martian", "dedup_key": "x", "title": "y"}]
        )
        assert [type(f) for f in restored] == [Finding]
        assert restored[0].kind == "martian"
        assert restored[0].dedup_key == "x"


class TestPayloadRidesJsonPrimitives:
    def test_base_finding_payload_round_trips(self):
        f = Finding(
            kind="footprint_element",
            dedup_key="sf:TARGET_EMAIL:1",
            title="some element",
            payload={"element_type": "EMAILADDR", "value": "a@b.com", "count": 2},
        )
        restored = FindingAdapter.validate_json(FindingAdapter.dump_json([f]))[0]
        assert restored is not None
        assert restored.payload == f.payload

    def test_payload_defaults_empty(self):
        assert Finding().payload == {}
