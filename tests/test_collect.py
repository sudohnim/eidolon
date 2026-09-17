"""REFACTOR.2 — collect(): every source emits findings, provenance stamped once.

Per-source mapping tests (fixture -> expected finding count/kind), the
provenance contract on every finding, the skipped/error envelope paths, and
merge_findings dedup precedence. The e2e test proves the pipeline populates
findings + results (the ScanState surface) end to end.
"""

import os
import shutil
from pathlib import Path

import pytest

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["AI_PLATFORMS"] = "claude,chatgpt,gemini,grok"

from eidolon.core.findings import (  # noqa: E402
    Severity,
    merge_findings,
)
from eidolon.core.state import PipelineState, SourceResult  # noqa: E402
from eidolon.sources.ai_audit import AiAudit, AiAuditInput  # noqa: E402
from eidolon.sources.base import collect  # noqa: E402
from eidolon.sources.blackbird import Blackbird, BlackbirdInput  # noqa: E402
from eidolon.sources.broker_scan import BrokerScan, BrokerScanInput  # noqa: E402
from eidolon.sources.commoncrawl import CommonCrawl, CommonCrawlInput  # noqa: E402
from eidolon.sources.dehashed import Dehashed, DehashedInput  # noqa: E402
from eidolon.sources.ghunt import Ghunt, GHuntInput  # noqa: E402
from eidolon.sources.hibp import Hibp, HibpInput  # noqa: E402
from eidolon.sources.holehe import Holehe, HoleheInput  # noqa: E402
from eidolon.sources.maigret import Maigret, MaigretInput  # noqa: E402
from eidolon.sources.paste import Paste, PasteInput  # noqa: E402
from eidolon.sources.phone import PhoneInput, PhoneLookup  # noqa: E402
from eidolon.sources.public_records import (  # noqa: E402
    PublicRecords,
    PublicRecordsInput,
)
from eidolon.sources.shodan import Shodan, ShodanInput  # noqa: E402
from eidolon.sources.spiderfoot import (  # noqa: E402
    Spiderfoot,
    SpiderfootInput,
)
from eidolon.sources.stealer import Stealer, StealerInput  # noqa: E402
from eidolon.sources.whoxy import Whoxy, WhoxyInput  # noqa: E402

EMAIL = "test@example.com"


def _all_findings(sr: SourceResult):
    assert sr.status == "ok", sr.detail
    return sr.findings


class TestPerSourceMapping:
    """Each source maps its fixture to the expected finding count and kind."""

    def _check_provenance(self, sr: SourceResult) -> None:
        assert sr.findings, "expected findings from this fixture"
        for f in sr.findings:
            assert f.provenance.source, f"finding {f.dedup_key} missing provenance"
            assert f.provenance.status == "ok"
            assert f.provenance.tool_version
            assert f.provenance.latency_ms >= 0
            assert len(f.provenance.response_sha256) == 64
            int(f.provenance.response_sha256, 16)  # 64 hex chars
            assert f.dedup_key

    def test_hibp_breaches(self):
        sr = collect(Hibp(), HibpInput(input_type="email", value=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 3
        assert all(f.kind == "breach" for f in sr.findings)
        # password-class breaches rank HIGH
        by_key = {f.title: f for f in sr.findings}
        assert by_key["Adobe"].severity == Severity.HIGH
        assert "Passwords" in by_key["LinkedIn"].data_classes

    def test_dehashed_credentials(self):
        sr = collect(Dehashed(), DehashedInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 4
        assert all(f.kind == "credential" for f in sr.findings)
        # plaintext password is SecretStr — masked even in the envelope dump
        plain = [f for f in sr.findings if f.password is not None]
        assert len(plain) == 1
        assert plain[0].severity == Severity.CRITICAL
        assert "hunter2" not in str(plain[0].model_dump(mode="json"))

    def test_whoxy_domains(self):
        sr = collect(Whoxy(), WhoxyInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 3
        assert all(f.kind == "registered_domain" for f in sr.findings)
        active = [f for f in sr.findings if f.payload.get("active")]
        assert len(active) == 1

    def test_paste(self):
        sr = collect(Paste(), PasteInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 3
        assert all(f.kind == "paste" for f in sr.findings)
        with_creds = [f for f in sr.findings if f.credential_count]
        assert with_creds and with_creds[0].severity == Severity.HIGH

    def test_stealer_logs(self):
        sr = collect(Stealer(), StealerInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 2
        assert all(f.kind == "infostealer_log" for f in sr.findings)
        assert all(f.severity == Severity.CRITICAL for f in sr.findings)

    def test_spiderfoot_elements(self):
        sr = collect(
            Spiderfoot(),
            SpiderfootInput(target=EMAIL, target_type="emailaddr"),
        )
        self._check_provenance(sr)
        assert len(sr.findings) == 5
        assert all(f.kind == "footprint_element" for f in sr.findings)
        types = {f.payload["element_type"] for f in sr.findings}
        assert "SOCIAL_MEDIA" in types

    def test_holehe_accounts_active(self):
        sr = collect(Holehe(), HoleheInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 2
        assert all(f.kind == "account" and f.active for f in sr.findings)

    def test_blackbird_accounts_active(self):
        sr = collect(Blackbird(), BlackbirdInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 3
        assert all(f.kind == "account" and f.active for f in sr.findings)

    def test_maigret_accounts_unconfirmed(self):
        sr = collect(Maigret(), MaigretInput(username="testuser"))
        self._check_provenance(sr)
        assert len(sr.findings) == 4
        assert all(f.kind == "account" and not f.active for f in sr.findings)

    def test_ghunt_footprint(self):
        sr = collect(Ghunt(), GHuntInput(email=EMAIL))
        self._check_provenance(sr)
        assert len(sr.findings) == 1
        f = sr.findings[0]
        assert f.kind == "google_footprint"
        assert f.account_name == "Test User"
        assert "YouTube" in f.services

    def test_shodan_hosts(self):
        sr = collect(Shodan(), ShodanInput(ip="93.184.216.34"))
        self._check_provenance(sr)
        assert len(sr.findings) == 2
        assert all(f.kind == "exposed_host" for f in sr.findings)
        vuln = [f for f in sr.findings if f.vulns]
        assert vuln and vuln[0].severity == Severity.HIGH

    def test_ai_audit_hits_with_removal(self):
        sr = collect(AiAudit(), AiAuditInput(platforms=["claude", "chatgpt"]))
        self._check_provenance(sr)
        assert len(sr.findings) == 4
        assert all(f.kind == "ai_training_hit" for f in sr.findings)
        removable = [f for f in sr.findings if f.removable]
        assert removable
        assert all(f.removal and f.removal.url for f in removable)

    def test_commoncrawl_presence(self):
        sr = collect(CommonCrawl(), CommonCrawlInput(targets=["janedoe.com"]))
        self._check_provenance(sr)
        assert len(sr.findings) == 2
        assert all(f.kind == "web_presence" for f in sr.findings)

    def test_broker_scan_exposures(self):
        sr = collect(
            BrokerScan(),
            BrokerScanInput(
                input_type="name", value="John Doe", state="CA", zip_code="94102"
            ),
        )
        self._check_provenance(sr)
        assert len(sr.findings) == 4
        assert all(f.kind == "broker_exposure" for f in sr.findings)
        # brokers are removable by construction, with the opt-out path attached
        assert all(f.removable and f.removal and f.removal.url for f in sr.findings)
        domains = {f.domain for f in sr.findings}
        assert "spokeo.com" in domains

    def test_phone_lookup_intel(self):
        sr = collect(PhoneLookup(), PhoneInput(phone="+14155551234"))
        self._check_provenance(sr)
        assert len(sr.findings) == 1
        f = sr.findings[0]
        assert f.kind == "phone_intel" and f.valid

    def test_public_records(self):
        sr = collect(PublicRecords(), PublicRecordsInput(name="John Doe", state="CA"))
        self._check_provenance(sr)
        kinds = sorted(f.kind for f in sr.findings)
        assert kinds == ["corporate_record", "court_record"]

    def test_every_source_carries_a_summary(self):
        """The SourceResult envelope carries the source's one-line run account."""
        sr = collect(Hibp(), HibpInput(input_type="email", value=EMAIL))
        assert sr.name == "hibp"
        assert sr.summary == "3 breaches"

    def test_response_sha256_is_deterministic_across_runs(self):
        """EVIDENCE.1 — the replay hash is a pure function of the typed output:
        the same fixture input yields the identical 64-hex sha256 every time."""
        a = collect(Hibp(), HibpInput(input_type="email", value=EMAIL))
        b = collect(Hibp(), HibpInput(input_type="email", value=EMAIL))
        assert a.evidence and b.evidence
        assert a.evidence.response_sha256
        assert a.evidence.response_sha256 == b.evidence.response_sha256
        assert len(a.evidence.response_sha256) == 64


class TestCollectEnvelopePaths:
    def test_skipped_source_emits_no_findings(self, monkeypatch):
        """No key -> skipped, no findings, honest reason (never '0 found')."""
        monkeypatch.setenv("TEST_MODE", "false")
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        sr = collect(Hibp(), HibpInput(input_type="email", value=EMAIL))
        assert sr.status == "skipped"
        assert sr.findings == []
        assert sr.detail and "HIBP_API_KEY" in sr.detail

    def test_error_source_emits_no_findings(self, monkeypatch):
        monkeypatch.setenv("TEST_MODE", "false")
        monkeypatch.setenv("HIBP_API_KEY", "test")

        class ExplodingHibp(Hibp):
            def _run(self, inp, log):  # pragma: no cover - exercised via collect
                raise RuntimeError("vendor 500")

        sr = collect(ExplodingHibp(), HibpInput(input_type="email", value=EMAIL))
        assert sr.status == "error"
        assert sr.findings == []
        assert sr.detail and "vendor 500" in sr.detail

    def test_collect_never_raises_on_mapping_failure(self, monkeypatch):
        """A broken to_findings degrades to an error result, never an exception."""

        class BrokenMap(Hibp):
            def to_findings(self, out):
                raise ValueError("mapping bug")

        sr = collect(BrokenMap(), HibpInput(input_type="email", value=EMAIL))
        assert sr.status == "error"
        assert sr.findings == []
        assert sr.detail and "mapping bug" in sr.detail


class TestMergeFindings:
    def _acct(self, platform, sev=Severity.LOW, active=False, source="maigret"):
        from eidolon.core.findings import Account, Provenance

        return Account(
            dedup_key=f"account:{platform}",
            title=platform,
            severity=sev,
            provenance=Provenance(source=source),
            platform=platform,
            active=active,
        )

    def test_dedup_by_key(self):
        a = self._acct("github")
        b = self._acct("github")
        assert len(merge_findings([a], [b])) == 1

    def test_severity_precedence_regardless_of_order(self):
        weak = self._acct("github", sev=Severity.LOW, source="maigret")
        strong = self._acct("github", sev=Severity.MEDIUM, source="holehe")
        assert merge_findings([weak], [strong])[0].severity == Severity.MEDIUM
        assert merge_findings([strong], [weak])[0].severity == Severity.MEDIUM

    def test_active_beats_unconfirmed_on_severity_tie(self):
        inactive = self._acct("twitter", sev=Severity.MEDIUM, source="maigret")
        active = self._acct("twitter", sev=Severity.MEDIUM, active=True, source="x")
        assert merge_findings([inactive], [active])[0].active
        assert merge_findings([active], [inactive])[0].active

    def test_source_tiebreak_is_deterministic(self):
        a = self._acct("adobe", sev=Severity.MEDIUM, active=True, source="holehe")
        b = self._acct("adobe", sev=Severity.MEDIUM, active=True, source="blackbird")
        # blackbird < holehe alphabetically — wins from either arrival order
        assert merge_findings([a], [b])[0].provenance.source == "blackbird"
        assert merge_findings([b], [a])[0].provenance.source == "blackbird"

    def test_merge_keeps_distinct_findings(self):
        a = self._acct("github")
        b = self._acct("reddit")
        assert len(merge_findings([a], [b])) == 2


class TestPipelinePopulation:
    """e2e: the graph populates findings + results (the scan's whole surface)."""

    @pytest.fixture(autouse=True)
    def _output_dir(self, tmp_path, monkeypatch):
        out = tmp_path / "reports"
        monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(out))
        yield out
        shutil.rmtree(out, ignore_errors=True)

    def _run(self):
        from eidolon.pipeline.graph import build_graph

        graph = build_graph()
        raw = "email:test@example.com\nname:John Doe\nstate:CA"
        final = graph.invoke(PipelineState(raw_input=raw))
        return (
            final
            if isinstance(final, PipelineState)
            else PipelineState.model_validate(final)
        )

    def test_findings_and_results_populated(self):
        state = self._run()
        assert state.findings, "dual-write produced no findings"
        keys = [f.dedup_key for f in state.findings]
        assert len(keys) == len(set(keys)), "duplicate dedup_keys in state.findings"
        # every source slot filled, every finding provenance-stamped
        expected_sources = {
            "hibp",
            "dehashed",
            "whoxy",
            "paste",
            "stealer",
            "spiderfoot",
            "holehe",
            "blackbird",
            "maigret",
            "ghunt",
            "broker_scan",
            "public_records",
            "ai_audit",
            "commoncrawl",
        }
        assert expected_sources <= set(state.results.keys())
        for f in state.findings:
            assert f.provenance.source

    def test_coverage_envelopes_populated(self):
        state = self._run()
        expected_sources = {
            "hibp",
            "dehashed",
            "whoxy",
            "paste",
            "stealer",
            "spiderfoot",
            "holehe",
            "blackbird",
            "maigret",
            "ghunt",
            "broker_scan",
            "public_records",
            "ai_audit",
            "commoncrawl",
        }
        assert expected_sources <= set(state.results.keys())
        assert all(state.results[n].status == "ok" for n in expected_sources)
        coverage = {c.name: c.status for c in state.coverage()}
        assert coverage["hibp"] == "ok"

    def test_expected_finding_mix(self):
        state = self._run()
        kinds = {}
        for f in state.findings:
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
        assert kinds["breach"] == 3
        assert kinds["credential"] == 4
        assert kinds["account"] == 6  # union across holehe/blackbird/maigret
        assert kinds["broker_exposure"] == 4
        assert kinds["infostealer_log"] == 2
        assert kinds["google_footprint"] == 1
        assert kinds["ai_training_hit"] == 4
        assert kinds["court_record"] == 1
        assert kinds["corporate_record"] == 1
        assert kinds["web_presence"] == 2
        assert kinds["registered_domain"] == 3
        assert kinds["footprint_element"] == 5

    def test_account_dedup_prefers_confirmation(self):
        state = self._run()
        accounts = {
            f.platform.lower(): f for f in state.findings if f.kind == "account"
        }
        # holehe's confirmed github beats maigret's unconfirmed GitHub claim
        assert accounts["github"].active
        assert accounts["github"].provenance.source == "holehe"
        # blackbird vs holehe on twitter: equal severity+active, source tiebreak
        assert accounts["twitter"].provenance.source == "blackbird"

    def test_findings_deterministic_across_runs(self):
        """Same fixture input -> identical finding sequence (wave merge sorts)."""
        a = self._run()
        b = self._run()
        assert [(f.kind, f.dedup_key) for f in a.findings] == [
            (f.kind, f.dedup_key) for f in b.findings
        ]

    def test_state_round_trips_through_json(self):
        """What report_node's .json artifact + the MCP reload path do."""
        import json

        state = self._run()
        dumped = json.loads(json.dumps(state.model_dump(), default=str))
        restored = PipelineState.model_validate(dumped)
        assert len(restored.findings) == len(state.findings)
        assert [type(f) for f in restored.findings] == [type(f) for f in state.findings]
        assert set(restored.results.keys()) == set(state.results.keys())
        # plaintext password never rides the finding through a dump
        assert "hunter2" not in json.dumps(
            [
                f.model_dump(mode="json")
                for f in restored.findings
                if f.kind == "credential"
            ]
        )
