import os

import pytest

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

import eidolon.tools.ai_audit as ai_audit_tool
import eidolon.tools.blackbird as blackbird_tool
import eidolon.tools.broker_scan as broker_scan_tool
import eidolon.tools.dehashed as dehashed_tool
import eidolon.tools.ghunt as ghunt_tool
import eidolon.tools.hibp as hibp_tool
import eidolon.tools.holehe as holehe_tool
import eidolon.tools.maigret as maigret_tool
import eidolon.tools.paste as paste_tool
import eidolon.tools.phone as phone_tool
import eidolon.tools.public_records as public_records_tool
import eidolon.tools.spiderfoot as spiderfoot_tool
import eidolon.tools.stealer as stealer_tool
import eidolon.tools.whoxy as whoxy_tool
from eidolon.core.models import ToolResult
from eidolon.tools.ai_audit import AiAudit, AiAuditInput, AiAuditOutput
from eidolon.tools.base import run_to_result
from eidolon.tools.blackbird import Blackbird, BlackbirdInput, BlackbirdOutput
from eidolon.tools.broker_scan import BrokerScanInput, BrokerScanOutput
from eidolon.tools.dehashed import Dehashed, DehashedInput, DehashedOutput
from eidolon.tools.ghunt import Ghunt, GHuntInput, GHuntOutput
from eidolon.tools.hibp import Hibp, HibpInput, HibpOutput
from eidolon.tools.holehe import Holehe, HoleheInput, HoleheOutput
from eidolon.tools.maigret import Maigret, MaigretInput, MaigretOutput
from eidolon.tools.paste import Paste, PasteInput, PasteOutput
from eidolon.tools.phone import PhoneInput, PhoneLookupOutput
from eidolon.tools.public_records import PublicRecordsOutput
from eidolon.tools.spiderfoot import Spiderfoot, SpiderfootInput, SpiderfootOutput
from eidolon.tools.stealer import Stealer, StealerInput, StealerOutput
from eidolon.tools.whoxy import Whoxy, WhoxyInput, WhoxyOutput


class TestHibpTool:
    def test_returns_tool_result(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = run_to_result(Hibp(), inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = run_to_result(Hibp(), inp)
        assert result.success is True

    def test_tool_name(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = run_to_result(Hibp(), inp)
        assert result.tool == "hibp"

    def test_data_validates_as_hibp_output(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = run_to_result(Hibp(), inp)
        output = HibpOutput(**result.data)
        assert output.breach_count == 3
        assert len(output.breaches) == 3

    def test_breach_records_have_expected_fields(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = run_to_result(Hibp(), inp)
        output = HibpOutput(**result.data)
        breach = output.breaches[0]
        assert breach.name == "Adobe"
        assert breach.domain == "adobe.com"
        assert isinstance(breach.data_classes, list)

    def test_error_is_none_on_success(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = run_to_result(Hibp(), inp)
        assert result.error is None


class TestSpiderfootTool:
    def test_returns_tool_result(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = run_to_result(Spiderfoot(), inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = run_to_result(Spiderfoot(), inp)
        assert result.success is True

    def test_data_validates_as_spiderfoot_output(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = run_to_result(Spiderfoot(), inp)
        output = SpiderfootOutput(**result.data)
        assert output.status == "FINISHED"
        assert output.element_count == 5
        assert len(output.elements) == 5

    def test_elements_have_expected_fields(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = run_to_result(Spiderfoot(), inp)
        output = SpiderfootOutput(**result.data)
        el = output.elements[0]
        assert el.module == "sfp_gravatar"
        assert isinstance(el.confidence, int)

    def test_default_modules_list(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        assert "sfp_hibp" in inp.modules
        assert "sfp_emailrep" in inp.modules
        # sfp_social removed — causes consistent timeouts; coverage via Holehe/Blackbird
        assert len(inp.modules) == 5


class TestBrokerScanTool:
    def test_returns_tool_result(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.scan(inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.scan(inp)
        assert result.success is True

    def test_data_validates_as_broker_output(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.scan(inp)
        output = BrokerScanOutput(**result.data)
        assert output.brokers_found_count == 4
        assert output.exposure_score == 100

    def test_easyoptouts_url_present(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.scan(inp)
        output = BrokerScanOutput(**result.data)
        assert output.easyoptouts_url == "https://easyoptouts.com/dashboard"

    def test_broker_profiles_have_optout_urls(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.scan(inp)
        output = BrokerScanOutput(**result.data)
        for profile in output.brokers_found:
            assert profile.optout_url != ""

    def test_priority_optouts_populated(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.scan(inp)
        output = BrokerScanOutput(**result.data)
        assert len(output.priority_optouts) > 0


class TestAiAuditTool:
    def test_returns_tool_result(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = run_to_result(AiAudit(), inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt"])
        result = run_to_result(AiAudit(), inp)
        assert result.success is True

    def test_data_validates_as_ai_audit_output(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = run_to_result(AiAudit(), inp)
        output = AiAuditOutput(**result.data)
        assert output.high_risk_count == 2
        assert output.overall_risk == "high"

    def test_platforms_found_count(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = run_to_result(AiAudit(), inp)
        output = AiAuditOutput(**result.data)
        assert len(output.platforms_found) == 4

    def test_action_items_populated(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = run_to_result(AiAudit(), inp)
        output = AiAuditOutput(**result.data)
        assert len(output.action_items) > 0


class TestHoleheTool:
    def test_returns_tool_result(self):
        inp = HoleheInput(email="test@example.com")
        result = run_to_result(Holehe(), inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = HoleheInput(email="test@example.com")
        result = run_to_result(Holehe(), inp)
        assert result.success is True

    def test_data_validates_as_holehe_output(self):
        inp = HoleheInput(email="test@example.com")
        result = run_to_result(Holehe(), inp)
        output = HoleheOutput(**result.data)
        assert output.platforms_checked > 0
        assert output.found_count == len(output.platforms_found)

    def test_found_platforms_have_expected_fields(self):
        inp = HoleheInput(email="test@example.com")
        result = run_to_result(Holehe(), inp)
        output = HoleheOutput(**result.data)
        for match in output.platforms_found:
            assert match.platform
            assert match.exists is True


class TestBlackbirdTool:
    def test_returns_tool_result(self):
        result = run_to_result(Blackbird(), BlackbirdInput(email="test@example.com"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = run_to_result(Blackbird(), BlackbirdInput(email="test@example.com"))
        assert result.success is True

    def test_data_validates_as_blackbird_output(self):
        result = run_to_result(Blackbird(), BlackbirdInput(email="test@example.com"))
        output = BlackbirdOutput(**result.data)
        assert output.found_count == len(output.accounts_found)

    def test_accounts_have_platform_and_url(self):
        result = run_to_result(Blackbird(), BlackbirdInput(email="test@example.com"))
        output = BlackbirdOutput(**result.data)
        for account in output.accounts_found:
            assert account.platform
            assert account.url.startswith("http")


class TestMaigretTool:
    def test_returns_tool_result(self):
        result = run_to_result(Maigret(), MaigretInput(username="testuser"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = run_to_result(Maigret(), MaigretInput(username="testuser"))
        assert result.success is True

    def test_data_validates_as_maigret_output(self):
        result = run_to_result(Maigret(), MaigretInput(username="testuser"))
        output = MaigretOutput(**result.data)
        assert output.found_count == len(output.profiles_found)

    def test_profiles_have_url(self):
        result = run_to_result(Maigret(), MaigretInput(username="testuser"))
        output = MaigretOutput(**result.data)
        for profile in output.profiles_found:
            assert profile.url.startswith("http")


class TestGHuntTool:
    def test_returns_tool_result(self):
        result = run_to_result(Ghunt(), GHuntInput(email="test@gmail.com"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = run_to_result(Ghunt(), GHuntInput(email="test@gmail.com"))
        assert result.success is True

    def test_data_validates_as_ghunt_output(self):
        result = run_to_result(Ghunt(), GHuntInput(email="test@gmail.com"))
        output = GHuntOutput(**result.data)
        assert isinstance(output.found, bool)

    def test_found_has_services(self):
        result = run_to_result(Ghunt(), GHuntInput(email="test@gmail.com"))
        output = GHuntOutput(**result.data)
        if output.found:
            assert isinstance(output.google_services, list)


class TestPhoneTool:
    def test_returns_tool_result(self):
        result = phone_tool.lookup("+14155551234")
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        result = phone_tool.lookup("+14155551234")
        assert result.success is True

    def test_data_validates_as_phone_output(self):
        result = phone_tool.lookup("+14155551234")
        output = PhoneLookupOutput(**result.data)
        assert output.valid is True
        assert output.line_type == "mobile"

    def test_carrier_populated(self):
        result = phone_tool.lookup("+14155551234")
        output = PhoneLookupOutput(**result.data)
        assert output.carrier is not None
        assert output.carrier.name != ""

    def test_location_populated(self):
        result = phone_tool.lookup("+14155551234")
        output = PhoneLookupOutput(**result.data)
        assert output.location != ""
        assert output.country_code == "US"


class TestPublicRecordsTool:
    def test_returns_tool_result(self):
        result = public_records_tool.lookup("John Doe")
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        result = public_records_tool.lookup("John Doe")
        assert result.success is True

    def test_data_validates_as_output(self):
        result = public_records_tool.lookup("John Doe")
        output = PublicRecordsOutput(**result.data)
        assert output.court_case_count == 1
        assert output.corporate_record_count == 1

    def test_court_case_fields(self):
        result = public_records_tool.lookup("John Doe")
        output = PublicRecordsOutput(**result.data)
        case = output.court_cases[0]
        assert case.case_name != ""
        assert case.docket_number != ""
        assert case.court != ""

    def test_corporate_record_fields(self):
        result = public_records_tool.lookup("John Doe")
        output = PublicRecordsOutput(**result.data)
        rec = output.corporate_records[0]
        assert rec.company_name != ""
        assert rec.role != ""
        assert rec.jurisdiction != ""


class TestDehashedTool:
    def test_returns_tool_result(self):
        result = run_to_result(Dehashed(), DehashedInput(email="test@example.com"))
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        result = run_to_result(Dehashed(), DehashedInput(email="test@example.com"))
        assert result.success is True

    def test_tool_name(self):
        result = run_to_result(Dehashed(), DehashedInput(email="test@example.com"))
        assert result.tool == "dehashed"

    def test_data_validates_as_output(self):
        result = run_to_result(Dehashed(), DehashedInput(email="test@example.com"))
        output = DehashedOutput(**result.data)
        assert output.total == 4
        assert len(output.entries) == 4

    def test_aggregated_counts(self):
        result = run_to_result(Dehashed(), DehashedInput(email="test@example.com"))
        output = DehashedOutput(**result.data)
        assert output.plaintext_password_count == 1
        assert output.hashed_password_count == 2

    def test_unique_fields(self):
        result = run_to_result(Dehashed(), DehashedInput(email="test@example.com"))
        output = DehashedOutput(**result.data)
        assert "testuser" in output.unique_usernames
        assert len(output.unique_addresses) == 1
        assert "+14155551234" in output.unique_phones
        assert set(output.unique_databases) == {
            "LinkedIn",
            "Adobe",
            "EatStreet",
            "Apollo",
        }


class TestWhoxyTool:
    def test_returns_tool_result(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        assert result.success is True

    def test_tool_name(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        assert result.tool == "whoxy"

    def test_data_validates_as_output(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        output = WhoxyOutput(**result.data)
        assert output.total_results == 3
        assert len(output.domains) == 3

    def test_active_expired_counts(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        output = WhoxyOutput(**result.data)
        assert output.active_domain_count == 1
        assert output.expired_domain_count == 2

    def test_aggregated_signals(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        output = WhoxyOutput(**result.data)
        assert "Test User Consulting LLC" in output.unique_company_names
        assert len(output.unique_addresses) == 2
        assert len(output.unique_registrar_names) == 2

    def test_domain_fields(self):
        result = run_to_result(Whoxy(), WhoxyInput(email="test@example.com"))
        output = WhoxyOutput(**result.data)
        dom = output.domains[0]
        assert dom.domain_name == "testuserconsulting.com"
        assert dom.registrant_company == "Test User Consulting LLC"
        assert dom.create_date == "2019-03-15"


class TestPasteTool:
    def test_returns_tool_result(self):
        result = run_to_result(Paste(), PasteInput(email="test@example.com"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = run_to_result(Paste(), PasteInput(email="test@example.com"))
        assert result.success is True

    def test_tool_name(self):
        result = run_to_result(Paste(), PasteInput(email="test@example.com"))
        assert result.tool == "paste"

    def test_output_schema(self):
        result = run_to_result(Paste(), PasteInput(email="test@example.com"))
        output = PasteOutput(**result.data)
        assert output.paste_count == 3
        assert output.credential_paste_count == 2
        assert output.recent_paste_count == 1
        assert output.plaintext_passwords_found == 2

    def test_is_recent_helper(self):
        from datetime import datetime, timedelta, timezone

        from eidolon.tools.paste import _is_recent

        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        assert _is_recent(recent) is True
        assert _is_recent(old) is False

    def test_paste_url_helper(self):
        from eidolon.tools.paste import _paste_url

        assert "pastebin.com/abc123" in _paste_url("Pastebin", "abc123")
        assert "pastie.org" in _paste_url("Pastie", "xyz")


class TestStealerTool:
    def test_returns_tool_result(self):
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        assert result.success is True

    def test_tool_name(self):
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        assert result.tool == "stealer"

    def test_output_schema(self):
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        output = StealerOutput(**result.data)
        assert output.found is True
        assert output.stealer_count == 2
        assert "RedLine" in output.malware_families
        assert "Vidar" in output.malware_families

    def test_compromise_dates(self):
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        output = StealerOutput(**result.data)
        assert output.earliest_compromise == "2023-08-14"
        assert output.latest_compromise == "2024-11-02"

    def test_log_fields(self):
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        output = StealerOutput(**result.data)
        log = output.logs[0]
        assert log.computer_name == "DESKTOP-A1B2C3"
        assert log.malware_family == "RedLine"
        assert log.credential_count == 147

    def test_ip_partially_masked_in_fixture(self):
        # Hudson Rock masks IPs server-side (e.g. "98.123.***.***")
        result = run_to_result(Stealer(), StealerInput(email="test@example.com"))
        output = StealerOutput(**result.data)
        for log in output.logs:
            if log.ip:
                assert "***" in log.ip, f"IP not masked: {log.ip}"


class TestDeterministicPivots:
    """Tests for _extract_deterministic_pivots in agent/nodes.py."""

    def _make_state(self, primary_email: str, dehashed_entries: list[dict]):
        from datetime import datetime, timezone

        from eidolon.core.models import InputClassification, PipelineState, ToolResult

        dehashed_result = ToolResult(
            success=True,
            tool="dehashed",
            input_type="email",
            input_value=primary_email,
            timestamp=datetime.now(timezone.utc),
            data={"entries": dehashed_entries, "total": len(dehashed_entries)},
        )
        return PipelineState(
            raw_input=primary_email,
            classifications=[
                InputClassification(
                    type="email", value=primary_email, raw=primary_email
                )
            ],
            dehashed_result=dehashed_result,
        )

    def test_plus_alias_detected(self):
        from eidolon.agent.nodes import _extract_deterministic_pivots

        state = self._make_state(
            "user@gmail.com",
            [{"email": "user+amazon@gmail.com", "database_name": "SomeSite"}],
        )
        pivots = _extract_deterministic_pivots(state)
        assert len(pivots) == 1
        assert pivots[0]["type"] == "email"
        assert pivots[0]["value"] == "user+amazon@gmail.com"
        assert "alias" in pivots[0]["reason"].lower()

    def test_alternate_domain_detected(self):
        from eidolon.agent.nodes import _extract_deterministic_pivots

        state = self._make_state(
            "user@gmail.com",
            [{"email": "user@comcast.net", "database_name": "SomeSite"}],
        )
        pivots = _extract_deterministic_pivots(state)
        assert len(pivots) == 1
        assert pivots[0]["value"] == "user@comcast.net"

    def test_original_email_not_duplicated(self):
        from eidolon.agent.nodes import _extract_deterministic_pivots

        state = self._make_state(
            "user@gmail.com",
            [{"email": "user@gmail.com", "database_name": "SomeSite"}],
        )
        pivots = _extract_deterministic_pivots(state)
        assert pivots == []

    def test_dedup_across_entries(self):
        from eidolon.agent.nodes import _extract_deterministic_pivots

        state = self._make_state(
            "user@gmail.com",
            [
                {"email": "user@comcast.net", "database_name": "Site1"},
                {"email": "user@comcast.net", "database_name": "Site2"},
            ],
        )
        pivots = _extract_deterministic_pivots(state)
        assert len(pivots) == 1

    def test_capped_at_three(self):
        from eidolon.agent.nodes import _extract_deterministic_pivots

        state = self._make_state(
            "user@gmail.com",
            [
                {"email": "user@comcast.net"},
                {"email": "user@yahoo.com"},
                {"email": "user@hotmail.com"},
                {"email": "user@aol.com"},
            ],
        )
        pivots = _extract_deterministic_pivots(state)
        assert len(pivots) == 3

    def test_no_dehashed_result_returns_empty(self):
        from eidolon.agent.nodes import _extract_deterministic_pivots
        from eidolon.core.models import InputClassification, PipelineState

        state = PipelineState(
            raw_input="user@gmail.com",
            classifications=[
                InputClassification(
                    type="email", value="user@gmail.com", raw="user@gmail.com"
                )
            ],
        )
        assert _extract_deterministic_pivots(state) == []


class TestToolResultEnvelope:
    def test_error_result_shape(self):
        import json
        from pathlib import Path

        raw = json.loads(
            (Path(__file__).parent / "fixtures" / "error_response.json").read_text()
        )
        result = ToolResult(**raw)
        assert result.success is False
        assert result.error is not None
        assert result.data == {}
