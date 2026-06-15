"""Unit tests for the analysis post-processing layer in agent/nodes.py.

The TEST_MODE pipeline returns the analysis fixture directly, so it never
exercises _postprocess_analysis. These tests cover the repair/normalization and
deterministic-remediation helpers in isolation.
"""

import os
from datetime import datetime, timezone

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("SCRAPFLY_API_KEY", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

from eidolon.agent import nodes
from eidolon.core.models import InputClassification, PipelineState, ToolResult


def _tr(tool: str, data: dict) -> ToolResult:
    return ToolResult(
        success=True,
        tool=tool,
        input_type="email",
        input_value="x@example.com",
        timestamp=datetime.now(timezone.utc),
        data=data,
    )


# ── what_is_known normalization ───────────────────────────────────────────────


def test_normalize_coerces_dict_items_to_strings():
    known = {
        "platforms_with_accounts": [
            {"PlatformName": "Twitter", "url": "https://twitter.com/x"}
        ],
        "credentials_exposed": [
            {
                "BreachName": "LinkedIn",
                "YYYY": "2012",
                "data_types": ["Email", "Passwords"],
            }
        ],
        "breach_history": [{"ServiceName": "Dropbox", "YYYY": "2012"}],
        "google_footprint": [
            {"Google service": "Medium", "url": "https://medium.com/@x"}
        ],
    }
    out = nodes._normalize_what_is_known(known)
    assert out["platforms_with_accounts"] == ["Twitter: https://twitter.com/x"]
    assert out["credentials_exposed"] == ["LinkedIn (2012) — Email, Passwords"]
    assert out["breach_history"] == ["Dropbox (2012)"]
    assert out["google_footprint"] == ["Medium: https://medium.com/@x"]
    # no raw dicts survive
    for key in known:
        assert all(isinstance(i, str) for i in out[key])


def test_normalize_drops_probe_endpoint_urls():
    known = {
        "platforms_with_accounts": [
            {
                "PlatformName": "Twitter",
                "url": "https://api.twitter.com/i/users/email_available.json?email=x",
            },
        ]
    }
    out = nodes._normalize_what_is_known(known)
    # bogus API endpoint stripped — platform name kept without the misleading URL
    assert out["platforms_with_accounts"] == ["Twitter"]


def test_clean_handles_drops_junk():
    out = nodes._clean_handles(
        [
            "ramiemilo",
            "1",
            "NTraditional",
            "na",
            "ab",
            "ramiemilo",
            "rmilo12648, 1",  # DeHashed packs multiple values into one string
            "4f58e43bfe5c7268b1238f341",  # hex hash / DB id, not a username
        ]
    )
    assert "ramiemilo" in out
    assert "NTraditional" in out
    assert "rmilo12648" in out  # split out of the comma-packed value
    assert "1" not in out  # all-digits (even when packed with a real handle)
    assert "na" not in out  # noise word
    assert "ab" not in out  # too short
    assert "4f58e43bfe5c7268b1238f341" not in out  # hash-like
    assert out.count("ramiemilo") == 1  # deduped
    assert out.count("rmilo12648") == 1


def test_clean_addresses_keeps_real_drops_geo_fragments():
    addrs = [
        "519 Idaho Ave Apt 4, Santa Monica, 90403",
        "US, san diego ca us 92115",
        "us, ca, 803, los angeles, 90013",
    ]
    out = nodes._clean_addresses(addrs)
    assert out == ["519 Idaho Ave Apt 4, Santa Monica, 90403"]


# ── top_risks grounding ───────────────────────────────────────────────────────


def test_filter_top_risks_drops_hallucinated_example():
    state = PipelineState(raw_input="x@example.com")
    state.hibp_result = _tr("hibp", {"breaches": [{"name": "LinkedIn"}]})
    risks = [
        "ParkMobile breach exposed your license plate + phone number.",
        "LinkedIn 2012 exposed your password hash.",
    ]
    out = nodes._filter_top_risks(risks, state)
    assert "LinkedIn 2012 exposed your password hash." in out
    assert not any("parkmobile" in r.lower() for r in out)


def test_filter_top_risks_keeps_grounded_brand():
    state = PipelineState(raw_input="x@example.com")
    state.hibp_result = _tr("hibp", {"breaches": [{"name": "ParkMobile"}]})
    risks = ["ParkMobile breach exposed your license plate."]
    out = nodes._filter_top_risks(risks, state)
    assert out == risks  # grounded in real scan state, so kept


# ── deterministic remediation ─────────────────────────────────────────────────


def test_monitoring_always_present():
    state = PipelineState(raw_input="x@example.com")
    rem = nodes._build_deterministic_remediation(state)
    assert rem["monitoring"]  # non-empty regardless of findings


def test_change_passwords_from_breaches():
    state = PipelineState(raw_input="x@example.com")
    state.hibp_result = _tr(
        "hibp",
        {
            "breach_count": 2,
            "breaches": [
                {
                    "name": "LinkedIn",
                    "breach_date": "2012-05-05",
                    "data_classes": ["Email addresses", "Passwords"],
                },
                {
                    "name": "SomeForum",
                    "breach_date": "2018-01-01",
                    "data_classes": ["Email addresses"],
                },
            ],
        },
    )
    rem = nodes._build_deterministic_remediation(state)
    assert rem["change_passwords"]
    assert "LinkedIn (2012)" in rem["change_passwords"][0]
    assert "SomeForum" not in rem["change_passwords"][0]  # no password class


def test_enable_2fa_and_reviews_from_active_accounts():
    state = PipelineState(raw_input="x@example.com")
    state.holehe_result = _tr("holehe", {"platforms_found": [{"platform": "Spotify"}]})
    state.blackbird_result = _tr(
        "blackbird", {"accounts_found": [{"platform": "Eventbrite"}]}
    )
    rem = nodes._build_deterministic_remediation(state)
    assert "Spotify" in rem["enable_2fa"][0]
    assert "Eventbrite" in rem["enable_2fa"][0]
    assert rem["account_reviews"]


def test_sim_swap_when_phone_valid():
    state = PipelineState(raw_input="x@example.com")
    state.phone_result = _tr("phone", {"valid": True, "line_type": "mobile"})
    rem = nodes._build_deterministic_remediation(state)
    assert rem["sim_swap_hardening"]


def test_broker_optouts_when_brokers_found():
    state = PipelineState(raw_input="x@example.com")
    state.broker_result = _tr("broker_scan", {"brokers_found_count": 3})
    rem = nodes._build_deterministic_remediation(state)
    assert rem["broker_optouts"]
    assert "easyoptouts" in rem["broker_optouts"][0].lower()


def test_stealer_hygiene_priority_item():
    state = PipelineState(raw_input="x@example.com")
    state.stealer_result = _tr("stealer", {"found": True})
    rem = nodes._build_deterministic_remediation(state)
    assert "infostealer" in rem["account_hygiene"][0].lower()
    assert rem["sim_swap_hardening"]  # also triggered by stealer


# ── finalize: deterministic wins, leftovers coerced, no empties ───────────────


def test_finalize_deterministic_overrides_and_coerces():
    state = PipelineState(raw_input="x@example.com")
    state.broker_result = _tr("broker_scan", {"brokers_found_count": 1})
    llm_rem = {
        "broker_optouts": ["model-supplied (should be overridden)"],
        # account_hygiene as the {action, platforms} object shape + an empty item
        "account_hygiene": [
            {"action": "Revoke OAuth", "platforms": ["Google", "GitHub"]},
            "",
        ],
        "gdpr_removals": ["GDPR erasure request to SomeEUco"],
    }
    final = nodes._finalize_remediation(state, llm_rem)
    # deterministic broker_optouts wins
    assert "easyoptouts" in final["broker_optouts"][0].lower()
    # account_hygiene comes from deterministic (always generated), all strings
    assert all(isinstance(i, str) for i in final["account_hygiene"])
    # llm-only section retained and stringified, no empty items
    assert final["gdpr_removals"] == ["GDPR erasure request to SomeEUco"]
    for items in final.values():
        assert all(isinstance(i, str) and i.strip() for i in items)


def test_finalize_coerces_llm_object_items_when_no_deterministic():
    state = PipelineState(raw_input="x@example.com")
    # no accounts → enable_2fa not generated deterministically → falls back to LLM
    llm_rem = {"enable_2fa": [{"action": "Enable 2FA", "platforms": ["Reddit"]}]}
    final = nodes._finalize_remediation(state, llm_rem)
    assert final["enable_2fa"] == ["Enable 2FA: Reddit"]


# ── B: hard schema contract ───────────────────────────────────────────────────


def _valid_analysis() -> dict:
    return {
        "overall_risk_score": 50,
        "overall_risk_level": "medium",
        "identity_summary": "Some narrative.",
        "what_is_known": {},
        "top_risks": [],
        "remediation": {},
    }


def test_validate_analysis_passes_on_complete_dict():
    nodes._validate_analysis(_valid_analysis())  # must not raise


def test_validate_analysis_hard_fails_on_missing_core_field():
    import pytest
    from pydantic import ValidationError

    bad = _valid_analysis()
    del bad["overall_risk_score"]  # model dropped a field it alone owns
    with pytest.raises(ValidationError):
        nodes._validate_analysis(bad)


def test_validate_analysis_hard_fails_on_bad_risk_level():
    import pytest
    from pydantic import ValidationError

    bad = _valid_analysis()
    bad["overall_risk_level"] = "catastrophic"  # not in the Literal
    with pytest.raises(ValidationError):
        nodes._validate_analysis(bad)


def test_postprocessed_output_satisfies_hard_contract():
    # A realistic model payload (object-shaped items, sparse remediation) must,
    # after post-processing, pass the hard schema contract.
    state = PipelineState(raw_input="x@example.com")
    state.hibp_result = _tr("hibp", {"breach_count": 1, "breaches": [{"name": "X"}]})
    raw = {
        "overall_risk_score": 70,
        "overall_risk_level": "high",
        "identity_summary": "narrative",
        "what_is_known": {
            "credentials_exposed": [{"BreachName": "X", "YYYY": "2020"}],
        },
        "top_risks": ["a real risk"],
        # remediation entirely omitted by the model
    }
    out = nodes._postprocess_analysis(state, raw)
    nodes._validate_analysis(out)  # must not raise


# ── D: pre-digest cleaning (model never sees junk) ────────────────────────────


def test_digest_strips_junk_usernames_and_geo_fragments():
    state = PipelineState(raw_input="x@example.com")
    state.classifications = [
        InputClassification(type="email", value="x@example.com", raw="x@example.com")
    ]
    state.dehashed_result = _tr(
        "dehashed",
        {
            "total": 3,
            "unique_usernames": ["1", "realhandle"],
            "unique_addresses": [
                "US, san diego ca us 92115",
                "519 Idaho Ave Apt 4, Santa Monica, 90403",
            ],
        },
    )
    digest = nodes._build_analysis_digest(state)
    # junk never reaches the model
    assert "realhandle" in digest
    assert (
        "Usernames exposed: 1," not in digest and "Usernames exposed: 1\n" not in digest
    )
    assert "san diego ca us 92115" not in digest
    # the real street address does
    assert "519 Idaho Ave Apt 4" in digest


# ── salvage: report survives an LLM failure (empty llm_analysis) ──────────────


def _breach_heavy_state() -> PipelineState:
    state = PipelineState(raw_input="x@example.com")
    state.hibp_result = _tr(
        "hibp",
        {
            "breach_count": 29,
            "breaches": [
                {
                    "name": "Adobe",
                    "breach_date": "2013-10-04",
                    "data_classes": ["Email addresses", "Passwords"],
                }
            ],
        },
    )
    state.dehashed_result = _tr(
        "dehashed",
        {"total": 44, "plaintext_password_count": 9, "hashed_password_count": 24},
    )
    state.holehe_result = _tr("holehe", {"platforms_found": [{"platform": "Spotify"}]})
    return state


def test_state_risk_floor_high_for_breach_heavy_target():
    assert nodes._state_risk_floor(_breach_heavy_state()) >= 67
    assert nodes._state_risk_floor(PipelineState(raw_input="x@example.com")) == 0


def test_postprocess_salvages_a_full_report_when_llm_fails():
    # Empty dict = the LLM returned nothing parseable.
    out = nodes._postprocess_analysis(_breach_heavy_state(), {})
    # risk is never understated to 0/low
    assert out["overall_risk_score"] >= 67
    assert out["overall_risk_level"] == "high"
    # what's-known and remediation are built from state, not the (absent) LLM
    assert out["what_is_known"]["breach_history"]
    assert out["what_is_known"]["credentials_exposed"]
    assert out["remediation"]["change_passwords"]
    assert out["remediation"]["monitoring"]
    # a factual summary stands in for the missing narrative
    assert "29 known data breach" in out["identity_summary"]
    # still satisfies the hard schema contract
    nodes._validate_analysis(out)


def test_postprocess_keeps_llm_narrative_when_present():
    out = nodes._postprocess_analysis(
        _breach_heavy_state(),
        {"identity_summary": "Bespoke narrative from the model.", "top_risks": []},
    )
    assert out["identity_summary"] == "Bespoke narrative from the model."
