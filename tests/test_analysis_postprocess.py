"""Unit tests for the analysis post-processing layer in agent/nodes.py.

The TEST_MODE pipeline returns the analysis fixture directly, so it never
exercises _postprocess_analysis. These tests cover the repair/normalization and
deterministic-remediation helpers in isolation.

Since REFACTOR.4 the helpers read the Finding domain, so these tests construct
findings directly (the shape the adapters emit).
"""

import os

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("SCRAPFLY_API_KEY", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

from datetime import date  # noqa: E402

from eidolon.analysis import risk as nodes  # noqa: E402
from eidolon.analysis.digest import _build_analysis_digest  # noqa: E402
from eidolon.analysis.narrative import (  # noqa: E402
    _postprocess_analysis,
    _save_raw_response,
    _validate_analysis,
)
from eidolon.core.findings import (
    Account,
    Breach,
    BrokerExposure,
    Credential,
    InfostealerLog,
    PhoneIntel,
)
from eidolon.core.state import InputClassification, PipelineState  # noqa: E402

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


def _breach(name: str, year: int | None = None, password_class: bool = False) -> Breach:
    return Breach(
        dedup_key=f"breach:{name}",
        title=name,
        breach_date=date(year, 1, 1) if year else None,
        data_classes=(
            ["Email addresses", "Passwords"] if password_class else ["Email addresses"]
        ),
    )


def test_filter_top_risks_drops_hallucinated_example():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [_breach("LinkedIn")]
    risks = [
        "ParkMobile breach exposed your license plate + phone number.",
        "LinkedIn 2012 exposed your password hash.",
    ]
    out = nodes._filter_top_risks(risks, state)
    assert "LinkedIn 2012 exposed your password hash." in out
    assert not any("parkmobile" in r.lower() for r in out)


def test_filter_top_risks_keeps_grounded_brand():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [_breach("ParkMobile")]
    risks = ["ParkMobile breach exposed your license plate."]
    out = nodes._filter_top_risks(risks, state)
    assert out == risks  # grounded in real scan findings, so kept


# ── deterministic remediation ─────────────────────────────────────────────────


def test_monitoring_always_present():
    state = PipelineState(raw_input="x@example.com")
    rem = nodes._build_deterministic_remediation(state)
    assert rem["monitoring"]  # non-empty regardless of findings


def test_change_passwords_from_breaches():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [
        _breach("LinkedIn", 2012, password_class=True),
        _breach("SomeForum", 2018, password_class=False),
    ]
    rem = nodes._build_deterministic_remediation(state)
    assert rem["change_passwords"]
    assert "LinkedIn (2012)" in rem["change_passwords"][0]
    assert "SomeForum" not in rem["change_passwords"][0]  # no password class


def test_enable_2fa_and_reviews_from_active_accounts():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [
        Account(dedup_key="account:spotify", platform="Spotify", active=True),
        Account(dedup_key="account:eventbrite", platform="Eventbrite", active=True),
    ]
    rem = nodes._build_deterministic_remediation(state)
    assert "Spotify" in rem["enable_2fa"][0]
    assert "Eventbrite" in rem["enable_2fa"][0]
    assert rem["account_reviews"]


def test_sim_swap_when_phone_valid():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [
        PhoneIntel(
            dedup_key="phone:+1555", phone="+1555", valid=True, line_type="mobile"
        )
    ]
    rem = nodes._build_deterministic_remediation(state)
    assert rem["sim_swap_hardening"]


def test_broker_optouts_when_brokers_found():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [
        BrokerExposure(dedup_key=f"broker:{d}", broker=d)
        for d in ("a.com", "b.com", "c.com")
    ]
    rem = nodes._build_deterministic_remediation(state)
    assert rem["broker_optouts"]
    assert "easyoptouts" in rem["broker_optouts"][0].lower()


def test_stealer_hygiene_priority_item():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [
        InfostealerLog(dedup_key="stealer:pc:2024:RedLine", malware_family="RedLine")
    ]
    rem = nodes._build_deterministic_remediation(state)
    assert "infostealer" in rem["account_hygiene"][0].lower()
    assert rem["sim_swap_hardening"]  # also triggered by stealer


# ── finalize: deterministic wins, leftovers coerced, no empties ───────────────


def test_finalize_deterministic_overrides_and_coerces():
    state = PipelineState(raw_input="x@example.com")
    state.findings = [BrokerExposure(dedup_key="broker:x.com", broker="X")]
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
        "findings_context": [],
    }


def test_validate_analysis_passes_on_complete_dict():
    _validate_analysis(_valid_analysis())  # must not raise


def test_validate_analysis_hard_fails_on_missing_core_field():
    import pytest
    from pydantic import ValidationError

    bad = _valid_analysis()
    del bad["overall_risk_score"]  # model dropped a field it alone owns
    with pytest.raises(ValidationError):
        _validate_analysis(bad)


def test_validate_analysis_hard_fails_on_bad_risk_level():
    import pytest
    from pydantic import ValidationError

    bad = _valid_analysis()
    bad["overall_risk_level"] = "catastrophic"  # not in the Literal
    with pytest.raises(ValidationError):
        _validate_analysis(bad)


def test_postprocessed_output_satisfies_hard_contract():
    # A realistic model payload (object-shaped items, sparse remediation) must,
    # after post-processing, pass the hard schema contract.
    state = PipelineState(raw_input="x@example.com")
    state.findings = [_breach("X", 2020)]
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
    out = _postprocess_analysis(state, raw)
    _validate_analysis(out)  # must not raise


# ── D: pre-digest cleaning (model never sees junk) ────────────────────────────


def test_digest_strips_junk_usernames_and_geo_fragments():
    state = PipelineState(raw_input="x@example.com")
    state.classifications = [
        InputClassification(type="email", value="x@example.com", raw="x@example.com")
    ]
    state.findings = [
        Credential(
            dedup_key="credential:db1:x@x.com:1:pw:abc",
            source_breach="db1",
            username="1",
        ),
        Credential(
            dedup_key="credential:db2:x@x.com:2:pw:abd",
            source_breach="db2",
            username="realhandle",
        ),
        Credential(
            dedup_key="credential:db3:x@x.com:3:nosec",
            source_breach="db3",
            address="US, san diego ca us 92115",
        ),
        Credential(
            dedup_key="credential:db4:x@x.com:4:nosec",
            source_breach="db4",
            address="519 Idaho Ave Apt 4, Santa Monica, 90403",
        ),
    ]
    digest = _build_analysis_digest(state)
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
    state.findings = [
        _breach("Adobe", 2013, password_class=True),
        Account(dedup_key="account:spotify", platform="Spotify", active=True),
    ]
    # 29 breaches total (Adobe + 28 more) to cross the high-risk floor
    state.findings += [
        _breach(f"Filler{i}", 2015 + (i % 5), password_class=(i % 2 == 0))
        for i in range(28)
    ]
    # breach dumps expose 9 plaintext + 24 hashed passwords
    state.findings += [
        Credential(
            dedup_key=f"credential:db:x@x.com:{i}:pw:h{i}",
            source_breach="db",
            password="plain",  # type: ignore[arg-type]
        )
        for i in range(9)
    ]
    state.findings += [
        Credential(
            dedup_key=f"credential:db:x@x.com:{i}:hash:h{i}",
            source_breach="db",
            password_hash="a" * 32,
        )
        for i in range(24)
    ]
    return state


def test_state_risk_floor_high_for_breach_heavy_target():
    assert nodes._state_risk_floor(_breach_heavy_state()) >= 67
    assert nodes._state_risk_floor(PipelineState(raw_input="x@example.com")) == 0


def test_postprocess_salvages_a_full_report_when_llm_fails():
    # Empty dict = the LLM returned nothing parseable.
    out = _postprocess_analysis(_breach_heavy_state(), {})
    # risk is never understated to 0/low
    assert out["overall_risk_score"] >= 67
    assert out["overall_risk_level"] == "high"
    # what's-known and remediation are built from findings, not the (absent) LLM
    assert out["what_is_known"]["breach_history"]
    assert out["what_is_known"]["credentials_exposed"]
    assert out["remediation"]["change_passwords"]
    assert out["remediation"]["monitoring"]
    # a factual summary stands in for the missing narrative
    assert "29 known data breach" in out["identity_summary"]
    # still satisfies the hard schema contract
    _validate_analysis(out)


def test_postprocess_keeps_llm_narrative_when_present():
    out = _postprocess_analysis(
        _breach_heavy_state(),
        {"identity_summary": "Bespoke narrative from the model.", "top_risks": []},
    )
    assert out["identity_summary"] == "Bespoke narrative from the model."
