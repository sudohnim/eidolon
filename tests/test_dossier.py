"""Tests for the exact-mailbox filter and the Leaked Credentials dossier."""

import os
from datetime import datetime, timezone

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("SCRAPFLY_API_KEY", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

from eidolon.agent.report import (  # noqa: E402
    _clean_cred_address,
    _clean_cred_hash,
    _clean_cred_username,
    _dossier_lines,
)
from eidolon.core.models import PipelineState, ToolResult  # noqa: E402
from eidolon.tools.dehashed import same_mailbox  # noqa: E402

# ── same_mailbox: the exact-email gate ────────────────────────────────────────


def test_same_mailbox_gmail_dot_and_alias():
    assert same_mailbox("nicholelopez@gmail.com", "nichole.lopez@gmail.com")
    assert same_mailbox("nicholelopez@gmail.com", "nicholelopez+spam@gmail.com")
    assert same_mailbox("a@gmail.com", "a@googlemail.com")


def test_same_mailbox_rejects_other_domains():
    assert not same_mailbox("nicholelopez@gmail.com", "nicholelopez@yahoo.com")
    assert not same_mailbox("nicholelopez@gmail.com", "nicholelopez@ymail.com")
    assert not same_mailbox("nicholelopez@gmail.com", "nicholelopez@earthlink.net")


# ── dossier field cleaners ────────────────────────────────────────────────────


def test_clean_cred_username_drops_junk_and_unpacks():
    assert _clean_cred_username("nicolychee, 1") == "nicolychee"  # DeHashed packing
    assert _clean_cred_username("20678977") == ""  # all-digits id
    assert _clean_cred_username("ab") == ""  # too short
    assert _clean_cred_username("sunshineaura7") == "sunshineaura7"


def test_clean_cred_address_drops_country_codes():
    assert _clean_cred_address("PH") == ""
    assert _clean_cred_address("NU") == ""
    assert _clean_cred_address("worcester ma us 01605") == "worcester ma us 01605"


def test_clean_cred_hash_strips_dehashed_suffix():
    h, algo = _clean_cred_hash("9403c10017c1bd65a236d662ea3e4c776804e5d7:None||SHA-1")
    assert h == "9403c10017c1bd65a236d662ea3e4c776804e5d7"
    assert algo == "SHA-1"
    # plain hash with no suffix → algo inferred from length
    h2, algo2 = _clean_cred_hash("8087f27e41a1de0ce70b641cae2a88c4")
    assert h2 == "8087f27e41a1de0ce70b641cae2a88c4" and algo2 == "MD5"
    # a salt that itself ends in '|' must not leak a stray pipe into the algo
    h3, algo3 = _clean_cred_hash("900352ae4991c67836a94cde9822dd5c:saltend|||MD5")
    assert h3 == "900352ae4991c67836a94cde9822dd5c" and algo3 == "MD5"


# ── dossier rendering ─────────────────────────────────────────────────────────


def _dehashed_state(entries: list[dict]) -> PipelineState:
    state = PipelineState(raw_input="x@example.com")
    state.dehashed_result = ToolResult(
        success=True,
        tool="dehashed",
        input_type="email",
        input_value="x@example.com",
        timestamp=datetime.now(timezone.utc),
        data={"entries": entries},
    )
    return state


def test_dossier_renders_real_records():
    state = _dehashed_state(
        [
            {"database_name": "Exploit.in", "password": "nichole"},
            {"database_name": "MyFitnessPal", "username": "sunshineaura7"},
            {"database_name": "Empty", "ip_address": "1.2.3.4"},  # nothing juicy
        ]
    )
    out = "\n".join(_dossier_lines(state))
    assert "## Your Actual Leaked Data" in out
    assert "password: nichole" in out
    assert "username: sunshineaura7" in out
    assert "Empty" not in out  # record with no credential is skipped


def test_dossier_empty_when_no_dehashed():
    assert _dossier_lines(PipelineState(raw_input="x@example.com")) == []
