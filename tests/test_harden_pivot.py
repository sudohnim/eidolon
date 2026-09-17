"""HARDEN.2 — prove `_valid_pivot_value` only ever pivots on real targets.

Properties:
- a globally routable IP is a pivot; private/loopback/link-local/multicast/
  documentation/reserved/unspecified addresses are never pivots
- all-same-digit and short sequential-run phones are never pivots
- whatever the input, the function returns a bool and never raises
"""

import ipaddress
import string

from hypothesis import given, settings
from hypothesis import strategies as st

from eidolon.pipeline.correlate import _valid_pivot_value

_PROP_SETTINGS = {"max_examples": 120, "deadline": None}

_DIGITS = "0123456789"

_FWD_SEQ = "01234567890123456789"
_REV_SEQ = "98765432109876543210"


@settings(**_PROP_SETTINGS)
@given(st.text(max_size=64))
def test_always_returns_bool_and_never_raises(text):
    for ptype in ("ip", "phone", "email", "username", "name", "bogus_type"):
        value = _valid_pivot_value(ptype, text)
        assert isinstance(value, bool)


@settings(**_PROP_SETTINGS)
@given(st.ip_addresses(v=4))
def test_ip_matches_is_global_v4(addr):
    expected = bool(addr.is_global)
    got = _valid_pivot_value("ip", str(addr))
    assert got is expected, f"{addr} is_global={expected}, got {got}"


@settings(**_PROP_SETTINGS)
@given(st.ip_addresses(v=6))
def test_ip_matches_is_global_v6(addr):
    expected = bool(addr.is_global)
    assert _valid_pivot_value("ip", str(addr)) is expected


@settings(**_PROP_SETTINGS)
@given(st.text(alphabet=_DIGITS, min_size=7, max_size=20))
def test_placeholder_digits_never_accepted_as_phone(digits):
    all_same = len(set(digits)) == 1
    short_run = digits in _FWD_SEQ or digits in _REV_SEQ
    if all_same or short_run:
        assert not _valid_pivot_value("phone", digits), digits


class TestIP:

    def test_private_ranges_rejected(self):
        for bad in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "172.16.5.4"):
            assert not _valid_pivot_value("ip", bad), bad

    def test_loopback_link_local_and_doc_ranges_rejected(self):
        for bad in ("169.254.169.254", "0.0.0.0", "255.255.255.255", "203.0.113.7"):
            assert not _valid_pivot_value("ip", bad), bad

    def test_public_ip_accepted(self):
        assert _valid_pivot_value("ip", "8.8.8.8")
        assert _valid_pivot_value("ip", "104.16.132.229")

    def test_garbage_ip_rejected(self):
        assert not _valid_pivot_value("ip", "not-an-ip")
        assert not _valid_pivot_value("ip", "999.1.1.1")


class TestPhone:
    def test_all_same_rejected(self):
        for bad in ("0000000", "1111111", "000 000 0000"):
            assert not _valid_pivot_value("phone", bad), bad

    def test_sequential_runs_rejected(self):
        for bad in ("0123456", "9876543", "4567890", "10987654"):
            assert not _valid_pivot_value("phone", bad), bad

    def test_real_shaped_phone_accepted(self):
        for good in ("+14155550100", "4155550100", "+44 20 7946 0958"):
            assert _valid_pivot_value("phone", good), good

    def test_too_short_rejected(self):
        assert not _valid_pivot_value("phone", "123")
        assert not _valid_pivot_value("phone", "")


class TestSlice:
    def test_email_rule(self):
        assert _valid_pivot_value("email", "jane.doe+tag@example.com")
        assert not _valid_pivot_value("email", "no-at-sign")
        assert not _valid_pivot_value("email", "user@localhost")

    def test_username_and_name_min_length(self):
        assert _valid_pivot_value("username", "janedoe")
        assert _valid_pivot_value("name", "Jane")
        assert not _valid_pivot_value("username", "ab")

    def test_empty_value_rejected_for_every_type(self):
        for ptype in ("ip", "phone", "email", "username", "name"):
            assert not _valid_pivot_value(ptype, ""), ptype

    def test_unknown_type_rejected(self):
        assert not _valid_pivot_value("frobnicate", "anything")
