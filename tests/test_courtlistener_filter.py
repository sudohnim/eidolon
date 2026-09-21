"""CourtListener precision: name-only full-text matches (e.g. an unrelated case
where the name appears as an attorney) are dropped; only cases whose *case name*
contains all the target's name tokens survive (still unverified — namesakes pass).
"""

import os

os.environ.setdefault("TEST_MODE", "true")

from eidolon.sources.courtlistener import _name_in_case  # noqa: E402


def test_drops_non_party_fulltext_match():
    # the real dogfood case: name not in the case name → dropped
    assert _name_in_case("Minh Mai", "Audet v. Garza") is False


def test_keeps_case_name_containing_all_tokens():
    assert _name_in_case("Minh Mai", "CHI MINH MAI") is True  # namesake still passes
    assert _name_in_case("Minh Mai", "Doe v. Minh Mai") is True


def test_requires_all_tokens_not_just_one():
    assert _name_in_case("Minh Mai", "John Mai v. State") is False  # only surname
    assert _name_in_case("Minh Mai", "Minh Nguyen v. Corp") is False  # only given


def test_empty_or_single_char_tokens():
    assert _name_in_case("", "Anything") is False
    assert _name_in_case("A B", "a b corp") is False  # tokens too short → no match
