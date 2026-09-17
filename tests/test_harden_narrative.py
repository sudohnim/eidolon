"""HARDEN.1 — prove `_parse_json_tolerant` ever holds its contract.

Arbitrary text in, dict-or-list (or a defined empty fallback) out, never a
raise — hypothesised over random text and valid round-trippable JSON.
"""

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from eidolon.analysis.narrative import _parse_json_tolerant

_PROP_SETTINGS = {
    "max_examples": 100,
    "deadline": None,
    "suppress_health_check": [HealthCheck.too_slow],
}

_scalar_value = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    st.text(max_size=20),
)
_value = st.recursive(
    _scalar_value,
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(max_size=10), children, max_size=6)
    ),
    max_leaves=50,
)
# top level is always a dict — the parser maps scalar JSON (e.g. "null") to {}
_dict_strategy = st.dictionaries(st.text(max_size=10), _value, max_size=6)


def _assert_serializable(result) -> None:
    assert isinstance(result, (dict, list)), f"expected dict/list, got {type(result)}"
    # whatever we return must be standard parseable JSON
    json.loads(json.dumps(result, ensure_ascii=True))


@settings(**_PROP_SETTINGS)
@given(st.text(max_size=300))
def test_arbitrary_text_never_raises_and_returns_serializable(text):
    _assert_serializable(_parse_json_tolerant(text))


@settings(**_PROP_SETTINGS)
@given(_dict_strategy)
def test_valid_json_round_trips(obj):
    assert _parse_json_tolerant(json.dumps(obj, ensure_ascii=True)) == obj


@settings(**_PROP_SETTINGS)
@given(_dict_strategy)
def test_garbage_around_valid_json_still_parses(obj):
    text = "xxx noise\n```json\n" + json.dumps(obj) + "\n```"
    assert _parse_json_tolerant(text) == obj


@settings(**_PROP_SETTINGS)
@given(st.text(min_size=0, max_size=400))
def test_empty_and_whitespace_has_defined_answer(text):
    result = _parse_json_tolerant(text)
    _assert_serializable(result)
    if not text.strip():
        assert result == {}


class TestExplicitCases:
    def test_markdown_fenced_json(self):
        assert _parse_json_tolerant('```json\n{"a": 1}\n```') == {"a": 1}

    def test_unquoted_keys_repaired(self):
        assert _parse_json_tolerant("{a: 1, b: 2}") == {"a": 1, "b": 2}

    def test_trailing_comma_repaired(self):
        assert _parse_json_tolerant('{"a": [1, 2,],}') == {"a": [1, 2]}

    def test_prose_wrapped_block(self):
        text = 'Here is the analysis:\n{"a": 1, "b": [true, null]}\nRegards, model.'
        assert isinstance(_parse_json_tolerant(text), dict)

    def test_garbage_returns_empty_dict(self):
        assert _parse_json_tolerant("this is not json at all ====") == {}
