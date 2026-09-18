"""Blindspot #2 — every source's fixture stays valid against its output schema.

Registry-driven guard: for each registered source, the TEST_MODE fixture (the
payload every tool returns when TEST_MODE=true) must still validate against that
tool's ``output_schema``. This is the schema-drift canary — a new field, a
renamed key, or a type change between a fixture and its schema fails here rather
than silently returning a half-empty result through the whole pipeline.

Scope note: this guards the fixture↔schema contract. It does NOT guard the
vendor↔fixture contract (whether the fixture still matches what the live API
returns) — that needs recorded real-response cassettes and network, tracked
separately. This canary is the cheap half that catches the common regression.
"""

import os

import pytest

os.environ.setdefault("TEST_MODE", "true")

from eidolon.core.registry import REGISTRY  # noqa: E402
from eidolon.utils import FIXTURES_DIR  # noqa: E402


def _sources_with_fixtures():
    out = []
    for spec in REGISTRY:
        tool = spec.factory()
        if (FIXTURES_DIR / f"{tool.name}_response.json").exists():
            out.append(pytest.param(tool, id=tool.name))
    return out


@pytest.mark.parametrize("tool", _sources_with_fixtures())
def test_fixture_validates_against_output_schema(tool):
    from eidolon.utils import load_fixture

    # raises pydantic.ValidationError if the fixture has drifted from the schema
    tool.output_schema.model_validate(load_fixture(tool.name))


def test_the_canary_actually_covers_sources():
    """Guard the guard: the parametrization must find real sources, so a future
    refactor that breaks fixture discovery can't turn this file into a no-op.
    (Aggregator sources synthesize output from per-vendor fixtures and legitimately
    have no fixture under their own name, so this is a floor, not a count.)"""
    assert len(_sources_with_fixtures()) >= 5
