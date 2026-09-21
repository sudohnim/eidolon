"""XposedOrNot — free keyless breach source; fixture → findings mapping."""

import os

os.environ["TEST_MODE"] = "true"

from eidolon.core.findings import Breach, Severity  # noqa: E402
from eidolon.sources.base import collect  # noqa: E402
from eidolon.sources.xposedornot import (  # noqa: E402
    XposedOrNot,
    XposedOrNotInput,
    XposedOrNotOutput,
)


def test_always_available_no_key():
    # free/keyless — must run even with no env configured
    assert XposedOrNot().available() is True


def test_fixture_maps_to_breach_findings():
    sr = collect(XposedOrNot(), XposedOrNotInput(email="a@b.com"))
    assert sr.status == "ok"
    breaches = [f for f in sr.findings if isinstance(f, Breach)]
    assert {b.title for b in breaches} == {"LinkedIn", "Dropbox"}
    # password-class breaches rank HIGH
    linkedin = next(b for b in breaches if b.title == "LinkedIn")
    assert linkedin.severity == Severity.HIGH
    assert linkedin.breach_date is not None and linkedin.breach_date.year == 2016
    assert "Passwords" in linkedin.data_classes
    assert linkedin.dedup_key == "breach:LinkedIn"


def test_to_findings_skips_nameless_and_dedups_key():
    out = XposedOrNotOutput.model_validate(
        {"breach_count": 1, "breaches": [{"name": "", "year": "2020"}]}
    )
    assert XposedOrNot().to_findings(out) == []  # nameless breach dropped
