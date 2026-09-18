"""REVIEW.2 — the scan index is derived from JSON content, not the filename.

An identifier that contains underscores lists with its real value; a corrupt or
non-scan ``.json`` in the output dir is skipped, never fatal.
"""

import json
import os

os.environ.setdefault("TEST_MODE", "true")

from eidolon.core import repository  # noqa: E402


def _write_scan(out, name, *, run_id, classifications):
    (out / f"{name}.json").write_text(
        json.dumps({"run_id": run_id, "classifications": classifications})
    )


def test_identifier_with_underscores_comes_from_json(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path))
    # filename identifier is the sanitized "john_q_public"; the JSON carries the
    # real one. Content wins.
    _write_scan(
        tmp_path,
        "john_q_public_2026-09-17_abcd1234",
        run_id="abcd1234",
        classifications=[{"type": "name", "value": "John Q Public"}],
    )
    scans = repository.list_scans()
    assert len(scans) == 1
    assert scans[0].scan_id == "abcd1234"
    assert scans[0].identifier == "John Q Public"  # from JSON, not the stem


def test_email_identifier_preferred_over_name(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path))
    _write_scan(
        tmp_path,
        "whatever_2026-09-17_ffff0000",
        run_id="ffff0000",
        classifications=[
            {"type": "name", "value": "Jane Doe"},
            {"type": "email", "value": "jane_doe@example.com"},
        ],
    )
    assert repository.list_scans()[0].identifier == "jane_doe@example.com"


def test_corrupt_and_non_scan_json_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path))
    _write_scan(
        tmp_path,
        "good_2026-09-17_00001111",
        run_id="00001111",
        classifications=[{"type": "email", "value": "a@b.com"}],
    )
    (tmp_path / "truncated_2026-09-17_dead.json").write_text('{"run_id": "dead"')  # bad
    (tmp_path / "sidecar.json").write_text('{"note": "not a scan"}')  # no run_id
    scans = repository.list_scans()
    assert [s.scan_id for s in scans] == ["00001111"]  # only the valid one, no crash
