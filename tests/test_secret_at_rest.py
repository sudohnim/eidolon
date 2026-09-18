"""Blindspot #5 — plaintext credentials never reach disk/stdout by default.

The redaction fix made masking a type property of ``SecretStr``; this locks it
as an *invariant*: a full scan whose findings include a known plaintext password
(``hunter2`` in the dehashed fixture) must not leak it into any written artifact
(.json / .md / .pdf) or the stdout print. The only path that exposes it is the
explicit MCP ``reveal_credentials`` gate (asserted in test_mcp).
"""

import os
from pathlib import Path

import pytest

os.environ["TEST_MODE"] = "true"
os.environ.setdefault("HIBP_API_KEY", "test")

from eidolon.core import runner  # noqa: E402

SECRET = "hunter2"  # the plaintext password in tests/fixtures/dehashed_response.json


@pytest.fixture()
def scanned(tmp_path, monkeypatch):
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(tmp_path))
    res = runner.run_scan(email="test@example.com")
    return res, tmp_path


def test_no_plaintext_secret_in_json_or_md(scanned, capsys):
    res, out = scanned
    # the print() side of write_report must not carry the secret either
    assert SECRET not in capsys.readouterr().out
    for artifact in (Path(res.report_json), Path(res.report_md)):
        assert artifact.exists(), artifact
        assert SECRET not in artifact.read_text(encoding="utf-8"), artifact.name
    # the masked marker is what shows instead
    assert "********" in Path(res.report_md).read_text(encoding="utf-8")


def test_no_plaintext_secret_in_pdf(scanned):
    pytest.importorskip("pypdf")
    import io

    from pypdf import PdfReader

    res, _ = scanned
    if not res.report_pdf or not Path(res.report_pdf).exists():
        pytest.skip("pdf not generated")
    reader = PdfReader(io.BytesIO(Path(res.report_pdf).read_bytes()))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    assert SECRET not in text
