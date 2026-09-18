"""SCALE.2 — the --targets-file CLI batch surface.

The CLI pushes a multi-target file through the same bounded run_batch core as
the library API, writing one independent report per target. Single-target
flags take the unchanged run_scan path (covered by test_runner / the MCP
tests) — this file pins the batch dispatch only.
"""

import os
import shutil
from argparse import Namespace

import pytest

os.environ["TEST_MODE"] = "true"
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")
os.environ["AI_PLATFORMS"] = "claude,chatgpt,gemini,grok"

from eidolon import main as cli  # noqa: E402


def _fixture(tmp_path):
    """Build the targets file + a Namespace wired to _run_batch."""
    out = tmp_path / "reports"
    targets = tmp_path / "targets.txt"
    targets.write_text(
        "# first target — comments and blank lines are skipped\n"
        "\n"
        "email:test@example.com\n"
        "phone:+14155550100\n"
        "name:John Smith;state:CA\n",
        encoding="utf-8",
    )
    args = Namespace(
        targets_file=str(targets),
        max_concurrency=2,
        email=None,
        phone=None,
        name=None,
        city=None,
        state=None,
        zip=None,
        authorized_by="op",
        reason="test",
    )
    return out, targets, args


def test_targets_file_writes_one_report_per_target(tmp_path, monkeypatch):
    out, targets, args = _fixture(tmp_path)
    monkeypatch.setenv("RESULTS_OUTPUT_PATH", str(out))

    cli._run_batch(args)

    assert out.exists()
    mds = sorted(out.glob("*.md"))
    jsons = sorted(out.glob("*.json"))
    assert len(mds) == 3, f"expected 3 md reports, got {[p.name for p in mds]}"
    assert len(jsons) == 3, f"expected 3 json artifacts, got {[p.name for p in jsons]}"

    # distinct run_ids: each target mints its own scan id (no shared state)
    run_ids = [p.name.rsplit("_", 2)[-1].rsplit(".", 1)[0] for p in mds]
    assert len(set(run_ids)) == 3

    # every report is real content, not an empty stub
    for p in mds:
        assert "# Privacy OSINT Report" in p.read_text(encoding="utf-8")


def test_missing_targets_file_exits_nonzero(tmp_path, monkeypatch, capsys):
    out, targets, args = _fixture(tmp_path)
    args.targets_file = str(tmp_path / "nope.txt")
    with pytest.raises(SystemExit) as exc:
        cli._run_batch(args)
    assert exc.value.code == 1


def test_targets_file_rejects_single_target_flags(monkeypatch):
    """--targets-file is mutually exclusive with --email/--phone/--name/..."""
    import sys

    parser = cli._build_parser()
    auth = ["--authorized-by", "op", "--reason", "test"]
    args = parser.parse_args(
        ["--targets-file", "targets.txt", "--max-concurrency", "2", *auth]
    )
    assert args.targets_file == "targets.txt"
    assert args.max_concurrency == 2
    # normal flags still parse the single-target path
    args = parser.parse_args(["--email", "a@b.com", *auth])
    assert args.email == "a@b.com"
    assert args.targets_file is None
    # combining them is a dispatch-time error (the manual guard in main)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "eidolon",
            "--targets-file",
            "targets.txt",
            "--email",
            "a@b.com",
            "--authorized-by",
            "op",
            "--reason",
            "test",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_batch_cleanup(tmp_path):
    out = tmp_path / "reports"
    if out.exists():
        shutil.rmtree(out)
