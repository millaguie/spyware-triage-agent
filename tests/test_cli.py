"""The ./sta entry point: operator-only commands, purge, next."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import make_case

ROOT = Path(__file__).resolve().parents[1]


def sta(sandbox, *args, stdin=""):
    env = {**os.environ, "STA_CASES": str(sandbox / "cases"), "STA_SECRETS": str(sandbox / "secrets"),
           "PYTHONPATH": str(ROOT / "src")}
    env.pop("STA_CASE", None)
    return subprocess.run([sys.executable, "-m", "sta", *args], capture_output=True, text=True,
                          env=env, input=stdin, timeout=60)


def test_new_case_refuses_without_a_terminal(sandbox):
    proc = sta(sandbox, "new-case", "--alias", "x", "--consent", "yes", "--network", "no")
    assert proc.returncode == 2
    assert "Only the operator can open a case" in proc.stderr
    assert not list((sandbox / "cases").glob("*/state.json"))


def test_purge_yes_refuses_without_a_terminal(sandbox):
    case = make_case(sandbox)
    proc = sta(sandbox, "purge", "--yes")
    assert proc.returncode == 2
    assert "Only the operator can delete" in proc.stderr
    assert (case.path / "acquisition").exists()


def test_purge_dry_run_lists_secrets_too(sandbox):
    case = make_case(sandbox)
    secret = sandbox / "secrets" / case.path.name / "ios-backup-password"
    secret.parent.mkdir(parents=True)
    secret.write_text("pw\n")
    proc = sta(sandbox, "purge")
    assert proc.returncode == 0
    assert str(case.path / "acquisition") in proc.stdout
    assert str(secret.parent) in proc.stdout
    assert secret.exists()


def test_purge_keeps_report_files_and_removes_secrets(sandbox, monkeypatch):
    """Call cmd_purge in-process with a fake terminal: the subprocess has none."""
    from sta import __main__ as cli
    from sta import report
    case = make_case(sandbox)
    for name in ("findings.json", "notes.json", "report.md"):
        (case.path / name).write_text("{}")
    secret = case.secrets_dir / "ios-backup-password"
    secret.parent.mkdir(parents=True)
    secret.write_text("pw\n")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": case.path.name)
    cli.cmd_purge(case, yes=True)
    assert sorted(p.name for p in case.path.iterdir()) == ["findings.json", "notes.json", "report.md", "state.json"]
    assert not secret.exists() and not secret.parent.exists()
    assert "purged" in json.loads((case.path / "state.json").read_text())
    assert report.notes(case) == {}


def test_purge_wrong_name_deletes_nothing(sandbox, monkeypatch):
    from sta import __main__ as cli
    case = make_case(sandbox)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "something-else")
    with pytest.raises(SystemExit):
        cli.cmd_purge(case, yes=True)
    assert (case.path / "acquisition").exists()


def test_next_names_the_pending_step(sandbox):
    make_case(sandbox)
    proc = sta(sandbox, "next")
    assert proc.returncode == 0
    assert "NEXT STEP: check-apps" in proc.stdout
    assert "./sta check-apps" in proc.stdout


def test_next_without_case(sandbox):
    proc = sta(sandbox, "next")
    assert proc.returncode == 2
    assert "No open case" in proc.stderr


def test_note_rejects_unknown_id_through_cli(sandbox):
    case = make_case(sandbox)
    case.mark("check-apps")
    case.mark("triage")
    (case.path / "findings.json").write_text(json.dumps({"schema": 1, "findings": [
        {"id": "F001", "kind": "sideloaded-app", "severity": "amber", "subject": "s", "detail": "d",
         "evidence": {}}]}))
    assert sta(sandbox, "note", "F002", "x").returncode == 2
    proc = sta(sandbox, "note", "f001", "the owner's words")
    assert proc.returncode == 0, proc.stderr
    notes = json.loads((case.path / "notes.json").read_text())["notes"]
    assert notes["F001"]["text"] == "the owner's words"
