"""Task 6.3-6.6: seal, verify, export, encryption at rest, the cleanup check
and the report's 'What was checked' table."""

import io
import json
import shutil
import subprocess
import tarfile

import pytest

from sta import acquire, checks, evidence, report
from sta.common import StepError

needs_age = pytest.mark.skipif(not (shutil.which("age") and shutil.which("age-keygen")),
                               reason="age is not installed")


def keypair(tmp_path):
    key = tmp_path / "key.txt"
    out = subprocess.run(["age-keygen", "-o", str(key)], capture_output=True, text=True, check=True)
    public = next(line.split(": ", 1)[1] for line in (out.stderr + out.stdout).splitlines()
                  if line.startswith("Public key"))
    return public, key


@pytest.fixture
def reported(case, no_apkid):
    checks.check_apps(case)
    report.triage(case)
    report.build_report(case)
    return case


def test_seal_then_verify_and_see_a_change(reported):
    evidence.seal(reported)
    manifest = (reported.path / evidence.MANIFEST).read_text()
    assert "  report.md\n" in manifest and "state.json" not in manifest
    assert reported.state["sealed"]["files"] == len(manifest.splitlines())
    assert evidence.verify(reported) is True
    (reported.path / "report.md").write_text("edited")
    (reported.path / "new.txt").write_text("x")
    assert evidence.verify(reported) is False


def test_verify_needs_a_seal(reported):
    with pytest.raises(StepError):
        evidence.verify(reported)


def test_export_leaves_out_the_acquisition_and_the_phone_ids(reported, tmp_path):
    dest = tmp_path / "out.tar.gz"
    evidence.export(reported, dest)
    with tarfile.open(dest) as tar:
        names = tar.getnames()
        state = json.load(tar.extractfile(f"{reported.path.name}/state.json"))
    assert f"{reported.path.name}/report.md" in names
    assert not any("/acquisition/" in n for n in names)
    assert "serial" not in state.get("device", {}) and "udid" not in state.get("device", {})


def test_a_private_key_is_refused(reported, tmp_path):
    with pytest.raises(StepError, match="age public key"):
        evidence.encrypt_phone_data(reported, "AGE-SECRET-KEY-1XYZ")


@needs_age
def test_encrypt_and_unseal_round_trip(reported, tmp_path):
    public, key = keypair(tmp_path)
    before = sorted(p.relative_to(reported.path) for p in (reported.path / "acquisition").rglob("*"))
    evidence.seal(reported, public)
    assert not (reported.path / "acquisition").exists() and (reported.path / evidence.ENCRYPTED).exists()
    assert reported.state["sealed"]["encrypted"] is True
    assert evidence.verify(reported) is True  # the seal covers the encrypted file
    evidence.unseal(reported, key)
    after = sorted(p.relative_to(reported.path) for p in (reported.path / "acquisition").rglob("*"))
    assert after == before and not (reported.path / evidence.ENCRYPTED).exists()


@needs_age
def test_encrypted_export_needs_the_key(reported, tmp_path):
    public, key = keypair(tmp_path)
    dest = tmp_path / "out.tar.gz.age"
    evidence.export(reported, dest, recipient=public)
    plain = subprocess.run(["age", "-d", "-i", str(key), str(dest)], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
        assert any(n.endswith("/report.md") for n in tar.getnames())


def test_cleanup_verify_marks_only_when_the_permission_is_gone(reported, monkeypatch):
    reported.mark("review")
    monkeypatch.setattr("sta.device.adb_devices", lambda: [(reported.state["device"]["serial"], "device")])
    with pytest.raises(StepError, match="still use USB debugging"):
        acquire.cleanup(reported, verify_only=True)
    assert not reported.done("cleanup")
    monkeypatch.setattr("sta.device.adb_devices", lambda: [(reported.state["device"]["serial"], "unauthorized")])
    acquire.cleanup(reported, verify_only=True)
    assert reported.done("cleanup")


def test_cleanup_without_a_terminal_asks_for_verify(reported, capsys):
    reported.mark("review")
    acquire.cleanup(reported)  # pytest gives no terminal
    assert "./sta cleanup --verify" in capsys.readouterr().out
    assert not reported.done("cleanup")


def test_report_lists_what_ran_and_why_not(reported):
    rows = dict(report.checked_rows(reported))
    assert rows["MVT analysis"] == "ran"
    assert rows["Store lookups"] == "off: no network consent"
    assert rows["VirusTotal"].startswith("off") and rows["Owner interview"] == "skipped"
    assert "## What was checked" in (reported.path / "report.md").read_text()
