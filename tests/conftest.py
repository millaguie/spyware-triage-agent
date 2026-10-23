"""Shared fixtures. Every test runs against a throwaway copy of the knowledge
base and a case folder under tmp_path, never against cases/ or kb/cache/."""

import json
import shutil
from pathlib import Path

import pytest

import sta.apkscan as apkscan
import sta.checks as checks
import sta.common as common
import sta.domains as domains
import sta.kbupdate as kbupdate
import sta.manifest as manifest
import sta.report as report
import sta.saf as saf
import sta.trackers as trackers

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Point every module at tmp_path: cases, the kb cache and the secrets.
    kb/*.yaml (findings text, signers, watched apps) is the real one, copied."""
    kb = tmp_path / "kb"
    shutil.copytree(ROOT / "kb", kb, ignore=shutil.ignore_patterns("cache"))
    shutil.copytree(FIXTURES / "kb-cache", kb / "cache")
    cases = tmp_path / "cases"
    cases.mkdir()
    secrets = tmp_path / "secrets"
    for module in (common, checks, apkscan, report, kbupdate, manifest, domains, trackers):
        for name, value in (("KB_DIR", kb), ("CACHE_DIR", kb / "cache"), ("CASES_DIR", cases),
                            ("CURRENT_FILE", cases / "CURRENT"), ("SECRETS_DIR", secrets)):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, value)
    monkeypatch.setattr(apkscan, "YARA_RULES", kb / "cache" / "stalkerware.yar")
    monkeypatch.delenv("MVT_VT_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("STA_ABUSECH_API_KEY", raising=False)
    # MVT's own indicator folder: empty unless a test fills it.
    monkeypatch.setenv("MVT_DATA_FOLDER", str(tmp_path / "mvt"))
    # saf on the developer's machine must not run on test archives.
    monkeypatch.setattr(saf, "which", lambda name: None)
    return tmp_path


def make_case(root: Path, name: str = "2026-01-01-test", *, platform: str = "android",
              network: bool = False, acquisition: str | None = "android-pixel",
              ios_quick: bool = False) -> common.Case:
    """A case that has gone through detect, update-kb, acquire and analyze,
    with the fixture as its acquisition and MVT results.

    `ios_quick=True` instead builds an iPhone case that only ran `ios-quick`:
    no backup, no MVT results; the ios-quick fixture is its acquisition."""
    path = root / "cases" / name
    path.mkdir(parents=True)
    done_steps = ("detect", "update-kb", "ios-quick") if ios_quick else ("detect", "acquire", "analyze")
    state = {
        "schema": common.SCHEMA_VERSION, "case_id": name, "alias": "test",
        "created": "2026-01-01T00:00:00+00:00",
        "consent": {"given": True, "at": "2026-01-01T00:00:00+00:00", "by": "operator terminal"},
        "network": network, "virustotal": False, "country": "us", "platform": platform,
        "device": ({"udid": "TESTUDID", "product_type": "iPhone16,2", "ios_version": "26.1", "build": "23B85"}
                   if platform == "ios" else
                   {"serial": "TESTSERIAL", "manufacturer": "Google", "model": "Pixel 8a",
                    "android_version": "17", "security_patch": "2026-10-05", "security_patch_age_days": 13}),
        "steps": {s: {"at": "2026-01-01T00:00:00+00:00"} for s in done_steps},
    }
    state["steps"]["update-kb"] = {"at": "2026-01-01T00:00:00+00:00", "mvt_indicator_files": 19,
                                   "sources": {"test/repo": "deadbeef"}, "indicators": {"ioc.yaml": "00"}}
    if acquisition:
        acq = path / "acquisition" / ("ios-quick" if ios_quick else "androidqf")
        shutil.copytree(FIXTURES / acquisition, acq)
        (path / "mvt-results").mkdir()
        if not ios_quick:
            shutil.move(acq / "alerts.json", path / "mvt-results" / "alerts.json")
            state["acquisition"] = {"path": "acquisition/androidqf", "androidqf_exit": 0,
                                    "androidqf_uuid": "00000000-0000-0000-0000-000000000000",
                                    "incomplete_modules": [], "hash_check": "ok", "hash_mismatches": []}
    (path / "state.json").write_text(json.dumps(state, indent=2))
    (root / "cases" / "CURRENT").write_text(name + "\n")
    return common.Case(path)


@pytest.fixture
def case(sandbox):
    return make_case(sandbox)


@pytest.fixture
def ios_case(sandbox):
    """iPhone case with only the ios-quick step done (no backup, no MVT)."""
    return make_case(sandbox, "2026-01-01-ios", platform="ios", acquisition="ios-quick",
                     ios_quick=True)


@pytest.fixture
def no_apkid(monkeypatch):
    """check_android runs APKiD on sideloaded APKs. The fixture has no APK
    files, so the scan finds nothing; skip the binary entirely."""
    monkeypatch.setattr(apkscan, "apkid_labels", lambda paths, log: {})
    monkeypatch.setattr(apkscan, "load_yara", lambda: None)
