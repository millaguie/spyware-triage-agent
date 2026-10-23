"""ios-quick through check-apps, triage and a partial report (no backup).

The expected findings are written out in full, like test_pipeline.py: the
fixture is synthetic (tests/fixtures/ios-quick), built from the JSON shapes
read from pymobiledevice3 11.43.1 (docs/format-notes.md section 11)."""

import json
import shutil
from types import SimpleNamespace

import pytest

from conftest import make_case
from sta import checks, report
from sta.common import StepError


def kinds(findings):
    return sorted((f["kind"], f["severity"], f["subject"]) for f in findings)


def test_check_ios_quick_emits_exactly_the_expected_kinds(ios_case):
    findings = checks.check_ios(ios_case)
    assert kinds(findings) == [
        ("ios-app-entitlements", "info", "com.example.securenotes"),      # vpn entitlement
        ("ios-app-hidden", "amber", "com.example.spyware.helper"),        # Hidden in a user container
        ("ios-app-not-store-signed", "amber", "com.example.unexplained"),  # no profile explains it
        ("ios-crash-pattern", "info", "WebKit.Networking"),               # 2 crashes inside 30 days
        ("ios-crash-suspicious-path", "red", "/private/var/tmp/updater"),
        ("ios-developer-app", "amber", "Jane's test build (expired)"),
        ("ios-enterprise-app", "amber", "Example Enterprise In-House"),
        ("ios-mdm-profile", "red", "Example MDM"),                        # PayloadRemovalDisallowed
        ("ios-provision-expired", "info", "Jane's test build (expired)"),
        ("stalkerware", "red", "com.fakespy.monitor"),                    # ioc.yaml applies to apps.json
    ]
    pattern = next(f for f in findings if f["kind"] == "ios-crash-pattern")
    assert len(pattern["evidence"]["dates"]) == 2
    # the enterprise-signed app is NOT asked: its profile explains it
    assert not any(f["subject"] == "com.example.securenotes" and f["kind"] == "ios-app-not-store-signed"
                   for f in findings)


def test_ios_quick_writes_the_crash_summary(ios_case):
    checks.check_apps(ios_case)
    summary = json.loads((ios_case.path / "acquisition/ios-quick/crashes.json").read_text())
    assert sorted(summary) == ["/private/var/tmp/updater", "SpringBoard", "WebKit.Networking"]
    webkit = summary["WebKit.Networking"]  # newest first, {at, bug_type, file} only
    assert [e["file"] for e in webkit] == ["WebKit-Networking-2026-10-15.ips",
                                           "WebKit-Networking-2026-10-01.ips"]
    assert sorted(webkit[0]) == ["at", "bug_type", "file"]


def test_check_apps_without_backup_marks_partial(ios_case):
    checks.check_apps(ios_case)
    step = ios_case.state["steps"]["check-apps"]
    assert step["partial"] is True
    assert (ios_case.path / "app-findings.json").exists()


def test_check_apps_neither_quick_nor_analyze_refuses(sandbox):
    case = make_case(sandbox, "2026-01-01-bare", platform="ios", acquisition=None)
    case.unmark("analyze")  # a real iPhone that only reached detect
    with pytest.raises(StepError, match="ios-quick"):
        checks.check_apps(case)


def test_report_demands_partial_and_says_so(ios_case):
    checks.check_apps(ios_case)
    report.triage(ios_case)  # triage accepts a partial check-apps
    with pytest.raises(StepError, match="--partial"):
        report.report(ios_case)
    report.report(ios_case, partial=True)
    text = (ios_case.path / "report.md").read_text()
    assert "PARTIAL CHECK: no backup was analysed. MVT did not run." in text
    assert "**3 red finding(s).**" in text  # crash path + MDM profile + stalkerware
    assert "| Network lookups | off |" in text


def test_partial_report_lists_no_store_source(ios_case):
    checks.check_apps(ios_case)
    report.triage(ios_case)
    report.report(ios_case, partial=True)
    text = (ios_case.path / "report.md").read_text()
    sources = text.split("## Sources")[1].split("### Indicator files")[0]
    assert "**Apple App Store" not in sources  # the quick check asks no store
    assert "**stalkerware-indicators" in sources  # the bundle-id lists did their job


def test_review_asks_one_question_per_ios_app(ios_case):
    checks.check_apps(ios_case)
    report.triage(ios_case)
    report.report(ios_case, partial=True)
    subjects = [f["subject"] for f in report.needs_answer(ios_case)]
    # the app that is both Hidden and unsigned asks once; profiles named by
    # their own kind ask apart; crash infos never ask.
    assert subjects.count("com.example.spyware.helper") == 1
    assert not any(s.startswith("/") for s in subjects)


def test_backup_results_still_win_over_quick_data(ios_case):
    """When a backup was analysed, its applications.json and profiles are used;
    the quick apps must not ask anything twice."""
    results = ios_case.path / "mvt-results"
    results.mkdir(exist_ok=True)
    (results / "applications.json").write_text(json.dumps([
        {"softwareVersionBundleId": "com.example.notes", "itemName": "Example Notes",
         "sourceApp": "com.apple.AppStore"}]))
    (results / "configuration_profiles.json").write_text(json.dumps([]))
    ios_case.mark("analyze")
    findings = checks.check_ios(ios_case)
    assert not any(f["subject"] == "com.example.notes" for f in findings)  # store app: clean
    assert any(f["kind"] == "ios-enterprise-app" for f in findings)  # provisioning still read from quick
    assert any(f["kind"] == "ios-crash-pattern" for f in findings)  # MVT never looks at crash logs


def fake_pmd(answers):
    """A `run` that answers like pymobiledevice3: JSON on stdout or exit 1."""

    def run(cmd, **kwargs):
        answer = answers.get(cmd[1])
        if answer is None:
            return SimpleNamespace(returncode=1, stdout="", stderr="device went away")
        return SimpleNamespace(returncode=0, stdout=answer, stderr="")

    return run


def test_quick_step_records_counts_and_survives_partial_failures(sandbox, monkeypatch):
    from sta import acquire

    answers = {"apps": '{"com.a": {"ApplicationType": "User"}}', "profile": '{"ProfileMetadata": {}}'}
    monkeypatch.setattr(acquire, "run", fake_pmd(answers))
    monkeypatch.setattr(acquire, "which", lambda name: "/bin/pymobiledevice3")
    case = make_case(sandbox, "2026-01-01-fail", platform="ios", acquisition=None)
    acquire.quick_ios(case)
    info = case.state["ios_quick"]
    assert info["apps"] == 1 and info["profiles"] == 0
    assert str(info["provision"]).startswith("failed") and str(info["crashes"]).startswith("failed")
    assert case.done("ios-quick")


def test_quick_step_fails_when_nothing_answers(sandbox, monkeypatch):
    from sta import acquire

    monkeypatch.setattr(acquire, "run", fake_pmd({}))
    monkeypatch.setattr(acquire, "which", lambda name: "/bin/pymobiledevice3")
    case = make_case(sandbox, "2026-01-01-dead", platform="ios", acquisition=None)
    with pytest.raises(StepError, match="none of the four"):
        acquire.quick_ios(case)
    assert not case.done("ios-quick")


def test_quick_step_never_writes_the_udid_to_state(sandbox, monkeypatch):
    from sta import acquire

    monkeypatch.setattr(acquire, "run", fake_pmd({"apps": "{}"}))
    monkeypatch.setattr(acquire, "which", lambda name: "/bin/pymobiledevice3")
    case = make_case(sandbox, "2026-01-01-clean", platform="ios", acquisition=None)
    acquire.quick_ios(case)  # TESTUDID is in every command line
    assert "TESTUDID" not in json.dumps(case.state["ios_quick"])


def test_next_suggests_partial_after_two_failed_backups(sandbox, capsys):
    from sta import __main__ as cli
    case = make_case(sandbox, "2026-01-01-next", platform="ios", acquisition=None)
    case.mark("update-kb")  # the fixture's detect/analyze marks must not confuse next
    case.unmark("acquire")
    case.unmark("analyze")
    case.mark("ios-quick")
    case.mark("ios-password")
    case.state["ios_acquire_fails"] = 2
    case.save()
    cli.cmd_next(case)
    out = capsys.readouterr().out
    assert "NEXT STEP: acquire" in out and "report --partial" in out


def test_read_crashes_is_recursive(ios_case, tmp_path):
    """`crash pull` keeps the phone's folder structure; we read all of it."""
    from sta import iosquick

    deep = tmp_path / "crashes" / "ResetPeriodization"
    deep.mkdir(parents=True)
    shutil.copy(ios_case.path / "acquisition/ios-quick/crashes/SpringBoard-2026-10-18.ips",
                deep / "SpringBoard.ips")
    assert list(iosquick.read_crashes(tmp_path / "crashes")) == ["SpringBoard"]
