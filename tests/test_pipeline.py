"""check-apps, triage, report and review on the android-pixel fixture.

The expected findings are written out in full: a change in a rule that moves
a finding from amber to info, or drops one, must show up here."""

import hashlib
import hmac
import json
import shutil
from pathlib import Path

import pytest

from conftest import make_case
from sta import apkscan, checks, report
from sta.common import StepError

FIXTURE_APK = Path(__file__).resolve().parent / "fixtures" / "apks" / "org.schabi.newpipe.apk"


def kinds(findings):
    return sorted((f["kind"], f["severity"], f["subject"]) for f in findings)


def test_check_android_offline(case, no_apkid):
    findings = checks.check_android(case)
    assert kinds(findings) == [
        ("accounts-review", "amber", "phone accounts"),   # 2 Google accounts in the fixture dumpsys
        ("notification-listener", "amber", "org.example.watch.companion"),      # Play app, not system: amber
        ("role-holder", "red", "org.example.sideloaded"),  # SMS holder, hand installed, no F-Droid match
        ("sideloaded-app", "amber", "org.example.conference.wifisetup"),  # lookup not done: offline
        ("sideloaded-app", "amber", "org.example.devtool.debug"),
        ("sideloaded-app", "amber", "org.example.sideloaded"),
        ("sideloaded-app", "info", "org.fdroid.fdroid"),  # signature matches the F-Droid build
        ("unreadable-package", "info", "com.android.privatespace"),
        ("webapk", "info", "org.chromium.webapk.0123456789abcdef0_v2"),
    ]
    # Signal from Play with its official key, and the system listeners: nothing.
    assert not any(f["subject"] == "org.thoughtcrime.securesms" for f in findings)
    assert not any(f["subject"] == "com.google.android.gms" for f in findings)
    # The dialer holder is Google Phone from kb/role-defaults.yaml: no question.
    assert not any(f["subject"] == "com.google.android.dialer" for f in findings)


def test_store_lookups_change_the_kind(case, no_apkid, monkeypatch):
    case.state["network"] = True
    answers = {"org.example.devtool.debug": False, "org.example.sideloaded": None,
               "org.example.conference.wifisetup": True}
    monkeypatch.setattr(checks.Stores, "on_play", lambda self, pkg: answers.get(pkg))
    # org.example.sideloaded now has a role-holder finding too; this test is
    # about the sideload kind that the store answer picks.
    by = {f["subject"]: f["kind"] for f in checks.check_android(case) if f["kind"] != "role-holder"}
    assert by["org.example.devtool.debug"] == "unknown-origin-app"
    assert by["org.example.sideloaded"] == "sideloaded-app"
    assert by["org.example.conference.wifisetup"] == "sideloaded-store-app"


def test_stalkerware_and_malware_indicators(case, no_apkid):
    acq = case.path / "acquisition" / "androidqf"
    packages = json.loads((acq / "packages.json").read_text())
    base = {"installer": "null", "system": False, "installed": True,
            "files": [{"path": "/data/app/x/base.apk", "sha256": "0" * 64,
                       "certificate": {"Sha1": "0" * 40, "Sha256": "0" * 64}}]}
    packages += [
        {**base, "name": "com.fakespy.monitor"},                      # ioc.yaml by package
        {**base, "name": "com.whatever", "files": [{**base["files"][0],
                 "certificate": {"Sha1": "0" * 39 + "1", "Sha256": "0" * 64}}]},  # ioc.yaml by cert
        {**base, "name": "com.kidwatch.parent"},                       # watchware
        {**base, "name": "com.testrat.dropper"},                       # androdr package, MEDIUM
        {**base, "name": "com.dropper.x", "files": [{**base["files"][0], "sha256": "1" * 64}]},  # androdr hash
        {**base, "name": "com.whatsapp.plus"},                         # impersonation
        {**base, "name": "org.thoughtcrime.securesms", "installer": "com.android.vending"},  # fake Signal (second user)
        {**base, "name": "com.android.system.update.service"},        # looks like system
    ]
    # Only the first entry per package name counts (several users can share
    # one package), so the fake Signal replaces the real one.
    packages = [p for p in packages if p["name"] != "org.thoughtcrime.securesms"] + packages[-2:]
    (acq / "packages.json").write_text(json.dumps(packages))
    by = {(f["subject"]): (f["kind"], f["severity"]) for f in checks.check_android(case)}
    assert by["com.fakespy.monitor"] == ("stalkerware", "red")
    assert by["com.whatever"] == ("stalkerware", "red")
    assert by["com.kidwatch.parent"] == ("watchware", "amber")
    assert by["com.testrat.dropper"] == ("known-malware", "amber")
    assert by["com.dropper.x"] == ("known-malware", "red")
    assert by["com.whatsapp.plus"] == ("impersonation", "red")
    assert by["org.thoughtcrime.securesms"] == ("signer-mismatch", "amber")  # from Play: amber
    # looks-like-system comes with the sideloaded finding; the dict keeps the last one
    subjects = [f["kind"] for f in checks.check_android(case) if f["subject"] == "com.android.system.update.service"]
    assert subjects == ["looks-like-system", "sideloaded-app"]


def test_check_apps_writes_file_and_marks_step(case, no_apkid):
    checks.check_apps(case)
    assert (case.path / "app-findings.json").exists()
    assert case.done("check-apps")
    assert case.state["steps"]["check-apps"]["counts"] == {"red": 1, "amber": 5, "info": 3}


def test_manifest_of_a_clean_store_app_adds_nothing(case, no_apkid, monkeypatch):
    """The real NewPipe fixture APK parsed through `python -m sta.manifest`.
    STA_MANIFEST_ALL makes check_android read it even though its origin is a
    store; with nothing to report, apk-scan.json still keeps the parse."""
    monkeypatch.setenv("STA_MANIFEST_ALL", "1")
    apks = case.path / "acquisition" / "androidqf" / "apks"
    apks.mkdir()
    shutil.copy(FIXTURE_APK, apks / "org.schabi.newpipe.apk")
    before = {(f["kind"], f["subject"]) for f in checks.check_android(case)}
    assert before == {
        ("accounts-review", "phone accounts"),
        ("notification-listener", "org.example.watch.companion"),
        ("role-holder", "org.example.sideloaded"),
        ("sideloaded-app", "org.example.conference.wifisetup"),
        ("sideloaded-app", "org.example.devtool.debug"),
        ("sideloaded-app", "org.example.sideloaded"),
        ("sideloaded-app", "org.fdroid.fdroid"),
        ("unreadable-package", "com.android.privatespace"),
        ("webapk", "org.chromium.webapk.0123456789abcdef0_v2"),
    }  # same as test_check_android_offline: NewPipe adds no manifest finding
    parsed = json.loads((case.path / "apk-scan.json").read_text())["org.schabi.newpipe"]["manifest"]
    assert parsed["package"] == "org.schabi.newpipe" and not parsed.get("error")


def test_manifest_hidden_app_end_to_end(case, no_apkid, monkeypatch):
    """The stalkerware shape through the whole check: APK whose launcher is in
    disabled_components + SMS permissions granted from dumpsys. inspect() is
    patched (there is no way to build a hostile manifest fixture), everything
    else — file mapping, package details, severities — runs for real."""
    acq = case.path / "acquisition" / "androidqf"
    packages = json.loads((acq / "packages.json").read_text())
    packages.append({"name": "org.example.hidden", "installer": "null", "system": False,
                     "installed": True,  # installed by adb: the fixture's dumpsys block is this app
                     "files": [{"path": "/data/app/x/base.apk", "sha256": "2" * 64,
                                "certificate": {"Sha1": "3" * 40, "Sha256": "4" * 64}}]})
    (acq / "packages.json").write_text(json.dumps(packages))
    apks = acq / "apks"
    apks.mkdir()
    shutil.copy(FIXTURE_APK, apks / "org.example.hidden.apk")  # matches the dumpsys block
    info = {"package": "org.example.hidden", "label": "System Update Service", "target_sdk": "22",
            "main_activity": "org.example.hidden.MainActivity",
            "launcher": ["org.example.hidden.MainActivity"],
            "permissions_declared": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                                     "android.permission.RECORD_AUDIO"],
            "receivers_boot": ["org.example.hidden.BootReceiver"], "receivers_sms": [],
            "device_admin_receivers": [], "services_accessibility": []}
    monkeypatch.setattr(apkscan.manifest, "inspect", lambda path: info)
    findings = checks.check_android(case)
    by = {(f["kind"], f["severity"]) for f in findings if f["subject"] == "org.example.hidden"}
    assert by == {("app-hidden", "red"), ("app-label-mimics-system", "red"),
                  ("app-boot-sms", "amber"), ("app-surveillance-permissions", "amber"),
                  ("app-old-target-sdk", "amber"), ("sideloaded-app", "amber")}
    hidden = next(f for f in findings if f["kind"] == "app-hidden")
    assert hidden["evidence"]["main_activity"] == "org.example.hidden.MainActivity"
    assert hidden["evidence"]["receivers_boot"] is True


def test_check_android_saves_package_details(case, no_apkid):
    """dumpsys package parsed once, kept for the timeline and the diff."""
    checks.check_android(case)
    details = json.loads((case.path / "package-details.json").read_text())
    # one block per package in the dumpsys, plus a stub for each app on the
    # battery whitelist that has no block (task 3.3 keeps the list in this file)
    assert sorted(details) == ["org.example.hidden", "org.example.sideloaded", "org.fdroid.fdroid"]
    assert details["org.fdroid.fdroid"] == {"battery_exempt": True}
    hidden = details["org.example.hidden"]
    assert hidden["first_install"] == "2026-10-10 11:00:00"
    assert hidden["last_update"] == "2026-10-10 11:00:05"
    assert hidden["installer"] is None  # installerPackageName=null
    assert hidden["target_sdk"] == 22
    assert hidden["install_reason"] == 4
    assert hidden["enabled"] == 0 and hidden["hidden"] is False
    assert sorted(hidden["flags"]) == ["ALLOW_CLEAR_USER_DATA", "HAS_CODE"]
    assert hidden["granted"] == ["android.permission.ACCESS_COARSE_LOCATION",
                                 "android.permission.ACCESS_NETWORK_STATE",
                                 "android.permission.INTERNET",
                                 "android.permission.POST_NOTIFICATIONS",
                                 "android.permission.READ_SMS",
                                 "android.permission.RECEIVE_BOOT_COMPLETED",
                                 "android.permission.RECEIVE_SMS",
                                 "android.permission.RECORD_AUDIO"]
    assert hidden["disabled_components"] == ["org.example.hidden.MainActivity"]
    assert hidden["users"] == [0]
    assert hidden["battery_exempt"] is False  # not on the deviceidle user whitelist


def test_accounts_and_users_never_write_personal_names(case, no_apkid):
    """Tasks 3.1 and 3.4: only counts, types, ids and HMACs reach the case files."""
    checks.check_android(case)
    accounts = json.loads((case.path / "accounts.json").read_text())
    text = json.dumps(accounts)
    for name in ("a@example.com", "b@example.com", "WhatsApp", "Owner"):
        assert name not in text
    assert sorted(accounts["google_accounts"]) == sorted(
        [hmac.new(checks.account_key(), name.encode(), hashlib.sha256).hexdigest()
         for name in ("a@example.com", "b@example.com")])


def test_battery_exempt_marks_every_finding_of_that_package(case, no_apkid):
    """Task 3.3: the exemption itself is not a finding; it rides along as
    evidence on anything else we already found about that package."""
    findings = checks.check_android(case)
    exempted = [f for f in findings if f["subject"] == "org.example.sideloaded"]
    assert exempted and all(f["evidence"]["battery_exempt"] for f in exempted)
    fdroid = [f for f in findings if f["subject"] == "org.fdroid.fdroid"]  # also on the list
    assert fdroid and all(f["evidence"]["battery_exempt"] for f in fdroid)
    assert not any(f["kind"] == "battery-exempt" for f in findings)  # never a finding itself
    other = next(f for f in findings if f["subject"] == "org.example.watch.companion")
    assert "battery_exempt" not in other["evidence"]


@pytest.fixture
def triaged(case, no_apkid):
    checks.check_apps(case)
    report.triage(case)
    return case


def test_triage_merges_mvt_and_app_findings(triaged):
    data = json.loads((triaged.path / "findings.json").read_text())
    assert data["schema"] == 1
    findings = data["findings"]
    assert [f["id"] for f in findings] == [f"F{n:03d}" for n in range(1, len(findings) + 1)]
    assert kinds(findings) == [
        ("accounts-review", "amber", "phone accounts"),       # counts only, never names
        ("crash-watchdog", "info", "tombstones"),
        ("mvt-low", "info", "com.android.chrome"),            # permission set to reject
        ("mvt-low", "info", "com.google.android.trichromelibrary_782700532"),
        ("mvt-low", "info", "dumpsys_adb_state"),
        ("mvt-low", "info", "org.schabi.newpipe"),
        ("mvt-medium", "amber", "org.telegram.messenger"),
        ("notification-listener", "amber", "org.example.watch.companion"),
        ("role-holder", "red", "org.example.sideloaded"),
        ("sideloaded-app", "amber", "org.example.conference.wifisetup"),
        ("sideloaded-app", "amber", "org.example.devtool.debug"),
        ("sideloaded-app", "amber", "org.example.sideloaded"),
        ("sideloaded-app", "info", "org.fdroid.fdroid"),
        ("unreadable-package", "info", "com.android.privatespace"),
        ("webapk", "info", "org.chromium.webapk.0123456789abcdef0_v2"),
    ]
    # the three trichrome uninstalls became one finding with the others as evidence
    tri = next(f for f in findings if f["subject"].startswith("com.google.android.trichromelibrary"))
    assert "(3 alerts like this)" in tri["detail"]
    assert len(tri["evidence"]["more_events"]) == 2
    # the MVT alert about the sideloaded app lives inside our finding
    dev = next(f for f in findings if f["subject"] == "org.example.devtool.debug")
    assert dev["evidence"]["mvt_alerts"] == [
        'MEDIUM: Found a non-system package installed via adb or another method: "org.example.devtool.debug"']
    # red first, then amber, then info
    sevs = [f["severity"] for f in findings]
    assert sevs == sorted(sevs, key=report.ORDER.__getitem__)


def test_triage_refuses_to_renumber_after_notes(triaged):
    report.add_note(triaged, "F001", "yes")
    with pytest.raises(StepError, match="already exist"):
        report.triage(triaged)


def test_mvt_red_wins_over_our_amber_but_not_over_watchware():
    mvt = [{"kind": "mvt-ioc-match", "severity": "red", "subject": "com.a", "detail": "x",
            "evidence": {"mvt_level": "HIGH"}},
           {"kind": "mvt-high", "severity": "red", "subject": "com.w", "detail": "y",
            "evidence": {"mvt_level": "HIGH"}}]
    ours = [{"kind": "sideloaded-app", "severity": "amber", "subject": "com.a", "detail": "", "evidence": {}},
            {"kind": "watchware", "severity": "amber", "subject": "com.w", "detail": "", "evidence": {}}]
    out = {f["subject"]: f for f in report.merge(mvt, ours)}
    assert out["com.a"]["severity"] == "red"
    assert out["com.w"]["severity"] == "amber"
    assert len(out) == 2


def test_review_asks_one_question_per_app_and_notes_cover_it(triaged, capsys):
    report.report(triaged)
    open_items = report.needs_answer(triaged)
    # In ID order, which follows KIND_PRIORITY: the sideloaded app whose question
    # is its red role-holder finding first, then the other sideloaded apps, then
    # capability holders, then plain MVT alerts, then the account count.
    assert [f["subject"] for f in open_items] == [
        "org.example.sideloaded", "org.example.conference.wifisetup", "org.example.devtool.debug",
        "org.example.watch.companion", "org.telegram.messenger", "phone accounts"]
    report.review(triaged, done=False)
    out = capsys.readouterr().out
    assert "«org.example.devtool.debug»" in out
    with pytest.raises(StepError, match="still have no owner answer"):
        report.review(triaged, done=True)
    for f in open_items:
        report.add_note(triaged, f["id"].lower(), f"answer for {f['subject']}")
    notes = json.loads((triaged.path / "notes.json").read_text())
    assert notes["schema"] == 1 and len(notes["notes"]) == 6
    report.review(triaged, done=True)
    assert triaged.done("review")
    text = (triaged.path / "report.md").read_text()
    assert "answer for org.example.sideloaded" in text


def test_add_note_rejects_unknown_id(triaged):
    with pytest.raises(StepError, match="not a finding"):
        report.add_note(triaged, "F999", "x")


def test_old_findings_file_without_schema_still_loads(triaged):
    path = triaged.path / "findings.json"
    data = json.loads(path.read_text())
    path.write_text(json.dumps(data["findings"]))
    assert len(report.load_findings(triaged)) == len(data["findings"])
    (triaged.path / "notes.json").write_text(json.dumps({"F001": {"text": "old", "at": "x"}}))
    assert report.notes(triaged) == {"F001": {"text": "old", "at": "x"}}


def test_report_content(triaged):
    report.report(triaged)
    text = (triaged.path / "report.md").read_text()
    assert "**1 red finding(s).**" in text  # the fixture's sideloaded SMS holder
    assert "| Device serial" not in text  # serial numbers stay out of the report
    assert "TESTSERIAL" not in text
    # account names and the user-profile name are personal data: nothing from a
    # UserInfo{...} or Account {...name=...} line may reach the report
    for secret in ("a@example.com", "b@example.com", "UserInfo{"):
        assert secret not in text
    # one paragraph per source, then the list of indicator files with its hashes
    assert "## Sources" in text and "**MVT indicators**" in text
    assert "### Indicator files" in text and "deadbeef" in text
    # an offline case consulted no store: it must not appear as a source
    assert "Google Play" not in text.split("## Sources")[1].split("### Indicator files")[0]
    assert "## What this check cannot see" in text


def test_report_lists_the_lookups_a_case_made(triaged):
    """A source appears only when its answer file exists in the case."""
    (triaged.path / "store-lookups.json").write_text('{"play:org.example.sideloaded": false}')
    report.report(triaged)
    text = (triaged.path / "report.md").read_text()
    assert "**Google Play**" in text and "**VirusTotal**" not in text


def test_report_result_lines(sandbox, no_apkid):
    case = make_case(sandbox, "2026-01-01-red")
    checks.check_apps(case)
    items = json.loads((case.path / "app-findings.json").read_text())
    items.append({"kind": "stalkerware", "severity": "red", "subject": "com.fakespy.monitor",
                  "detail": "x", "evidence": {}})
    (case.path / "app-findings.json").write_text(json.dumps(items))
    report.triage(case)
    report.report(case)
    text = (case.path / "report.md").read_text()
    assert "**2 red finding(s).**" in text  # the added one plus the fixture's role-holder
    assert "do not remove it or confront anyone" in text

    # same phone without the role finding: the amber result line and its steps
    case = make_case(sandbox, "2026-01-01-amber")
    checks.check_apps(case)
    items = [f for f in json.loads((case.path / "app-findings.json").read_text())
             if f["kind"] != "role-holder"]
    (case.path / "app-findings.json").write_text(json.dumps(items))
    report.triage(case)
    report.report(case)
    text = (case.path / "report.md").read_text()
    assert "**No red findings. 6 amber finding(s)**" in text
    assert "2. Remove apps that nobody recognises" in text  # amber next steps


def test_guided_review_keeps_the_typed_words(triaged, capsys):
    """The operator's typed answers go into the notes byte for byte: no model in between."""
    report.report(triaged)
    questions = report.open_questions(triaged)
    typed = iter(["", "  Mi hermano la instaló «no sé»  ", *[f"answer {n}" for n in range(len(questions))]])
    report.review_interactive(triaged, read=lambda prompt: next(typed))
    notes = json.loads((triaged.path / "notes.json").read_text())["notes"]
    assert notes[questions[0]["id"]]["text"] == "Mi hermano la instaló «no sé»"
    assert triaged.done("review")
    assert f"1/{len(questions)}" in capsys.readouterr().out


def test_show_finding_gives_clean_fields_and_no_evidence(triaged, capsys):
    report.show_finding(triaged, "f001", as_json=True)
    shown = json.loads(capsys.readouterr().out)
    assert shown["id"] == "F001" and shown["subject"].startswith("«")
    assert set(shown) == {"id", "severity", "title", "subject", "detail", "why", "what_to_do"}
    with pytest.raises(StepError, match="not a finding"):
        report.show_finding(triaged, "F999")
