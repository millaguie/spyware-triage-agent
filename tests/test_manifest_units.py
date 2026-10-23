"""The manifest rules, one test per row of the task-1 table.

`info` dicts are built by hand (the way parse_apk returns them): the only real
APK fixture is a clean store app, so every hostile shape has to be synthetic.
The subprocess boundary (`python -m sta.manifest`) is tested against the real
fixture at the end."""

from pathlib import Path

import pytest

from sta import manifest

FIXTURE_APK = Path(__file__).resolve().parent / "fixtures" / "apks" / "org.schabi.newpipe.apk"


def spy(**over):
    """A hand-installed stalkerware manifest: icon hidden, SMS + boot, three
    surveillance permissions."""
    info = {"package": "com.spyware.thing", "label": "System Update Service", "target_sdk": "22",
            "main_activity": "com.spyware.thing.MainActivity",
            "launcher": ["com.spyware.thing.MainActivity"],
            "permissions_declared": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                                     "android.permission.RECORD_AUDIO"],
            "receivers_boot": ["com.spyware.thing.BootReceiver"], "receivers_sms": [],
            "device_admin_receivers": [], "services_accessibility": []}
    info.update(over)
    return info


GRANTED = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
           "android.permission.RECORD_AUDIO"}


def run(info, origin="sideload", granted=None, **over):
    over.setdefault("disabled", set())  # dumpsys known, nothing disabled
    return manifest.manifest_findings(info.get("package", "com.spyware.thing"), info, origin,
                                      GRANTED if granted is None else granted,
                                      hidden_ok=set(), **over)


def kinds(out):
    return {(f["kind"], f["severity"]) for f in out}


class TestAppHidden:
    def test_disabled_launcher_is_the_main_signal(self):
        out = run(spy(), disabled={"com.spyware.thing.MainActivity"})
        hidden = [f for f in out if f["kind"] == "app-hidden"]
        assert len(hidden) == 1 and hidden[0]["severity"] == "red"  # sideload
        assert "source" not in hidden[0]["evidence"]

    def test_store_app_is_amber(self):
        out = run(spy(), origin="play", disabled={"com.spyware.thing.MainActivity"})
        assert ("app-hidden", "amber") in kinds(out)

    def test_manifest_fallback_is_one_level_lower_and_marked(self):
        info = spy(launcher=[], main_activity=None)
        out = manifest.manifest_findings("com.spyware.thing", info, "sideload", GRANTED,
                                         disabled=None, hidden_ok=set())
        hidden = [f for f in out if f["kind"] == "app-hidden"]
        assert len(hidden) == 1 and hidden[0]["severity"] == "amber"
        assert hidden[0]["evidence"]["source"] == "manifest"

    def test_launcher_present_but_not_disabled_is_not_hidden(self):
        out = run(spy(), disabled={"com.spyware.thing.OtherReceiver"})
        assert not any(f["kind"] == "app-hidden" for f in out)

    def test_store_app_without_icon_is_not_hidden_when_dumpsys_is_known(self):
        # iconless by design (a keyboard): with dumpsys data there is no story
        out = run(spy(launcher=[]), origin="play")
        assert not any(f["kind"] == "app-hidden" for f in out)

    def test_sideloaded_app_without_icon_is_amber_even_with_dumpsys(self):
        # an APK shipped with no launcher at all: disabled_components never sees it
        hidden = [f for f in run(spy(launcher=[])) if f["kind"] == "app-hidden"]
        assert len(hidden) == 1 and hidden[0]["severity"] == "amber"
        assert hidden[0]["evidence"]["source"] == "manifest"

    def test_hidden_ok_package_is_skipped(self):
        info = spy(package="org.chromium.webapk.abc_v2", launcher=["x.MainActivity"])
        out = manifest.manifest_findings(info["package"], info, "sideload", GRANTED,
                                         disabled={"x.MainActivity"},
                                         hidden_ok={"org.chromium.webapk.*"})
        assert not any(f["kind"] == "app-hidden" for f in out)


class TestLabel:
    def test_two_system_words(self):
        out = run(spy(label="System Update Service"))
        assert ("app-label-mimics-system", "amber") in kinds(out)

    def test_exact_label(self):
        out = run(spy(label="Settings", launcher=["x.MainActivity"]))
        assert any(f["kind"] == "app-label-mimics-system" for f in out)

    def test_store_app_is_info(self):
        out = run(spy(label="Google Play Services Helper", launcher=["x.MainActivity"]), origin="play")
        assert ("app-label-mimics-system", "info") in kinds(out)

    def test_unresolved_label_is_skipped(self):
        out = run(spy(label="@7F1254BB", launcher=["x.MainActivity"]))
        assert not any(f["kind"] == "app-label-mimics-system" for f in out)

    def test_one_word_is_not_enough(self):
        out = run(spy(label="System Tools"))
        assert not any(f["kind"] == "app-label-mimics-system" for f in out)

    def test_red_when_also_hidden(self):
        out = run(spy(), disabled={"com.spyware.thing.MainActivity"})
        assert ("app-label-mimics-system", "red") in kinds(out)


class TestBootSms:
    def test_boot_plus_sms_permission(self):
        assert ("app-boot-sms", "amber") in kinds(run(spy()))

    def test_boot_plus_sms_receiver(self):
        out = run(spy(receivers_boot=["B"], receivers_sms=["S"]), granted=set())
        assert any(f["kind"] == "app-boot-sms" for f in out)

    def test_store_app_is_info(self):
        assert ("app-boot-sms", "info") in kinds(run(spy(), origin="play"))

    def test_boot_alone_is_silent(self):
        out = run(spy(receivers_boot=[]), origin="play",
                  granted={"android.permission.INTERNET"})
        assert not any(f["kind"] == "app-boot-sms" for f in out)


class TestAccessibility:
    def test_declared_not_enabled_is_info(self):
        info = spy(services_accessibility=["com.spyware.thing.A11y"])
        out = run(info)
        assert ("app-accessibility-declared", "info") in kinds(out)

    def test_no_duplicate_when_enabled(self):
        # checks.py adds declared=True to the accessibility-service finding instead
        info = spy(services_accessibility=["com.spyware.thing.A11y"])
        out = run(info, accessibility_enabled=True)
        assert not any(f["kind"] == "app-accessibility-declared" for f in out)


class TestDeviceAdmin:
    def test_declared_is_info(self):
        info = spy(device_admin_receivers=["com.spyware.thing.Admin"])
        assert ("app-device-admin-declared", "info") in kinds(run(info))

    def test_amber_when_it_holds_the_rights(self):
        info = spy(device_admin_receivers=["com.spyware.thing.Admin"])
        out = run(info, device_admins=["com.spyware.thing"])
        assert ("app-device-admin-declared", "amber") in kinds(out)


class TestSurveillancePermissions:
    def test_three_granted_is_amber(self):
        assert ("app-surveillance-permissions", "amber") in kinds(run(spy()))

    def test_five_granted_sideload_is_red(self):
        five = {f"android.permission.{p}" for p in
                ("READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "RECORD_AUDIO", "CAMERA")}
        out = run(spy(), granted=five)
        assert ("app-surveillance-permissions", "red") in kinds(out)

    def test_two_is_silent(self):
        out = run(spy(), granted={"android.permission.READ_SMS", "android.permission.CAMERA"})
        assert not any(f["kind"] == "app-surveillance-permissions" for f in out)

    def test_declared_only_counts_and_is_marked(self):
        info = spy(launcher=[])
        out = manifest.manifest_findings("com.spyware.thing", info, "sideload", set(),
                                         disabled=None, hidden_ok=set())
        surv = [f for f in out if f["kind"] == "app-surveillance-permissions"][0]
        assert surv["severity"] == "amber" and surv["evidence"]["source"] == "manifest"

    def test_battery_exempt_turns_a_sideloaded_one_red(self):
        # three permissions are amber on their own; this app also sits on the
        # deviceidle user whitelist, so somebody made sure it never sleeps
        surv = [f for f in run(spy(), battery_exempt=True)
                if f["kind"] == "app-surveillance-permissions"][0]
        assert surv["severity"] == "red" and "battery saving" in surv["detail"]

    def test_store_app_is_info(self):
        # messengers and banks reach three permissions by design
        assert ("app-surveillance-permissions", "info") in kinds(run(spy(), origin="play"))

    def test_battery_exempt_alone_does_not_raise_a_store_app(self):
        # the pair is what worries us: a store app stays info, but the
        # evidence still says somebody kept it awake
        surv = [f for f in run(spy(), origin="play", battery_exempt=True)
                if f["kind"] == "app-surveillance-permissions"][0]
        assert surv["severity"] == "info" and "battery saving" in surv["detail"]

    def test_declared_only_and_exempt_is_still_red_when_sideloaded(self):
        info = spy(launcher=[])
        out = manifest.manifest_findings("com.spyware.thing", info, "sideload", set(),
                                         disabled=None, hidden_ok=set(), battery_exempt=True)
        surv = [f for f in out if f["kind"] == "app-surveillance-permissions"][0]
        assert surv["severity"] == "red" and surv["evidence"]["source"] == "manifest"


class TestOldTargetSdk:
    def test_old_sideload_is_amber(self):
        assert ("app-old-target-sdk", "amber") in kinds(run(spy(target_sdk="22")))

    def test_old_from_store_is_info(self):
        out = run(spy(target_sdk="19"), origin="play")
        assert ("app-old-target-sdk", "info") in kinds(out)

    def test_modern_and_missing_are_silent(self):
        assert not any(f["kind"] == "app-old-target-sdk" for f in run(spy(target_sdk="35")))
        assert not any(f["kind"] == "app-old-target-sdk" for f in run(spy(target_sdk=None)))


def test_failed_parse_emits_nothing():
    assert manifest.manifest_findings("com.x", {"error": "boom"}, "sideload", set()) == []
    assert manifest.manifest_findings("com.x", None, "sideload", set()) == []


def test_hidden_ok_patterns_default_to_the_kb_file(sandbox):
    # the real kb/hidden-ok.yaml (copied into the sandbox) allows Chrome webapps
    assert manifest.hidden_ok_packages() == {"org.chromium.webapk.*"}


def test_evidence_fields_match_the_plan_table():
    f = run(spy(), disabled={"com.spyware.thing.MainActivity"})[0]
    assert {"package", "origin", "label", "target_sdk", "main_activity", "has_launcher",
            "permissions_declared", "permissions_granted", "receivers_boot", "receivers_sms",
            "services_accessibility"} <= set(f["evidence"])
    ev = f["evidence"]
    assert ev["package"] == "com.spyware.thing" and ev["label"] == "System Update Service"
    assert ev["has_launcher"] is True and ev["receivers_boot"] is True
    assert ev["permissions_granted"] == sorted(GRANTED)


class TestChildProcess:
    def test_real_fixture_parses_in_the_child(self):
        info = manifest.inspect(FIXTURE_APK)
        assert not info.get("error"), info
        assert info["package"] == "org.schabi.newpipe"
        assert info["launcher"] == ["org.schabi.newpipe.MainActivity"]
        assert info["target_sdk"] == "35"
        # the fixture has no resources.arsc: the label stays a raw reference
        assert info["label"].startswith("@")
        assert info["receivers_boot"] == ["androidx.work.impl.background.systemalarm.RescheduleReceiver"]

    def test_broken_apk_reports_an_error_and_nothing_else(self, tmp_path):
        bad = tmp_path / "broken.apk"
        bad.write_bytes(b"not a zip at all")
        info = manifest.inspect(bad)
        assert "error" in info and "package" not in info

    def test_clean_fixture_emits_no_findings(self):
        # NewPipe boots at startup but asks for no SMS permission, so the one
        # rule it comes near (app-boot-sms) stays silent. This is the shape of
        # every clean store app in the pipeline test.
        info = manifest.inspect(FIXTURE_APK)
        assert manifest.manifest_findings("org.schabi.newpipe", info, "store", set(),
                                          disabled=set(), hidden_ok=set()) == []


@pytest.mark.parametrize("flag, want", [(None, False), ("1", True)])
def test_manifest_all_flag_selects_who_gets_read(case, no_apkid, monkeypatch, flag, want):
    """STA_MANIFEST_ALL widens the manifest pass from sideload/adb to every
    non-system APK (task 4 reuses the result)."""
    import shutil

    from sta import apkscan

    if flag is None:
        monkeypatch.delenv("STA_MANIFEST_ALL", raising=False)
    else:
        monkeypatch.setenv("STA_MANIFEST_ALL", flag)
    apks = case.path / "acquisition" / "androidqf" / "apks"
    apks.mkdir()
    shutil.copy(FIXTURE_APK, apks / "org.schabi.newpipe.apk")  # origin 'store' in the fixture
    calls = []

    def fake_inspect(path):
        calls.append(Path(path))
        return {"error": "stub"}

    monkeypatch.setattr(apkscan.manifest, "inspect", fake_inspect)
    findings, manifests, _ = apkscan.scan_apks(case, case.path / "acquisition" / "androidqf",
                                            {"org.schabi.newpipe": "store"}, set())
    assert bool(calls) == want
    assert findings == [] and manifests == {}


def test_a_missing_parser_is_said_not_hidden(case, monkeypatch, capsys):
    """An old image without pyaxmlparser must not look like 'every APK unreadable'."""
    import shutil

    from sta import apkscan, report
    apks = case.path / "acquisition" / "androidqf" / "apks"
    apks.mkdir(exist_ok=True)
    shutil.copy(FIXTURE_APK, apks / "org.example.sideloaded.apk")
    monkeypatch.setattr(manifest, "parser_available", lambda: False)
    monkeypatch.setattr(apkscan, "apkid_labels", lambda paths, log: {})
    apkscan.scan_apks(case, case.path / "acquisition" / "androidqf", {"org.example.sideloaded": "sideload"}, set())
    assert "pyaxmlparser is missing" in capsys.readouterr().out
    rows = dict(report.checked_rows(case))
    assert rows["APK manifests"] == "not read: pyaxmlparser is not installed"
