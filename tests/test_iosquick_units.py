"""The ios-quick rules: .ips parsing, provisioning, profiles, apps (units)."""

import datetime as dt

from sta import iosquick


def entry(at="/System/x", when="2026-10-01 10:00:00.00 +0000", bug="309", name="x.ips"):
    return {"at": when, "bug_type": bug, "file": name, "path": at}


IPS_TWO_LINES = ('{"app_name":"WebKit.Networking","timestamp":"2026-10-01 10:00:00.00 +0200",'
                 '"bug_type":"309","incident_id":"X"}\n'
                 '{"procName":"com.apple.WebKit.Networking","procPath":"/System/Library/x",'
                 '"exception":{"type":"EXC_BAD_ACCESS"}}\n')


def test_parse_ips_two_lines():
    parsed = iosquick.parse_ips(IPS_TWO_LINES)
    assert parsed["process"] == "com.apple.WebKit.Networking"  # the body wins over app_name
    assert parsed["bug_type"] == "309"
    assert parsed["at"] == "2026-10-01 10:00:00.00 +0200"
    assert parsed["path"] == "/System/Library/x"


def test_parse_ips_old_plain_body_still_gives_metadata():
    text = ('{"app_name":"backboardd","timestamp":"2026-09-01 03:00:00.00 +0000","bug_type":"309"}\n'
            "Date/Time: ...\n")
    parsed = iosquick.parse_ips(text)
    assert parsed["process"] == "backboardd" and parsed["path"] == ""


def test_parse_ips_rejects_junk():
    assert iosquick.parse_ips("not json\nat all\n") is None


def test_crash_time_reads_the_phone_timezone():
    stamp = iosquick.crash_time("2026-10-01 10:00:00.00 +0200")
    assert stamp == dt.datetime(2026, 10, 1, 8, 0, tzinfo=dt.UTC)


def test_crash_pattern_needs_two_crashes_inside_the_window():
    near = [entry(when=f"2026-06-{d:02d} 10:00:00.00 +0000") for d in (1, 15)]
    out = iosquick.crash_findings({"backboardd": near})
    assert [(f["kind"], f["severity"]) for f in out] == [("ios-crash-pattern", "info")]
    far = [entry(when="2026-01-01 10:00:00.00 +0000"), entry(when="2026-05-01 10:00:00.00 +0000")]
    kinds = [f["kind"] for f in iosquick.crash_findings({"backboardd": far})]
    assert "ios-crash-pattern" not in kinds  # four months apart is not a pattern


def test_unknown_process_recognises_daemons_and_apps():
    out = iosquick.crash_findings({"com.apple.WebKit.Networking": [entry()]})
    assert out == []  # the yaml lists it with the prefix; summaries use both forms
    out = iosquick.crash_findings({"SpringBoard": [entry()]})
    assert out == []
    out = iosquick.crash_findings({"com.example.notes": [entry()]}, bundle_ids=["com.example.notes"])
    assert out == []
    kinds = [(f["kind"], f["severity"]) for f in iosquick.crash_findings({"weird_daemon": [entry()]})]
    assert kinds == [("ios-crash-unknown-process", "info")]


def test_crash_from_spyware_folder_is_red_and_never_also_unknown():
    out = iosquick.crash_findings({"/private/var/tmp/updater": [entry(at="/private/var/tmp/updater")]})
    assert [(f["kind"], f["severity"]) for f in out] == [("ios-crash-suspicious-path", "red")]


def test_only_crash_bug_types_count_as_crashes():
    # a 'spin' report (343) of an unknown process is not a process crash
    assert iosquick.crash_findings({"mystery": [entry(bug="343")]}) == []


ENTERPRISE = {
    "Name": "BigCorp In-House", "UUID": "u1", "TeamName": "BigCorp", "TeamIdentifier": ["TEAM1"],
    "AppIDName": "Corp Notes", "ExpirationDate": "2029-01-05T09:00:00", "ProvisionsAllDevices": True,
    "Entitlements": {"application-identifier": "TEAM1.*", "get-task-allow": False}}
DEVELOPER = {
    "Name": "Dev build", "TeamName": "Solo", "TeamIdentifier": ["TEAM2"],
    "ExpirationDate": "2020-06-01T09:00:00", "ProvisionedDevices": ["UDID-A"],
    "Entitlements": {"application-identifier": "TEAM2.com.solo.app"}}


def test_provision_findings():
    out = iosquick.provision_findings([ENTERPRISE, DEVELOPER])
    assert [(f["kind"], f["severity"], f["subject"]) for f in out] == [
        ("ios-enterprise-app", "amber", "BigCorp In-House"),
        ("ios-developer-app", "amber", "Dev build"),
        ("ios-provision-expired", "info", "Dev build")]
    dev = next(f for f in out if f["kind"] == "ios-developer-app")
    assert dev["evidence"]["entitlements"] == ["application-identifier"]
    assert dev["evidence"]["app_id"] == "TEAM2.com.solo.app"
    ent = next(f for f in out if f["kind"] == "ios-enterprise-app")
    assert ent["evidence"].get("provisioned_devices") is None  # enterprise: no device list to count


def test_provision_never_copies_device_udids():
    import json
    text = json.dumps(iosquick.provision_findings([DEVELOPER]))
    assert "UDID-A" not in text and '"provisioned_devices": 1' in text


def covered(app_id):
    return bool(iosquick.covered_by_provision(app_id, [ENTERPRISE]))


def test_wildcard_profile_only_covers_its_own_team():
    assert covered("TEAM1.com.corp.notes")        # same team, wildcard suffix
    assert not covered("OTHER.com.corp.notes")    # another team cannot use this profile
    assert covered("TEAM1.exact.name")            # wildcard covers anything of the team


def test_classify_profile_from_types_and_from_words():
    assert iosquick.classify_profile(["com.apple.mdm"], "") == "ios-mdm-profile"
    assert iosquick.classify_profile(["com.apple.security.root"], "") == "ios-root-certificate"
    assert iosquick.classify_profile(["com.apple.vpn.managed"], "") == "ios-vpn-profile"
    assert iosquick.classify_profile([], "Example Management Profile") == "ios-mdm-profile"
    assert iosquick.classify_profile([], "Charles Proxy CA (1 Jan 2026)") == "ios-root-certificate"
    assert iosquick.classify_profile([], "Work VPN") == "ios-vpn-profile"
    assert iosquick.classify_profile([], "Campus Wi-Fi") == "ios-config-profile"


def test_profiles_from_quick_shape():
    # The GetProfileList shape read from pmd3 source (format-notes 11).
    data = {"OrderedIdentifiers": ["id1"],
            "ProfileManifest": {"id1": {"Description": "Example MDM enrollment", "IsActive": True}},
            "ProfileMetadata": {"id1": {"PayloadDisplayName": "Example MDM", "PayloadOrganization": "Ex",
                                        "PayloadRemovalDisallowed": True, "PayloadUUID": "u"}}}
    out = iosquick.profile_findings(iosquick.profiles_from_quick(data))
    assert [(f["kind"], f["severity"]) for f in out] == [("ios-mdm-profile", "red")]
    assert out[0]["detail"].startswith("The live profile list does not include")  # heuristic is declared


def test_profiles_from_backup_keeps_severity_and_removal_rule():
    backup = [{"plist": {"PayloadDisplayName": "Corp", "PayloadContent": [{"PayloadType": "com.apple.mdm"}],
                         "PayloadRemovalDisallowed": False}}]
    out = iosquick.profile_findings(iosquick.profiles_from_backup(backup))
    assert [(f["kind"], f["severity"]) for f in out] == [("ios-mdm-profile", "amber")]


def app(signer=iosquick.APP_STORE_SIGNER, app_type="User", path="/private/var/containers/Bundle/Application/X/A.app",
        ent=None):
    return {"CFBundleName": "A", "SignerIdentity": signer, "ApplicationType": app_type,
            "Path": path, "Entitlements": ent or {"application-identifier": "T.com.a"}}


def test_quick_app_findings_rules():
    apps = {"com.store.app": app(),
            "com.corp.app": app(signer="iPhone Distribution: BigCorp (TEAM1)",
                                ent={"application-identifier": "TEAM1.com.corp.app"}),
            "com.dark.app": app(app_type="Hidden"),
            "com.hidden.sys": app(app_type="Hidden", path="/Applications/HiddenThing.app"),
            "com.strange.app": app(signer="iPhone Distribution: Nobody (ZZ9)")}
    provisions = [dict(ENTERPRISE, Entitlements={"application-identifier": "TEAM1.*"})]
    out = iosquick.quick_app_findings(apps, provisions, {})
    got = {(f["kind"], f["subject"]) for f in out}
    assert got == {("ios-app-hidden", "com.dark.app"),          # user container: hidden from the owner
                   ("ios-app-not-store-signed", "com.strange.app")}  # no profile explains it
    # com.corp.app is explained by the enterprise profile; system-hidden is not a finding.


def test_quick_app_ioc_cross_reference():
    apps = {"com.fakespy.monitor": app()}
    out = iosquick.quick_app_findings(apps, [], {"com.fakespy.monitor": ("FakeSpy", "stalkerware")})
    assert [(f["kind"], f["severity"]) for f in out] == [("stalkerware", "red")]


def test_watch_entitlements_are_info():
    apps = {"com.vpn.app": app(ent={"application-identifier": "T.com.vpn.app",
                                    "com.apple.developer.networking.vpn.api": ["allow-vpn"]})}
    out = iosquick.quick_app_findings(apps, [], {})
    assert [(f["kind"], f["severity"]) for f in out] == [("ios-app-entitlements", "info")]
