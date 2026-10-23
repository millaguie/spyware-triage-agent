"""Pure helpers in sta.checks: parsing and the rules that pick a severity."""

import hashlib
import hmac
import json

from sta import checks, common, dumpsys

# The `device_policy` section of an unmanaged Pixel (format-notes.md section 7):
# no Device Owner line at all.
FIXTURE_POLICY = ("Current Device Policy Manager state:\n  Immutable state:\n    mHasFeature=true\n"
                  "  Enabled Device Admins (User 0, provisioningState: 0):\n\n    mPasswordOwner=-1\n")


def test_parse_getprop():
    text = "[ro.boot.verifiedbootstate]: [green]\n[ro.build.tags]: [release-keys]\n[empty]: []\nnoise\n"
    assert checks.parse_getprop(text) == {"ro.boot.verifiedbootstate": "green",
                                          "ro.build.tags": "release-keys", "empty": ""}


def test_parse_settings_keeps_values_with_equals():
    assert checks.parse_settings("a=1\nb=x=y\nno_equals\n") == {"a": "1", "b": "x=y"}


def test_component_packages():
    value = "com.a/com.a.Svc:com.b/.Svc:null:com.a/com.a.Other"
    assert checks.component_packages(value) == ["com.a", "com.b"]
    assert checks.component_packages("") == []


def test_device_admin_packages_reads_only_its_section():
    text = ("-" * 79 + "\nDUMP OF SERVICE device_policy:\n  Enabled Device Admins:\n"
            "    ComponentInfo{com.evil.admin/com.evil.Receiver}\n"
            + "-" * 79 + "\nDUMP OF SERVICE other:\n ComponentInfo{com.other/x}\n")
    policy = dumpsys.sections(text)["device_policy"]
    assert checks.device_admin_packages(policy) == ["com.evil.admin"]
    assert checks.device_admin_packages("") == []


def test_origin():
    assert checks.origin({"system": True, "installer": "com.android.vending"}) == "system"
    assert checks.origin({"installer": "com.android.vending"}) == "play"
    assert checks.origin({"installer": "org.fdroid.fdroid"}) == "store"
    assert checks.origin({"installer": "null"}) == "adb"
    assert checks.origin({}) == "adb"
    assert checks.origin({"installer": "com.google.android.packageinstaller"}) == "sideload"


def test_impersonates():
    watched = {"com.whatsapp": "WhatsApp", "org.telegram.messenger": "Telegram"}
    assert checks.impersonates("com.whatsapp", watched) is None  # the real one
    assert checks.impersonates("com.whatsapp.plus", watched) == "com.whatsapp"
    assert checks.impersonates("org.telegram.messenger2", watched) == "org.telegram.messenger"
    assert checks.impersonates("com.example.notes", watched) is None


def test_norm_hash():
    assert checks.norm_hash("ab:cd ef") == "ABCDEF"
    assert checks.norm_hash(None) == ""


class TestPosture:
    def test_clean_pixel_has_no_findings(self):
        props = {"ro.boot.verifiedbootstate": "green", "ro.boot.flash.locked": "1",
                 "ro.build.tags": "release-keys", "ro.build.type": "user", "ro.debuggable": "0"}
        assert checks.posture_findings(props, {"adb_wifi_enabled": "0"}, "Enforcing") == []

    def test_missing_values_mean_no_finding(self):
        assert checks.posture_findings({}, {}, "") == []

    def test_unlocked_bootloader_is_amber_and_red_boot_is_red(self):
        amber = checks.posture_findings({"ro.boot.verifiedbootstate": "orange", "ro.boot.flash.locked": "0"}, {}, "")
        assert [(f["kind"], f["severity"]) for f in amber] == [("boot-not-verified", "amber")]
        red = checks.posture_findings({"ro.boot.verifiedbootstate": "red"}, {}, "")
        assert red[0]["severity"] == "red"

    def test_debug_build(self):
        out = checks.posture_findings({"ro.build.tags": "test-keys", "ro.build.type": "userdebug"}, {}, "")
        assert [f["kind"] for f in out] == ["debug-build"]

    def test_selinux_proxy_wifi_adb_private_dns(self):
        glob = {"http_proxy": "10.0.0.1:8080", "adb_wifi_enabled": "1",
                "private_dns_mode": "hostname", "private_dns_specifier": "dns.example"}
        out = checks.posture_findings({}, glob, "Permissive")
        kinds = {f["kind"]: f for f in out}
        assert set(kinds) == {"selinux-not-enforcing", "global-proxy", "wifi-adb", "private-dns"}
        assert kinds["global-proxy"]["subject"] == "10.0.0.1:8080"
        assert kinds["private-dns"]["severity"] == "info"

    def test_empty_proxy_is_not_a_proxy(self):
        assert checks.posture_findings({}, {"http_proxy": ":0"}, "") == []
        assert checks.posture_findings({}, {"http_proxy": "null"}, "") == []


class TestCapabilities:
    secure = {"enabled_accessibility_services": "com.spy/.A11y:com.sys/.A11y",
              "enabled_notification_listeners": "com.play.app/.Listener",
              "default_input_method": "com.sys/.Ime"}
    seen = {"com.spy": {"installer": "null"},
            "com.sys": {"installer": "null", "system": True},
            "com.play.app": {"installer": "com.android.vending"}}

    def test_system_apps_are_skipped_and_sideloaded_are_red(self):
        out = checks.capability_findings(self.secure, "", self.seen)
        by = {(f["kind"], f["subject"]): f["severity"] for f in out}
        assert by == {("accessibility-service", "com.spy"): "red",
                      ("notification-listener", "com.play.app"): "amber"}

    def test_unknown_package_is_amber(self):
        out = checks.capability_findings({"always_on_vpn_app": "com.gone"}, "", {})
        assert [(f["kind"], f["severity"]) for f in out] == [("always-on-vpn", "amber")]

    def test_trusted_certificate_is_skipped(self):
        seen = {"com.oem": {"installer": "null", "files": [{"path": "/x/base.apk", "trusted_certificate": True}]}}
        assert checks.capability_findings({"default_input_method": "com.oem/.Ime"}, "", seen) == []


class TestAccounts:
    """Task 3.1: counts by type out, names never; HMAC with a machine key."""

    SECTION = ("User UserInfo{0:Owner:4c13}:\n  Accounts: 3\n"
               "    Account {name=a@example.com, type=com.google}\n"
               "    Account {name=other@gmail.com, type=com.google}\n"
               "    Account {name=WhatsApp, type=com.whatsapp}\n")

    def test_key_is_random_32_bytes_and_mode_600(self, sandbox):
        key = checks.account_key()
        path = common.SECRETS_DIR / checks.ACCOUNT_HMAC
        assert len(key) == 32 and path.exists()
        assert path.stat().st_mode & 0o777 == 0o600
        assert checks.account_key() == key  # created once: the diff needs it stable

    def test_accounts_json_has_counts_and_hmacs_but_no_names(self, case):
        findings = checks.account_findings(case, self.SECTION)
        assert [f["kind"] for f in findings] == ["accounts-review"]  # 2 Google accounts: amber
        data = json.loads((case.path / "accounts.json").read_text())
        assert data["by_type"] == {"com.google": 2, "com.whatsapp": 1}
        assert len(data["google_accounts"]) == 2
        assert not any("example.com" in json.dumps(data) or "WhatsApp" in v for v in data["google_accounts"])

    def test_the_hash_is_an_hmac_not_a_plain_digest(self, case):
        # sha256 of an address is reversed by trying a list of known addresses,
        # and links the same person across machines
        checks.account_findings(case, self.SECTION)
        stored = json.loads((case.path / "accounts.json").read_text())["google_accounts"]
        key = checks.account_key()
        want = hmac.new(key, b"a@example.com", hashlib.sha256).hexdigest()
        assert want in stored
        assert hashlib.sha256(b"a@example.com").hexdigest() not in stored

    def test_two_google_accounts_are_amber_one_is_info(self):
        two = checks.account_review({"com.google": 2})
        one = checks.account_review({"com.google": 1, "com.whatsapp": 3})
        assert two[0]["severity"] == "amber" and one[0]["severity"] == "info"
        # the counts are in the detail; the types are evidence, never a name
        assert two[0]["evidence"]["types"] == {"com.google": 2}
        assert one[0]["detail"] == "The phone has 1 Google account(s) and 3 other account(s)."

    def test_a_watched_account_type_is_amber(self):
        out = checks.account_review({"com.google": 1, "com.evil.mdm": 1}, {"com.evil.mdm"})
        assert out[0]["severity"] == "amber" and out[0]["evidence"]["watched_types"] == ["com.evil.mdm"]

    def test_no_accounts_is_silent(self, case):
        assert checks.account_review({}) == [] and checks.account_findings(case, "") == []
        assert not (case.path / "accounts.json").exists()

    def test_only_non_google_accounts_still_records_counts_but_asks_nothing(self, case):
        section = "    Account {name=WhatsApp, type=com.whatsapp}\n"
        assert checks.account_findings(case, section) == []  # the question is about Google accounts
        # the counts are still written: the follow-up diff wants them
        assert json.loads((case.path / "accounts.json").read_text())["by_type"] == {"com.whatsapp": 1}

    def test_watch_account_types_file_starts_empty(self):
        assert checks.load_watch_account_types() == {}


class TestRoles:
    """Task 3.2: the holder of a one-app role, checked against F-Droid."""

    SMS = "android.app.role.SMS"

    class Stores(checks.Stores):
        """The real signer lookups over a given table, no case needed."""
        def __init__(self, signers=None):
            self.signers = {name: keys if isinstance(keys, dict) else {"fdroid": keys}
                            for name, keys in (signers or {}).items()}

    seen = {"org.example.sideloaded": {"installer": "null", "system": False,
                                       "files": [{"path": "/x/base.apk",
                                                  "certificate": {"Sha256": "a" * 64}}]},
            "org.fdroid.messaging": {"installer": "org.fdroid.fdroid", "system": False,
                                     "files": [{"path": "/y/base.apk",
                                                "certificate": {"Sha256": "b" * 64}}]},
            "com.play.app": {"installer": "com.android.vending", "system": False},
            "com.oem.sms": {"installer": "null", "system": True},
            "org.example.watch.companion": {"installer": "com.android.vending", "system": False,
                                    "files": [{"path": "/z/base.apk", "trusted_certificate": True}]}}

    def run(self, holder, store=None, **over):
        return checks.role_findings({self.SMS: [holder]}, self.seen,
                                    store or self.Stores(), over.pop("defaults", {}))

    def test_sideloaded_holder_with_its_own_key_is_red(self):
        out = self.run("org.example.sideloaded")
        assert [(f["kind"], f["severity"]) for f in out] == [("role-holder", "red")]
        assert out[0]["evidence"]["fdroid_match"] is False and out[0]["evidence"]["role"] == self.SMS

    def test_sideloaded_holder_matching_izzy_is_amber(self):
        out = self.run("org.example.sideloaded",
                       self.Stores({"org.example.sideloaded": {"izzy": ["A" * 64]}}))
        assert [(f["kind"], f["severity"]) for f in out] == [("role-holder", "amber")]
        assert "IzzyOnDroid" in out[0]["detail"]

    def test_sideloaded_holder_matching_fdroid_is_amber(self):
        store = self.Stores({"org.example.sideloaded": ["A" * 64]})
        out = self.run("org.example.sideloaded", store)
        assert [(f["kind"], f["severity"]) for f in out] == [("role-holder", "amber")]
        assert "F-Droid" in out[0]["detail"]

    def test_a_store_app_holding_it_is_amber(self):
        assert self.run("com.play.app")[0]["severity"] == "amber"

    def test_trusted_certificate_is_amber_not_red(self):
        assert self.run("org.example.watch.companion")[0]["severity"] == "amber"

    def test_system_holder_and_listed_defaults_are_silent(self):
        assert self.run("com.oem.sms") == []
        defaults = {self.SMS: {"org.example.sideloaded"}}
        assert self.run("org.example.sideloaded", defaults=defaults) == []

    def test_a_holder_packages_json_does_not_list_is_amber(self):
        out = self.run("com.other.user.app")
        assert [(f["kind"], f["severity"]) for f in out] == [("role-holder", "amber")]
        assert out[0]["evidence"]["origin"] == "unknown"

    def test_only_the_roles_that_matter_are_read(self):
        holders = {"android.app.role.HOME": ["com.a"], "android.app.role.BROWSER": ["com.b"]}
        assert checks.role_findings(holders, {}, self.Stores(), {}) == []

    def test_supervision_by_googles_client_is_info_and_by_anything_else_amber(self):
        role = checks.SUPERVISION_ROLE
        out = checks.role_findings({role: ["com.google.android.gms.supervision"]}, {}, self.Stores(), {})
        assert [(f["kind"], f["severity"]) for f in out] == [("supervision-active", "info")]
        out = checks.role_findings({role: ["com.evil.monitor"]}, {}, self.Stores(), {})
        assert [(f["kind"], f["severity"]) for f in out] == [("role-holder", "amber")]

    def test_device_policy_management_holder_is_amber(self):
        role = checks.POLICY_ROLE
        # Google's own work/school client is a default in the kb: no question
        assert checks.role_findings({role: ["com.google.android.apps.work.clouddpc"]}, {},
                                    self.Stores(), checks.load_role_defaults()) == []
        out = checks.role_findings({role: ["com.evil.mdm"]}, {}, self.Stores(),
                                   checks.load_role_defaults())
        assert [(f["kind"], f["severity"]) for f in out] == [("role-holder", "amber")]

    def test_the_kb_lists_the_google_defaults(self):
        defaults = checks.load_role_defaults()
        assert "com.google.android.apps.messaging" in defaults[self.SMS]
        assert "com.google.android.apps.work.clouddpc" in defaults[checks.POLICY_ROLE]


class TestUsersAndOwners:
    """Task 3.4: profiles and who owns the phone, without profile names."""

    owner = {"id": 0, "flags": {"ADMIN", "FULL", "PRIMARY", "SYSTEM"}}
    work = {"id": 11, "flags": {"ADMIN", "MANAGED_PROFILE", "MAIN"}}

    def test_a_single_full_user_is_silent(self):
        assert checks.user_findings([self.owner], None) == []

    def test_work_profile_is_info_and_amber_when_an_app_manages_it(self):
        out = checks.user_findings([self.owner, self.work], None)
        assert [(f["kind"], f["severity"]) for f in out] == [("work-profile", "info")]
        assert out[0]["evidence"]["profiles"] == [11]
        out = checks.user_findings([self.owner, self.work], None, ["com.evil.mdm"])
        assert out[0]["severity"] == "amber" and out[0]["evidence"]["managed_by"] == ["com.evil.mdm"]

    def test_more_than_one_full_user_is_info(self):
        second = {"id": 12, "flags": {"FULL", "MAIN"}}
        out = checks.user_findings([self.owner, second], None)
        assert [(f["kind"], f["severity"]) for f in out] == [("multiple-users", "info")]
        assert out[0]["evidence"]["users"] == [0, 12]

    def test_device_owner_is_amber_with_its_origin(self):
        seen = {"com.acme.mdm": {"installer": "com.android.vending"}}
        out = checks.user_findings([self.owner], "com.acme.mdm", seen=seen)
        assert [(f["kind"], f["severity"]) for f in out] == [("device-owner", "amber")]
        assert out[0]["subject"] == "com.acme.mdm" and out[0]["evidence"]["origin"] == "play"

    def test_no_owner_line_means_not_managed(self):
        assert checks.device_owner_package(FIXTURE_POLICY) is None
        assert checks.device_owner_package("") is None

    def test_a_managed_phone_grows_the_device_owner_block(self):
        text = (FIXTURE_POLICY + "  Device Owner: \n"
                "    admin=ComponentInfo{com.acme.mdm/com.acme.Admin}\n"
                "    package=com.acme.mdm\n    isOrganizationOwnedDevice=true\n")
        assert checks.device_owner_package(text) == "com.acme.mdm"

    def test_a_profile_owner_is_not_a_device_owner(self):
        text = ("  Profile Owner (User 11): \n"
                "    admin=ComponentInfo{com.acme.mdm/com.acme.Admin}\n")
        assert checks.device_owner_package(text) is None

    def test_an_admin_that_is_not_listed_under_the_owner_line_is_ignored(self):
        text = "  Device Owner: \n  Enabled Device Admins (User 0, provisioningState: 0):\n"
        assert checks.device_owner_package(text) is None


class TestKnownMalware:
    iocs = {"hash": {"A" * 64: {"family": "Bad", "category": "SPYWARE", "severity": "CRITICAL", "source": "t"}},
            "package": {"com.bad.pkg": {"family": "Bad", "category": "BANKER", "severity": "MEDIUM", "source": "t"}},
            "cert": {"B" * 40: {"family": "Bad", "category": "SPYWARE", "severity": "HIGH", "source": "t"}}}

    def test_hash_match_is_red(self):
        f = checks.known_malware("com.x", {"files": [{"sha256": "a" * 64}]}, self.iocs)
        assert (f["kind"], f["severity"], f["evidence"]["matched_by"]) == ("known-malware", "red", "APK hash")

    def test_medium_severity_is_amber(self):
        f = checks.known_malware("com.bad.pkg", {"files": []}, self.iocs)
        assert f["severity"] == "amber"
        assert "banker" in f["detail"]

    def test_certificate_sha1_matches(self):
        f = checks.known_malware("com.y", {"files": [{"certificate": {"Sha1": "b" * 40}}]}, self.iocs)
        assert f["evidence"]["matched_by"] == "signing certificate"

    def test_no_match(self):
        assert checks.known_malware("com.z", {"files": [{"sha256": "c" * 64}]}, self.iocs) is None
