"""The dumpsys.txt parsers: section cutting and the package block reader."""

from sta.dumpsys import (
    accounts,
    battery_exemptions,
    for_json,
    main_activities,
    packages,
    roles,
    sections,
    users,
)

DASHES = "-" * 79

THREE_SECTIONS = (
    "Currently running services:\n  account\n  device_policy\n"
    + DASHES + "\nDUMP OF SERVICE account:\n"
    "  Accounts: 1\n"
    # a dump can echo a header-looking line; it is body text, not a section
    "DUMP OF SERVICE fake_service:\n"
    "--------- 0.014s was the duration of dumpsys account, ending at: 2026-10-18 17:52:54\n"
    + DASHES + "\nDUMP OF SERVICE device_policy:\n"
    "  ComponentInfo{com.evil.admin/com.evil.Receiver}\n"
    + "-" * 163 + "\n  a long decorative run inside the body\n"
    + DASHES + "\nDUMP OF SERVICE user:\n"
    "  Users:\n"
    "    UserInfo{0:Owner:4c13} serialNo=0 isPrimary=true\n"
)

TWO_PACKAGES = """Activity Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        6e3541e com.example.launcher/.MainActivity
        6e3541f org.example.hidden/.MainActivity
Receiver Resolver Table:
  Non-Data Actions:
      android.intent.action.MAIN:
        aabbccd org.example.hidden/.BootReceiver

Packages:
  Package [org.fdroid.fdroid] (d5d3538):
    appId=10550
    codePath=/data/app/~~X/org.fdroid.fdroid-X==
    versionCode=1023052 minSdk=23 targetSdk=30
    versionName=1.23.2
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP KILL_AFTER_RESTORE ]
    timeStamp=2026-03-06 21:43:29
    lastUpdateTime=2026-03-06 21:43:42
    installerPackageName=com.google.android.packageinstaller
    initiatingPackageName=com.google.android.packageinstaller
    originatingPackageName=org.fdroid.fdroid
    packageSource=3
    signatures=PackageSignatures{e8a9a76 version:3, signatures:[8b8a3ff5], past signatures:[]}
    declared permissions:
      org.fdroid.fdroid.permission.UPDATE_REPOS: prot=signature|privileged
    install permissions:
      android.permission.NFC: granted=true
      android.permission.REQUEST_INSTALL_PACKAGES: granted=false, flags=[ USER_SET]
    User 0: ceDataInode=961346 installed=true hidden=false suspended=false stopped=false enabled=0 instant=false virtual=false
      installReason=4
      dataDir=/data/user/0/org.fdroid.fdroid
      firstInstallTime=2026-03-06 21:40:10
      overlay paths:
        /overlay/fdroid
      lastDisabledCaller: com.google.android.packageinstaller
      gids=[3003]
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED]
        android.permission.CAMERA: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED]
        android.permission.ACCESS_COARSE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED]
      disabledComponents:
        androidx.work.impl.background.systemalarm.RescheduleReceiver
      enabledComponents:
        androidx.work.impl.background.systemjob.SystemJobService
  Package [com.example.launcher] (aa11bb22):
    appId=10901
    codePath=/data/app/~~Y/com.example.launcher-Y==
    versionCode=1 minSdk=24 targetSdk=34
    flags=[ HAS_CODE ]
    lastUpdateTime=2026-10-01 10:00:00
    installerPackageName=null
    User 0: installed=true hidden=false suspended=false stopped=false enabled=0 instant=false virtual=false
      installReason=2
      firstInstallTime=2026-10-01 09:00:00
Hidden system packages:
  Package [com.android.chrome] (33f9bb9):
    appId=10196
    codePath=/product/app/Chrome-Stub
    versionName=149.0.7827.5
    timeStamp=2009-01-01 01:00:00
    lastUpdateTime=1970-01-01 00:59:59
    installerPackageName=null
"""


class TestSections:
    def test_cuts_on_separator_plus_header(self):
        out = sections(THREE_SECTIONS)
        assert list(out) == ["account", "device_policy", "user"]
        assert "ComponentInfo{com.evil.admin" in out["device_policy"]
        # the duration line belongs to the section it closes, and only to it
        assert "duration of dumpsys account" in out["account"]
        assert "duration" not in out["device_policy"]

    def test_a_header_line_inside_a_value_does_not_cut_a_section(self):
        out = sections(THREE_SECTIONS)
        assert "DUMP OF SERVICE fake_service:" in out["account"]
        assert "fake_service" not in out  # no section named after the echo line

    def test_long_hyphen_run_without_a_header_after_it_stays_in_the_body(self):
        out = sections(THREE_SECTIONS)
        assert "-" * 163 in out["device_policy"]
        assert "long decorative run" in out["device_policy"]

    def test_last_section_runs_to_the_end_of_the_file(self):
        out = sections(THREE_SECTIONS)
        assert "UserInfo{0:Owner" in out["user"]

    def test_an_empty_section_and_no_headers(self):
        text = DASHES + "\nDUMP OF SERVICE a:\n" + DASHES + "\nDUMP OF SERVICE b:\nbody"
        assert sections(text) == {"a": "", "b": "body"}
        assert sections("") == {} and sections("no dumps here") == {}


class TestPackages:
    def test_only_the_live_blocks_count(self):
        parsed = packages(TWO_PACKAGES)
        # the stub under `Hidden system packages:` is never read
        assert set(parsed) == {"org.fdroid.fdroid", "com.example.launcher"}

    def test_package_wide_fields(self):
        fdroid = packages(TWO_PACKAGES)["org.fdroid.fdroid"]
        assert fdroid["installer"] == "com.google.android.packageinstaller"
        assert fdroid["initiating"] == "com.google.android.packageinstaller"
        assert fdroid["originating"] == "org.fdroid.fdroid"
        assert fdroid["last_update"] == "2026-03-06 21:43:42"
        assert fdroid["target_sdk"] == 30
        assert fdroid["flags"] == {"HAS_CODE", "ALLOW_CLEAR_USER_DATA", "ALLOW_BACKUP",
                                   "KILL_AFTER_RESTORE"}

    def test_user_zero_fields(self):
        fdroid = packages(TWO_PACKAGES)["org.fdroid.fdroid"]
        assert fdroid["first_install"] == "2026-03-06 21:40:10"
        assert fdroid["install_reason"] == 4
        assert fdroid["hidden"] is False
        assert fdroid["enabled"] == 0
        assert fdroid["users"] == [0]

    def test_granted_is_install_plus_runtime_permissions_of_user_zero(self):
        fdroid = packages(TWO_PACKAGES)["org.fdroid.fdroid"]
        assert fdroid["granted"] == {"android.permission.NFC",
                                     "android.permission.POST_NOTIFICATIONS",
                                     "android.permission.CAMERA"}

    def test_disabled_components_of_user_zero(self):
        parsed = packages(TWO_PACKAGES)
        assert parsed["org.fdroid.fdroid"]["disabled_components"] == {
            "androidx.work.impl.background.systemalarm.RescheduleReceiver"}
        assert parsed["com.example.launcher"]["disabled_components"] == set()

    def test_null_and_missing_values_become_none(self):
        launcher = packages(TWO_PACKAGES)["com.example.launcher"]
        assert launcher["installer"] is None
        assert launcher["originating"] is None
        assert launcher["first_install"] == "2026-10-01 09:00:00"

    def test_no_packages_marker_is_nothing_to_parse(self):
        assert packages("Activity Resolver Table:\n  nothing\n") == {}

    def test_a_stub_copy_never_replaces_the_live_block(self):
        text = ("Packages:\n"
                "  Package [com.android.chrome] (7ec312):\n"
                "    codePath=/data/app/~~X/com.android.chrome-X==\n"
                "    lastUpdateTime=2026-10-16 14:06:04\n"
                "  Package [com.android.chrome] (33f9bb9):\n"
                "    codePath=/product/app/Chrome-Stub\n"
                "    lastUpdateTime=1970-01-01 00:59:59\n")
        assert packages(text)["com.android.chrome"]["last_update"] == "2026-10-16 14:06:04"


class TestMainActivities:
    def test_only_the_first_main_block_after_the_activity_table(self):
        # the Receiver Resolver Table has its own MAIN block: not launcher
        assert main_activities(TWO_PACKAGES) == {"com.example.launcher", "org.example.hidden"}

    def test_no_resolver_table_is_nothing(self):
        assert main_activities("Packages:\n") == set()


# The shapes of docs/format-notes.md sections 3 to 6, with invented names.
ACCOUNT_SECTION = """User UserInfo{0:Owner:4c13}:
  Accounts: 3
    Account {name=a@example.com, type=com.google}
    Account {name=b@example.com, type=com.google}
    Account {name=WhatsApp, type=com.whatsapp}

  Accounts History
id,action,name,type,timestamp,uid
7,login,a@example.com,com.google,1760000000,10086
  Active Sessions: 0
RegisteredServicesCache: 1 services
  ServiceInfo: AuthenticatorDescription {type=com.google}, ComponentInfo{pkg/svc}, uid 10086
"""

ROLE_SECTION = """ROLE STATE (dumpsys role):
{
  user_states={
    user_id=0
    version=1
    packages_hash=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    roles=[
      {
        name=android.app.role.SMS
        fallback_enabled=true
        holders=com.google.android.apps.messaging
      }
      {
        name=android.app.role.CALL_REDIRECTION
        fallback_enabled=true
      }
      {
        name=android.app.role.SYSTEM_SUPERVISION
        fallback_enabled=true
        active_user_id=0
        holders=org.example.parental.app
      }
    ]
  }
}
"""

DEVICEIDLE_SECTION = """  Flags:
    com.android.server.deviceidle.remove_idle_location=true
  Settings:
    inactive_to=+15s0ms
  Whitelist (except idle) system apps:
    com.google.android.gms
    com.android.shell
  Whitelist system apps:
    com.google.android.gms
  Whitelist user apps:
    org.example.sideloaded
    org.fdroid.fdroid
  Whitelist (except idle) all app ids:
    1000
  Whitelist user app ids:
  Whitelist all app ids:
 mIdleState=true
"""

USER_SECTION = """Current user: 0

Users:
  UserInfo{0:Owner:4c13} serialNo=0 isPrimary=true
    Type: android.os.usertype.full.SYSTEM
    Flags: 19475 (ADMIN|FULL|INITIALIZED|MAIN|PRIMARY|SYSTEM)
    State: RUNNING_UNLOCKED
  UserInfo{11:Maria:4c15} serialNo=11 isPrimary=false
    Type: android.os.usertype.profile.MANAGED
    Flags: 16432 (ADMIN|INITIALIZED|MAIN|MANAGED_PROFILE|PRELOADING)
    State: RUNNING_LOCKED
Defaults tables follow, which name users too but have no Flags line:
  mDefaultUserInfoFlags: 0
  UserInfo{12:Ghost:4c17}
"""


class TestAccounts:
    def test_name_and_type_of_every_account(self):
        assert accounts(ACCOUNT_SECTION) == [("a@example.com", "com.google"),
                                             ("b@example.com", "com.google"),
                                             ("WhatsApp", "com.whatsapp")]

    def test_history_and_service_lines_add_nothing(self):
        # the CSV row repeats an account name but is not an Account {...} line
        assert len(accounts(ACCOUNT_SECTION)) == 3

    def test_a_name_with_spaces_survives_and_the_section_can_be_empty(self):
        assert accounts("Account {name=Some One, type=x.y}") == [("Some One", "x.y")]
        assert accounts("") == []


class TestRoles:
    def test_only_roles_with_a_holder_are_returned(self):
        assert roles(ROLE_SECTION) == {"android.app.role.SMS": ["com.google.android.apps.messaging"],
                                       "android.app.role.SYSTEM_SUPERVISION": ["org.example.parental.app"]}

    def test_the_user_states_brace_is_not_a_role(self):
        # user_states={ has no name= line: nothing is keyed by it
        assert "" not in roles(ROLE_SECTION) and len(roles(ROLE_SECTION)) == 2

    def test_several_holders_are_split(self):
        text = "      {\n        name=android.app.role.SMS\n        holders=com.a;com.b\n      }\n"
        assert roles(text) == {"android.app.role.SMS": ["com.a", "com.b"]}

    def test_empty_section(self):
        assert roles("") == {}


class TestBatteryExemptions:
    def test_only_the_user_list_counts(self):
        # the system lists are vendor defaults; the app-ids lists hold uids
        assert battery_exemptions(DEVICEIDLE_SECTION) == {"org.example.sideloaded", "org.fdroid.fdroid"}

    def test_a_later_header_ends_the_list(self):
        text = "  Whitelist user apps:\n    com.a\n  Whitelist all app ids:\n    com.b\n"
        assert battery_exemptions(text) == {"com.a"}

    def test_an_empty_whitelist_is_empty(self):
        assert battery_exemptions("  Whitelist user apps:\n  Whitelist all app ids:\n") == set()
        assert battery_exemptions("") == set()


class TestUsers:
    def test_id_and_flags_without_the_personal_name(self):
        parsed = users(USER_SECTION)
        assert [user["id"] for user in parsed] == [0, 11]
        assert {"ADMIN", "FULL", "PRIMARY"} <= parsed[0]["flags"]
        assert "MANAGED_PROFILE" in parsed[1]["flags"] and "FULL" not in parsed[1]["flags"]
        assert "Owner" not in str(parsed) and "Maria" not in str(parsed)

    def test_a_userinfo_line_without_its_flags_line_is_not_a_user(self):
        # the UserManager defaults tables name users too; only the real entries
        # have the Flags line under them (the Ghost above has none)
        assert len(users(USER_SECTION)) == 2
        assert users("  UserInfo{12:Ghost:4c17}\n") == []

    def test_empty_section(self):
        assert users("") == []


class TestForJson:
    def test_sets_become_sorted_lists_and_code_path_stays_out(self):
        parsed = packages(TWO_PACKAGES)
        out = for_json(parsed)
        assert out["org.fdroid.fdroid"]["flags"] == sorted(parsed["org.fdroid.fdroid"]["flags"])
        assert "code_path" not in out["org.fdroid.fdroid"]

    def test_battery_exempt_marks_packages_and_adds_stubs(self):
        # org.example.sideloaded is on the deviceidle list but has no block here,
        # so package-details.json still carries it for the follow-up diff
        out = for_json(packages(TWO_PACKAGES), {"com.example.launcher", "org.example.sideloaded"})
        assert out["com.example.launcher"]["battery_exempt"] is True
        assert out["org.fdroid.fdroid"]["battery_exempt"] is False
        assert out["org.example.sideloaded"] == {"battery_exempt": True}
