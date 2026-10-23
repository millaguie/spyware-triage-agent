# Format notes from real acquisitions

Written by the local agent against a real test phone (a Pixel on
Android 17, androidqf 1.8.3). These are format facts only: field names, shapes,
counts. All account names, device names and identifiers in the examples are
invented (`Owner`, `a@example.com`, `org.example.*`). The cloud agent codes
against this file plus `tests/fixtures/`; it never reads `cases/`.

## 1. dumpsys.txt separators (task L1.1)

Verified over the whole 65 MB / 862k-line `dumpsys.txt` of that case.

- Section header: `DUMP OF SERVICE <service>:` at column 0, one line, regex
  `^DUMP OF SERVICE (\S+):$`. Service names contain dots and slashes
  (`android.hardware.wifi.IWifi/default`) but never spaces or inner colons.
  385 headers, every service name unique (no service dumped twice).
- Separator before EVERY header: a line of exactly 79 hyphens. There is no
  other way to reach a header (verified on all 385).
- `DUMP OF SERVICE` never appears inside a block body: total occurrences in the
  file equal the number of headers (385). So counting "headers without dashes
  in front": **0**. Splitting only at `^-{5,}$` followed by a header is safe.
- Duration line after each section body:
  `--------- 0.014s was the duration of dumpsys account, ending at: 2026-10-18 17:52:54`
  It has exactly **9** leading dashes (not 79) and the service name matches the
  header it closes. 384 of 385 sections have it on its own line. The one
  exception: `user` does not terminate its output with a newline, so its
  duration is glued to the last text line:
  `...Not logging context storage issues--------- 0.013s was the duration of dumpsys user, ending at: ...`
  Lesson: cut sections by "next header preceded by a 79-dash line", not by
  duration lines; treat the duration as optional and possibly mid-line.
- A 79-hyphen line also closes the last section? No: the file ENDS with the
  `window` duration line, no trailing separator. The header of the first
  section (`DockObserver`) is preceded by a separator, after a preamble list
  "Currently running services:" (one service name per line, then the separator).
- Long decorative hyphen runs (up to 163 chars) exist inside some block bodies.
  A parser that splits at any `^-{5,}$` over-splits; require the header line
  right after the dashes (as task 0.1 prescribes).
- The file contains NUL bytes (20 of them, inside binary blobs like the `adb`
  keystore dump), so `grep` wants `-a` and Python must read with
  `errors="replace"`.

## 2. `dumpsys package` (task L1.2)

Section is ~121k lines here. Layout, in order: `Database versions:`,
`Known Packages:` (role-name lists), `Activity Resolver Table:`,
`Receiver Resolver Table:`, `Service Resolver Table:`,
`Provider Resolver Table:`, `Preferred Activities User 0:`,
`Domain verification status:`, `Permissions:`, then all package blocks.

- Package block headers match `^  Package \[([^\]]+)\] \(([0-9a-f]+)\):$`
  exactly (2-space indent, hex id in parens; no other shape appears).
  597 blocks but only 532 distinct packages: the live blocks (532, one per
  package) sit after a `Packages:` line at column 0; the other 65 sit under a
  later `Hidden system packages:` line and are older/stub copies that PackageManager
  keeps. **Parser rule: only read blocks between `^Packages:$` and
  `^Hidden system packages:$`.** Example of a hidden copy (anonymised paths,
  invented dates):

  ```
    Package [com.android.chrome] (7ec312):      <- installed update
      appId=10196
      codePath=/data/app/~~X/com.android.chrome-X==
      versionName=155.0.8059.84
      timeStamp=2026-01-02 10:00:00
      installerPackageName=com.android.vending
    Package [com.android.chrome] (33f9bb9):     <- stub in /product/app/Chrome-Stub
      appId=10196                               <- same appId
      codePath=/product/app/Chrome-Stub
      versionName=149.0.7827.5
      timeStamp=2009-01-01 01:00:00
      lastUpdateTime=1970-01-01 00:59:59        <- pre-epoch stub marker
      installerPackageName=null
  ```

  A parser keyed by package name must decide which block wins; the live one is
  the one whose `codePath` starts with `/data/app/` (or, equivalently, is not a
  `timeStamp` from 2009/epoch). Deduplicate by `appId`.
- Full block of public apps: NewPipe and F-Droid blocks below are copied shape,
  with paths/hashes/dates invented and everything kept that a parser needs:

  ```
    Package [org.fdroid.fdroid] (d5d3538):
      appId=10550
      pccId=-1
      pkg=Package{836e911 org.fdroid.fdroid}
      codePath=/data/app/~~X/org.fdroid.fdroid-X==
      resourcePath=/data/app/~~X/org.fdroid.fdroid-X==
      legacyNativeLibraryDir=/data/app/~~X/org.fdroid.fdroid-X==/lib
      extractNativeLibs=false
      primaryCpuAbi=arm64-v8a
      secondaryCpuAbi=null
      cpuAbiOverride=null
      versionCode=1023052 minSdk=23 targetSdk=30
      minExtensionVersions=[]
      versionName=1.23.2
      hiddenApiEnforcementPolicy=2
      usesNonSdkApi=false
      splits=[base]
      apkSigningVersion=3
      flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP KILL_AFTER_RESTORE ]
      privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION ... ]
      forceQueryable=false
      pageSizeCompat=0
      queriesIntents=[Intent { act=android.intent.action.SEND dat=content://*/... typ=message/rfc822 }]
      scannedAsStoppedSystemApp=false
      supportsScreens=[small, medium, large, xlarge, resizeable, anyDensity]
      usesOptionalLibraries:
        androidx.window.extensions
      usesLibraryFiles:
        /system_ext/framework/androidx.window.extensions.jar
      timeStamp=2026-01-01 10:00:00
      lastUpdateTime=2026-01-01 10:00:05
      installerPackageName=com.google.android.packageinstaller
      installerPackageUid=10086
      initiatingPackageName=com.google.android.packageinstaller
      originatingPackageName=org.fdroid.fdroid
      packageSource=3
      appMetadataFilePath=null
      appMetadataSource=0
      signatures=PackageSignatures{e8a9a76 version:3, signatures:[8b8a3ff5], past signatures:[]}
      installPermissionsFixed=false
      pkgFlags=[ ... same as flags ... ]
      privatePkgFlags=[ ... ]
      apexModuleName=null
      declared permissions:
        org.fdroid.fdroid.permission.UPDATE_REPOS: prot=signature|privileged
      install permissions:
        android.permission.NFC: granted=true
        android.permission.REQUEST_INSTALL_PACKAGES: granted=false, flags=[ USER_SET]
      User 0: ceDataInode=961346 deDataInode=1005254 pccCeDataInode=0 pccDeDataInode=0 installed=true hidden=false suspended=false appLockEnabled=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false quarantined=false
        installReason=4
        dataDir=/data/user/0/org.fdroid.fdroid
        firstInstallTime=2026-01-01 09:58:00
        uninstallReason=0
        overlay paths:
          ...
        lastDisabledCaller: com.google.android.packageinstaller
        gids=[3003]
        runtime permissions:
          android.permission.POST_NOTIFICATIONS: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
          android.permission.CAMERA: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
          android.permission.ACCESS_COARSE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        disabledComponents:
          androidx.work.impl.background.systemalarm.RescheduleReceiver
        enabledComponents:
          androidx.work.impl.background.systemjob.SystemJobService
  ```

  NewPipe's block has the identical shape (`installerPackageName=org.fdroid.fdroid`,
  `initiatingPackageName=org.fdroid.fdroid`, `originatingPackageName=null`,
  `packageSource=2`; F-Droid itself reports `packageSource=3`). Note install
  permissions can carry `granted=false, flags=[...]` inline.
- `User N:` sub-blocks: only `    User 0:` exists in this dump — there is no
  `User 10`, so **the case has no work profile and multi-user package blocks
  remain unverified here**. `users: [0]`.
- `disabledComponents:` / `enabledComponents:` live INSIDE the `User 0:`
  sub-block at 6-space indent; component names at 8-space indent, always fully
  qualified (`com.x.Y`, never `.Y`, never with `/`). Counts in this case: 99
  packages have a `disabledComponents:` line, 170 an `enabledComponents:` line.
  Empty lists never appear (when the app has none, the header itself is absent).
  267 blocks also carry `lastDisabledCaller: <package>` right above the runtime
  permissions — useful evidence for "who hid a component".
- `Activity Resolver Table:` (1 per section): under it come
  `  Full MIME Types:` and `  Non-Data Actions:`. `android.intent.action.MAIN:`
  appears 4 times in the whole package section, once inside each of the four
  resolver tables; the launcher one is the first, at indent 6 under
  `Non-Data Actions:` of `Activity Resolver Table:` (679 entries here). Entry
  lines look like:

  ```
        android.intent.action.MAIN:
          6e3541e org.example.notes/.MainActivity
          ac4beea org.example.charging/.LaunchActivity
  ```

  The `LAUNCHER` category NEVER appears on these lines — resolver tables do not
  print categories (grepping LAUNCHER in the table only matches unrelated
  custom action names). So "in MAIN" is necessary but not sufficient for
  "has launcher icon"; keep the manifest as primary source (task 1) and use the
  MAIN list of the Activity Resolver Table only as fallback. Also note the MAIN
  list includes non-launcher activities (suggestion activities, aliases).
  Trap found: the MAIN resolver still lists components that are in
  `disabledComponents:` (17 overlaps in this case). A package can have its
  launcher activity disabled and still appear under MAIN — cross-check the two
  lists when deciding "no icon" (`app-hidden`).

## 3. `dumpsys account` (task L1.3)

Shape (`name=` values replaced by invented ones; real name data must never be
copied):

```
DUMP OF SERVICE account:
User UserInfo{0:Owner:4c13}:
  Accounts: 3
    Account {name=a@example.com, type=com.google}
    Account {name=b@example.com, type=com.google}
    Account {name=Meet, type=com.google.android.apps.tachyon}
```

- One `User UserInfo{...}:` block per user; this dump has only User 0.
- The plan's regex `Account \{name=(.*?), type=(\S+)\}` parsed every account
  here; no name contained a comma, but keep it non-greedy anyway.
- Never emit the `name`. After the account list come sections that parsers
  should skip: an `Accounts History` CSV (`id,action...,timestamp,uid,...` — contains
  dates), `Active Sessions: N`, and `RegisteredServicesCache: N services` with
  lines `ServiceInfo: AuthenticatorDescription {type=X}, ComponentInfo{pkg/svc}, uid NNNNN, lastUpdateTime <epoch ms>`.
- Distinct `type` values look like this (app ids; the list below is invented,
  the real one is the owner's):

  ```
    com.google: 2
    org.example.contacts.address_book: 3
    org.example.contacts: 2
    org.telegram.messenger: 1
    com.whatsapp: 1
  ```

## 4. `dumpsys role` (task L1.4)

```
DUMP OF SERVICE role:
ROLE STATE (dumpsys role):
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
    ]
  }
}
```

- Indents exactly: braces at col 0/2, `user_id`…`roles=[` at 4, role block
  braces at 6, fields at 8. Closing order is `]`, `}` (user_states), `}`.
- One block per role (45 here). Fields seen: `name=`, `fallback_enabled=`
  (always `true` here), optional `holders=`, and once `active_user_id=0`. A
  role with no holder simply omits the line.
- `holders=` had exactly ONE package in every one of the 30 held roles; **the
  separator for multiple holders is unverified** (no role here has two; the
  AOSP Role module source was not reachable to confirm). Parse defensively: if
  a value ever contains separators (`;` or `,`), split on both.
- Roles with a holder in this case (30 of 45). Holders shown only where they are
  Android/Pixel system defaults; the one third-party holder was renamed to an
  invented package:

  ```
    ASSISTANT                      com.google.android.googlequicksearchbox
    BROWSER                        com.android.chrome
    CALL_SCREENING                 com.google.android.dialer
    COMPANION_DEVICE_COMPUTER      com.google.android.gms
    COMPANION_DEVICE_WATCH         org.example.sideloaded   (was a Play watch app)
    DEVICE_POLICY_MANAGEMENT       com.google.android.apps.work.clouddpc
    DIALER                         com.google.android.dialer
    EMERGENCY                      com.google.android.apps.safetyhub
    HOME                           com.google.android.apps.nexuslauncher
    SMS                            com.google.android.apps.messaging
    SYSTEM_ACTIVITY_RECOGNIZER     com.google.android.gms
    SYSTEM_AMBIENT_AUDIO_INTELLIGENCE  com.google.android.as
    SYSTEM_APP_PROTECTION_SERVICE  com.google.android.odad
    SYSTEM_AUDIO_INTELLIGENCE      com.google.android.as
    SYSTEM_AUTOMOTIVE_PROJECTION   com.google.android.projection.gearhead
    SYSTEM_BLUETOOTH_STACK         com.google.android.bluetooth
    SYSTEM_COMPANION_DEVICE_PROVIDER com.google.android.gms
    SYSTEM_CONTACTS                com.google.android.contacts
    SYSTEM_DOCUMENT_MANAGER        com.google.android.documentsui
    SYSTEM_GALLERY                 com.google.android.apps.photos
    SYSTEM_NOTIFICATION_INTELLIGENCE com.google.android.as
    SYSTEM_SETTINGS_INTELLIGENCE   com.google.android.settings.intelligence
    SYSTEM_SHELL                   com.android.shell
    SYSTEM_SPEECH_RECOGNIZER       com.google.android.tts
    SYSTEM_TEXT_INTELLIGENCE       com.google.android.as
    SYSTEM_UI                      com.android.systemui
    SYSTEM_UI_INTELLIGENCE         com.google.android.as
    SYSTEM_VISUAL_INTELLIGENCE     com.google.android.as
    SYSTEM_WELLBEING               com.google.android.apps.wellbeing
    WALLET                         com.google.android.gms
  ```

  Roles of interest to task 3.2 present but WITHOUT holder: SUPERVISION,
  SYSTEM_SUPERVISION, CALL_REDIRECTION. So this phone has no supervision and no
  call-redirection holder.

## 5. `dumpsys deviceidle` (task L1.5)

Top-level lines at 2-space indent, in this order: `Flags:` (`com.android.server.deviceidle.<k>=<v>`),
`Settings:` (`key=+4m0s0ms` durations), `Idling history:`, then six list
headers, then a wall of `mXxx=true/false` state lines:

```
  Whitelist (except idle) system apps:
    com.google.android.gms            <- 34 entries here
  Whitelist system apps:              <- 23 entries
  Whitelist user apps:                <- 6 entries here (invented packages below)
    org.fdroid.fdroid
    org.example.sideloaded
  Whitelist (except idle) all app ids:
    1000                              <- raw uid at 4-space indent
  Whitelist user app ids:
  Whitelist all app ids:
```

- Package lists: header at 2 spaces, one package per line at 4. The three
  `... app ids:` headers hold numeric uids instead of packages. All six appear;
  a list can be empty in general (not in this dump) — parser must stop at the
  next 2-space header either way.
- Task 3.3 only needs `Whitelist user apps:` = exemptions set by the owner (or
  whoever held the phone). The other lists are system defaults, not evidence.

## 6. `dumpsys user` (task L1.6)

```
DUMP OF SERVICE user:
Current user: 0

Users:
  UserInfo{0:Owner:4c13} serialNo=0 isPrimary=true
    Type: android.os.usertype.full.SYSTEM
    Flags: 19475 (ADMIN|FULL|INITIALIZED|MAIN|PRIMARY|SYSTEM)
    State: RUNNING_UNLOCKED
    Created: <unknown>
    Last logged in: +2d15h34m39s981ms ago
    Last logged in fingerprint: eb64e0...
    Start time: +2d15h36m6s687ms ago
```

- One user here (Owner is our invented name; the real value is personal). The
  third token inside `{}` (`4c13`) is the hex of the decimal flag value on the
  `Flags:` line: 0x4C13 == 19475. Either source works for flags.
- The rest of the section is UserManager internals (defaults tables, listener
  dumps) with many other `mDefaultUserInfoFlags:` lines — only match lines that
  contain `UserInfo{`. Task 3.4's regex fits. Beware: this service ends its
  output WITHOUT a trailing newline, gluing the duration line to the last text
  line (see section 1). The `serialNo=0` hit in the privacy grep is the AOSP
  field NAME with a zero value, not an identifier.

## 7. `dumpsys device_policy` (task L1.7)

This phone is NOT managed: the dump contains **no** `Device Owner:` line and
**no** `Profile Owner` line. The only related line is
`  Device Owner Type: -1` (meaning none). No `ComponentInfo{...}` appears
anywhere in the section, so today's `device_admin_packages()` correctly returns
[] here. Observed shape of the empty state:

```
DUMP OF SERVICE device_policy:
Current Device Policy Manager state:
  Immutable state:
    mHasFeature=true
    ...
  Enabled Device Admins (User 0, provisioningState: 0):
  
    mPasswordOwner=-1
    mPasswordTokenHandle=0
    ...
```

Note the header `Enabled Device Admins (User N, provisioningState: P):` is
followed by per-admin blocks when admins exist; none here.

Format for owners below is **unverified against a real managed phone** — taken
from AOSP `OwnersData.dump()` (frameworks/base android16-release, read
2026-10-22). When a device IS managed the section grows, after "Current Device
Policy Manager state:", with:

```
  Device Owner: 
    admin=ComponentInfo{pkg/class}
    package=pkg
    isOrganizationOwnedDevice=true|false
    User ID: 0
```

(and `Profile Owner (User N): ` blocks with the same three inner lines). Match
`^\s+Device Owner:` — note the trailing space in AOSP's println, and that
"Enabled Device Admins" admins are unrelated to owners. Until someone checks a
managed phone, treat these lines as unverified and keep any owner detection
additive (absence of the line = not managed).

## 8. Fixture `tests/fixtures/dumpsys-extra.txt`

Synthetic sections written with the exact shapes above: closing duration for
the `device_state` stub already in `tests/fixtures/android-pixel/dumpsys.txt`,
then `account` (2 Google accounts a@/b@example.com), `role` (SMS holder
`org.example.sideloaded`, plus defaults), `deviceidle` (`Whitelist user apps:`
with `org.example.sideloaded`), `user` (one FULL user, Owner), and a minimal
`package` section with one non-system package `org.example.hidden` whose main
activity sits in `disabledComponents`. Regenerated fixtures must append this
file instead of copying the real sections (task L3).

## 9. APK fixture from a public app (task L2)

`tests/make_apk_fixture.py <newpipe.apk>` builds
`tests/fixtures/apks/org.schabi.newpipe.apk`: the real binary
`AndroidManifest.xml` of NewPipe 0.29.1 (public F-Droid app, manifest is not
personal data) + a 4 KB `classes.dex` of zero bytes. 7.8 KB total, parsed fine
by pyaxmlparser 0.3.31 in under a second.

- Verified equal against the original APK: `package=org.schabi.newpipe`,
  `get_main_activity()=org.schabi.newpipe.MainActivity`,
  `get_target_sdk_version()='35'` (a string), permission/receiver/service/
  activity counts (11/5/11/13).
- `resources.arsc` is deliberately NOT copied (it is 5 MB, fixture must stay
  under 100 KB). Consequence: on the fixture `get_app_name()` returns the raw
  reference `'@7F13003A'`; on a full APK it resolves to `'NewPipe'`. Tests
  that assert the label must accept the `@...` form or parse against the
  source, not assume a human-readable name.
- stdout noise ("res1 is not zero!" lines, task 1 warns about them) appears
  when parsing the FULL APK (it comes from resources.arsc reading), NOT with
  this fixture: parsing the fixture prints nothing on stdout or stderr in
  pyaxmlparser 0.3.31. Keep the redirect_stdout guard anyway for real APKs.

## 10. Verification of tasks 0, 1 and 3 (task L4)

Run against a copy of the real Pixel case after commits `00c73ef` (task 0),
`8d3624c` (task 1) and `0b5c07e` (task 3). The case has network consent on, so
store lookups ran; VirusTotal stayed off (no per-tool consent in the state — the
check skips it silently, nothing was printed). No step refused to run.

### Counts

Default `./sta check-apps`: 530 packages checked, YARA over 157 non-system
apps, APKiD on the 6 apps from outside a store, manifest read for those 6.
App findings: red 0 / amber 4 / info 5; triage total 0 / 7 / 19 (26).

`STA_MANIFEST_ALL=1 ./sta check-apps` ("Reading the manifest of 157 APK(s)"):
app findings red 0 / amber 16 / info 5; triage total **0 red / 19 amber /
19 info (38)**. Per kind and severity:

| count | severity | kind |
|---|---|---|
| 13 | info | mvt-low (MVT, unchanged) |
| 5 | amber | app-surveillance-permissions |
| 4 | amber | app-label-mimics-system |
| 3 | amber | app-boot-sms |
| 3 | amber | mvt-medium (MVT, unchanged) |
| 2 | info | sideloaded-app (F-Droid signature match) |
| 2 | info | webapk |
| 1 | amber | unknown-origin-app, sideloaded-store-app, notification-listener, accounts-review |
| 1 | info | unreadable-package, crash-watchdog |

The 12 new amber findings come from the manifest rules; the MVT and origin
findings are the ones L4 already knew.

### Likely false positives and their general cause (owner packages omitted)

- `app-label-mimics-system`: 4/4 false positives, all Play-installed. Two
  genuine preinstalled Google components whose real names are legitimately
  system-like (`com.google.android.apps.gcs`,
  `com.google.android.apps.helprtc`), and two label artifacts: one Google
  component whose manifest label string is a Play-services error sentence, and
  a game where pyaxmlparser picked the Play-services base-library string
  "%1$s won't run without Google Play services..." instead of the app name.
  General cause: SYSTEM_WORDS matches "google"+"services" in base-library and
  vendor strings, and a wrong label from pyaxmlparser feeds the rule. A fake
  copy would be sideloaded, not play-installed — consider requiring
  origin != play (or resolving labels better) before amber.
- `app-boot-sms`: 3/3 false positives for stalkerware intent: two consumer apps
  with a boot receiver + SMS_RECEIVED filter to auto-fill one-time codes, and
  one watch companion holding READ_SMS to mirror notifications. The detail text
  is factually correct; the pattern (OTP autofill, notification mirroring) is
  mainstream. Play origin keeps them amber — reasonable.
- `app-surveillance-permissions`: 5/5 play-origin, all mainstream (two global
  messengers, a bank app, a watch companion, a camera companion). Any chat app
  reaches ≥3 surveillance permissions by design, so the rule is only sharp in
  combination — and it worked: the camera companion is on the battery-saving
  user whitelist and got the "exempt from battery saving" sentence, yet stayed
  amber because it is not sideloaded, exactly as coded. Consider an exception
  list of known Play messengers/banks for the plain ≥3 case.
- `role-holder`: no findings — correct. All sensitive-role holders on this
  phone are system apps or kb/role-defaults entries (Google Messages SMS,
  Google Dialer, quicksearchbox assistant; the device-management role is held
  by the standard work-profile client and skipped via defaults). F-Droid apps
  hold no role here, so the red path was not exercised; the F-Droid signature
  match itself did show up (2x `sideloaded-app` info with `fdroid_match: true`,
  including `org.fdroid.fdroid`).
- `app-hidden`: never fired, correctly — across all 157 parsed manifests no
  app has its launcher set inside `disabled_components`. `disabledComponents`
  holds real data (99 packages, 396 components, mostly GMS receivers; the top
  package alone has 62) and five apps disable only *some* launcher aliases
  (brand skins, seasonal variants like a Christmas activity or a mourning-mode
  alias in big retail apps) — the subset test `launcher <= disabled` rightly
  ignores those. **Coverage gap for the cloud agent**: with package details
  present, an app whose manifest declares NO launcher never triggers app-hidden
  (the no-launcher fallback only runs when details are absent). A stalkerware
  shipped as its own APK without any icon would slip past task 1's main signal
  on a phone with dumpsys. Something to address in a later task, not a bug in
  what was specified.
- `work-profile`, `multiple-users`, `device-owner`: none emitted — correct for
  this phone (single FULL user id 0, no MANAGED_PROFILE flag, `device_policy`
  only has "Device Owner Type: -1", no Device Owner block). The positive paths
  stay unverified against a real managed phone.
- `accounts-review`: 1 amber: "N Google account(s) and M other account(s)"
  over several types. `accounts.json` holds only by_type counts + HMACs — verified
  no plain account name lands there (names dropped inside the parser).

### Manifest parse results with STA_MANIFEST_ALL=1 (for task 1 hardening)

- 157/157 manifests parsed: **0 errors, 0 timeouts** in `apk-scan.json`.
- Labels resolved to real names for 153/157. 4 stay as raw ids (`@7F1254BB`,
  `@7F1312A9`, `@7F142148`, `@7F1420AB`): split AABs (e.g. `com.whatsapp`,
  `com.google.android.keep`). The base APK's own resources do not carry the
  label table lookup pyaxmlparser needs; a config split parsed alone gives an
  empty label instead. Consequence for findings: the label check runs on junk —
  one of them (WhatsApp) still produced a correct app-surveillance finding
  because that rule does not use the label, but a real-name-only mimics-system
  check would be blind there. Consider merging splits (or skipping `@`-labels
  in app-label-mimics-system).
- Cost: second full run with MANIFEST_ALL took ~69 s wall once store lookups
  were cached (first run a few minutes). Fine as an expert flag, still off by
  default.

### Other verified behavior

- YARA exceptions worked: 2 apps had an "android_police" match discarded by
  kb/yara-exceptions.yaml (visible only in `apk-scan.json` as
  `yara_discarded`).
- The battery-saving whitelist parse gave exactly 6 user apps; each got
  `battery_exempt: true` in package-details.json with a full block (no stubs
  needed). No finding carried the per-finding `battery_exempt` tag because none
  of those 6 has its own finding besides the camera companion above.
- report.md renders every new kind; Sources section lists Play because lookups
  ran. Privacy grep over report/findings/accounts/package-details: no device
  identifier and no account address from our checks (accounts.json holds only
  counts and HMACs); the only hits are owner package names and one adb host-key
  string inside MVT's own pre-existing mvt-low text, allowed in a case folder.

## 11. iOS quick formats (from pymobiledevice3 source, not seen on a phone)

Written by the cloud agent on 2026-10-22 for task 2, from the code of the
pinned versions — **pymobiledevice3 11.43.1** (`requirements-image.txt`) and
its dependency **pycrashreport 2.0.0**, read from the PyPI wheels
(`pip download --no-deps`, files cited per item). There is no iPhone case, so
everything below is a code reading, never observed traffic: field lists are
what the code sends or prints, not what a phone answered. The synthetic
fixtures in `tests/fixtures/ios-quick/` follow these shapes exactly.

JSON writing (all four commands): `cli_common.print_json` →
`json.dumps(buf, sort_keys=True, indent=4)` with `default_json_encoder`:
`bytes` become the object `{"$hex": "<hex>"}`, `datetime` ISO strings, UUID
strings. Not a terminal: no pygments colour (colour only when stdout is a tty
and requested), so sta can capture stdout directly — note that `common.run()`
with a `log` streams stdout to the log instead, so ios-quick captures JSON
without logging (see `acquire.quick_ios`).

### 11.1 `apps list -t Any` — installation proxy lookup

`cli/apps.py:apps_list` calls `InstallationProxyService.get_apps(application_type=...)`,
which sends the `Lookup` command and returns its `LookupResult` **as-is**: a
dict `{bundle_id: {attributes...}}`. The service adds nothing; every attribute
comes from the phone's LaunchServices database. So only the two words `-t Any`
are verified here, never the per-app field names. The fields sta reads
(`CFBundleName`, `ApplicationType`, `SignerIdentity`, `Path`, `Entitlements`)
are the installation-proxy documented attributes named in the plan; treat each
as unverified until a phone confirms it. `SignerIdentity: "Apple iPhone OS
Application Signing"` for App Store apps is likewise the plan's claim, not
something this source can confirm. Code facts that DO matter:

- `-t/--type` takes exactly `System|User|Hidden|Any` (Literal in apps.py);
  default Any; unknown values are refused by typer before reaching the phone.
- `--calculate-sizes` merges only `CFBundleIdentifier`, `StaticDiskUsage`,
  `DynamicDiskUsage` in a second lookup (`GET_APPS_ADDITIONAL_INFO`). We do
  not use it: an extra slow round-trip for nothing.
- Placeholder apps (installing/downloading stubs) appear only with
  `--show-placeholders`; we leave them out deliberately.

### 11.2 `profile list` — MCInstall GetProfileList

`cli/profile.py:profile_list` prints `MobileConfigService.get_profile_list()`,
which returns the device's reply to `{"RequestType": "GetProfileList"}`
verbatim (`services/mobile_config.py`). The service code itself only ever
indexes `["ProfileMetadata"]` (and inside it `PayloadUUID` and
`PayloadVersion`, see `remove_profile`), so **those three keys are the only
shape provable from pymobiledevice3**. The full response shape —

```json
{"OrderedIdentifiers": ["<identifier>", ...],
 "ProfileManifest":  {"<identifier>": {"Description": "...", "IsActive": true}},
 "ProfileMetadata":  {"<identifier>": {"PayloadDisplayName": "...",
                       "PayloadOrganization": "...", "PayloadDescription": "...",
                       "PayloadRemovalDisallowed": false, "PayloadUUID": "...",
                       "PayloadVersion": 1}},
 "Status": "Acknowledged"}
```

— was cross-checked against an independent client of the same request:
appium-xcuitest-driver's `MobileConfigService.getProfileList` documents it with
an example response (fetched 2026-10-22). Consequence for the checks: this
reply carries **no payload types** (`com.apple.mdm`, certificate types...). A
profile kind from ios-quick comes from words in the display name and
`ProfileManifest[].Description` (documented heuristic;
`iosquick.classify_profile`) and its detail says so. `PayloadRemovalDisallowed`
does exist here, so the red "owner cannot remove it" rule works without a
backup. `profiles.json` is this reply unchanged.

### 11.3 `provision list` — misagent CopyAll

`cli/provision.py:provision_list` prints `[p.plist for p in
await MisagentService(...).copy_all()]`: a JSON **array**, one entry per
`.mobileprovision`, each the embedded plist parsed from the profile bytes
(`ProvisioningProfile.__init__` cuts between `<?xml` and `</plist>` and runs
`plistlib.loads`). The certificate fields inside it are `bytes` → `{"$hex": ...}`
objects (`DeveloperCertificates`). Field names of a provisioning profile
(`Name`, `TeamName`, `TeamIdentifier` list, `AppIDName`, `CreationDate`,
`ExpirationDate`, `ProvisionsAllDevices`, `ProvisionedDevices`, `Entitlements`,
`UUID`) are Apple's fixed keys for that plist format (same content as any
`.mobileprovision` file). Dates arrive as ISO strings via the JSON encoder —
that is why `iosquick._iso` only accepts strings, and expiry compares with
`datetime.fromisoformat`. The wildcard rule matters: enterprise profiles carry
`application-identifier: TEAM.*`, so a match must also compare the team, or one
profile explains every non-store app (`iosquick.covered_by_provision`).
`provision dump DIR` writes each profile as `DIR/<UUID>.mobileprovision`
(`device_file_path`: one sanitised component per UUID).

### 11.4 `crash pull` and the `.ips` format

`cli/crash.py:crash_pull` → `CrashReportsManager.pull(out, "/", erase=False)`
→ `AfcService.pull`: an **asynchronous copy** (no tar), mirroring the remote
tree under `out`, so files arrive keeping their folders (`/ResetPeriodization/…`
and `/Retired/…` show up as subfolders — readers must recurse). 0 files is a
normal outcome, not an error. `crash ls [--depth N]` (not used by sta) prints
plain paths, one per line — NOT JSON, unlike the other three commands.

`.ips` format, from pycrashreport 2.0.0 (`pycrashreport/crash_report.py`):
`get_crash_report_from_file` reads **line 1 with `json.loads` as metadata**,
the rest as the body; the body parses as JSON on current iOS (key/value crash)
and stays text on older formats — pycrashreport tries and falls back
(`_parse`, `_is_json`). Metadata keys used: `bug_type` (a **string**; e.g.
`"309"` = userspace crash, `"209"` = wifi crash, `BugType` enum), `app_name`,
`timestamp`, `incident_id`. Timestamp format `"%Y-%m-%d %H:%M:%S.%f"` plus a
space and `%z` offset (`YYYY-MM-DD HH:MM:SS.ss +HHMM`). The JSON body names the
crashing program `procName` (daemon names usually carry the `com.apple.`
prefix; App Store processes show their executable name) and its binary path
`procPath`; exception details live in `exception.type/signal/subtype`, plus
`faultingThread`. sta's parser (`iosquick.parse_ips`) reads exactly metadata +
`procName`/`procPath`/`bug_type` and never touches thread data.


## 12. Verification of phase 2b (tasks 4 to 6)

Run 2026-10-23 on a copy of the real Pixel case (`sta update-kb` →
`check-apps` → `triage` → `report`, then `seal`/`verify`/`diff`) over commits
f79b1c4..c324149. The case has network consent, so KEV, OSV, the IzzyOnDroid
index and Exodus signatures all downloaded ("ok" for each in state.json; 19
MVT indicator files). No step refused to run.

### Counts (after triage: 0 red / 7 amber / 19 info, 26 total)

| count | severity | kind |
|---|---|---|
| 13 | info | mvt-low (8 = "installed via third-party store org.fdroid.fdroid", 2 = appops 'reject' events, 1 uninstall churn of a Chrome library component ×8 alerts, 1 accessibility dump limit, 1 trusted-ADB-host note) |
| 3 | amber | mvt-medium (all dumpsys_appops: REQUEST_INSTALL_PACKAGES access in Chrome and in a messenger, VIBRATE by shell during our own acquisition) |
| 2 | info | sideloaded-app with signature matching the F-Droid build |
| 2 | info | webapk (Chrome home-screen web apps) |
| 1 each amber | — | unknown-origin-app (the owner's own debug build), sideloaded-store-app (event APK from a website, differs from the F-Droid build), notification-listener (vendor wearable companion from Play), accounts-review (count-only) |
| 1 each info | — | unreadable-package (Android 17 Private Space system feature androidqf cannot read), crash-watchdog (a system HAL tombstone) |

### Per feature checked

- **outdated-os-exploited**: kb/cache/kev-android.json holds 16 KEV CVEs
  mapped through OSV to their fixing SPL; newest fix is 2026-09-05 and the
  phone's patch is 2026-10-05, so **0 open holes and no finding — correct**.
  Two CVEs spot-checked against source.android.com bulletins: a Pixel modem
  EoP listed in KEV 2026-09-16 is fixed at SPL 2026-09-05 (Pixel Bulletin
  Sept 2026; OSV spl matches), and a Framework integer overflow listed 2026-
  06-02 is fixed at 2026-06-01/05 (ASB June 2026). The phone's patch is newer
  than both, as the tool says. A KEV entry whose OSV record lacks `spl` is
  dropped silently — fine, but invisible to the reader.
- **IzzyOnDroid signers**: merge into fdroid-signers.json ok; 6 installed
  packages have an izzy key list (one is a system Google app listed only in
  that repo by mistake; its cert does not match). Exactly 2 installed apps'
  certs match an izzy key (both also F-Droid-adjacent), but both came from a
  store, so **no sideloaded finding ever reported "Signature matches the
  IzzyOnDroid build" — the izzy branch of `signer_repo` is untested on real
  data**. The string "IzzyOnDroid" only appears in the generic "Not found in
  Google Play, F-Droid or IzzyOnDroid" text and in the report's Sources
  section. No role-holder finding names it.
- **ioc-domain-in-app**: **0 findings** (no app's dex contains an indicator
  domain; no blocker/antivirus installed, so nothing to demote). apk-scan.json
  keeps up to MAX_KEPT=200 domains/app: 156 of 157 scanned apps got a list
  (the one missing has unreadable dex), 11 946 kept → **avg 76.6 per app**,
  median 61, 9 apps pinned at the cap. abuse.ch off (no API key), as the
  "What was checked" row says.
- **trackers (Exodus)**: kb/cache/exodus-trackers.json = 428 tracker name →
  dex-prefix entries. 157 scanned apps, all with a `trackers` key, **108
  non-empty**. Among the 23 apps signed with an F-Droid cert only 5 are
  non-empty — so "F-Droid apps show no trackers" is mostly true but NOT
  absolute: crash reporters (ACRA in the store client and a video downloader)
  and Firebase/CrashLytics in two apps do match. ACRA as a "tracker" reads as
  mild noise; severity-neutral context, which is the intended design.
- **Install timeline**: exactly 20 rows, dates descending and plausible (no
  1970/2009 epoch values), origins play/store/adb/unknown all sensible; one
  "unknown" row is a Chrome library component. Values match
  package-details.json first_install.
- **What was checked table**: every row true for this case, including
  "APK manifests | 6 read". Caveat found: on the OLD container image (built
  before pyaxmlparser/age/saf were added) the same run printed "0 read, 6
  unreadable" with error "no APK copy of this app could be read" — a stale
  image silently degrades the scan and nothing tells you; `./sta doctor`
  does not detect it. After rebuild, all 6 manifests parsed.
- **seal / verify**: seal hashed 1062 files (no ots client → clean warning +
  proceed). verify OK. A bare `touch` on a file is NOT reported (the seal is
  a content hash — by design); appending one line to a file IS reported as
  `CHANGED: store-lookups.json` with exit ERROR line. Restoring the file
  makes verify OK again. state.json/.lock/MANIFEST are excluded, as documented.
- **diff**: both cases had triage, so it ran; wrote the diff into the newer
  case. The older case predates package-details.json, so the apps section
  prints "App details are missing from one case (purged, or an iPhone)" and
  only findings compare — here exactly `new: amber accounts-review on phone
  accounts`, because the rule was added after the original triage.

### False positives, general causes

- ~12/19 info are MVT's own generic rules: F-Droid as installer (8), appops
  'reject' events (2), component uninstall churn, a dumpsys limit, trusted ADB
  hosts of the owner's computers. Not sta bugs.
- mvt-medium appops accesses by Chrome/messenger update mechanisms and by our
  own adb run: 3/3 benign here.
- unreadable-package for a newer Android system feature not in the system
  allowlist (would deserve an exemption upstream).
- trackers: ACRA counted as a tracker in clean F-Droid apps (2 cases).
