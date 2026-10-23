# spyware-triage-agent

Guided phone check for spyware, stalkerware and fake apps. A small local LLM
agent ([pi](https://pi.dev)) talks to the operator. A script (`./sta`) does
the technical work with [MVT](https://mvt.re), [androidqf](https://github.com/mvt-project/androidqf)
and [pymobiledevice3](https://github.com/doronz88/pymobiledevice3).

The phone data never leaves this computer. Use a model that runs on your own
machine or LAN.

> Use this tool only with the informed consent of the phone owner. MVT and
> androidqf are under the MVT License 1.1, which forbids non-consensual use.

## Install

```bash
./install.sh            # system packages (sudo), mvt, pymobiledevice3, androidqf, .venv
./install.sh --check    # only show what is missing
```

Supported: Arch, Debian/Ubuntu, Fedora, macOS. Without sudo: `./install.sh --no-system`.

### With Docker (Linux)

The container holds MVT, androidqf, pymobiledevice3, adb and usbmuxd. The
computer needs only Docker, and pi for the agent.

```bash
./install.sh --docker        # build the image; run again to update the tools
STA_RUNTIME=docker ./agent.sh
```

`./sta` uses Docker by itself when `.venv` does not exist. Set
`STA_RUNTIME=local` or `docker` to choose.

- `./sta` starts one container and keeps it running (`docker compose exec`).
  Stop it with `STA_DIR=$PWD docker compose down`.
- The container mounts this folder at the same path. Cases stay in `cases/`
  and belong to your user.
- It sees all USB devices (`/dev/bus/usb`, also those plugged in later) and uses the host network, so
  usbmuxd sees an iPhone when you plug it in.
- Stop `adb` and `usbmuxd` on the computer first (`adb kill-server`,
  `sudo systemctl stop usbmuxd`). They hold the phone and the container
  cannot reach it. `./sta` warns you.
- The adb key, the iPhone pairing records and the MVT indicators stay in the
  volumes `spyware-triage-agent_home` and `spyware-triage-agent_lockdown`. Delete them with
  `docker compose down -v` to forget all paired phones.
- macOS: Docker Desktop cannot pass USB devices to a container. Use `./install.sh`.
- pi stays on the computer: it needs your model settings and the network to
  the model, and it only runs `./sta`.

## Run a check

```bash
./agent.sh
```

The agent asks for consent and a short alias, then repeats this loop:
`./sta next` → tell the user what to do with the phone → run the command.

Change the model with `STA_PROVIDER` and `STA_MODEL` (default: `llm` /
`qwen3.8-27b`). The agent only gets the `read` and `bash` tools, and its
prompt (`agent/OPERATOR.md`) allows only `./sta` commands.

You can also run every step by hand. `./sta next` always says what comes next.

### The owner's interview (optional)

Before `detect`, the operator can run `./sta interview` in their own
terminal. It asks since when the owner worries, what they noticed, whether
somebody else had the phone unlocked, shares an account with them, set the
phone up, or manages it for an employer or school. Every question can be
skipped. The answers stay in `.sta/secrets/<case>/interview.json` (mode 600),
outside the folder the agent reads; purge removes them. The report says only
"Interview: done".

`triage` uses them, the code and never the agent:

- physical access: an amber hidden app, stalkerware code, accessibility
  service or role holder becomes red;
- nobody manages the phone: a device owner, work profile, MDM profile or
  enterprise app becomes red; an employer does: a work profile or MDM profile
  becomes info;
- a shared account: the account question becomes amber;
- the date: apps installed within two weeks of it get
  `installed-near-suspicion`, or that flag in their existing finding.

The report also has an "Install timeline": the 20 most recent installs of
apps that did not come with the phone (Android).

## Steps

| Step | Android | iPhone |
|---|---|---|
| `new-case` | consent, alias, network yes/no | same |
| `interview` (optional, operator only) | a few questions to the owner; answers in `.sta/secrets/<case>/` | same |
| `detect` | `adb devices`, model, patch level | `pymobiledevice3 usbmux list` |
| `ios-quick` | – | apps, profiles, provisioning profiles and crash logs in about a minute (see below) |
| `update-kb` | `mvt download-iocs`, stalkerware lists and YARA rules, android-sigma-rules indicators, F-Droid and IzzyOnDroid signers, CISA KEV and the Android bulletins (OSV) | same, without F-Droid, IzzyOnDroid and android-sigma-rules; endoflife.date instead of OSV |
| `ios-password` | – | makes sure backups are encrypted (see below) |
| `acquire` | `androidqf` unattended, checks `hashes.csv` | `pymobiledevice3 backup2 backup --full` |
| `sysdiagnose` | – | `pymobiledevice3 crash sysdiagnose`: the owner presses the buttons (see below) |
| `decrypt` | – | `mvt-ios decrypt-backup` |
| `analyze` | `mvt-android check-androidqf` | `mvt-ios check-backup` |
| `check-apps` | fake apps, known malware, risky permissions, system integrity, store lookups, YARA and APKiD on the APKs, APK manifests (hidden icon, boot+SMS, surveillance permissions) | MDM, profiles, App Store lookups, `shutdown.log`; with only `ios-quick`: provisioning profiles, hidden and non-store apps, crash-log rules |
| `triage` | MVT alerts + app checks → `findings.json` (F001…) | same |
| `report` | `report.md` (`--partial` allows it without a backup: the report warns that MVT did not run) | same |
| `review` | questions for the owner, `./sta note F003 "…"` | same |
| `cleanup` | revoke USB debugging | turn backup encryption off if we turned it on |

Each case lives in `cases/<date>-<alias>/`. `./sta purge` deletes the phone
data (and the case's entry in `.sta/secrets/`) and keeps `report.md`,
`findings.json`, `notes.json` and `state.json`.

### Quick iPhone check (no backup)

`./sta ios-quick` takes about a minute instead of the hour-long backup and
copies what an iPhone gives over a trusted cable: `apps list` (every app with
its signer), `profile list`, `provision list` (the iOS equivalent of apps from
outside a store: enterprise and developer certificates) and `crash pull`
(the crash logs that Pegasus and Triangulation indicators are built on — MVT
only ever sees the ones inside a sysdiagnose). From there you can run the
whole first pass in the field without a backup:

```bash
./sta detect && ./sta ios-quick && ./sta update-kb
./sta check-apps && ./sta triage && ./sta report --partial
```

The report says **PARTIAL CHECK: no backup was analysed. MVT did not run** at
the top. Keep the iPhone unlocked while it runs; a command that fails is noted
and the rest continues. The files land in `acquisition/ios-quick/`.

### iPhone sysdiagnose

A sysdiagnose is a diagnostic archive that only the owner can start. While
`./sta sysdiagnose` waits, press and release both volume buttons and the
side button at the same time. The phone vibrates; the archive takes up to
10 minutes. It holds `shutdown.log`, the list of processes that ran at each
reboot. If the owner cannot do it, `./sta sysdiagnose --skip "<reason>"`
goes on and the report says why.

### iPhone backup password

Encrypted backups hold more data, so the check always uses one.

- Encryption off: `sta` turns it on with a random password, stored in
  `.sta/secrets/<case>/` (mode 600, outside `cases/` so the agent cannot
  read it), and turns it off again at cleanup. `purge` deletes it too.
- Encryption on: only the owner knows the password. They type it in a
  second terminal with `./sta ios-password`. The agent never sees it.
  If the owner forgot it, stop. Resetting the settings destroys evidence.

## What `check-apps` adds to MVT

MVT already flags known spyware indicators, stalkerware, root, apps installed
outside the store and Play Protect off. `check-apps` adds:

- **Fake apps.** Compares the signing certificate with
  `kb/known-signers.yaml` and with the F-Droid and IzzyOnDroid indexes. A Play Store app is
  always genuine for its package name; a copy from outside the store may not be.
- **Impersonation.** Package names close to a popular app (`kb/watched-apps.yaml`),
  for example `com.gbwhatsapp`.
- **Store lookups.** Google Play, F-Droid, IzzyOnDroid and the App Store. Only package
  names go out, never phone data. Off with `new-case --network no`.
- **Spyware domains inside app code.** The code (`classes*.dex`) of every
  non-system app is searched for domain names, and these are compared with
  the domains in MVT's indicator files. A match is `ioc-domain-in-app`: amber,
  red next to hidden or stalkerware code, info when an app holds five or more
  (blockers and antivirus apps carry such lists). Common SDK and CDN domains
  are dropped first (`kb/domain-allowlist.yaml`); the domains found stay in
  `apk-scan.json`. Nothing goes out.
- **Tracker SDKs (context).** Exodus Privacy's signatures list the
  advertising and analytics SDKs in each app's code. They go into
  `apk-scan.json` and into the evidence of every finding about that app. They
  change no severity: an app with no trackers is as often a privacy-minded
  F-Droid app as stalkerware.
- **Quark-Engine (optional, slow).** With `STA_QUARK=1` and Quark installed
  (`pipx install quark-engine`, then `freshquark`), the APKs that already have a
  red or amber finding go through Quark (up to 10 minutes each). Three or more
  spying behaviours at 100 % confidence (send or read SMS, location, audio,
  hide icon, contacts, upload) give `app-behaviour` (amber). The detail stays
  in `apk-scan.json` and `mvt-results/quark/`.
- **abuse.ch (optional).** With `STA_ABUSECH_API_KEY` (free key) and its own
  yes in `new-case`, the SHA-256 of apps from outside a store goes to
  MalwareBazaar, and the domains in their code to ThreatFox: `known-malware`
  and `c2-domain`, both red. This is the one lookup that sends more than
  package names, hashes and versions, and the question says so.
- **Exploited holes the phone still has.** Android: CISA's list of exploited
  vulnerabilities (KEV), with the patch level that fixes each one from the
  Android security bulletins (OSV). A phone whose patch is older than a fix gets
  `outdated-os-exploited` (amber). KEV's own dates are never compared with the
  phone: they say when CISA listed a hole, not when it was fixed. iPhone:
  endoflife.date gives the newest release of each iOS version; an iPhone behind
  the newest release of its own version, or on a version Apple no longer
  updates, gets `outdated-os`. Nothing about the phone goes out: these lists
  are downloaded by `update-kb`.
- **Risky permissions.** Accessibility, notification access, keyboard,
  always-on VPN, device administrator.
- **Watchware.** Parental-control and monitoring apps (amber, not red: they
  are only abuse if the owner did not agree).
- **iPhone profiles.** MDM, root certificates, VPN and other profiles; a
  profile the owner is not allowed to remove (`PayloadRemovalDisallowed`) is
  red. Without a backup the kinds come from words in the profile's description
  instead of its payload types, and the finding says so.
- **iPhone provisioning and apps (ios-quick).** An enterprise certificate or a
  developer profile that lists this phone means apps Apple never saw; an app
  whose signer is not the App Store with no profile to explain it, or a Hidden
  app in a user folder, asks the same question as an Android sideload. The
  stalkerware bundle-id lists apply here too.
- **iPhone crash logs (ios-quick).** Repeated crashes of the processes Amnesty
  and Kaspersky watched during Pegasus and Triangulation, crashes of a process
  nothing else knows, and any process running from `/private/var/tmp/` or
  `/private/var/db/` (red, like the shutdown.log rule). The first two are
  info: nobody can explain a crash, so they are specialist context, never an
  amber question. The summary is kept in `acquisition/ios-quick/crashes.json`.
- **Stalkerware code.** Echap's YARA rules (`rules.yar` in
  [stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators))
  on the dex and native code inside every APK that is not a system app. They
  find stalkerware that changed its package name.
  `kb/yara-exceptions.yaml` drops matches made only of strings from common
  libraries (for example WebRTC in `android_police`).
- **Known Android malware.** The indicators of
  [android-sigma-rules](https://github.com/android-sigma-rules/rules) (AndroDR,
  CC-BY-4.0): about 1000 APK hashes, package names and signing certificates
  from Amnesty, Zimperium, PRODAFT, MalwareBazaar and others. androidqf already
  records the SHA-256 of every APK, so this needs no network at check time.
- **System integrity.** From `getprop.txt`, `selinux.txt` and
  `settings_global.txt`: verified boot not 'green' or an unlocked bootloader,
  a test build, SELinux off, a global HTTP proxy, wireless debugging, private DNS.
- **VirusTotal (optional).** With `MVT_VT_API_KEY` set and network on, the
  SHA-256 of each app from outside a store goes to VirusTotal (only the hash,
  never the APK). 5 or more engines: red; 1 to 4: amber. A free key allows 4
  lookups a minute, so sta waits 15 s between them (`STA_VT_DELAY` changes
  it) and keeps the answers in `virustotal.json`. `STA_VT_ALL=1` also runs
  MVT's lookup of every non-system APK: hundreds of hashes, for a paid key.
- **Packed and rebuilt apps.** [APKiD](https://github.com/rednaga/APKiD) on
  apps from outside a store. Packers and protectors, and code rebuilt with
  dexlib (smali, apktool), become amber findings. Its other labels (anti-VM,
  anti-debug, obfuscators) are in `apk-scan.json` only: genuine apps have them too.
- **App manifests.** The `AndroidManifest.xml` inside every APK from outside a
  store is read with pyaxmlparser (in a separate process: a hostile APK
  attacks its parser). Seven checks on what the app was built to do: an icon
  that was switched off while the app runs (`app-hidden`, red for sideloaded:
  this is how stalkerware hides), a name like 'System Update Service', a boot
  receiver plus SMS access, declared-but-unenabled accessibility or device-
  admin code, three or more granted surveillance permissions (SMS, call log,
  microphone, background location...), and a targetSdk so old that every
  permission was granted at install. What each manifest says is kept in
  `apk-scan.json`; `STA_MANIFEST_ALL=1` reads the manifest of every non-system
  APK instead.
- **Accounts, roles and profiles.** All from dumpsys sections androidqf
  already copies, and no personal name is ever written down:
  - Accounts are only counted by type (`accounts-review`; amber when there are
    two Google accounts, because a second one added by somebody else is how
    Find My Device, the location history or Family Link follow a phone). The
    owner checks them on the phone itself. `accounts.json` keeps the counts and,
    for Google accounts only, an HMAC of the name with a key in `.sta/secrets/`
    (never a plain hash: those are reversed by trying known addresses); a
    follow-up check of the same phone can then count new accounts.
  - Android gives some jobs to one app at a time: the messages app, the dialer,
    the assistant, call screening and call redirection. An app holding one of
    these roles that was installed by hand and whose signature is not the
    F-Droid or IzzyOnDroid build is `role-holder` (red); from a store or matching one of them,
    amber. The normal holders live in `kb/role-defaults.yaml`.
  - Supervision (Family Link), a device owner, a work profile and extra user
    profiles become `supervision-active`, `device-owner`, `work-profile` and
    `multiple-users`. Profile names ('Work', 'Maria') are personal: only ids
    and flags are kept.
- **Battery-saving exemptions.** The apps somebody took out of battery saving
  (`dumpsys deviceidle`) are meant to keep running day and night. That is not a
  finding by itself; it goes into the evidence of every finding about that
  package and turns a hand-installed app with three or more surveillance
  permissions from amber to red.
- **iPhone reboot log.** Kaspersky's `shutdown.log` method: processes that ran
  from `/private/var/db/` or `/private/var/tmp/` at a reboot (red), and reboots
  delayed 3 or more times (amber). See
  [Securelist](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/).
  The method is written again in `src/sta/sysdiag.py`, because Kaspersky's
  iShutdown scripts have no open-source license.
- **The whole sysdiagnose (optional).** With EC-DIGIT-CSIRC's
  [saf](https://github.com/EC-DIGIT-CSIRC/sysdiagnose) installed (`install.sh`
  and the image pin a commit), `check-apps` parses the whole archive in
  `mvt-results/saf/` (up to 20 minutes): every process seen anywhere from a
  spyware folder is `ios-suspicious-process-path` (red; same kind as the
  shutdown.log rule, the evidence names the source), and an app the logs,
  App Store history or privacy database mention but the app list does not
  is `ios-app-not-listed` (amber if it was granted a privacy permission,
  else info). Without saf the shutdown.log check still runs.

MVT alerts and app checks about the same app become one finding.

## Sources

`kb/sources.yaml` lists every place a check can get information from outside
the phone: URL, what goes out, licence and key. The report prints a paragraph
for each source the case used. Only package names, SHA-256 hashes, OS versions
and the store country go out, plus, with its own yes in `new-case`, the
domains found in the code of hand-installed apps (abuse.ch). Downloads (MVT
indicators, Echap, AndroDR, F-Droid, IzzyOnDroid, CISA KEV, OSV,
endoflife.date, Exodus) send nothing about the phone.

## Follow-up checks

Check the same phone again later with a new case, then compare:

```bash
./sta diff 2026-10-18-first 2026-11-20-second
```

It writes `cases/<second>/diff-from-<first>.md`: apps installed, removed or
updated, permissions granted since, new Google accounts (counted by HMAC,
never named), iPhone profiles added or removed, and findings that are new,
resolved or changed severity. Both cases need `triage`. After `purge` only
the findings remain to compare.

## Evidence handling

When the case may go to a specialist, a lawyer or a court:

```bash
./sta seal                      # MANIFEST.sha256: the hash of every file in the case
./sta verify                    # what changed, appeared or went missing since the seal
./sta export case.tar.gz        # operator only: report, findings, MVT results, manifest
./sta export case.tar.gz.age --with-apks --age-recipient age1...   # encrypted, with flagged APKs
./sta seal --encrypt age1...    # operator only: encrypt the phone data instead of purging it
./sta unseal --identity key.txt # operator only: decrypt it back
```

- `MANIFEST.sha256` uses the `sha256sum` format: `sha256sum -c` checks it
  without this tool. With the OpenTimestamps client (`ots`) and network
  consent, `seal` also requests a timestamp proof; only the manifest's hash
  goes out. The proof completes hours later with `ots upgrade`.
- `export` never includes the raw acquisition or `.sta/secrets/`, and its
  `state.json` has no serial or UDID.
- `seal --encrypt` takes an age **public** key. Create the key pair on
  another device (`age-keygen -o key.txt`) and keep `key.txt` there: a private
  key next to the data would protect nothing. `purge` still works on an
  encrypted case.
- On Android, `cleanup` checks that the computer really lost its USB
  debugging permission (`./sta cleanup --verify` when there is no terminal).
- The report has a "What was checked" table: every check, and why one did
  not run (offline, no consent, partial check, failed download).

## Knowledge base

| File | Use |
|---|---|
| `kb/findings.yaml` | Text for every finding kind: why it matters, what to do, question for the owner |
| `kb/threats.md` | What can be dangerous on a phone. The agent reads it to explain |
| `kb/limits.yaml` | What the check cannot see, and next steps by result |
| `kb/sources.yaml` | Every outside source a check can query: URL, what goes out, licence, key |
| `kb/known-signers.yaml` | Official signing keys. Add only values from the developer's site |
| `kb/watched-apps.yaml` | Popular apps that fakes copy. Add your local banks |
| `kb/yara-exceptions.yaml` | Echap YARA rules that also match common libraries, and the strings that must match too |
| `kb/hidden-ok.yaml` | Apps allowed to have no launcher icon without raising `app-hidden` (webapps, keyboards) |
| `kb/role-defaults.yaml` | Normal holders of the one-app Android roles (SMS, dialer...): no question for them |
| `kb/watch-account-types.yaml` | Account types that are a signal by themselves; starts empty, add only what you verified |
| `kb/cache/` | Downloaded lists (not in git) |

## Development

```bash
.venv/bin/pip install -e '.[dev]'   # pytest, ruff, pyright
.venv/bin/python -m pytest          # a few seconds; no phone, no network, no MVT
.venv/bin/ruff check src tests
```

The tests run `check-apps`, `triage`, `report` and `review` on
`tests/fixtures/android-pixel`, an anonymised cut of a real androidqf
acquisition (`tests/make_fixture.py` builds it from a case). The expected
findings are written out in `tests/test_pipeline.py`: a rule change that
moves or drops a finding fails there.

Dependency versions are pinned in `requirements.txt` (venv and image) and
`requirements-image.txt` (MVT and pymobiledevice3 inside the image). The
case files `findings.json` and `notes.json` carry a `schema` field
(`SCHEMA_VERSION` in `src/sta/common.py`); bump it when a field changes
meaning.

## Known issues

- androidqf 1.8.3 asks its questions in menus and has no flags for them.
  `sta acquire` answers the menus through a terminal. With `-output` it writes
  a folder, not a zip, so MVT reads it directly.
- A zip from a newer androidqf has its files at the root, but MVT looks for
  them under a folder. Given the zip, MVT finds nothing and reports zero
  alerts. `sta acquire` extracts the zip.
- Tested on a real Android phone (Pixel 8a, Android 17). The iPhone steps,
  `sysdiagnose` included, were only tested with synthetic data.

## Manual procedure

See [docs/manual.md](docs/manual.md) for the same check without the agent.
