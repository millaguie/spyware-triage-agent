# Manual phone check with MVT

The commands `./sta` runs, for when you work without it. Checked against
MVT 2026.10.12, androidqf 1.8.3 and pymobiledevice3 (October 2026).

What changed since 2021:

- `mvt-android check-adb` is removed. Use androidqf, then `check-androidqf`.
- For iPhone backups, MVT now recommends pymobiledevice3 instead of
  `idevicebackup2` (libimobiledevice).
- The package is `mvt`: `pipx install mvt`.

## Setup

```bash
pipx install mvt
pipx install pymobiledevice3
mvt download-iocs          # indicators, stored in ~/.local/share/mvt/indicators
                           # (macOS: ~/Library/Application Support/mvt/indicators,
                           #  Windows: %LOCALAPPDATA%\mvt\mvt\indicators)
```

Download androidqf from https://github.com/mvt-project/androidqf/releases/latest
and check it against `checksums.txt`.

## Android

1. On the phone: Settings > About phone > tap "Build number" 7 times.
   Then Developer options > turn on "USB debugging".
2. Connect it and accept the USB debugging prompt.
3. Collect the data. androidqf 1.8.3 asks questions in menus. Answer:
   Backup "Only SMS", Download "All", Remove trusted "Yes".

   ```bash
   androidqf -serial "$(adb get-serialno)" -output ./acq
   ```

   With "Only SMS" the phone shows a backup screen: tap "Back up my data".
   androidqf writes a folder. Newer builds may write a zip with the files at
   its root: extract it first (see "Known issues" in the README).
4. Analyze the folder:

   ```bash
   mvt-android check-androidqf --non-interactive -o ./results ./acq
   ```

5. Read `results/alerts.json`.
6. Look inside the APKs that are not from a store. Echap's YARA rules match
   dex files, so scan the code inside each APK:

   ```bash
   curl -fsSLO https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/rules.yar
   pipx install apkid                      # brings yara
   mkdir x && cd x && unzip -q ../acq/apks/<package>.apk '*.dex' 'lib/*' && cd ..
   yara -r rules.yar x                     # yara CLI from your package manager
   apkid acq/apks/<package>.apk            # packer, protector, "dexlib" = rebuilt
   ```

7. Read the manifest of those APKs (pyaxmlparser is a manifest-only parser):

   ```bash
   pipx install pyaxmlparser==0.3.31
   python - <<'EOF'
   from pyaxmlparser import APK
   a = APK("acq/apks/<package>.apk")
   print(a.get_app_name(), "|", a.get_main_activity(), "|", sorted(a.get_permissions()))
   for r in a.get_receivers():
       print(r, a.get_intent_filters("receiver", r))
   EOF
   ```

   An app whose manifest has no MAIN+LAUNCHER activity shows no icon. Compare
   its launcher activity with the `disabledComponents:` list of that package in
   `dumpsys package`: an app that switched its own icon off while holding SMS
   or microphone permissions is the classic stalkerware shape.
8. Read the rest of `acq/dumpsys.txt` by section (search for
   `DUMP OF SERVICE <name>:`). Four sections say something a store check cannot:

   ```bash
   grep -n "^DUMP OF SERVICE" acq/dumpsys.txt          # where each section starts
   sed -n '/^DUMP OF SERVICE role:/,/^---/p' acq/dumpsys.txt | grep -E "name=|holders="
   ```

   - `role`: which app holds the SMS, DIALER, ASSISTANT, CALL_SCREENING or
     CALL_REDIRECTION role. Anything there that is not a preinstalled app and
     whose signature is not the F-Droid or IzzyOnDroid build needs an explanation: the holder
     reads every message or places every call. SYSTEM_SUPERVISION with a holder
     means parental or school supervision.
   - `deviceidle`, list `Whitelist user apps:`: apps somebody exempted from
     battery saving so they never sleep. Look for them among the hand-installed
     apps and the ones with SMS, microphone or location permissions.
   - `user`: how many profiles exist and their `Flags:` (MANAGED_PROFILE is a
     work profile). Check who set them up. `device_policy`: a `Device Owner:`
     line means one app owns the whole phone.
   - `account`: count the `Account {name=..., type=...}` lines by type and ask
     the owner to read them on the phone. Do not copy the names anywhere: a
     second Google account is the usual way to follow a phone from outside.
9. On the phone: Developer options > "Revoke USB debugging authorizations",
   then turn Developer options off.

## iPhone

A first pass takes a minute and needs no backup (apps, profiles,
provisioning profiles, crash logs — the same data `./sta ios-quick` reads).
Keep the phone unlocked; all four work over the pairing you already trusted:

```bash
pymobiledevice3 apps list --udid U -t Any      # JSON {bundle_id: {...}}; SignerIdentity tells who signed
pymobiledevice3 profile list --udid U          # JSON: ProfileMetadata per installed profile
pymobiledevice3 provision list --udid U        # JSON: one plist per .mobileprovision
pymobiledevice3 crash pull --udid U ./crashes  # all .ips crash reports (0 files is fine)
```

What to look for:

- `apps list`: `SignerIdentity` other than `Apple iPhone OS Application
  Signing` on an `ApplicationType: User` app means it did not come from the
  App Store; `ApplicationType: Hidden` with a `Path` under
  `/private/var/containers/Bundle/Application/` is hidden from the owner.
- `provision list`: `ProvisionsAllDevices: true` is an enterprise certificate
  (apps without Apple's review); `ProvisionedDevices` means someone compiled
  an app for this exact phone. Cross-check each app's bundle id against the
  profiles' `Entitlements.application-identifier`.
- `profiles.json` (`profile list`): `PayloadRemovalDisallowed: true` means the
  owner cannot remove that profile — check who put it there.
- `crash pull`: repeated crashes of the same process (compare dates across
  `.ips` files), and any `procPath` under `/private/var/tmp/` or
  `/private/var/db/` — the Kaspersky shutdown.log folders, now live in the
  crash logs themselves.

1. Connect, unlock and tap "Trust".

   ```bash
   pymobiledevice3 lockdown info
   pymobiledevice3 backup2 encryption        # prints on or off
   ```

2. If encryption is off, turn it on with a password you choose:

   ```bash
   pymobiledevice3 backup2 encryption on 'PASSWORD'
   ```

   If it is on, you need the owner's password. Do not reset settings to
   remove it: that destroys evidence.
3. Make the backup and decrypt it:

   ```bash
   pymobiledevice3 backup2 backup --full ./backup
   MVT_IOS_BACKUP_PASSWORD='PASSWORD' mvt-ios decrypt-backup -d ./decrypted ./backup/<UDID>
   mvt-ios check-backup -o ./results ./decrypted
   ```

4. Get a sysdiagnose. Start it, then press and release both volume buttons
   and the side button at the same time. It takes up to 10 minutes.

   ```bash
   pymobiledevice3 crash sysdiagnose ./sysdiagnose
   ```

   Check its `shutdown.log` with Kaspersky's iShutdown
   (https://github.com/KasperskyLab/iShutdown):
   `python3 iShutdown_detect.py ./sysdiagnose/sysdiagnose_*.tar.gz`.
   Processes under `/private/var/db/` or `/private/var/tmp/` need expert review.
5. If you turned encryption on, turn it off again:

   ```bash
   pymobiledevice3 backup2 encryption off 'PASSWORD'
   ```

## Domains inside an app's code

For an app you doubt, list the domains in its code and search them in the
indicator files MVT downloaded:

```bash
unzip -p app.apk 'classes*.dex' | strings | grep -oE '([a-z0-9-]+\.)+[a-z]{2,}' | sort -u > domains.txt
grep -F -f domains.txt ~/.local/share/mvt/indicators/*.stix2
```

A hit in a blocker or an antivirus is normal: they carry lists of bad domains.

## Is the system missing fixes for exploited holes?

The check does this with public lists. By hand:

- Android: read the patch level (`adb shell getprop ro.build.version.security_patch`).
  Open CISA's catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  filter by Android, and for each CVE look up its bulletin in
  https://source.android.com/docs/security/bulletin: the bulletin's patch level
  is the fix. A patch older than that fix leaves the hole open. Do not compare
  with CISA's "date added": it says when CISA listed the hole.
- iPhone: compare Settings > General > About > iOS Version with the newest
  release of that version on https://endoflife.date/ios.

## Keep the evidence

Before you hand a case over, write down the hash of every file and encrypt
the phone data for a key you keep elsewhere:

```bash
cd case-folder
find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256
sha256sum -c MANIFEST.sha256                       # later: anything changed?
age-keygen -o key.txt                              # on another device; keep key.txt there
tar -cf - acquisition | age -r age1... -o phone-data.tar.age && rm -rf acquisition
age -d -i key.txt phone-data.tar.age | tar -xf -   # to read it again
```

## Options worth knowing

- `MVT_NETWORK_ACCESS_ALLOWED=false`: MVT does not resolve short URLs.
- `MVT_VT_API_KEY=... mvt-android check-androidqf --virustotal --delay 15`:
  looks up the hashes (not the files) of every non-system APK on VirusTotal.
  A free key allows 4 lookups a minute and 500 a day: with hundreds of apps,
  look up only the ones from outside a store instead.
- `mvt-ios check-sysdiagnose`: reads a sysdiagnose archive. Without plugin
  modules it only records the device details.
- androidqf with a `key.txt` (age recipients) encrypts the acquisition.
  Useful when you carry acquisitions across borders.
