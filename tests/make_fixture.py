"""Build tests/fixtures/android-pixel from a real androidqf acquisition.

Run by hand, once, when the fixture needs a refresh (a local agent only:
it reads cases/):

    .venv/bin/python tests/make_fixture.py cases/<case>/acquisition/androidqf

It keeps only what check-apps and triage read, drops everything personal
(serial numbers, identifiers, the owner's own apps, the full dumpsys) and
replaces real certificate hashes with fake ones, except Google's platform
keys, which are public. The result is small enough to live in git.

The account/role/deviceidle/user sections of the real dumpsys hold personal
data (account names, user names), so they are NEVER copied: tests/fixtures/
dumpsys-extra.txt carries synthetic versions of those sections instead and is
concatenated after the device_policy head. See docs/format-notes.md for the
formats and the reason for that file.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "fixtures" / "android-pixel"

# Packages to keep, chosen to cover every branch of check_android.
KEEP = {
    # system apps with Google platform keys
    "com.android.emergency", "com.android.shell", "com.android.settings", "com.android.systemui",
    # Play Store apps
    "com.android.chrome", "org.telegram.messenger", "com.google.android.inputmethod.latin",
    "com.google.android.apps.dreamliner", "com.google.android.gms", "org.thoughtcrime.securesms",
    # F-Droid apps
    "org.fdroid.fdroid", "org.schabi.newpipe",
    # other installers
    "com.android.privatespace",
}
# Personal packages renamed to neutral ones, keeping their origin. The real
# names are the owner's, so the map lives outside git, in
# tests/fixture-renames.json ({"real.package": "org.example.x"}).
RENAMES_FILE = HERE / "fixture-renames.json"
RENAME = json.loads(RENAMES_FILE.read_text()) if RENAMES_FILE.exists() else {}
SECURE_KEYS = ("enabled_accessibility_services", "enabled_notification_listeners", "default_input_method",
               "always_on_vpn_app")
GLOBAL_KEYS = ("http_proxy", "global_http_proxy_host", "global_http_proxy_port", "adb_wifi_enabled",
               "private_dns_mode", "private_dns_specifier")
PROP_KEYS = ("ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
             "ro.build.tags", "ro.build.type", "ro.debuggable", "ro.build.fingerprint",
             "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
             "ro.build.version.security_patch")


def fake_hash(seed: str, length: int) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:length]


def scrub_file(entry: dict, package: str, old: str) -> dict:
    cert = entry.get("certificate") or {}
    # Store apps have public certificates (Signal's is in kb/known-signers.yaml);
    # only the owner's own apps get a made-up one.
    if cert and old in RENAME:
        for key, length in (("Md5", 32), ("Sha1", 40), ("Sha256", 64)):
            cert[key] = fake_hash(f"{package}:cert:{key}", length)
        cert["Issuer"] = cert["Subject"] = f"CN={package}"
        cert["SerialNumber"] = 1
    for key, length in (("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)):
        entry[key] = fake_hash(f"{package}:{key}", length)
    entry["path"] = re.sub(r"~~[^/]+/" + re.escape(old) + r"-[^/]+/", f"~~X/{package}-X/", entry["path"])
    entry["local_name"] = ""
    return entry


def main(src: Path) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    packages = json.loads((src / "packages.json").read_text())
    kept = []
    present = {p["name"] for p in packages}
    for pkg in packages:
        name = pkg["name"]
        if name not in KEEP and name not in RENAME:
            continue
        new = RENAME.get(name, name)
        pkg["name"] = new
        pkg["files"] = [scrub_file(f, new, name) for f in pkg.get("files") or []]
        pkg["uid"] = 10000 + len(kept)
        kept.append(pkg)
    missing = (KEEP | set(RENAME)) - present
    if missing:
        print(f"not in this acquisition: {sorted(missing)}", file=sys.stderr)
    (OUT / "packages.json").write_text(json.dumps(kept, indent=1) + "\n")

    def filter_settings(name: str, keys: tuple) -> None:
        lines = [l for l in (src / name).read_text().splitlines() if l.split("=", 1)[0] in keys]
        text = "\n".join(lines) + "\n"
        for old, new in RENAME.items():
            text = text.replace(old, new)
        (OUT / name).write_text(text)

    filter_settings("settings_secure.txt", SECURE_KEYS)
    # Keep only components of kept packages: an unknown holder is an amber finding.
    lines = []
    for line in (OUT / "settings_secure.txt").read_text().splitlines():
        key, _, value = line.partition("=")
        comps = [c for c in value.split(":") if c.split("/")[0] in KEEP | set(RENAME.values())]
        lines.append(f"{key}={':'.join(comps)}")
    (OUT / "settings_secure.txt").write_text("\n".join(lines) + "\n")
    filter_settings("settings_global.txt", GLOBAL_KEYS)

    props = dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", (src / "getprop.txt").read_text(), re.M))
    (OUT / "getprop.txt").write_text("".join(f"[{k}]: [{props[k]}]\n" for k in PROP_KEYS if k in props))
    (OUT / "selinux.txt").write_text((src / "selinux.txt").read_text())

    # dumpsys: only the head of the device_policy section, the one
    # check_android reads; account/role/deviceidle/user are personal and get
    # replaced by the synthetic sections in tests/fixtures/dumpsys-extra.txt.
    text = (src / "dumpsys.txt").read_text(errors="replace")
    match = re.search(r"DUMP OF SERVICE device_policy:.*?(?=\n-{5,}\nDUMP OF SERVICE)", text, re.S)
    section = "\n".join((match.group(0) if match else "DUMP OF SERVICE device_policy:").splitlines()[:14])
    extra = (HERE / "fixtures" / "dumpsys-extra.txt").read_text()
    (OUT / "dumpsys.txt").write_text("-" * 79 + "\n" + section + "\n" + "-" * 79 + "\nDUMP OF SERVICE device_state:\n"
                                     + extra)
    (OUT / "acquisition.json").write_text(json.dumps({"uuid": "00000000-0000-0000-0000-000000000000",
                                                      "androidqf_version": "1.8.3"}, indent=1) + "\n")
    print(f"wrote {OUT}: {len(kept)} packages")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
