"""Checks on what `./sta ios-quick` copies off an iPhone, with no backup.

The JSON read here comes from pymobiledevice3 11.43.1 (`apps list`,
`profile list`, `provision list`, `crash pull`); its shapes were read from the
package source, written down in docs/format-notes.md section 11 and not yet
seen on a real phone. The crash rules follow published spyware methodology
(Amnesty's Pegasus forensics 2021, Kaspersky's Triangulation writeup 2023)."""

import datetime as dt
import json
import re
from pathlib import Path

from sta.common import KB_DIR, plain


def finding(kind: str, severity: str, subject: str, detail: str, **evidence) -> dict:
    # Same shape as checks.finding(); importing checks here would close a loop.
    return {"kind": kind, "severity": severity, "subject": subject,
            "detail": detail, "evidence": evidence}


def load_yaml(path):  # same helper as checks.load_yaml, kept local for the loop
    import yaml
    try:
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle) or []
    except FileNotFoundError:
        return []


# App Store apps are re-signed by Apple under this identity; anything else on
# a user app came in through a provisioning profile (plan claim, unverified).
APP_STORE_SIGNER = "Apple iPhone OS Application Signing"

# Where the system's own apps live. An app hidden from there is iOS hiding its
# own parts; a hidden app anywhere else is hidden from the owner.
SYSTEM_APP_PATHS = ("/Applications/", "/System/Applications/")

# Entitlements an app gets only with Apple's special permission. Info only:
# several owners have good reasons (a VPN app, a keyboard): the list is
# context for a specialist, so no severity is invented per entitlement here.
WATCH_ENTITLEMENTS = {
    "com.apple.developer.networking.vpn.api": "it can set up a VPN that sees all traffic",
    "com.apple.developer.screen-capture": "it can capture what is on the screen",
    "com.apple.developer.device-information.user-assigned-device-name": "it can read and change the phone's name",
}

# Processes Amnesty (Pegasus) and Kaspersky (Triangulation) list as crashing in
# repeatable patterns during exploitation. Normal phones crash these too, so a
# match is info: context for a specialist, not something to ask the owner.
CRASH_WATCH = {"WebKit.Networking", "backboardd", "mediaserverd", "bluetoothd", "imagent",
               "MessagesBlastDoorService", "IMTransferAgent", "locationd", "CommCenter", "assistantd"}
CRASH_WINDOW_DAYS = 30

# Same folders as the shutdown.log rule: spyware was found running from them.
SUSPICIOUS_PATHS = ("/private/var/tmp/", "/private/var/db/", "/tmp/")

# .ips bug_type values of a process crash (pycrashreport: Crash_309, WifiCrash_209).
CRASH_TYPES = {"309", "209"}

METADATA_TIME = "%Y-%m-%d %H:%M:%S.%f %z"


def system_processes() -> set[str]:
    """Names in kb/ios-system-processes.yaml: known daemons, never unknown."""
    return {str(entry) for entry in load_yaml(KB_DIR / "ios-system-processes.yaml") if entry}


def crash_key(name: str) -> str:
    """'com.apple.WebKit.Networking' and 'WebKit.Networking' name one process."""
    return str(name).removeprefix("com.apple.")


# ---------------------------------------------------------------- .ips crash logs

def parse_ips(text: str) -> dict | None:
    """One .ips file: the first line is a JSON metadata object, the rest is a
    JSON body (new format; older iOS files are plain text we do not read).
    Returns {process, path, bug_type, at} or None when even the first line is
    not JSON. Same split pycrashreport (pymobiledevice3's crash dependency)
    does."""
    first, _, rest = text.partition("\n")
    try:
        meta = json.loads(first)
    except ValueError:
        return None
    if not isinstance(meta, dict):
        return None
    body = {}
    try:
        parsed = json.loads(rest)
        if isinstance(parsed, dict):
            body = parsed
    except ValueError:
        pass  # old plain-text body: metadata still gives process and type
    process = str(body.get("procName") or meta.get("app_name") or "") or None
    return {"process": process, "path": str(body.get("procPath") or ""),
            "bug_type": str(meta.get("bug_type", "")), "at": str(meta.get("timestamp") or "")}


def crash_time(value: str | None) -> dt.datetime | None:
    """The metadata timestamp is '2026-10-01 10:00:00.00 +0200'."""
    try:
        return dt.datetime.strptime(str(value), METADATA_TIME)
    except ValueError:
        return None


def read_crashes(folder: Path) -> dict[str, list[dict]]:
    """{process: [{at, bug_type, file, path}]} over every .ips under folder,
    newest first. The unreadable files are skipped: a crash log we cannot
    parse is not evidence."""
    out: dict[str, list[dict]] = {}
    for path in sorted(folder.rglob("*.ips")) if folder.exists() else []:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parsed = parse_ips(text)
        if not parsed or not parsed["process"]:
            continue
        out.setdefault(crash_key(parsed["process"]), []).append(
            {"at": parsed["at"], "bug_type": parsed["bug_type"], "file": path.name,
             "path": parsed["path"]})
    for entries in out.values():
        entries.sort(key=lambda e: crash_time(e["at"]) or dt.datetime.min.replace(tzinfo=dt.UTC),
                     reverse=True)
    return out


def summary_for_json(summary: dict[str, list[dict]]) -> dict:
    """The summary as stored in the case: {process: [{at, bug_type, file}]}.
    The procPath stays out of the file; it lives in the finding's evidence."""
    return {proc: [{"at": e["at"], "bug_type": e["bug_type"], "file": e["file"]}
                   for e in entries] for proc, entries in summary.items()}


def crash_findings(summary: dict[str, list[dict]], bundle_ids=()) -> list[dict]:
    """The three crash rules over a read_crashes() result.

    Only a process running from a spyware folder is red. Repeated crashes of
    the watched processes and crashes of unknown processes are info: amber
    means 'the owner explains it', and nobody can explain a crash."""
    known = {crash_key(p) for p in system_processes()} | {crash_key(b) for b in bundle_ids}
    out = []

    from_paths: dict[str, list[dict]] = {}
    suspicious_procs: set[str] = set()
    for proc, entries in summary.items():
        for entry in entries:
            if entry["path"].startswith(SUSPICIOUS_PATHS) or proc.startswith(SUSPICIOUS_PATHS):
                from_paths.setdefault(entry["path"] or proc, []).append({**entry, "process": proc})
                suspicious_procs.add(proc)
    for path, hits in sorted(from_paths.items()):
        out.append(finding("ios-crash-suspicious-path", "red", plain(path, 120),
                           "A crash report comes from a process running in a folder spyware "
                           "uses (/private/var/tmp/, /private/var/db/, /tmp/).",
                           path=plain(path, 200), processes=sorted({h["process"] for h in hits}),
                           files=[h["file"] for h in hits][:20], at=[h["at"] for h in hits][:20]))

    for proc, entries in sorted(summary.items()):
        if crash_key(proc) not in {crash_key(w) for w in CRASH_WATCH}:
            continue
        times = [t for t in (crash_time(e["at"]) for e in entries) if t]
        dates = [e["at"] for e in entries]
        recent = _in_window(times, dt.timedelta(days=CRASH_WINDOW_DAYS))
        if len(recent) >= 2:
            out.append(finding("ios-crash-pattern", "info", plain(proc, 120),
                               f"{len(recent)} crashes of this process within {CRASH_WINDOW_DAYS} days. "
                               "Amnesty (Pegasus) and Kaspersky (Triangulation) list repeated crashes "
                               "of it during spyware campaigns; normal phones crash like this too.",
                               count=len(recent), dates=dates[:20],
                               source="crash logs (Amnesty 2021 / Kaspersky 2023 watchlist)"))

    for proc, entries in sorted(summary.items()):
        crashes = [e for e in entries if e["bug_type"] in CRASH_TYPES]
        if not crashes or crash_key(proc) in known or proc in suspicious_procs:
            continue  # a spyware-folder process is already the red finding above
        out.append(finding("ios-crash-unknown-process", "info", plain(proc, 120),
                           "A process that is neither a known iOS daemon nor one of the listed apps "
                           f"crashed {len(crashes)} time(s). iOS has hundreds of daemons, so an unknown "
                           "name alone usually means our short list is incomplete.",
                           crashes=[{"at": e["at"], "file": e["file"], "path": plain(e["path"], 200) or None}
                                    for e in crashes[:20]],
                           source="crash logs, kb/ios-system-processes.yaml"))
    return out


def _in_window(times: list[dt.datetime], window: dt.timedelta) -> list[dt.datetime]:
    """The largest set of timestamps that fit inside one `window` span."""
    best: list[dt.datetime] = []
    start = sorted(times)
    for left, first in enumerate(start):
        run = [t for t in start[left:] if t - first <= window]
        if len(run) > len(best):
            best = run
    return best


# ---------------------------------------------------------------- provisioning profiles

def _iso(value) -> str:
    """provision list prints plist dates as ISO strings (bytes arrive as
    {"$hex": ...}, which is not a date)."""
    return value if isinstance(value, str) else ""


def _expired(value: str) -> bool | None:
    """True/False when the expiry is readable, None when it is missing."""
    text = _iso(value).replace("Z", "+00:00")
    if not text:
        return None
    try:
        stamp = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.UTC)
    return stamp < dt.datetime.now(dt.UTC)


def provision_app_id(provision: dict) -> str:
    """The application identifier a profile signs for ('TEAMID.bundle' or
    'TEAMID.*'); empty when the profile has none."""
    entitlements = provision.get("Entitlements") or {}
    value = entitlements.get("application-identifier") or entitlements.get("com.apple.application-identifier")
    return value if isinstance(value, str) else ""


def covered_by_provision(app_id: str, provisions: list[dict]) -> dict | None:
    """The provisioning profile that signs an app whose application-identifier
    entitlement is `app_id` ('TEAM.bundle'). A wildcard profile ('TEAM.*') only
    covers apps of the same team: without that check one enterprise profile
    would explain away every non-store app on the phone."""
    app_team, _, app_bundle = str(app_id).partition(".")
    for provision in provisions:
        prov_team, sep, suffix = provision_app_id(provision).partition(".")
        if not sep:
            continue
        if suffix == app_bundle or (suffix == "*" and prov_team == app_team):
            return provision
    return None


def provision_findings(provisions: list[dict]) -> list[dict]:
    """Provisioning profiles are the iOS sideload: an enterprise profile puts
    apps on any phone without Apple seeing them; a developer profile was made
    for exactly this phone."""
    out = []
    for provision in provisions:
        if not isinstance(provision, dict):
            continue
        name = plain(provision.get("Name") or provision.get("UUID") or "unnamed", 120)
        devices = provision.get("ProvisionedDevices")
        ev = {"profile": name,
              "team_name": plain(provision.get("TeamName"), 120) or None,
              "team_identifier": provision.get("TeamIdentifier"),
              "app_id_name": plain(provision.get("AppIDName"), 120) or None,
              "app_id": provision_app_id(provision) or None,
              "expiration_date": _iso(provision.get("ExpirationDate")) or None,
              "entitlements": sorted(provision["Entitlements"]) if isinstance(
                  provision.get("Entitlements"), dict) else None}
        expired = _expired(provision.get("ExpirationDate"))
        # The device UDIDs stay out: count only, they identify the phone.
        if provision.get("ProvisionsAllDevices") is True:
            out.append(finding("ios-enterprise-app", "amber", name,
                               f"An enterprise certificate ({ev['team_name'] or 'unknown team'}) put apps "
                               "on this iPhone outside the App Store. Companies do this; so does anyone "
                               "who wants Apple not to see what they install.",
                               provisions_all_devices=True, **ev))
        elif devices:
            out.append(finding("ios-developer-app", "amber", name,
                               f"A developer built an app and signed this profile for {len(devices)} "
                               "specific phone(s), this one included. Normal only for someone who tests "
                               "apps they wrote.",
                               provisioned_devices=len(devices), **ev))
        if expired:
            out.append(finding("ios-provision-expired", "info", name,
                               f"This provisioning profile expired on {ev['expiration_date']}. "
                               "The apps it signed can stay installed and keep running.", **ev))
    return out


# ---------------------------------------------------------------- configuration profiles

MDM_WORDS = re.compile(r"mdm|manag", re.I)
CERT_WORDS = re.compile(r"certificat|\bca \(", re.I)
VPN_WORDS = re.compile(r"vpn", re.I)


def classify_profile(types: list, text: str) -> str:
    """Kind for one profile. From a backup the payload types say everything.
    The live `profile list` only carries metadata and a free-text description,
    so there the kind comes from words in that text: a documented heuristic,
    never more precise than it."""
    if "com.apple.mdm" in types:
        return "ios-mdm-profile"
    if any(t in ("com.apple.security.root", "com.apple.security.pem", "com.apple.security.pkcs1")
           for t in types):
        return "ios-root-certificate"
    if any(t and "vpn" in t.lower() for t in types):
        return "ios-vpn-profile"
    if not types:
        if MDM_WORDS.search(text):
            return "ios-mdm-profile"
        if CERT_WORDS.search(text):
            return "ios-root-certificate"
        if VPN_WORDS.search(text):
            return "ios-vpn-profile"
    return "ios-config-profile"


def profile_findings(profiles: list[dict]) -> list[dict]:
    """`profiles` is a list of {display, organization, types, uuid, removed_ok,
    description, source}: built from MVT's configuration_profiles.json (backup)
    or from `profile list` metadata (ios-quick). PayloadRemovalDisallowed makes
    it red: the owner cannot remove what manages them."""
    out = []
    for profile in profiles:
        types = [t for t in profile["types"] if t]
        display = plain(profile["display"], 120) or "unnamed"
        text = f"{display} {profile.get('description') or ''}"
        kind = classify_profile(types, text)
        detail = (f"Profile types: {', '.join(types)}." if types else
                  ("The profile's contents hold no payload types."
                   if profile.get("source") == "backup" else
                   "The live profile list does not include the payload types: the kind above comes from "
                   "words in the profile's description."))
        ev = {"display_name": display, "organization": plain(profile.get("organization"), 120) or None,
              "payload_types": types or None, "uuid": profile.get("uuid"),
              "removal_disallowed": bool(profile.get("removed_ok"))}
        severity = "red" if profile.get("removed_ok") else "amber"
        out.append(finding(kind, severity, display, detail, **ev))
    return out


def profiles_from_backup(data: list) -> list[dict]:
    """The configuration_profiles.json MVT writes from a decrypted backup."""
    out = []
    for prof in data or []:
        plist = prof.get("plist", {}) if isinstance(prof, dict) else {}
        out.append({"display": plist.get("PayloadDisplayName") or plist.get("PayloadIdentifier") or "unnamed",
                    "organization": plist.get("PayloadOrganization"),
                    "types": [c.get("PayloadType") for c in plist.get("PayloadContent", []) or []
                              if isinstance(c, dict)],
                    "uuid": plist.get("PayloadUUID"),
                    "removed_ok": bool(plist.get("PayloadRemovalDisallowed")),
                    "source": "backup"})
    return out


def profiles_from_quick(data: dict) -> list[dict]:
    """The JSON of `profile list` (MobileConfigService GetProfileList): names
    and metadata per identifier, no payload contents. See format-notes 11."""
    metadata = data.get("ProfileMetadata") or {}
    manifest = data.get("ProfileManifest") or {}
    identifiers = data.get("OrderedIdentifiers") or list(metadata)
    out = []
    for identifier in identifiers:
        meta = metadata.get(identifier) or {}
        man = manifest.get(identifier) or {}
        if not isinstance(meta, dict):
            continue
        out.append({"display": meta.get("PayloadDisplayName") or identifier,
                    "organization": meta.get("PayloadOrganization"), "types": [],
                    "uuid": meta.get("PayloadUUID"),
                    "removed_ok": bool(meta.get("PayloadRemovalDisallowed")),
                    "description": man.get("Description") if isinstance(man, dict) else None})
    return out


# ---------------------------------------------------------------- apps list

def quick_app_findings(apps: dict, provisions: list[dict], by_pkg: dict) -> list[dict]:
    """The apps of `apps list` (bundle id -> Info.plist dump). `by_pkg` is the
    bundle-id map of checks.load_ioc_lists(): it already carries ioc.yaml and
    watchware.yaml, so those lists apply to ios-quick too."""
    out = []
    for bundle_id, app in sorted(apps.items()):
        if not isinstance(app, dict):
            continue
        name = plain(app.get("CFBundleName") or bundle_id, 120)
        signer = str(app.get("SignerIdentity") or "")
        app_type = str(app.get("ApplicationType") or "")
        path = str(app.get("Path") or "")
        ev = {"bundle_id": bundle_id, "name": name, "application_type": app_type or None,
              "signer_identity": signer or None, "path": plain(path, 200) or None}
        if bundle_id in by_pkg:
            family, typ = by_pkg[bundle_id]
            out.append(finding("watchware" if typ == "watchware" else "stalkerware",
                               "amber" if typ == "watchware" else "red", bundle_id,
                               f"Matches '{family}'.", **ev))
            continue
        watched = sorted(k for k in WATCH_ENTITLEMENTS if k in (app.get("Entitlements") or {}))
        # A Hidden app whose files sit in a user container is hidden from the
        # owner; iOS hides its own parts under /Applications.
        if app_type == "Hidden" and not path.startswith(SYSTEM_APP_PATHS):
            out.append(finding("ios-app-hidden", "amber", bundle_id,
                               f"'{name}' is installed but hidden: iOS does not show it to the owner.", **ev))
        if app_type == "User" and signer != APP_STORE_SIGNER:
            # What explains this signature? The app's own application-identifier
            # entitlement matched against the installed profiles. Apps whose
            # response has no Entitlements can only be matched by exact profile.
            app_id = provision_app_id(app) or f".{bundle_id}"
            if not covered_by_provision(app_id, provisions):
                out.append(finding("ios-app-not-store-signed", "amber", bundle_id,
                                   f"'{name}' was not signed by the App Store (it says it was signed by "
                                   f"'{plain(signer, 100) or 'nobody'}') and no installed provisioning "
                                   "profile explains it.", **ev))
        if watched:
            out.append(finding("ios-app-entitlements", "info", bundle_id,
                               "Special entitlements that need Apple's permission: "
                               + "; ".join(WATCH_ENTITLEMENTS[e] for e in watched) + ".",
                               entitlements=watched, **ev))
    return out
