"""Checks that MVT does not do: fake apps, risky permissions, watchware,
configuration profiles, store lookups and an outdated OS.

Each check emits a finding: {kind, severity, subject, detail, evidence}.
`kind` is a key in kb/findings.yaml, which holds the plain-language text.
Severity is red, amber or info. The agent never changes it."""

import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from sta import abusech, vt
from sta.apkscan import scan_apks
from sta.common import CACHE_DIR, KB_DIR, SECRETS_DIR, Case, StepError, read_json, say, write_json
from sta.dumpsys import accounts as dumpsys_accounts
from sta.dumpsys import battery_exemptions as dumpsys_exempt
from sta.dumpsys import for_json as package_details_json
from sta.dumpsys import packages as dumpsys_packages
from sta.dumpsys import roles as dumpsys_roles
from sta.dumpsys import sections as dumpsys_sections
from sta.dumpsys import users as dumpsys_users

PLAY_INSTALLERS = {"com.android.vending", "com.google.android.feedback"}
STORE_INSTALLERS = {
    "com.sec.android.app.samsungapps": "Samsung Galaxy Store",
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.amazon.venezia": "Amazon Appstore",
    "org.fdroid.fdroid": "F-Droid",
    "com.xiaomi.market": "Xiaomi GetApps",
    "com.xiaomi.mipicks": "Xiaomi GetApps",
    "com.heytap.market": "OPPO App Market",
    "com.oppo.market": "OPPO App Market",
    "com.bbk.appstore": "vivo App Store",
}
SYSTEM_WORDS = {"android", "system", "google", "update", "service", "services",
                "security", "samsung", "settings", "battery", "sync"}
IOS_STORE_SOURCES = {"com.apple.AppStore", "com.apple.AppStore.ProductPageExtension"}

# The one account type whose name is an email address, and whose second entry
# means somebody else added an account to this phone.
GOOGLE_ACCOUNT_TYPE = "com.google"


def finding(kind: str, severity: str, subject: str, detail: str, **evidence) -> dict:
    return {"kind": kind, "severity": severity, "subject": subject,
            "detail": detail, "evidence": evidence}


def norm_hash(value) -> str:
    # str(): an unquoted all-digit hash in a YAML list arrives as an int.
    return str(value or "").replace(":", "").replace(" ", "").upper()


# ---------------------------------------------------------------- knowledge base

def load_yaml(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return yaml.safe_load(handle) or []
    except FileNotFoundError:
        return []


def load_ioc_lists() -> tuple[dict, dict]:
    """Map package name and certificate SHA-1 to (family, type) for
    stalkerware and watchware from AssoEchap/stalkerware-indicators."""
    by_pkg, by_cert = {}, {}
    for name in ("ioc.yaml", "watchware.yaml"):
        for entry in load_yaml(CACHE_DIR / name):
            label = (entry.get("name"), entry.get("type", "stalkerware"))
            for pkg in entry.get("packages") or []:
                by_pkg[pkg] = label
            for cert in entry.get("certificates") or []:
                by_cert[norm_hash(cert)] = label
    return by_pkg, by_cert


def load_androdr_iocs() -> dict[str, dict]:
    """{"hash"|"package"|"cert": {indicator: entry}} from android-sigma-rules.
    Certificates come as SHA-1 or SHA-256; both are kept, upper case."""
    out: dict[str, dict] = {"hash": {}, "package": {}, "cert": {}}
    for key, name in (("hash", "malware-hashes.yml"), ("package", "package-names.yml"),
                      ("cert", "cert-hashes.yml")):
        data = load_yaml(CACHE_DIR / f"androdr-{name}") or {}
        for entry in data.get("entries") or []:
            value = str(entry.get("indicator", "")).strip()
            if value:
                out[key][value if key == "package" else norm_hash(value)] = entry
    return out


def known_malware(name: str, pkg: dict, iocs: dict) -> dict | None:
    """First android-sigma-rules match for this package, as a finding."""
    files = pkg.get("files") or []
    hits = [("APK hash", iocs["hash"].get(norm_hash(f.get("sha256")))) for f in files]
    hits.append(("package name", iocs["package"].get(name)))
    for f in files:
        cert = f.get("certificate") or {}
        hits += [("signing certificate", iocs["cert"].get(norm_hash(cert.get(k)))) for k in ("Sha256", "Sha1")]
    for why, entry in hits:
        if not entry:
            continue
        sev = "amber" if str(entry.get("severity", "")).upper() == "MEDIUM" else "red"
        family = entry.get("family") or "unknown family"
        category = str(entry.get("category", "malware")).lower().replace("_", " ")
        return finding("known-malware", sev, name,
                       f"Matches {family} ({category}) by {why}. Source: {entry.get('source')}.",
                       package=name, matched_by=why, family=family, category=entry.get("category"),
                       ioc_source=entry.get("source"), ioc_description=entry.get("description"),
                       installer=pkg.get("installer"), origin=origin(pkg))
    return None


def load_known_signers() -> dict:
    data = load_yaml(KB_DIR / "known-signers.yaml")
    return {e["package"]: {"name": e.get("name", e["package"]),
                           "sha256": {norm_hash(h) for h in e.get("sha256", [])},
                           "source": e.get("source", "")}
            for e in data if e.get("package")}


def load_watched_apps() -> dict:
    """Popular apps that fakes copy. Only names, no signatures."""
    return {e["package"]: e["name"] for e in load_yaml(KB_DIR / "watched-apps.yaml")}


# ---------------------------------------------------------------- store lookups

class Stores:
    def __init__(self, case: Case):
        self.enabled = case.network
        self.country = case.state.get("country", "us")
        self.cache_file = case.path / "store-lookups.json"
        self.cache = read_json(self.cache_file) or {}
        from sta.kbupdate import load_signers
        self.signers = load_signers()  # {package: {"fdroid": [...], "izzy": [...]}}
        self.throttled = False

    def _get(self, url: str) -> tuple[int | None, bytes]:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 spyware-triage-agent"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and not self.throttled:
                self.throttled = True
                say("WARNING: the store asked us to slow down (HTTP 429). "
                    "Apps not looked up stay 'store lookup not done'; run ./sta check-apps again later.")
            return exc.code, b""
        except (urllib.error.URLError, TimeoutError):
            return None, b""
        finally:
            time.sleep(1)  # be polite; we may do dozens of lookups

    def on_play(self, package: str) -> bool | None:
        """True/False if Google Play has the app, None if unknown. Only a
        definite answer (200 or 404) is cached: a 429 or an outage today must
        not read as 'not in the store' tomorrow."""
        if not self.enabled:
            return None
        key = f"play:{package}"
        if self.cache.get(key) is None and not self.throttled:
            url = "https://play.google.com/store/apps/details?" + urllib.parse.urlencode(
                {"id": package, "hl": "en", "gl": self.country})
            status, _ = self._get(url)
            if status in (200, 404):
                self.cache[key] = status == 200
                write_json(self.cache_file, self.cache)
        return self.cache.get(key)

    def fdroid_signers(self, package: str) -> set:
        """Signing keys of this package in F-Droid and in IzzyOnDroid."""
        return {key for keys in self.signers.get(package, {}).values() for key in keys}

    def signer_repo(self, package: str, sha256: str | None) -> str | None:
        """'F-Droid' or 'IzzyOnDroid' when this key signs that repo's build."""
        for repo, label in (("fdroid", "F-Droid"), ("izzy", "IzzyOnDroid")):
            if sha256 and sha256 in self.signers.get(package, {}).get(repo, []):
                return label
        return None

    def signer_repos(self, package: str) -> list[str]:
        """The repos that build this package at all."""
        repos = self.signers.get(package, {})
        return [label for repo, label in (("fdroid", "F-Droid"), ("izzy", "IzzyOnDroid")) if repos.get(repo)]

    def app_store(self, bundle_id: str) -> dict | None:
        """iTunes lookup. Returns {} if not found, None if unknown."""
        if not self.enabled:
            return None
        key = f"appstore:{self.country}:{bundle_id}"
        if self.cache.get(key) is None and not self.throttled:
            url = "https://itunes.apple.com/lookup?" + urllib.parse.urlencode(
                {"bundleId": bundle_id, "country": self.country})
            status, body = self._get(url)
            if status == 200:
                try:
                    results = json.loads(body or b"{}").get("results", [])
                except ValueError:
                    return None
                self.cache[key] = ({"name": results[0].get("trackName"),
                                    "seller": results[0].get("sellerName")} if results else {})
                write_json(self.cache_file, self.cache)
        return self.cache.get(key)


# ---------------------------------------------------------------- Android

def read_acq_text(folder: Path, name: str) -> str:
    path = folder / name
    return path.read_text("utf-8", "replace") if path.exists() else ""


def parse_settings(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep:
            out[key] = value
    return out


def component_packages(value: str) -> list[str]:
    """'pkg/cls:pkg2/cls2' -> ['pkg', 'pkg2']"""
    pkgs = []
    for comp in (value or "").split(":"):
        pkg = comp.split("/")[0].strip()
        if pkg and pkg != "null" and pkg not in pkgs:
            pkgs.append(pkg)
    return pkgs


def device_admin_packages(policy_section: str) -> list[str]:
    """Packages holding a device admin, from the `device_policy` dumpsys section."""
    return sorted(set(re.findall(r"ComponentInfo\{([^/}]+)/", policy_section)))


DEVICE_OWNER_HEAD = re.compile(r"^\s+Device Owner:")  # AOSP prints a trailing space
DEVICE_OWNER_ADMIN = re.compile(r"^\s+admin=ComponentInfo\{([^/}]+)/")


def device_owner_package(policy_section: str) -> str | None:
    """The package that owns the whole phone, or None. AOSP prints

        Device Owner:
          admin=ComponentInfo{pkg/class}

    after 'Current Device Policy Manager state:'; a phone nobody manages has no
    such line at all (only `Device Owner Type: -1`), so nothing here is guesswork
    when the line is missing. 'Profile Owner' blocks are work profiles, not a
    device owner, and are left to the MANAGED_PROFILE flag of `dumpsys user`.
    This shape comes from AOSP's OwnersData.dump() and has not been seen on a
    managed phone yet (docs/format-notes.md section 7)."""
    lines = policy_section.splitlines()
    for number, line in enumerate(lines):
        if DEVICE_OWNER_HEAD.match(line):
            for after in lines[number + 1:number + 5]:
                if found := DEVICE_OWNER_ADMIN.match(after):
                    return found.group(1)
            return None
    return None


def main_cert(pkg: dict) -> dict:
    files = pkg.get("files") or []
    base = next((f for f in files if f.get("path", "").endswith("/base.apk")), None)
    return base or (files[0] if files else {})


def origin(pkg: dict) -> str:
    """play | store | sideload | adb | system"""
    installer = pkg.get("installer") or "null"
    if pkg.get("system"):
        return "system"
    if installer in PLAY_INSTALLERS:
        return "play"
    if installer in STORE_INSTALLERS:
        return "store"
    if installer == "null":
        return "adb"
    return "sideload"


def check_android(case: Case) -> list[dict]:
    folder = case.path / case.state["acquisition"]["path"]
    packages = json.loads(read_acq_text(folder, "packages.json") or "[]")
    secure = parse_settings(read_acq_text(folder, "settings_secure.txt"))
    sections = dumpsys_sections(read_acq_text(folder, "dumpsys.txt"))
    exempt = dumpsys_exempt(sections.get("deviceidle", ""))
    pkg_details = dumpsys_packages(sections["package"]) if "package" in sections else None
    if pkg_details is not None:
        # Parsed details per package (dates, permissions, disabled components)
        # plus who somebody exempted from battery saving: the timeline and the
        # follow-up diff read this file.
        write_json(case.path / "package-details.json", package_details_json(pkg_details, exempt))

    by_pkg, by_cert = load_ioc_lists()
    androdr = load_androdr_iocs()
    known = load_known_signers()
    watched = load_watched_apps()
    stores = Stores(case)
    findings: list[dict] = []
    flagged: set[str] = set()

    # Several users can share a package; check each package name once.
    seen: dict[str, dict] = {}
    for pkg in packages:
        if pkg.get("installed") is False:
            continue
        seen.setdefault(pkg["name"], pkg)

    say(f"Checking {len(seen)} installed packages...")
    for name, pkg in sorted(seen.items()):
        how = origin(pkg)
        installer = pkg.get("installer") or "null"
        cert_file = main_cert(pkg)
        cert = cert_file.get("certificate") or {}
        sha256 = norm_hash(cert.get("Sha256"))
        sha1 = norm_hash(cert.get("Sha1"))
        trusted = bool(cert_file.get("trusted_certificate"))
        ev = {"package": name, "installer": installer, "origin": how,
              "cert_sha256": sha256 or None, "trusted_certificate": trusted}

        if name in by_pkg or (sha1 and sha1 in by_cert):
            family, typ = by_pkg[name] if name in by_pkg else by_cert[sha1]
            why = "package name" if name in by_pkg else "signing certificate"
            flagged.add(name)
            if typ == "watchware":
                findings.append(finding("watchware", "amber", name,
                                        f"Matches monitoring app '{family}' by {why}.", **ev))
            else:
                findings.append(finding("stalkerware", "red", name,
                                        f"Matches stalkerware '{family}' by {why}.", **ev))
            continue

        bad = known_malware(name, pkg, androdr)
        if bad:
            flagged.add(name)
            findings.append(bad)
            continue

        if how == "system":
            continue

        if cert_file and not cert_file.get("verified_certificate", True) and cert_file.get("certificate_error"):
            findings.append(finding("apk-signature-invalid", "amber", name,
                                    f"APK signature did not verify: {cert_file['certificate_error']}", **ev))

        if name in known and sha256:
            if sha256 in known[name]["sha256"]:
                continue  # official build, signature confirmed
            sev = "amber" if how == "play" else "red"
            findings.append(finding("signer-mismatch", sev, name,
                                    f"Signed with a key that is not the official {known[name]['name']} key.",
                                    official_source=known[name]["source"], **ev))
            continue

        similar = impersonates(name, watched)
        if similar and how != "play" and not trusted:
            findings.append(finding("impersonation", "red" if how in ("sideload", "adb") else "amber", name,
                                    f"Package name looks like {watched[similar]} ({similar}) but is a different app.",
                                    looks_like=similar, **ev))
            continue

        if how in ("sideload", "adb") and not trusted:
            words = set(re.split(r"[._]", name.lower()))
            if len(words & SYSTEM_WORDS) >= 2:
                findings.append(finding("looks-like-system", "amber", name,
                                        "Name looks like a system component but it was installed by hand.", **ev))
            findings.append(sideload_finding(name, how, installer, sha256, stores, ev))

    findings += capability_findings(secure, sections.get("device_policy", ""), seen)
    findings += posture_findings(parse_getprop(read_acq_text(folder, "getprop.txt")),
                                 parse_settings(read_acq_text(folder, "settings_global.txt")),
                                 read_acq_text(folder, "selinux.txt").strip())
    policy_section = sections.get("device_policy", "")
    apk_findings, manifests, code_domains = scan_apks(
        case, folder, {name: origin(pkg) for name, pkg in seen.items()}, flagged,
        details=pkg_details,
        device_admins=device_admin_packages(policy_section),
        accessibility_enabled=component_packages(secure.get("enabled_accessibility_services", "")),
        battery_exempt=exempt)
    findings += apk_findings
    # A declared-but-not-enabled accessibility service gets its own info
    # finding (apkscan did that); one that is enabled is this very finding.
    declared_a11y = {name for name, m in manifests.items() if m.get("services_accessibility")}
    for f in findings:
        if f["kind"] == "accessibility-service" and f["subject"] in declared_a11y:
            f["evidence"]["declared"] = True
    holders = dumpsys_roles(sections.get("role", ""))
    findings += role_findings(holders, seen, stores, load_role_defaults())
    findings += account_findings(case, sections.get("account", ""))
    findings += user_findings(dumpsys_users(sections.get("user", "")),
                              device_owner_package(policy_section),
                              holders.get(POLICY_ROLE, ()), seen)
    outside = {name: [f.get("sha256") for f in pkg.get("files") or []]
               for name, pkg in seen.items()
               if origin(pkg) in ("sideload", "adb") and name not in flagged}
    findings += vt.check(case, outside)
    findings += abusech.check(case, outside, {name: code_domains[name] for name in outside if name in code_domains})
    # Being on the battery-saving whitelist means somebody wanted this app to
    # keep running all the time: an expert reading any finding about that
    # package wants to see it. The rule that acts on it is manifest's.
    # Tracker SDKs (Exodus) are context for whoever reads a finding about the app.
    scan = read_json(case.path / "apk-scan.json") or {}
    for f in findings:
        if f["subject"] in exempt:
            f["evidence"]["battery_exempt"] = True
        found = (scan.get(f["subject"]) or {}).get("trackers")
        if found is not None:
            f["evidence"]["trackers"] = found
    findings += os_findings(case)
    say(f"App checks done. Store lookups: {'on' if stores.enabled else 'off (offline case)'}.")
    return findings


def os_findings(case: Case) -> list[dict]:
    """Exploited holes the phone's patch level misses (Android), or an iOS behind
    its newest release. Uses what update-kb left in kb/cache; nothing goes out."""
    import datetime as dt

    from sta import osinfo

    device = case.state.get("device") or {}
    if case.platform == "android":
        return osinfo.android_findings(device, read_json(CACHE_DIR / "kev-android.json") or [])
    return osinfo.ios_findings(device, read_json(CACHE_DIR / "eol-ios.json") or [],
                               read_json(CACHE_DIR / "kev-ios.json") or [], dt.date.today())


def impersonates(name: str, watched: dict) -> str | None:
    if name in watched:
        return None
    for official in watched:
        if name.startswith(official + "."):
            return official
        if difflib.SequenceMatcher(None, name, official).ratio() >= 0.9:
            return official
    return None


def sideload_finding(name, how, installer, sha256, stores: Stores, ev) -> dict:
    via = "adb or an unknown method" if how == "adb" else f"'{installer}'"
    if not sha256:
        # No APK to read (for example Android's private space): nothing to compare.
        return finding("unreadable-package", "info", name,
                       f"Installed via {via}. androidqf could not read its files, so its signature is unknown.", **ev)
    if name.startswith("org.chromium.webapk.") and installer == "com.android.chrome":
        return finding("webapk", "info", name,
                       "A web app that Chrome installed (Add to Home screen). Not in a store by design.", **ev)
    repo = stores.signer_repo(name, sha256)
    if repo:
        return finding("sideloaded-app", "info", name,
                       f"Installed via {via}. Signature matches the {repo} build.", fdroid_match=True,
                       signature_repo=repo, **ev)
    play = stores.on_play(name)
    repos = stores.signer_repos(name)
    found = (["Google Play"] if play is True else []) + repos
    if found:
        extra = f" Its signature differs from the {' and '.join(repos)} build." if repos else ""
        return finding("sideloaded-store-app", "amber", name,
                       f"Installed via {via}. The app exists in {' and '.join(found)}, "
                       f"but this copy did not come from there.{extra}", stores=found, **ev)
    if play is False:
        return finding("unknown-origin-app", "amber", name,
                       f"Installed via {via}. Not found in Google Play, F-Droid or IzzyOnDroid.", **ev)
    return finding("sideloaded-app", "amber", name,
                   f"Installed via {via}. Store lookup not done (offline or no answer).", **ev)


# ---------------------------------------------------------------- accounts and users

ACCOUNT_HMAC = "account-hmac.key"


def account_key() -> bytes:
    """The machine key that lets a later check of the same phone say 'one
    Google account was added'. A plain sha256(name) would not do: trying a list
    of known addresses reverses it, and the same person's cases on two machines
    would link up. With a random key only this machine can answer 'is this the
    same account', which is all the follow-up diff needs."""
    path = SECRETS_DIR / ACCOUNT_HMAC
    if not path.exists():
        # mkdir's mode only applies to the last folder; close the parents too.
        for folder in reversed([path.parent, *path.parent.parents]):
            if not folder.exists():
                folder.mkdir(mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(32))
    return path.read_bytes()


def account_review(by_type: dict, watched_types=()) -> list[dict]:
    """The one question we can ask about accounts without naming them. The owner
    checks them on the phone, not in the report: this is the only finding that
    works that way, and it is on purpose."""
    google = by_type.get(GOOGLE_ACCOUNT_TYPE, 0)
    watched = sorted(set(watched_types) & set(by_type))
    if not google and not watched:
        return []  # no Google account and nothing we watch: the counts ask nothing
    other = sum(count for kind, count in by_type.items() if kind != GOOGLE_ACCOUNT_TYPE)
    # Two Google accounts usually mean a second one somebody else added: Find My
    # Device, the location history or Family Link then follow that account.
    sev = "amber" if google >= 2 or watched else "info"
    detail = (f"The phone has {google} Google account(s) and {other} other account(s)."
              + (f" Of the types we watch, it has: {', '.join(watched)}." if watched else ""))
    return [finding("accounts-review", sev, "phone accounts", detail,
                    google_accounts=google, other_accounts=other,
                    types=dict(sorted(by_type.items())), watched_types=watched)]


def account_findings(case: Case, section: str) -> list[dict]:
    """The accounts of the phone, counted by type.

    `accounts.json` keeps {type: count} and, for Google accounts only, an HMAC
    of the name with this machine's key: enough for a follow-up check to count
    new accounts, useless to anyone who gets the file. Names never go any further."""
    found = dumpsys_accounts(section)
    if not found:
        return []
    by_type: dict[str, int] = {}
    for _, kind in found:
        by_type[kind] = by_type.get(kind, 0) + 1
    key = account_key()
    google = sorted(name for name, kind in found if kind == GOOGLE_ACCOUNT_TYPE)
    watched = load_watch_account_types()
    data = {"by_type": dict(sorted(by_type.items())),
            "google_accounts": [hmac.new(key, name.encode(), hashlib.sha256).hexdigest()
                                for name in google],
            "watched_types": sorted(kind for kind in by_type if kind in watched)}
    write_json(case.path / "accounts.json", data)
    return account_review(by_type, {kind for kind in by_type if kind in watched})


def load_watch_account_types() -> dict:
    """Account types that are a signal by themselves (kb/watch-account-types.yaml)."""
    return {str(entry["type"]): entry.get("explain", "")
            for entry in load_yaml(KB_DIR / "watch-account-types.yaml") if entry.get("type")}


# ---------------------------------------------------------------- roles

# Roles whose single holder can read messages, place or screen calls, listen.
ROLE_MEANING = {
    "android.app.role.SMS": "it reads and sends the owner's text messages",
    "android.app.role.DIALER": "it is the app that places the owner's calls",
    "android.app.role.ASSISTANT": "it is the assistant: it can read the screen and listens for its wake word",
    "android.app.role.CALL_SCREENING": "it screens every incoming call before the owner sees it",
    "android.app.role.CALL_REDIRECTION": "it can send calls to another number",
}
# The management role and the supervision role are handled apart: their normal
# holder is a known Google app, so they only ask a question, they do not accuse.
POLICY_ROLE = "android.app.role.DEVICE_POLICY_MANAGEMENT"
SUPERVISION_ROLE = "android.app.role.SYSTEM_SUPERVISION"
# Family Link / Google Business Services supervision client.
SUPERVISION_CLIENTS = {"com.google.android.gms.supervision"}


def load_role_defaults() -> dict:
    """{role: {packages}} from kb/role-defaults.yaml: the holders of each role
    that need no explanation (Google Messages holding SMS, Chrome holding the
    browser role...). The operator adds a package here when they vouch for it."""
    out = {}
    for entry in load_yaml(KB_DIR / "role-defaults.yaml"):
        if entry.get("role"):
            out.setdefault(entry["role"], set()).update(entry.get("packages") or [])
    return out


def role_findings(holders: dict, seen: dict, stores: Stores, defaults: dict) -> list[dict]:
    """Who holds the roles Android gives to one app at a time.

    `holders` is dumpsys_roles() ({role: [package]}). A holder missing from
    packages.json belongs to another user or androidqf dropped it: its origin
    is 'unknown', which is amber (needs explaining), never red."""
    out = []
    for role, held in sorted(holders.items()):
        special = role in (POLICY_ROLE, SUPERVISION_ROLE)
        meaning = ROLE_MEANING.get(role)
        if not meaning and not special:
            continue
        for name in sorted(held):
            how = origin(seen[name]) if name in seen else "unknown"
            # A preinstalled system holder of SMS or DIALER is the vendor's own
            # app; nobody but the owner can put anything in another role.
            if name in defaults.get(role, ()) or (how == "system" and not special):
                continue
            pkg = seen.get(name, {})
            cert_file = main_cert(pkg)
            sha256 = norm_hash((cert_file.get("certificate") or {}).get("Sha256"))
            repo = stores.signer_repo(name, sha256)
            fdroid_match = repo is not None
            trusted = bool(cert_file.get("trusted_certificate"))
            short = role.rsplit(".", 1)[-1].replace("_", " ")  # 'android.app.role.SMS' -> 'SMS'
            ev = {"package": name, "role": role, "origin": how,
                  "installer": pkg.get("installer") if pkg else None,
                  "cert_sha256": sha256 or None, "fdroid_match": fdroid_match}
            if role == SUPERVISION_ROLE:
                if name not in SUPERVISION_CLIENTS:
                    out.append(finding("role-holder", "amber", name,
                                       "It holds the phone's supervision role: it can set rules over this "
                                       f"phone and see what happens on it. Installed from: {how}.", **ev))
                    continue
                out.append(finding("supervision-active", "info", name,
                                   "Something supervises this phone: parental control or a school account "
                                   "can set rules over it and see where it is.", **ev))
            elif role == POLICY_ROLE:
                out.append(finding("role-holder", "amber", name,
                                   "It holds the phone's device-management role: it can push settings and "
                                   f"apps to this phone. Installed from: {how}.", **ev))
            elif how in ("sideload", "adb") and not (fdroid_match or trusted):
                out.append(finding("role-holder", "red", name,
                                   f"It holds the phone's {short} role: {meaning}. It was installed by hand "
                                   "and its signature does not match the F-Droid or IzzyOnDroid build of this "
                                   "app.", **ev))
            else:
                why = (f"its signature matches the {repo} build" if repo else
                       "it is signed with a trusted vendor key" if trusted else
                       f"it came from {how}" if how != "unknown" else
                       "androidqf did not list it as an installed package, so nobody knows where it came from")
                out.append(finding("role-holder", "amber", name,
                                   f"It holds the phone's {short} role: {meaning}. Worth a look because "
                                   f"{why}.", **ev))
    return out


# ---------------------------------------------------------------- users and owners

def user_findings(users: list[dict], owner: str | None, policy_holders=(), seen=None) -> list[dict]:
    """The user profiles of the phone and who owns it.

    `users` is dumpsys_users() ([{'id', 'flags'}]): ids and flags only, since a
    profile name the owner typed ('Work', 'Maria') is personal data and tells the
    check nothing."""
    seen = seen or {}
    out = []
    profiles = [user for user in users if "MANAGED_PROFILE" in user["flags"]]
    full = [user for user in users if "FULL" in user["flags"]]
    holders = sorted(set(policy_holders))
    # A work profile with an app holding the device-management role is a phone
    # somebody else actively manages: the owner should say who.
    if profiles:
        out.append(finding("work-profile", "amber" if holders else "info", "work profile",
                           f"The phone has {len(profiles)} managed (work) profile(s)"
                           + (f", with a device-management app holding its role: {', '.join(holders)}."
                              if holders else "."),
                           profiles=[user["id"] for user in profiles], managed_by=holders))
    if len(full) > 1:
        out.append(finding("multiple-users", "info", "phone users",
                           f"{len(full)} separate user profiles live on this phone, each with its own apps "
                           "and accounts.", users=[user["id"] for user in full]))
    if owner:
        pkg = seen.get(owner, {})
        out.append(finding("device-owner", "amber", owner,
                           "One app owns this whole phone: it decides the security rules and is hard to "
                           "remove. Companies and schools do this; so does anyone who sets up a phone for "
                           "somebody else.",
                           package=owner, origin=origin(pkg) if pkg else "unknown",
                           installer=pkg.get("installer") if pkg else None))
    return out


def capability_findings(secure: dict, policy_section: str, seen: dict) -> list[dict]:
    out = []
    holders = [
        ("accessibility-service", component_packages(secure.get("enabled_accessibility_services", ""))),
        ("notification-listener", component_packages(secure.get("enabled_notification_listeners", ""))),
        ("input-method", component_packages(secure.get("default_input_method", ""))),
        ("always-on-vpn", component_packages(secure.get("always_on_vpn_app", ""))),
        ("device-admin", device_admin_packages(policy_section)),
    ]
    for kind, pkgs in holders:
        for name in pkgs:
            pkg = seen.get(name, {})
            how = origin(pkg) if pkg else "unknown"
            trusted = bool(main_cert(pkg).get("trusted_certificate")) if pkg else False
            if how == "system" or trusted:
                continue
            sev = "red" if how in ("sideload", "adb") else "amber"
            out.append(finding(kind, sev, name, f"Holds this capability. Installed from: {how}.",
                               package=name, origin=how,
                               installer=pkg.get("installer") if pkg else None))
    return out


def parse_getprop(text: str) -> dict:
    """'[ro.boot.verifiedbootstate]: [green]' -> {'ro.boot.verifiedbootstate': 'green'}"""
    return dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", text, re.M))


def posture_findings(props: dict, glob: dict, selinux: str) -> list[dict]:
    """Signs that the operating system or the network path was changed.
    Same ideas as AndroDR's device_auditor rules, on the data androidqf
    already collects. Empty values mean androidqf did not get them: no finding."""
    out = []
    boot = props.get("ro.boot.verifiedbootstate", "")
    locked = props.get("ro.boot.flash.locked", "")
    if boot and boot != "green" or locked == "0":
        sev = "red" if boot == "red" else "amber"
        out.append(finding("boot-not-verified", sev, "operating system",
                           f"Verified boot state is '{boot or 'unknown'}'; bootloader locked: "
                           f"{ {'1': 'yes', '0': 'no'}.get(locked, 'unknown') }.",
                           verifiedbootstate=boot, flash_locked=locked,
                           vbmeta_device_state=props.get("ro.boot.vbmeta.device_state")))
    tags, build_type = props.get("ro.build.tags", ""), props.get("ro.build.type", "")
    if (tags and tags != "release-keys") or (build_type and build_type != "user") \
            or props.get("ro.debuggable") == "1":
        out.append(finding("debug-build", "amber", "operating system",
                           f"The system is a test build: tags '{tags}', type '{build_type}', "
                           f"debuggable '{props.get('ro.debuggable')}'.",
                           build_tags=tags, build_type=build_type, debuggable=props.get("ro.debuggable"),
                           fingerprint=props.get("ro.build.fingerprint")))
    if selinux and selinux.lower() != "enforcing":
        out.append(finding("selinux-not-enforcing", "amber", "operating system",
                           f"SELinux is '{selinux}', not 'Enforcing'.", selinux=selinux))
    proxy = glob.get("http_proxy") or glob.get("global_http_proxy_host")
    if proxy and proxy not in (":0", "null"):
        out.append(finding("global-proxy", "amber", proxy,
                           "All web traffic of the phone goes through this proxy.",
                           http_proxy=glob.get("http_proxy"),
                           global_http_proxy_host=glob.get("global_http_proxy_host"),
                           global_http_proxy_port=glob.get("global_http_proxy_port")))
    if glob.get("adb_wifi_enabled") == "1":
        out.append(finding("wifi-adb", "amber", "wireless debugging",
                           "Wireless debugging is on: a computer on the same network can control the phone."))
    if glob.get("private_dns_mode") == "hostname" and glob.get("private_dns_specifier"):
        out.append(finding("private-dns", "info", glob["private_dns_specifier"],
                           "Private DNS sends every name lookup to this server.",
                           private_dns_specifier=glob["private_dns_specifier"]))
    return out


# ---------------------------------------------------------------- iOS

def quick_dir(case: Case) -> Path:
    return case.acquisition_dir / "ios-quick"


def check_ios(case: Case) -> list[dict]:
    """iPhone findings from whatever the case has: MVT's backup results when a
    backup was analysed, otherwise the ios-quick files copied in a minute
    (apps, profiles, provisioning, crash logs). Where both exist the backup
    wins: it holds the payload types, which the live profile list lacks."""
    from sta import iosquick

    res = case.results_dir
    quick = quick_dir(case)
    findings: list[dict] = []
    by_pkg, _ = load_ioc_lists()
    stores = Stores(case)

    provisions = read_json(quick / "provision.json") or []
    apps_backup = read_json(res / "applications.json")
    apps_quick = read_json(quick / "apps.json")
    # The names the crash rules must recognise as 'an app of this phone'.
    bundle_ids = [a.get("softwareVersionBundleId") for a in apps_backup or [] if isinstance(a, dict)]
    bundle_ids += list(apps_quick or {})

    if apps_backup is not None:
        say(f"Checking {len(apps_backup)} iOS apps from the backup...")
        for app in apps_backup:
            bundle = app.get("softwareVersionBundleId")
            if not bundle:
                continue
            name = app.get("itemName") or app.get("name") or bundle
            source = app.get("sourceApp", "com.apple.AppStore")
            ev = {"bundle_id": bundle, "name": name, "source_app": source,
                  "artist": app.get("artistName")}
            if bundle in by_pkg:
                family, typ = by_pkg[bundle]
                findings.append(finding("watchware" if typ == "watchware" else "stalkerware",
                                        "amber" if typ == "watchware" else "red", bundle,
                                        f"Matches '{family}'.", **ev))
                continue
            if source == "com.apple.dmd":
                findings.append(finding("ios-mdm-app", "amber", bundle,
                                        f"'{name}' was installed by a device management (MDM) server.", **ev))
                continue
            if source not in IOS_STORE_SOURCES:
                continue  # MVT already raises an alert for these
            hit = stores.app_store(bundle)
            if hit == {}:
                findings.append(finding("ios-app-not-in-store", "info", bundle,
                                        f"'{name}' is not in the App Store for country "
                                        f"'{stores.country}' today. It may have been removed.", **ev))
    elif apps_quick:
        # No backup: the same ioc.yaml and watchware.yaml lists apply to the
        # bundle ids that `apps list` shows, plus the ios-quick-only rules.
        say(f"Checking {len(apps_quick)} iOS apps from ios-quick...")
        findings += iosquick.quick_app_findings(apps_quick, provisions, by_pkg)

    profiles_backup = read_json(res / "configuration_profiles.json")
    if profiles_backup is not None:
        profiles = iosquick.profiles_from_backup(profiles_backup)
    else:
        profiles = iosquick.profiles_from_quick(read_json(quick / "profiles.json") or {})
    findings += iosquick.profile_findings(profiles)

    if provisions:
        findings += iosquick.provision_findings(provisions)

    crashes = quick / "crashes"
    if crashes.exists():
        summary = iosquick.read_crashes(crashes)
        say(f"Reading {sum(len(v) for v in summary.values())} iOS crash log(s)...")
        write_json(quick / "crashes.json", iosquick.summary_for_json(summary))
        findings += iosquick.crash_findings(summary, bundle_ids=bundle_ids)

    diag = case.state.get("sysdiagnose", {})
    if diag.get("path"):
        from sta import sysdiag
        say("Checking shutdown.log in the sysdiagnose...")
        found, data = sysdiag.check(case.path / diag["path"])
        write_json(res / "shutdown-log.json", data)
        findings += found
        from sta import saf
        parsed = saf.analyse(case, case.path / diag["path"])
        if parsed:
            apps_list = read_json(quick_dir(case) / "apps.json")
            known = {f["subject"]: f for f in found if f["kind"] == "ios-suspicious-process-path"}
            for f in saf.findings(parsed, set(apps_list) if isinstance(apps_list, dict) else None):
                if f["subject"] in known:  # shutdown.log saw it too: one finding, two sources
                    known[f["subject"]]["evidence"]["source"] = "shutdown.log, saf ps_everywhere"
                else:
                    findings.append(f)
    elif diag.get("skipped"):
        findings.append(finding("sysdiagnose-skipped", "info", "sysdiagnose",
                                f"No sysdiagnose was taken: {diag['skipped']}"))

    findings += os_findings(case)
    # Store lookups belong to the backup path (they ask Apple per app name).
    if apps_backup is not None:
        say(f"App checks done. Store lookups: {'on' if stores.enabled else 'off (offline case)'}.")
    else:
        say("App checks done.")
    return findings


def check_apps(case: Case) -> None:
    partial = False
    if case.platform == "android":
        case.require("analyze")
        findings = check_android(case)
    elif case.platform == "ios":
        # ios-quick (a minute, no backup) is enough for a first pass: the field
        # flow ends in `report --partial` without ever taking a backup.
        if not (case.done("analyze") or case.done("ios-quick")):
            raise StepError("Neither 'ios-quick' nor 'analyze' is done. Run ./sta ios-quick for the "
                            "quick check, or ./sta next to take the full backup first.")
        findings = check_ios(case)
        partial = not case.done("analyze")
    else:
        raise StepError("Unknown platform. Run ./sta detect.")
    write_json(case.path / "app-findings.json", findings)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("red", "amber", "info")}
    case.mark("check-apps", counts=counts, **({"partial": True} if partial else {}))
    say(f"Findings from app checks: {counts}" + (" (partial: no backup was analysed)" if partial else ""))
