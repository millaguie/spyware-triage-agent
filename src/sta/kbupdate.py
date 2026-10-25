"""Refresh indicators: MVT's STIX2 files, stalkerware/watchware lists and YARA
rules, android-sigma-rules indicators, F-Droid and IzzyOnDroid signers, and the
OS data of sta.osinfo (exploited vulnerabilities, newest releases)."""

import json
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

from sta import osinfo
from sta.common import CACHE_DIR, Case, StepError, now, read_json, run, say, sha256_file, try_lock, which, write_json

# Indicator lists change every week, so we take the newest commit, not a fixed
# one. What we record is which commit and which file hashes each case used:
# the report can then say exactly what produced a verdict.
STALKERWARE_REPO = ("AssoEchap/stalkerware-indicators", "master", "")
FDROID_INDEX = "https://f-droid.org/repo/index-v2.json"
# A second F-Droid repository with its own builds, same index format.
IZZY_INDEX = "https://apt.izzysoft.de/fdroid/repo/index-v2.json"
SIGNER_REPOS = (("fdroid", FDROID_INDEX, "F-Droid", "about 40 MB"),
                ("izzy", IZZY_INDEX, "IzzyOnDroid", "about 15 MB"))
# AndroDR's indicator data (CC-BY-4.0): APK hashes, package names, certificates.
ANDROID_SIGMA_REPO = ("android-sigma-rules/rules", "main", "ioc-data/")
ANDROID_SIGMA_FILES = ("malware-hashes.yml", "package-names.yml", "cert-hashes.yml")
SOURCES_FILE = CACHE_DIR / "SOURCES.json"


def github_commit(repo: str, branch: str) -> str:
    """The commit the branch points to now, or the branch name if GitHub does not answer."""
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/commits/{branch}",
                                 headers={"Accept": "application/vnd.github.sha", "User-Agent": "spyware-triage-agent"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            sha = resp.read().decode().strip()
        return sha if len(sha) == 40 else branch
    except OSError:
        return branch


def raw_base(repo: str, branch: str, folder: str, sources: dict) -> str:
    ref = github_commit(repo, branch)
    sources[repo] = ref
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{folder}"


def indicator_hashes() -> dict[str, str]:
    """SHA-256 of every indicator file a check can use."""
    out = {}
    for path in sorted(CACHE_DIR.glob("*")):
        if path.is_file() and path.suffix in (".yaml", ".yml", ".yar", ".json") and path != SOURCES_FILE:
            out[path.name] = sha256_file(path)
    folder = mvt_indicator_dir()
    for path in sorted(folder.glob("*")) if folder.exists() else []:
        if path.suffix in (".stix2", ".json"):
            out[f"mvt/{path.name}"] = sha256_file(path)
    return out


def mvt_indicator_dir() -> Path:
    # Same rule as mvt/common/indicators.py: MVT_DATA_FOLDER, else
    # appdirs.user_data_dir("mvt"), which differs per system.
    if os.environ.get("MVT_DATA_FOLDER"):
        return Path(os.environ["MVT_DATA_FOLDER"]) / "indicators"
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "mvt" / "mvt"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "mvt"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "mvt"
    return base / "indicators"


def count_indicator_files() -> int:
    folder = mvt_indicator_dir()
    return len([p for p in folder.iterdir() if p.suffix in (".stix2", ".json")]) if folder.exists() else 0


def fetch(url: str, dest: Path, timeout: int = 60, tries: int = 3) -> None:
    """`timeout` is per socket read. F-Droid mirrors sometimes stall mid-download;
    a new try usually lands on another mirror."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "spyware-triage-agent"})
    for attempt in range(1, tries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            break
        except OSError:
            if attempt == tries:
                raise
            say(f"  download stalled, trying again ({attempt + 1}/{tries})...")
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)


def build_fdroid_signers(index_path: Path) -> dict:
    """Keep only {package: [signer sha256, ...]} from the large F-Droid index."""
    index = json.loads(index_path.read_text(encoding="utf-8"))
    signers: dict[str, set] = {}
    for name, pkg in index.get("packages", {}).items():
        for version in pkg.get("versions", {}).values():
            for digest in version.get("manifest", {}).get("signer", {}).get("sha256", []):
                signers.setdefault(name, set()).add(digest.upper())
    return {name: sorted(values) for name, values in signers.items()}


def update_kb(case: Case, skip_fdroid: bool = False) -> None:
    # kb/cache is shared by all cases. Without this lock, two update-kb runs
    # could mix files from two commits, and a case would record hashes of
    # files it did not use.
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(CACHE_DIR / ".lock", "a+", encoding="utf-8") as handle:
        if not try_lock(handle):
            raise StepError("Another case is updating the indicators now. Wait until it ends, then run ./sta next.")
        refresh(case, skip_fdroid)


def refresh(case: Case, skip_fdroid: bool) -> None:
    if not case.network:
        have = count_indicator_files()
        if have == 0 or not (CACHE_DIR / "ioc.yaml").exists():
            raise StepError("This case is offline and there are no cached indicators. "
                            "Run ./sta update-kb once on a case with network, or copy kb/cache/ "
                            f"and {mvt_indicator_dir()} from another machine.")
        say(f"Offline case: using {have} cached MVT indicator files and kb/cache/.")
        case.mark("update-kb", mvt_indicator_files=have, offline=True,
                  sources=read_json(SOURCES_FILE) or {}, indicators=indicator_hashes())
        return

    mvt = which("mvt")
    if not mvt:
        raise StepError("mvt is not installed. Run ./install.sh")
    say("Downloading MVT indicators (mvt download-iocs)...")
    run([mvt, "--disable-update-check", "download-iocs"], log=case.logs_dir / "update-kb.log")
    have = count_indicator_files()
    if have == 0:
        raise StepError(f"mvt download-iocs finished but {mvt_indicator_dir()} has no .stix2 files.")

    sources = read_json(SOURCES_FILE) or {}
    say("Downloading stalkerware and watchware lists...")
    base = raw_base(*STALKERWARE_REPO, sources)
    for name in ("ioc.yaml", "watchware.yaml"):
        fetch(base + name, CACHE_DIR / name)
    # YARA rules for stalkerware code inside APKs (used by check-apps).
    fetch(base + "rules.yar", CACHE_DIR / "stalkerware.yar")

    if case.platform == "android":
        say("Downloading Android malware indicators (android-sigma-rules)...")
        base = raw_base(*ANDROID_SIGMA_REPO, sources)
        for name in ANDROID_SIGMA_FILES:
            fetch(base + name, CACHE_DIR / f"androdr-{name}")

    fdroid = izzy = "skipped"
    if not skip_fdroid and case.platform == "android":
        fdroid, izzy = refresh_signers()
    os_data, unmapped = refresh_os_data(case.platform)
    exodus = "skipped"
    if case.platform == "android":
        exodus = refresh_trackers()

    write_json(SOURCES_FILE, sources)
    (CACHE_DIR / "UPDATED").write_text(now() + "\n", encoding="utf-8")
    case.mark("update-kb", mvt_indicator_files=have, fdroid=fdroid, izzy=izzy, os_data=os_data, kev_android_unmapped=unmapped, exodus=exodus,
              sources=sources, indicators=indicator_hashes())
    say(f"Done. MVT indicator files: {have}. F-Droid signers: {fdroid}. IzzyOnDroid signers: {izzy}. "
        f"OS data: {os_data}.")


def load_signers() -> dict[str, dict[str, list]]:
    """{package: {"fdroid": [sha256], "izzy": [sha256]}}. Files written before
    IzzyOnDroid held {package: [sha256]}, all from F-Droid."""
    data = read_json(CACHE_DIR / "fdroid-signers.json") or {}
    return {name: (value if isinstance(value, dict) else {"fdroid": value}) for name, value in data.items()}


def refresh_signers() -> tuple[str, str]:
    """Download each repository's index and keep only the signing keys. A repo
    that fails keeps its keys from the last good download."""
    merged = load_signers()
    status = {}
    for repo, url, label, size in SIGNER_REPOS:
        say(f"Downloading the {label} index to learn official signing keys ({size})...")
        raw = CACHE_DIR / f"{repo}-index-v2.json"
        try:
            fetch(url, raw)
            fresh = build_fdroid_signers(raw)
        except (OSError, ValueError) as exc:
            status[repo] = f"failed: {exc}"
            say(f"WARNING: {label} index not updated ({exc}). App checks use the last copy, if any.")
            continue
        finally:
            raw.unlink(missing_ok=True)
        for repos in merged.values():
            repos.pop(repo, None)
        for name, keys in fresh.items():
            merged.setdefault(name, {})[repo] = keys
        status[repo] = "ok"
    write_json(CACHE_DIR / "fdroid-signers.json",
               {name: repos for name, repos in sorted(merged.items()) if repos})
    return status["fdroid"], status["izzy"]


def refresh_trackers() -> str:
    """Exodus Privacy's tracker signatures, reduced to the dex prefixes."""
    from sta import trackers
    say("Downloading Exodus Privacy's tracker signatures...")
    tmp = CACHE_DIR / "exodus-download.tmp"
    try:
        fetch(trackers.TRACKERS_URL, tmp)
        write_json(CACHE_DIR / trackers.TRACKERS_NAME, trackers.reduce(json.loads(tmp.read_text(encoding="utf-8"))))
        return "ok"
    except (OSError, ValueError) as exc:
        say(f"WARNING: tracker signatures not updated ({exc}). The APK scan uses the last copy, if any.")
        return f"failed: {exc}"
    finally:
        tmp.unlink(missing_ok=True)


def refresh_os_data(platform: str | None) -> tuple[str, int]:
    """CISA KEV, plus OSV's Android bulletins or endoflife.date's iOS releases.
    Only small extracts stay in kb/cache; a failure keeps the last copy. The
    count is of Android KEV holes OSV gives no fix level for: not compared."""
    say("Downloading CISA's list of exploited vulnerabilities and OS release data...")
    tmp = CACHE_DIR / "os-download.tmp"
    try:
        fetch(osinfo.KEV_URL, tmp)
        kev = json.loads(tmp.read_text(encoding="utf-8"))
        if platform == "android":
            fetch(osinfo.OSV_ANDROID_URL, tmp, timeout=120)
            rows = osinfo.android_kev(kev, tmp.read_bytes())
            write_json(CACHE_DIR / "kev-android.json", rows)
            return "ok", osinfo.android_kev_total(kev) - len(rows)
        else:
            write_json(CACHE_DIR / "kev-ios.json", osinfo.ios_kev(kev))
            fetch(osinfo.EOL_URL.format("ios"), tmp)
            write_json(CACHE_DIR / "eol-ios.json", osinfo.eol_releases(json.loads(tmp.read_text(encoding="utf-8"))))
        return "ok", 0
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        say(f"WARNING: OS data not updated ({exc}). The OS check uses the last copy, if any.")
        return f"failed: {exc}", 0
    finally:
        tmp.unlink(missing_ok=True)
