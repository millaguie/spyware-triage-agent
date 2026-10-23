"""Look inside the APKs that androidqf downloaded.

- Echap's YARA rules (kb/cache/stalkerware.yar) find stalkerware code, even
  when the package name was changed. They match dex and ELF files, so we
  scan the dex and native libraries inside each APK, not the APK itself.
- APKiD finds packers, protectors and code rebuilt with dexlib (smali or
  apktool), the usual way to make a fake copy of a real app. Only for apps
  from outside a store: its other labels (anti-VM, anti-debug, obfuscators)
  show up in many genuine apps, F-Droid's own client included.
- The manifest (sta.manifest) is read for every app from outside a store: a
  hidden icon, a system-like name or a boot-plus-SMS receiver shows what the
  app was built to do before running any of its code. Set STA_MANIFEST_ALL=1
  to read it for every non-system app."""

import json
import os
import zipfile
from pathlib import Path

from sta import domains as dom
from sta import kbupdate, manifest, quark, trackers
from sta.common import CACHE_DIR, KB_DIR, StepError, run, say, which

YARA_RULES = CACHE_DIR / "stalkerware.yar"
MAX_ENTRY = 100 << 20  # same limit as APKiD: skip larger zip entries
PACKER_LABELS = ("packer", "protector", "dropper")


def apk_files(folder: Path, packages: list[str]) -> dict[str, list[Path]]:
    """androidqf saves apks/<package>[_<split>][_<n>].apk. Package names can
    hold '_', so the longest matching name wins."""
    apks = folder / "apks"
    names = sorted(packages, key=len, reverse=True)
    out: dict[str, list[Path]] = {}
    for path in sorted(apks.rglob("*.apk")) if apks.exists() else []:
        rel = path.relative_to(apks).as_posix()
        for name in names:
            if rel == f"{name}.apk" or rel.startswith(f"{name}_"):
                out.setdefault(name, []).append(path)
                break
    return out


def load_yara():
    if not YARA_RULES.exists():
        say("WARNING: no stalkerware YARA rules in kb/cache. Run ./sta update-kb to get them.")
        return None
    try:
        import yara
    except ImportError:
        raise StepError("The yara module is missing (it comes with apkid). Run ./install.sh "
                        "or ./install.sh --docker.")
    return yara.compile(filepath=str(YARA_RULES))


def load_exceptions() -> dict:
    import yaml
    path = KB_DIR / "yara-exceptions.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def string_ids(match) -> set[str]:
    # yara-python 4.3+ gives StringMatch objects; the yara-python-dex build
    # that APKiD needs gives (offset, identifier, data) tuples.
    return {getattr(s, "identifier", None) or s[1] for s in match.strings}


def yara_hits(rules, apk: Path, exceptions: dict) -> tuple[list[str], list[str]]:
    """Rules that matched, and rules dropped by kb/yara-exceptions.yaml."""
    found: dict[str, set[str]] = {}
    try:
        with zipfile.ZipFile(apk) as archive:
            for entry in archive.infolist():
                if entry.file_size > MAX_ENTRY or not entry.filename.endswith((".dex", ".so")):
                    continue
                for match in rules.match(data=archive.read(entry), timeout=60):
                    found.setdefault(match.rule, set()).update(string_ids(match))
    except (zipfile.BadZipFile, OSError):
        pass  # a broken APK is not evidence by itself; androidqf reports it
    kept, dropped = [], []
    for rule, ids in sorted(found.items()):
        need = set((exceptions.get(rule) or {}).get("require", []))
        (dropped if need and not ids & need else kept).append(rule)
    return kept, dropped


def apkid_command() -> str:
    found = which("apkid")
    if not found:
        raise StepError("apkid is missing. Run ./install.sh or ./install.sh --docker.")
    return found


def apkid_labels(paths: list[Path], log: Path) -> dict[str, dict[str, set]]:
    """{apk path: {category: {labels}}}, nested entries (apk!classes.dex) folded in."""
    out: dict[str, dict[str, set]] = {}
    if not paths:
        return out
    # 60 s per APK inside apkid; the whole run gets a limit in step with that.
    proc = run([apkid_command(), "-j", "-t", "60", *map(str, paths)], check=False,
               timeout=max(600, 90 * len(paths)))
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(proc.stdout + proc.stderr, encoding="utf-8")
    # One JSON document per scanned APK, one per line.
    items = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            items += json.loads(line).get("files", [])
        except json.JSONDecodeError:
            raise StepError(f"apkid did not return JSON. See {log}.")
    for item in items:
        apk = item["filename"].split("!")[0]
        for category, labels in (item.get("matches") or {}).items():
            out.setdefault(apk, {}).setdefault(category, set()).update(labels)
    return out


def scan_apks(case, folder: Path, origins: dict[str, str], skip: set[str], *,
              details: dict | None = None, device_admins=(),
              accessibility_enabled=(), battery_exempt=()) -> tuple[list[dict], dict]:
    """`origins` maps package to play|store|sideload|adb|system. Packages in
    `skip` already have a stalkerware finding. `details` is the parsed dumpsys
    package section ({package: {granted, disabled_components, ...}}); None when
    the acquisition has no dumpsys.txt. `battery_exempt` is the packages somebody
    took out of battery saving (task 3.3). Returns the findings and the parsed
    manifests ({package: info}) so checks.py can cross-reference them."""
    from sta.checks import finding

    files = apk_files(folder, list(origins))
    targets = {name: paths for name, paths in files.items()
               if origins[name] != "system" and name not in skip}
    findings: list[dict] = []
    raw: dict[str, dict] = {}
    manifests: dict[str, dict] = {}
    flagged_here: set[str] = set()

    rules = load_yara()
    if rules:
        exceptions = load_exceptions()
        say(f"Scanning the code of {len(targets)} apps with the stalkerware YARA rules...")
        for name, paths in sorted(targets.items()):
            results = [yara_hits(rules, path, exceptions) for path in paths]
            hits = sorted({rule for kept, _ in results for rule in kept})
            dropped = sorted({rule for _, gone in results for rule in gone} - set(hits))
            if dropped:
                raw.setdefault(name, {})["yara_discarded"] = dropped
            if hits:
                flagged_here.add(name)
                raw.setdefault(name, {})["yara"] = hits
                findings.append(finding("stalkerware-code", "red", name,
                                        f"Code inside the app matches the stalkerware rule(s) {', '.join(hits)} "
                                        "(Echap YARA rules).",
                                        package=name, origin=origins[name], yara_rules=hits))

    outside = {name: paths for name, paths in targets.items() if origins[name] in ("sideload", "adb")}
    by_path = {str(path): name for name, paths in outside.items() for path in paths}
    say(f"Checking {len(by_path)} APKs from outside a store with APKiD...")
    labels: dict[str, dict[str, set]] = {}
    for path, cats in apkid_labels(sorted(map(Path, by_path)), case.logs_dir / "apkid.json").items():
        merged = labels.setdefault(by_path.get(path, path), {})
        for category, values in cats.items():
            merged.setdefault(category, set()).update(values)

    for name, cats in sorted(labels.items()):
        raw.setdefault(name, {})["apkid"] = {c: sorted(v) for c, v in cats.items()}
        packers = sorted({v for c in PACKER_LABELS for v in cats.get(c, ())})
        rebuilt = sorted(v for v in cats.get("compiler", ()) if v.startswith("dexlib"))
        ev = {"package": name, "origin": origins[name], "apkid": raw[name]["apkid"]}
        if packers:
            findings.append(finding("apk-packed", "amber", name,
                                    f"The app is packed or protected: {', '.join(packers)}.", **ev))
        if rebuilt:
            findings.append(finding("apk-rebuilt", "amber", name,
                                    f"The code was rebuilt with {', '.join(rebuilt)}, the tool used to "
                                    "modify an existing app.", **ev))

    # The manifest says what the app was built to do, before running any code.
    # Packages already flagged (by skip or by a YARA hit above) stay out: like
    # YARA, one finding asks the question.
    all_manifests = os.environ.get("STA_MANIFEST_ALL") == "1"
    wanted = {name: paths for name, paths in targets.items()
              if name not in flagged_here
              and (all_manifests or origins[name] in ("sideload", "adb"))}
    if wanted and not manifest.parser_available():
        # Say it loudly: an old image without the parser would otherwise just
        # report every app as unreadable.
        say("WARNING: pyaxmlparser is missing, so no APK manifest was read (hidden icons, boot + SMS, "
            "surveillance permissions). Run ./install.sh, or ./install.sh --docker to rebuild the image.")
        for name in wanted:
            raw.setdefault(name, {})["manifest"] = {"error": "pyaxmlparser is not installed"}
        wanted = {}
    if wanted:
        say(f"Reading the manifest of {len(wanted)} APK(s)...")
    hidden_ok = manifest.hidden_ok_packages()
    a11y_holders = set(accessibility_enabled)
    for name, paths in sorted(wanted.items()):
        tried = [manifest.inspect(path) for path in paths]
        info = next((m for m in tried if not m.get("error")),
                    {"error": "; ".join(sorted({m["error"] for m in tried if m.get("error")})) or "no APK file for this app"})
        raw.setdefault(name, {})["manifest"] = info
        if info.get("error"):
            continue
        manifests[name] = info
        pkg = (details or {}).get(name)
        out = manifest.manifest_findings(
            name, info, origins[name], granted=set(pkg["granted"]) if pkg else set(),
            disabled=set(pkg["disabled_components"]) if pkg else None,
            device_admins=device_admins, hidden_ok=hidden_ok,
            accessibility_enabled=name in a11y_holders, battery_exempt=name in battery_exempt)
        findings += out

    found_domains = domain_pass(targets, raw, findings, flagged_here)
    if quark.enabled():
        quark_pass(case, targets, raw, findings)
    (case.path / "apk-scan.json").write_text(json.dumps(raw, indent=2), encoding="utf-8")
    say(f"APK scan done: {len(findings)} finding(s).")
    return findings, manifests, found_domains


QUARK_KINDS = {"stalkerware-code", "app-hidden", "app-label-mimics-system", "app-boot-sms",
               "app-surveillance-permissions", "app-device-admin-declared", "ioc-domain-in-app"}


def quark_pass(case, targets: dict[str, list[Path]], raw: dict, findings: list[dict]) -> None:
    """Quark only on apps already red or amber from this scan."""
    from sta.checks import finding

    if not quark.which("quark"):
        say("STA_QUARK=1 but Quark is not installed (pipx install quark-engine, then freshquark).")
        return
    names = sorted({f["subject"] for f in findings
                    if f["kind"] in QUARK_KINDS and f["severity"] in ("red", "amber") and f["subject"] in targets})
    if names:
        say(f"Running Quark on {len(names)} app(s) (up to 10 minutes each)...")
    out_dir = case.results_dir / "quark"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        crimes = quark.analyse(targets[name][0], out_dir / f"{name}.json", case.logs_dir / "quark.log")
        if crimes is None:
            continue
        raw.setdefault(name, {})["quark"] = crimes
        seen = quark.behaviours(crimes)
        if len(seen) >= quark.RAISE_AT:
            findings.append(finding("app-behaviour", "amber", name,
                                    f"Quark found code that can {', '.join(seen)}.",
                                    package=name, behaviours=seen, quark_crimes=crimes[:30]))


def domain_pass(targets: dict[str, list[Path]], raw: dict, findings: list[dict],
                flagged: set[str]) -> dict[str, list[str]]:
    """Domains inside every non-system app's code, matched with MVT's STIX
    indicators. Stalkerware renamed to look like a store app is still in
    `targets`, so this is not limited to sideloaded apps. Returns
    {package: [domains]} for the abuse.ch lookup."""
    from sta.checks import finding

    indicators = dom.stix_domains(kbupdate.mvt_indicator_dir())
    allowlist = dom.load_allowlist()
    say(f"Looking for indicator domains and tracker SDKs in the code of {len(targets)} apps...")
    signatures = trackers.load()
    # Red only next to a finding that already says spyware or hiding.
    serious = flagged | {f["subject"] for f in findings if f["kind"] in ("stalkerware-code", "app-hidden")}
    out = {}
    for name, paths in sorted(targets.items()):
        if signatures:
            raw.setdefault(name, {})["trackers"] = trackers.find(paths, signatures)
        names = sorted({d for path in paths for d in dom.dex_domains(path, allowlist)})
        if not names:
            continue
        out[name] = names
        raw.setdefault(name, {})["domains"] = names[:dom.MAX_KEPT]
        hits = dom.match(names, indicators)
        if not hits:
            continue
        distinct = sorted({h["indicator"] for h in hits})
        if len(distinct) >= dom.MANY:
            findings.append(finding("ioc-domain-in-app", "info", name,
                                    f"The app's code holds {len(distinct)} domains that spyware indicators "
                                    "list: the app contains a list of known bad domains, as blockers and "
                                    "antivirus apps do.", package=name, matches=hits[:20]))
            continue
        first = hits[0]
        findings.append(finding("ioc-domain-in-app", "red" if name in serious else "amber", name,
                                f"The app's code contains the domain «{first['domain']}», listed in the "
                                f"indicator «{first['indicator_name']}» ({first['indicator_file']}).",
                                package=name, domain=first["domain"], indicator_file=first["indicator_file"],
                                indicator_name=first["indicator_name"], matches=hits))
    return out
