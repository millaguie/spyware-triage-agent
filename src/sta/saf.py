"""The full sysdiagnose, read by EC-DIGIT-CSIRC's Sysdiagnose Analysis
Framework (saf, EUPL-1.2, github.com/EC-DIGIT-CSIRC/sysdiagnose).

sta's own sysdiag.py reads only shutdown.log. saf parses the whole archive;
two of its analysers matter here:

- ps_everywhere: every process seen anywhere (ps, spindump, logs, shutdown.log),
  one JSON line each, with the path in `message`. A process running from
  /private/var/tmp, /private/var/db or /tmp is how Pegasus-era spyware showed.
- apps: bundle ids seen in the logs, the App Store history and the privacy
  database. An app seen there but missing from the phone's app list was there
  once, or hides.

saf is optional: without it the check keeps sysdiag.py's result. It runs in
mvt-results/saf/ with a 20-minute limit and logs to logs/saf.log."""

import json
import re
from pathlib import Path

from sta.common import Case, StepError, run, say, which

TIMEOUT = 20 * 60
SUSPICIOUS = ("/private/var/tmp/", "/private/var/db/", "/tmp/")
BUNDLE_ID = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+){2,}$")
# Where an app was seen, apart from the logs: these come from real installs.
STRONG_SOURCES = {"itunesstore", "accessibility-tcc", "brctl"}


def available() -> str | None:
    return which("saf")


def analyse(case: Case, archive: Path) -> Path | None:
    """parse all + the two analysers. Returns the parsed_data folder, or None
    when saf is missing or failed (the check goes on without it)."""
    saf = available()
    if not saf:
        say("saf (sysdiagnose analysis framework) is not installed: only shutdown.log is checked. "
            "./install.sh installs it.")
        return None
    root = case.results_dir / "saf"
    root.mkdir(parents=True, exist_ok=True)
    env = {"SYSDIAGNOSE_CASES_PATH": str(root)}
    log = case.logs_dir / "saf.log"
    say("Reading the whole sysdiagnose with saf (up to 20 minutes)...")
    try:
        for args in (["-c", "sta", "create", "--force", str(archive)], ["-c", "sta", "parse", "all"],
                     ["-c", "sta", "analyse", "ps_everywhere"], ["-c", "sta", "analyse", "apps"]):
            proc = run([saf, *args], check=False, log=log, timeout=TIMEOUT, env=env)
            if proc.returncode != 0 and args[2] != "parse":  # one failing parser must not stop the rest
                say(f"WARNING: saf {' '.join(args[2:3])} failed. See {log}.")
                return None
    except StepError as exc:
        say(f"WARNING: saf stopped: {exc}")
        return None
    return root / "sta" / "parsed_data"


def read_jsonl(path: Path) -> list[dict]:
    out = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                out.append(item)
    return out


def findings(parsed: Path, listed_apps: set[str] | None) -> list[dict]:
    """`listed_apps`: bundle ids of the phone's app list (ios-quick), or None
    when there is none to compare with."""
    from sta.checks import finding
    from sta.common import plain

    out = []
    seen: dict[str, list[str]] = {}
    for item in read_jsonl(parsed / "ps_everywhere.jsonl"):
        path = str(item.get("message") or "")
        if path.startswith(SUSPICIOUS):
            seen.setdefault(path, []).append(str(item.get("datetime") or ""))
    for path, dates in sorted(seen.items()):
        out.append(finding("ios-suspicious-process-path", "red", plain(path, 120),
                           f"A process ran from a folder that spyware uses (seen {len(dates)} time(s) "
                           "in the sysdiagnose).",
                           path=plain(path, 200), seen=sorted(dates)[:20], source="saf ps_everywhere"))

    if listed_apps is not None:
        try:
            apps = json.loads((parsed / "apps.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            apps = {}
        for bundle_id, info in sorted(apps.items() if isinstance(apps, dict) else []):
            sources = set((info or {}).get("found") or [])
            if (not BUNDLE_ID.match(bundle_id) or bundle_id.startswith("com.apple.")
                    or bundle_id in listed_apps or not sources & STRONG_SOURCES):
                continue
            granted = "accessibility-tcc" in sources
            out.append(finding("ios-app-not-listed", "amber" if granted else "info", plain(bundle_id, 120),
                               "The sysdiagnose shows this app, but it is not in the phone's app list"
                               + (" — and it was granted a privacy permission." if granted else
                                  ": it was removed, or it hides."),
                               bundle_id=plain(bundle_id, 120), seen_in=sorted(sources),
                               services=(info or {}).get("services")))
    return out
