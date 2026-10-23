"""Check shutdown.log from an iPhone sysdiagnose.

iOS writes the processes that still run at each reboot to shutdown.log.
Kaspersky found that Pegasus, Reign and Predator leave two marks there
(securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734):

- processes that run from /private/var/db/ or /private/var/tmp/;
- reboots delayed 3 or more times by processes that do not stop.

This is the published method, written again here: Kaspersky's iShutdown
scripts carry no open-source license. The log only covers past reboots,
so it sees more when the owner restarts the phone often."""

import datetime as dt
import re
import tarfile
from pathlib import Path

SUSPICIOUS_PATHS = ("/private/var/db/", "/private/var/tmp/")
DELAY_LINE = "these clients are still here"
DELAY_THRESHOLD = 3
SIGTERM = re.compile(r"SIGTERM: \[(\d+)\]")
CLIENT = re.compile(r"remaining client pid: (\d+) \((.*)\)")


def read_shutdown_log(archive: Path) -> str | None:
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            if member.isfile() and member.name.endswith("shutdown.log"):
                handle = tar.extractfile(member)
                return handle.read().decode("utf-8", "replace") if handle else None
    return None


def iso(stamp: str) -> str:
    return dt.datetime.fromtimestamp(int(stamp), dt.UTC).isoformat(timespec="seconds")


def parse(text: str) -> dict:
    """One entry per reboot: when, how many delay notices, which clients."""
    reboots, delays, clients = [], 0, []
    for line in text.splitlines():
        if DELAY_LINE in line:
            delays += 1
        elif match := CLIENT.search(line):
            clients.append({"pid": match.group(1), "client": match.group(2)})
        elif match := SIGTERM.search(line):
            reboots.append({"at": iso(match.group(1)), "delays": delays, "clients": clients})
            delays, clients = 0, []
    return {"reboots": reboots}


def check(archive: Path) -> tuple[list[dict], dict]:
    from sta.checks import finding

    text = read_shutdown_log(archive)
    if text is None:
        return [finding("sysdiagnose-no-shutdown-log", "info", archive.name,
                        "The sysdiagnose has no shutdown.log, so the reboot checks did not run.")], {}
    data = parse(text)
    reboots = data["reboots"]
    findings = []

    paths: dict[str, list[str]] = {}
    for reboot in reboots:
        for item in reboot["clients"]:
            if item["client"].startswith(SUSPICIOUS_PATHS):
                paths.setdefault(item["client"], []).append(reboot["at"])
    for client, dates in sorted(paths.items()):
        findings.append(finding("ios-suspicious-process-path", "red", client,
                                f"A process ran from a folder that spyware uses, at {len(dates)} reboot(s).",
                                client=client, reboots=dates[:20], source="shutdown.log"))

    slow = [r for r in reboots if r["delays"] >= DELAY_THRESHOLD]
    if slow:
        findings.append(finding("ios-shutdown-delay", "amber", "shutdown.log",
                                f"{len(slow)} of {len(reboots)} reboots waited {DELAY_THRESHOLD} or more times "
                                "for processes that did not stop.",
                                reboots=[{"at": r["at"], "delays": r["delays"],
                                          "clients": sorted({c["client"] for c in r["clients"]})[:10]}
                                         for r in slow[:20]],
                                source="shutdown.log"))

    summary = {"reboots": len(reboots),
               "first": reboots[0]["at"] if reboots else None,
               "last": reboots[-1]["at"] if reboots else None}
    if len(reboots) < 2:
        findings.append(finding("sysdiagnose-few-reboots", "info", "shutdown.log",
                                f"shutdown.log holds {len(reboots)} reboot(s). The reboot checks see little.",
                                **summary))
    return findings, {**summary, "entries": data["reboots"]}
