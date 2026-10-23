"""Domain names written inside an app's code, and the ones MVT's indicators know.

Stalkerware reports to its own server, and that server's domain is often a
plain string in classes.dex. MVT's STIX files list the domains of known
spyware and stalkerware campaigns. Nothing here goes out: both sides are on
this computer.

A string in the code is not a connection: blockers and antivirus apps carry
whole lists of bad domains on purpose. So a match is amber, an app with many
matches is info, and only a match on an app that is already hidden or carries
stalkerware code is red (decided in apkscan)."""

import json
import re
import zipfile
from pathlib import Path

from sta.common import KB_DIR

MAX_ENTRY = 100 << 20  # same limit as the YARA scan
MAX_KEPT = 200  # domains kept per app in apk-scan.json, for the specialist
MANY = 5  # this many matched indicator domains look like a blocklist

TLDS = ("com|net|org|io|ru|cn|xyz|top|info|biz|co|me|app|dev|cc|tk|ml|ga|cf|pw|site|online|"
        "club|live|store|tech|space|website|fun|icu")
# On the raw dex bytes: strings there are UTF-8 (MUTF-8), and domains are ASCII.
DOMAIN = re.compile(rb"(?<![a-z0-9.-])((?:[a-z0-9-]{1,63}\.)+(?:" + TLDS.encode() + rb"))(?![a-z0-9-])")
STIX_DOMAIN = re.compile(r"domain-name:value\s*=\s*'([^']+)'")


def load_allowlist() -> list[str]:
    """kb/domain-allowlist.yaml: SDK, CDN and schema domains every app carries."""
    import yaml
    path = KB_DIR / "domain-allowlist.yaml"
    if not path.exists():
        return []
    return [str(d).lower().lstrip(".") for d in yaml.safe_load(path.read_text(encoding="utf-8")) or []]


def allowed(domain: str, allowlist: list[str]) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allowlist)


def dex_blobs(apk: Path):
    """The bytes of each classes*.dex in one APK. A broken APK yields nothing:
    it is not evidence by itself."""
    try:
        with zipfile.ZipFile(apk) as archive:
            for entry in archive.infolist():
                name = entry.filename
                if entry.file_size <= MAX_ENTRY and name.startswith("classes") and name.endswith(".dex"):
                    yield archive.read(entry)
    except (zipfile.BadZipFile, OSError):
        return


def dex_domains(apk: Path, allowlist: list[str]) -> list[str]:
    """Domain-looking strings in the classes*.dex of one APK, minus the allowlist."""
    found = {match.group(1).decode("ascii") for blob in dex_blobs(apk) for match in DOMAIN.finditer(blob.lower())}
    return sorted(d for d in found if not allowed(d, allowlist) and not d.startswith("-"))


def stix_domains(folder: Path) -> dict[str, tuple[str, str]]:
    """{domain: (stix file, indicator name)} from MVT's indicator folder."""
    out: dict[str, tuple[str, str]] = {}
    for path in sorted(folder.glob("*.stix2")) if folder.exists() else []:
        try:
            objects = json.loads(path.read_text(encoding="utf-8")).get("objects", [])
        except (OSError, ValueError):
            continue
        names = {o.get("id"): o.get("name", "") for o in objects if o.get("type") == "malware"}
        targets = {}
        for rel in objects:
            if rel.get("type") == "relationship" and rel.get("target_ref") in names:
                targets[rel.get("source_ref")] = names[rel["target_ref"]]
        for obj in objects:
            if obj.get("type") != "indicator":
                continue
            label = targets.get(obj.get("id")) or obj.get("name") or path.stem
            for domain in STIX_DOMAIN.findall(obj.get("pattern", "")):
                out.setdefault(domain.lower(), (path.name, label))
    return out


def match(domains: list[str], indicators: dict[str, tuple[str, str]]) -> list[dict]:
    """Exact or parent-domain matches: sub.evil.com matches evil.com."""
    hits = []
    for domain in domains:
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in indicators:
                stix, label = indicators[parent]
                hits.append({"domain": domain, "indicator": parent, "indicator_file": stix,
                             "indicator_name": label})
                break
    return hits
