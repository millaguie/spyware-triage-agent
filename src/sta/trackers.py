"""Tracker SDKs inside an app, from Exodus Privacy's signatures.

Exodus publishes, for each tracker, the Java package prefixes of its code
(`code_signature`, like `com.google.firebase.analytics.`). In a dex file the
classes appear as descriptors (`Lcom/google/firebase/analytics/...;`), so the
prefixes are searched in that form. This is context for the specialist, not a
finding, and it changes no severity: an app without trackers is as likely a
privacy-minded F-Droid app as stalkerware."""

import json
from pathlib import Path

from sta.common import CACHE_DIR
from sta.domains import dex_blobs

TRACKERS_URL = "https://reports.exodus-privacy.eu.org/api/trackers"
TRACKERS_NAME = "exodus-trackers.json"


def reduce(api: dict) -> dict[str, list[str]]:
    """{tracker name: [dex descriptor prefixes]} from the Exodus API answer."""
    out = {}
    for item in (api.get("trackers") or {}).values():
        prefixes = [p.strip() for p in (item.get("code_signature") or "").split("|") if p.strip()]
        if item.get("name") and prefixes:
            out[item["name"]] = sorted({"L" + p.replace(".", "/") for p in prefixes})
    return out


def load() -> dict[str, list[str]]:
    try:
        return json.loads((CACHE_DIR / TRACKERS_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def find(paths: list[Path], signatures: dict[str, list[str]]) -> list[str]:
    """Trackers whose code is in any of these APKs."""
    found = set()
    for blob in (b for path in paths for b in dex_blobs(path)):
        for name, prefixes in signatures.items():
            if name not in found and any(p.encode() in blob for p in prefixes):
                found.add(name)
    return sorted(found)
