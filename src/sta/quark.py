"""Quark-Engine on APKs that already look bad (optional, STA_QUARK=1).

Quark matches the code's API call sequences with rules ("crimes") such as
sending SMS or recording audio. It is slow and heavy, so it runs only when
asked, and only on APKs that already have a red or amber finding from the
manifest, YARA or the domain scan. Install it apart: pipx install quark-engine,
then `freshquark` to download its rules."""

import json
import os
import re
from pathlib import Path

from sta.common import StepError, run, say, which

TIMEOUT = 10 * 60  # per APK
# Behaviours that together make a spying app. Quark's crime texts vary, so
# each is a pattern over the crime description.
BEHAVIOURS = {
    "send SMS": re.compile(r"send.{0,20}sms|sms.{0,20}send", re.I),
    "read SMS": re.compile(r"(read|get|query).{0,30}sms", re.I),
    "get location": re.compile(r"location|gps|latitude", re.I),
    "record audio": re.compile(r"record.{0,20}(audio|sound|voice)|microphone", re.I),
    "hide icon": re.compile(r"hide.{0,20}icon|icon.{0,20}hid", re.I),
    "read contacts": re.compile(r"contact", re.I),
    "upload files": re.compile(r"upload|send.{0,20}file", re.I),
}
MIN_CONFIDENCE = 80
RAISE_AT = 3  # behaviours at 100 % confidence for app-behaviour


def enabled() -> bool:
    return os.environ.get("STA_QUARK") == "1"


def confidence(text) -> int:
    match = re.match(r"(\d+)", str(text or ""))
    return int(match.group(1)) if match else 0


def analyse(apk: Path, out: Path, log: Path) -> list[dict] | None:
    """Quark's crimes at MIN_CONFIDENCE or more, or None when it failed."""
    quark = which("quark")
    if not quark:
        return None
    try:
        run([quark, "-a", str(apk), "-s", "-o", str(out)], check=False, log=log, timeout=TIMEOUT)
    except StepError as exc:
        say(f"WARNING: Quark stopped on {apk.name}: {exc}")
        return None
    try:
        crimes = json.loads(out.read_text(encoding="utf-8")).get("crimes") or []
    except (OSError, ValueError, AttributeError):
        return None
    return [{"crime": c.get("crime"), "confidence": confidence(c.get("confidence"))}
            for c in crimes if isinstance(c, dict) and confidence(c.get("confidence")) >= MIN_CONFIDENCE]


def behaviours(crimes: list[dict]) -> list[str]:
    """The spying behaviours Quark is sure of (100 %)."""
    sure = [c["crime"] or "" for c in crimes if c["confidence"] >= 100]
    return sorted(name for name, pattern in BEHAVIOURS.items() if any(pattern.search(t) for t in sure))
