"""The operator's short interview with the owner, and the install timeline.

The answers change how serious some findings are (somebody else had the
phone unlocked; nobody should be managing it), and `since` dates the install
timeline. They are sensitive: they live in .sta/secrets/<case>/, outside the
case folder the agent may read, and purge removes them. The report says only
whether the interview was done."""

import datetime as dt
import json
import os
import re

from sta.common import Case, now, read_json

CHOICES = ("yes", "no", "unsure")
QUESTIONS = [
    ("since", "Since when do you worry about the phone? (YYYY-MM or YYYY-MM-DD)", "date"),
    ("signs", "What made you worry? (free text, kept only on this computer)", "text"),
    ("physical_access", "Did anybody else have the phone unlocked in their hands?", "choice"),
    ("shared_account", "Do you share an Apple ID, a Google account or a family plan with anybody?", "choice"),
    ("second_hand", "Is the phone second-hand, or did somebody else set it up?", "choice"),
    ("managed", "Does an employer or a school manage this phone?", "choice"),
]

# With physical access, these amber findings become red: they are what
# somebody holding the phone installs or switches on.
ACCESS_KINDS = {"app-hidden", "stalkerware-code", "accessibility-service", "role-holder"}
# Somebody manages the phone. With managed == no nobody should: red.
MANAGED_KINDS = {"device-owner", "work-profile", "ios-mdm-profile", "ios-enterprise-app"}
WINDOW = dt.timedelta(days=14)
TIMELINE_ROWS = 20


def path(case: Case):
    return case.secrets_dir / "interview.json"


def load(case: Case) -> dict:
    return read_json(path(case)) or {}


def valid(kind: str, answer: str) -> bool:
    if not answer or kind == "text":
        return True
    if kind == "date":
        return bool(re.fullmatch(r"\d{4}-\d{2}(-\d{2})?", answer)) and since_range(answer) is not None
    return answer in CHOICES


def ask(read=input) -> dict:
    """Every question is optional: Enter skips it."""
    answers = {}
    for key, question, kind in QUESTIONS:
        hint = " [yes/no/unsure]" if kind == "choice" else ""
        while True:
            answer = read(f"{question}{hint} (Enter to skip): ").strip()
            if kind == "choice":
                answer = answer.lower()
            if valid(kind, answer):
                break
            print("Please answer in the format shown, or press Enter to skip.")
        if answer:
            answers[key] = answer
    return answers


def save(case: Case, answers: dict) -> None:
    folder = case.secrets_dir
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path(case), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(answers, handle, indent=2, ensure_ascii=False)
    # Only the fact, never the content: the agent reads state.json.
    case.state["interview"] = {"at": now(), "answered": len(answers)}
    case.save()


def since_range(since: str) -> tuple[dt.date, dt.date] | None:
    """The day, or the whole month, the owner named."""
    try:
        if len(since) == 7:
            first = dt.date.fromisoformat(since + "-01")
            last = (first.replace(day=28) + dt.timedelta(days=4)).replace(day=1) - dt.timedelta(days=1)
            return first, last
        day = dt.date.fromisoformat(since)
        return day, day
    except ValueError:
        return None


def note(finding: dict, text: str) -> None:
    finding["evidence"].setdefault("context", []).append(text)


def adjust(items: list[dict], answers: dict) -> None:
    """Raise or lower severities from the answers. The code decides, never the agent."""
    for f in items:
        kind, sev = f["kind"], f["severity"]
        if answers.get("physical_access") == "yes" and kind in ACCESS_KINDS and sev == "amber":
            f["severity"] = "red"
            note(f, "physical access")
        if answers.get("shared_account") == "yes" and kind == "accounts-review" and sev == "info":
            f["severity"] = "amber"
            note(f, "shared account")
        if answers.get("managed") == "no" and kind in MANAGED_KINDS and f["severity"] != "red":
            f["severity"] = "red"
            note(f, "the owner says nobody manages the phone")
        if answers.get("managed") == "yes" and kind in ("ios-mdm-profile", "work-profile"):
            f["severity"] = "info"
            note(f, "the owner says an employer or school manages the phone")


def installs(case: Case) -> list[dict]:
    """Non-system apps with their first install time, newest first (Android)."""
    from sta import checks

    details = read_json(case.path / "package-details.json") or {}
    acq = case.state.get("acquisition", {}).get("path")
    if not details or not acq:
        return []
    packages = json.loads(checks.read_acq_text(case.path / acq, "packages.json") or "[]")
    origins = {p["name"]: checks.origin(p) for p in packages if p.get("name")}
    rows = [{"package": name, "installed": info.get("first_install"), "origin": origins.get(name, "unknown")}
            for name, info in details.items()
            if info.get("first_install") and origins.get(name, "unknown") != "system"]
    return sorted(rows, key=lambda row: row["installed"], reverse=True)


def near_suspicion(case: Case, items: list[dict], answers: dict) -> list[dict]:
    """Apps installed within two weeks of when the owner started to worry."""
    from sta.checks import finding

    span = since_range(answers.get("since", ""))
    if not span:
        return []
    start, end = span[0] - WINDOW, span[1] + WINDOW
    by_subject: dict[str, list[dict]] = {}
    for f in items:
        by_subject.setdefault(f["subject"], []).append(f)
    out = []
    for row in installs(case):
        try:
            day = dt.date.fromisoformat(row["installed"][:10])
        except ValueError:
            continue
        if not start <= day <= end:
            continue
        others = by_subject.get(row["package"], [])
        if others:
            for f in others:
                f["evidence"]["installed_near_suspicion"] = True
                if f["kind"] in ACCESS_KINDS and f["severity"] == "amber":
                    f["severity"] = "red"
                    note(f, "installed around the time the owner started to worry")
            continue
        out.append(finding("installed-near-suspicion", "info", row["package"],
                           f"Installed on {row['installed'][:10]}, near the time the owner started to worry.",
                           package=row["package"], installed=row["installed"], origin=row["origin"]))
    return out
