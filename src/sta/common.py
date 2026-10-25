"""Shared helpers: paths, case state, subprocess calls and output."""

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
KB_DIR = Path(os.environ.get("STA_KB", ROOT / "kb"))
CACHE_DIR = KB_DIR / "cache"
CASES_DIR = Path(os.environ.get("STA_CASES", ROOT / "cases"))
CURRENT_FILE = CASES_DIR / "CURRENT"
# Passwords live outside cases/: the agent may read cases/ and kb/, never .sta/.
SECRETS_DIR = Path(os.environ.get("STA_SECRETS", ROOT / ".sta" / "secrets"))

# Layout of the JSON files a case writes (findings.json, notes.json,
# state.json). Bump it when a field changes meaning, so a reader of an old
# case knows what it has in front of it.
SCHEMA_VERSION = 1

ANDROID_STEPS = ["detect", "update-kb", "acquire", "analyze", "check-apps",
                 "triage", "report", "review", "cleanup"]
IOS_STEPS = ["detect", "ios-quick", "update-kb", "ios-password", "acquire", "sysdiagnose", "decrypt",
             "analyze", "check-apps", "triage", "report", "review", "cleanup"]


class StepError(Exception):
    """A step failed in a way the operator can fix. The message says how."""


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def say(text: str = "") -> None:
    print(text, flush=True)


def fail(text: str, code: int = 2) -> None:
    print(f"ERROR: {text}", file=sys.stderr, flush=True)
    sys.exit(code)


CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]+")


def plain(text, limit: int = 300) -> str:
    """Text that came from the phone (app names, profile names, MVT messages),
    made safe to show to the agent: one line, no control or invisible
    characters, no « » (the agent is told that « » marks phone data), and short."""
    text = CONTROL.sub(" ", str(text)).replace("«", "\"").replace("»", "\"")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    # pipx tools, and tools in this venv (apkid), which may not be on PATH.
    for folder in (Path.home() / ".local" / "bin", Path(sys.executable).parent):
        for candidate in (folder / name, folder / f"{name}.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


# Windows locks a byte range, and a locked byte cannot be read by anyone else.
# Lock one far past the text, so the holder's name stays readable.
LOCK_OFFSET = 1 << 20


def try_lock(handle) -> bool:
    """Take an exclusive lock on an open file, without waiting. False when
    another process holds it. Closing the file (or the process ending) drops it."""
    if os.name == "nt":
        import msvcrt
        handle.seek(LOCK_OFFSET)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        finally:
            handle.seek(0)
        return True
    import fcntl
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


# A command never hangs forever on a bad cable or a stuck daemon. Quick
# commands (adb getprop, version checks) get a short limit; the long ones
# (backup, MVT, downloads) pass their own.
QUICK_TIMEOUT = 120
LONG_TIMEOUT = 3 * 3600


def run(cmd: list[str], *, check: bool = True, env: dict | None = None,
        cwd: Path | None = None, timeout: int | None = None,
        log: Path | None = None) -> subprocess.CompletedProcess:
    """Run a command. With `log`, stream output to that file instead of
    returning it, so long tool output never reaches the agent's context.
    Without `timeout`, logged (long) commands get LONG_TIMEOUT and the rest
    QUICK_TIMEOUT."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    if timeout is None:
        timeout = LONG_TIMEOUT if log else QUICK_TIMEOUT
    shown = " ".join(redact(cmd))
    try:
        if log:
            log.parent.mkdir(parents=True, exist_ok=True)
            with open(log, "a", encoding="utf-8") as handle:
                handle.write(f"\n### {now()} $ {shown}\n")
                handle.flush()
                proc = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT,
                                      env=full_env, cwd=cwd, timeout=timeout,
                                      stdin=subprocess.DEVNULL)
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=full_env,
                                  cwd=cwd, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        where = f" See {log}." if log else ""
        raise StepError(f"`{shown}` did not finish in {timeout // 60} minutes and was stopped.{where}\n"
                        "Check the cable and that the phone is unlocked, then run the same command again.")
    if check and proc.returncode != 0:
        detail = "" if log else (proc.stderr or proc.stdout or "").strip()[-800:]
        where = f" See {log}." if log else ""
        raise StepError(f"`{shown}` exited with {proc.returncode}.{where}\n{detail}")
    return proc


def redact(cmd: list[str]) -> list[str]:
    """Hide backup passwords from logs and error messages.
    pymobiledevice3 takes the password as the argument after on/off."""
    out = list(cmd)
    if "encryption" in out and len(out) >= 2 and out[-2] in ("on", "off"):
        out[-1] = "<redacted>"
    return out


def tail(path: Path, lines: int = 15) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)


def cached_fetch(case, cache_name: str, key: str, fetch: Callable[[], Any]) -> Any | None:
    """One external lookup, answered from `case.path / cache_name` when the case
    already asked it. Offline cases ask nothing and get None without calling
    `fetch`. A None answer means "unknown" (no answer today): it is not cached,
    so a later run asks again — same rule as the store lookups for HTTP 429.
    Waits 1 s before each real call; we may do dozens in a row."""
    if not case.network:
        return None
    path = case.path / cache_name
    cache = read_json(path) or {}
    if key in cache:
        return cache[key]
    time.sleep(1)
    try:
        answer = fetch()
    except (OSError, ValueError):
        # OSError covers urllib and timeouts; ValueError covers a bad JSON body.
        # A failed lookup must not look like an answer: run check-apps again later.
        return None
    if answer is None:
        return None
    cache[key] = answer
    write_json(path, cache)
    return answer


class Case:
    def __init__(self, path: Path):
        self.path = path
        self.state_file = path / "state.json"
        self.state: dict = read_json(self.state_file) or {}

    @classmethod
    def current(cls) -> "Case":
        # STA_CASE pins the case for one runner, so `./sta use` in another
        # terminal cannot switch it under the agent.
        case_id = os.environ.get("STA_CASE") or (CURRENT_FILE.read_text(encoding="utf-8").strip()
                                                    if CURRENT_FILE.exists() else "")
        if not case_id:
            raise StepError("No open case. The operator opens one in a terminal with ./sta new-case.")
        # ":" too: on Windows "C:" is a drive, and the path would leave cases/.
        if any(c in case_id for c in "/\\:") or case_id.startswith("."):
            raise StepError(f"Bad case name {case_id!r}.")
        path = CASES_DIR / case_id
        if not (path / "state.json").exists():
            raise StepError(f"Case folder {path} has no state.json. Run ./sta new-case again.")
        return cls(path)

    def save(self) -> None:
        write_json(self.state_file, self.state)

    def lock(self, command: str) -> None:
        """One command that changes the case at a time. Two at once (an agent
        and the operator, or two terminals) would each write state.json from
        an old copy. The lock goes away when the process ends."""
        handle = open(self.path / ".lock", "a+", encoding="utf-8")
        if not try_lock(handle):
            handle.seek(0)
            raise StepError(f"Another ./sta command is running on this case ({handle.read().strip() or 'unknown'}). "
                            "Wait until it ends, then run ./sta next.")
        handle.truncate(0)
        handle.write(f"{command}, pid {os.getpid()}\n")
        handle.flush()
        self._lock = handle  # keep it open: closing the file drops the lock
        self.state = read_json(self.state_file) or {}  # what the last command wrote

    @property
    def platform(self) -> str | None:
        return self.state.get("platform")

    @property
    def steps(self) -> list[str]:
        if self.platform == "ios":
            return IOS_STEPS
        if self.platform == "android":
            return ANDROID_STEPS
        return ["detect"]

    def done(self, step: str) -> bool:
        return step in self.state.get("steps", {})

    def mark(self, step: str, **info) -> None:
        self.state.setdefault("steps", {})[step] = {"at": now(), **info}
        self.save()

    def unmark(self, step: str) -> None:
        self.state.get("steps", {}).pop(step, None)
        self.save()

    def require(self, *steps: str) -> None:
        missing = [s for s in steps if not self.done(s)]
        if missing:
            raise StepError(f"Step(s) {', '.join(missing)} not done yet. Run ./sta next.")

    @property
    def network(self) -> bool:
        return bool(self.state.get("network"))

    # Fixed folder layout inside a case.
    @property
    def acquisition_dir(self) -> Path:
        return self.path / "acquisition"

    @property
    def decrypted_dir(self) -> Path:
        return self.path / "decrypted"

    @property
    def results_dir(self) -> Path:
        return self.path / "mvt-results"

    @property
    def logs_dir(self) -> Path:
        return self.path / "logs"

    @property
    def secrets_dir(self) -> Path:
        """Outside the case folder, so a tool limited to cases/ cannot read it.
        Not kept by purge: the password is useless once the backup is gone."""
        return SECRETS_DIR / self.path.name
