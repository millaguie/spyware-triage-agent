"""Copy the data off the phone: androidqf for Android, an encrypted backup for iOS."""

import csv
import fcntl
import getpass
import hashlib
import io
import json
import os
import pty
import re
import secrets
import select
import signal
import struct
import sys
import termios
import time
import zipfile
from pathlib import Path

from sta.common import Case, StepError, now, read_json, run, say, sha256_file, tail, which

# ---------------------------------------------------------------- Android

def acquire_android(case: Case, sms_backup: bool) -> None:
    case.require("detect", "update-kb")
    androidqf = which("androidqf")
    if not androidqf:
        raise StepError("androidqf is not installed. Run ./install.sh")
    serial = case.state["device"]["serial"]
    base = case.acquisition_dir
    base.mkdir(parents=True, exist_ok=True)
    for folder in (base, Path(androidqf).resolve().parent):
        if (folder / "key.txt").exists():
            raise StepError(f"{folder}/key.txt exists. androidqf would encrypt the acquisition with it "
                            "and MVT could not read it. Move that file away and run again.")
    out = base / "androidqf"
    if out.exists():
        # A failed earlier try. Keep it, but androidqf must start in an empty folder.
        n = 1
        while (base / f"androidqf.failed-{n}").exists():
            n += 1
        out.rename(base / f"androidqf.failed-{n}")

    log = case.logs_dir / "androidqf.log"
    say("Running androidqf. This takes 5 to 30 minutes. Do not disconnect the phone.")
    if sms_backup:
        say("The phone shows a 'Full backup' screen soon. The user must tap 'Back up my data' "
            "and leave the password field empty.")

    if has_menus(androidqf):
        code = run_with_menus([androidqf, "-serial", serial, "-output", str(out)],
                              cwd=base, log=log, answers=menu_answers(sms_backup))
        if not (out / "packages.json").exists():
            raise StepError(f"androidqf did not finish (exit {code}). Last log lines:\n{tail(log)}")
        check = verify_androidqf_folder(out, log)
    else:
        # -remove-trusted only skips copies of APKs signed with a known vendor
        # key; nothing is deleted from the phone. -hash-files hashes files ON
        # the phone (slow, can stop the collector). The archive's hashes.csv,
        # which we check below, is written either way.
        cmd = [androidqf, "-serial", serial, "-output", str(base),
               "-backup", "sms" if sms_backup else "none",
               "-download", "all", "-remove-trusted", "yes",
               "-intrusion-logs", "no", "-hash-files", "no",
               "-browser-history", "no", "-magisk-modules", "no",
               "-non-interactive"]
        code = run(cmd, check=False, cwd=base, log=log).returncode
        zips = sorted(base.glob("*.zip"), key=lambda p: p.stat().st_mtime)
        if not zips:
            raise StepError(f"androidqf made no archive (exit {code}). Last log lines:\n{tail(log)}")
        check = verify_androidqf_archive(zips[-1])
        check["archive_sha256"] = sha256_file(zips[-1])
        extract_archive(zips[-1], out)

    case.state["acquisition"] = {"path": str(out.relative_to(case.path)),
                                 "androidqf_exit": code, **check}
    case.mark("acquire")
    say(f"Acquisition: {out}")
    say(f"Internal hashes: {check['hash_check']}")
    if check["incomplete_modules"]:
        say("WARNING: some androidqf modules are incomplete. The report lists them:")
        for item in check["incomplete_modules"]:
            say(f"  - {item['name']}: {item['status']} {item.get('error', '')}")


def has_menus(androidqf: str) -> bool:
    """androidqf up to 1.8.x asks its questions with arrow-key menus and has no
    flags for them. Newer builds add -non-interactive."""
    proc = run([androidqf, "-h"], check=False)
    return "-non-interactive" not in (proc.stdout or "") + (proc.stderr or "")


def menu_answers(sms_backup: bool) -> dict[str, int]:
    """Menu label -> how many times to press Down from the first item.
    Items in androidqf 1.8.3 (modules/backup.go, packages.go, intrusion_logs.go):
      Backup: Only SMS | Everything | No backup
      Download: All | Only non-system packages | Do not download any
      Remove (trusted APKs): Yes | No
      Intrusion Logs: Yes | No"""
    return {"Backup": 0 if sms_backup else 2, "Download": 0, "Remove": 0, "Intrusion Logs": 1}


ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def run_with_menus(cmd: list[str], *, cwd: Path, log: Path, answers: dict[str, int],
                   timeout: int = 3 * 3600) -> int:
    """Run androidqf in a pseudo-terminal and answer its menus.
    Its output goes to the log, never to the agent."""
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(cwd)
        os.execv(cmd[0], cmd)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
    answered: set[str] = set()
    recent = ""
    not_ready = 0
    deadline = time.monotonic() + timeout
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(f"\n### {now()} $ {' '.join(cmd)}\n")
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 5)
            if not ready:
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:  # EIO: androidqf exited
                break
            if not data:
                break
            text = data.decode("utf-8", "replace")
            handle.write(text)
            handle.flush()
            recent = ANSI.sub("", recent + text)[-4000:]
            if "Unable to get device state" in text:
                not_ready += 1
                if not_ready >= 36:  # about 3 minutes to tap "Allow" on the phone
                    os.kill(pid, signal.SIGTERM)
                    raise StepError("androidqf cannot reach the phone. Check that it is connected, "
                                    "unlocked and that USB debugging is allowed. Then run ./sta acquire again.")
            for label, downs in answers.items():
                if label not in answered and f"{label}: " in recent:
                    time.sleep(0.5)  # let the menu draw its items
                    for _ in range(downs):
                        os.write(fd, b"\x1b[B")
                        time.sleep(0.2)
                    os.write(fd, b"\r")
                    answered.add(label)
                    recent = ""
            if "to finish" in recent:  # final "Press Enter to finish"
                os.write(fd, b"\r")
                recent = ""
        else:
            os.kill(pid, signal.SIGTERM)
            raise StepError(f"androidqf ran for more than {timeout // 3600} hours. Stopped. See {log}.")
        handle.write(f"\n### menus answered: {sorted(answered)}\n")
    os.close(fd)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def verify_androidqf_folder(folder: Path, log: Path) -> dict:
    """Recompute hashes.csv. androidqf 1.8 has no module status file, so take
    failed modules from its log ("ERROR: failed to run module X: ...")."""
    incomplete = []
    for line in ANSI.sub("", log.read_text(encoding="utf-8", errors="replace")).splitlines():
        match = re.search(r"failed to run module (\S+): (.*)", line)
        if match:
            incomplete.append({"name": match.group(1), "status": "failed", "error": match.group(2).strip()})
    mismatches = []
    hashes = folder / "hashes.csv"
    if hashes.exists():
        with open(hashes, newline="") as handle:
            for row in csv.reader(handle):
                if len(row) != 2:
                    continue
                path = Path(row[0]) if Path(row[0]).is_absolute() else folder.parent / row[0]
                # androidqf hashes hashes.csv while it is still empty, and keeps
                # writing command.log after it hashes it.
                if path.parent == folder and path.name in ("hashes.csv", "command.log"):
                    continue
                if not path.exists() or sha256_file(path) != row[1].lower():
                    mismatches.append(path.name)
        hash_check = "ok" if not mismatches else f"MISMATCH in {len(mismatches)} files"
    else:
        hash_check = "no hashes.csv"
    meta = read_json(folder / "acquisition.json") or {}
    return {"androidqf_uuid": meta.get("uuid"), "androidqf_version": meta.get("androidqf_version"),
            "incomplete_modules": incomplete, "hash_check": hash_check, "hash_mismatches": mismatches}


def extract_archive(archive: Path, target: Path) -> None:
    """androidqf writes its files at the root of the zip, but MVT looks for
    them with patterns like "*/packages.json". Given a zip it finds nothing and
    reports zero alerts. Given a folder it lists "folder/packages.json", which
    matches. So MVT always gets a folder."""
    target.mkdir(parents=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(target)  # extractall drops absolute and ".." paths


def verify_androidqf_archive(archive: Path) -> dict:
    """Check acquisition.json module status and recompute hashes.csv."""
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        meta_name = next((n for n in names if n.endswith("acquisition.json")), None)
        meta = json.loads(zf.read(meta_name)) if meta_name else {}
        incomplete = [m for m in meta.get("module_results", []) if m.get("status") != "completed"]

        hash_name = next((n for n in names if n.endswith("hashes.csv")), None)
        mismatches = []
        if hash_name:
            rows = csv.reader(io.StringIO(zf.read(hash_name).decode()))
            for row in rows:
                if len(row) != 2:
                    continue
                entry, expected = row
                digest = hashlib.sha256()
                with zf.open(entry) as handle:
                    for chunk in iter(lambda: handle.read(1 << 20), b""):
                        digest.update(chunk)
                if digest.hexdigest() != expected.lower():
                    mismatches.append(entry)
            hash_check = "ok" if not mismatches else f"MISMATCH in {len(mismatches)} entries"
        else:
            hash_check = "no hashes.csv in archive"
    return {
        "androidqf_uuid": meta.get("uuid"),
        "incomplete_modules": [{"name": m.get("name"), "status": m.get("status"),
                                "error": m.get("error", "")} for m in incomplete],
        "hash_check": hash_check,
        "hash_mismatches": mismatches,
    }


# ---------------------------------------------------------------- iOS

def pmd() -> str:
    path = which("pymobiledevice3")
    if not path:
        raise StepError("pymobiledevice3 is not installed. Run ./install.sh")
    return path


def password_file(case: Case) -> Path:
    return case.secrets_dir / "ios-backup-password"


def forget_password(case: Case) -> None:
    """Remove the password and its folder. Called by cleanup and purge."""
    path = password_file(case)
    if path.exists():
        path.unlink()
    if path.parent.is_dir() and not any(path.parent.iterdir()):
        path.parent.rmdir()


def read_password(case: Case) -> str:
    path = password_file(case)
    if not path.exists():
        raise StepError("No backup password stored. Run ./sta ios-password first.")
    return path.read_text().strip()


def ios_password(case: Case) -> None:
    """Make sure the iPhone encrypts backups and that we know the password.
    If encryption is off we turn it on with a random password and turn it off
    again at cleanup. If it is already on, only the owner knows the password:
    they type it here, in a real terminal, so the agent never sees it."""
    case.require("detect")
    udid = case.state["device"]["udid"]
    state = run([pmd(), "backup2", "encryption", "--udid", udid], check=False).stdout.strip().lower()

    if state.endswith("off"):
        password = secrets.token_urlsafe(18)
        say("Backup encryption is off. Turning it on with a random password.")
        say("The iPhone may ask for its passcode. The user must type it on the phone.")
        run([pmd(), "backup2", "encryption", "--udid", udid, "on", password],
            log=case.logs_dir / "ios-backup.log")
        write_secret(password_file(case), password)
        case.state.setdefault("ios", {})["we_enabled_encryption"] = True
        case.mark("ios-password", source="generated")
        say("Done. The password is stored in .sta/secrets/ and removed at cleanup.")
        return

    if not state.endswith("on"):
        raise StepError(f"Could not read the backup encryption state (got '{state}'). "
                        "Unlock the iPhone and run ./sta detect, then try again.")

    if not sys.stdin.isatty():
        raise StepError(
            "Backup encryption is already ON. Only the phone owner knows that password.\n"
            "TELL THE USER: open a second terminal in this folder and run:\n"
            "    ./sta ios-password\n"
            "and type the backup password there. Do not type it in this chat.\n"
            "If the owner does not know it, STOP. Do not reset the phone settings: that destroys evidence.\n"
            "After the user has done it, run ./sta next.")
    password = getpass.getpass("iPhone backup password (input hidden): ")
    if not password:
        raise StepError("Empty password.")
    write_secret(password_file(case), password)
    case.state.setdefault("ios", {})["we_enabled_encryption"] = False
    case.mark("ios-password", source="owner")
    say("Password stored. Go back to the agent and continue.")


def write_secret(path: Path, value: str) -> None:
    # mkdir's mode only applies to the last folder; close the parents too.
    for folder in reversed([path.parent, *path.parent.parents]):
        if not folder.exists():
            folder.mkdir(mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value + "\n")


def acquire_ios(case: Case) -> None:
    case.require("detect", "update-kb", "ios-password")
    udid = case.state["device"]["udid"]
    case.acquisition_dir.mkdir(parents=True, exist_ok=True)
    log = case.logs_dir / "ios-backup.log"
    say("Making a full encrypted backup. This takes 10 to 60 minutes.")
    say("Keep the iPhone unlocked and connected. It may ask for its passcode.")
    run([pmd(), "backup2", "backup", "--udid", udid, "--full", str(case.acquisition_dir)],
        log=log)
    backup = case.acquisition_dir / udid
    if not (backup / "Manifest.db").exists():
        raise StepError(f"No Manifest.db in {backup}. The backup did not finish. Last log lines:\n{tail(log)}")
    case.state["acquisition"] = {"path": str(backup.relative_to(case.path)),
                                 "manifest_sha256": sha256_file(backup / "Manifest.db")}
    case.mark("acquire")
    say(f"Backup done: {backup}")


def sysdiagnose_ios(case: Case, skip: str | None) -> None:
    """Pull a sysdiagnose for its shutdown.log. Only the owner can start one,
    with a button press on the phone; pymobiledevice3 waits for it."""
    case.require("acquire")
    if skip:
        case.state["sysdiagnose"] = {"skipped": skip}
        case.mark("sysdiagnose", skipped=skip)
        say(f"Sysdiagnose skipped: {skip}")
        return
    udid = case.state["device"]["udid"]
    out = case.acquisition_dir / "sysdiagnose"
    out.mkdir(parents=True, exist_ok=True)
    log = case.logs_dir / "sysdiagnose.log"
    say("Waiting for the sysdiagnose. On the iPhone, press and release BOTH volume buttons and the")
    say("side button at the same time. The phone vibrates. Then wait: it takes up to 10 minutes.")
    proc = run([pmd(), "crash", "sysdiagnose", "--udid", udid, "--timeout", "1200", str(out)],
               check=False, log=log)
    archives = sorted(out.rglob("*.tar.gz"))
    if proc.returncode != 0 or not archives:
        raise StepError(
            f"No sysdiagnose arrived (exit {proc.returncode}). Last log lines:\n{tail(log)}\n"
            "Check the iPhone is unlocked and connected, then press the three buttons again and "
            "run ./sta sysdiagnose. If the owner cannot do it, run: "
            "./sta sysdiagnose --skip \"<reason>\"")
    archive = archives[-1]
    case.state["sysdiagnose"] = {"path": str(archive.relative_to(case.path)),
                                 "sha256": sha256_file(archive)}
    case.mark("sysdiagnose")
    say(f"Sysdiagnose saved: {archive}")


def decrypt_ios(case: Case) -> None:
    case.require("acquire")
    mvt_ios = which("mvt-ios")
    if not mvt_ios:
        raise StepError("mvt-ios is not installed. Run ./install.sh")
    backup = case.path / case.state["acquisition"]["path"]
    run([mvt_ios, "--disable-update-check", "--disable-indicator-update-check",
         "decrypt-backup", "-d", str(case.decrypted_dir), str(backup)],
        env={"MVT_IOS_BACKUP_PASSWORD": read_password(case)},
        log=case.logs_dir / "mvt-decrypt.log")
    if not (case.decrypted_dir / "Manifest.db").exists():
        raise StepError("Decryption produced no Manifest.db. Wrong password? "
                        f"See {case.logs_dir / 'mvt-decrypt.log'}")
    case.mark("decrypt")
    say(f"Decrypted backup: {case.decrypted_dir}")


# ---------------------------------------------------------------- iOS quick (no backup)

QUICK_LOG_TIMEOUT = 600  # `crash pull` can be hundreds of small files over USB


def quick_ios(case: Case) -> None:
    """Copy in a minute what the iPhone gives without a backup: app list,
    configuration profiles, provisioning profiles, crash logs. These are the
    iOS data our checks read fastest (crash logs are the base of the Pegasus
    and Triangulation indicators), and with them check-apps can already run a
    partial report while the hour-long backup is still on its way.

    Tolerant by design: a subcommand that fails is recorded and the rest
    continues; only all four failing means the phone does not answer."""
    case.require("detect")
    udid = case.state["device"]["udid"]
    out = case.acquisition_dir / "ios-quick"
    crashes = out / "crashes"
    crashes.mkdir(parents=True, exist_ok=True)
    log = case.logs_dir / "ios-quick.log"
    pmd3 = pmd()

    def grab(name: str, argv: list[str], dest: Path | None) -> bool:
        """One pymobiledevice3 command. With `dest`, stdout is captured to
        that JSON file (a logged run sends stdout to the log instead, so it
        cannot capture); crash pull writes its own files and only logs."""
        cmd = [pmd3, *argv, "--udid", udid]
        try:
            if dest:
                proc = run(cmd, check=False)
                text = proc.stdout or ""
                if proc.returncode != 0 or not text.strip():
                    detail = (proc.stderr or proc.stdout or "").strip()[-200:]
                    say(f"WARNING: {name} did not answer (exit {proc.returncode}). "
                        f"{detail.replace(udid, '<udid>')}")
                    return False
                try:
                    json.loads(text)  # a colored/plain-text answer is not data
                except ValueError:
                    say(f"WARNING: {name} returned no JSON: {text.strip()[-200:].replace(udid, '<udid>')}")
                    return False
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text, encoding="utf-8")
            else:
                proc = run(cmd, check=False, log=log, timeout=QUICK_LOG_TIMEOUT)
                if proc.returncode != 0:
                    say(f"WARNING: {name} exited {proc.returncode}. See {log}")
                    return False
        except StepError as exc:  # a timeout must not stop the other three
            say(f"WARNING: {name} failed: {exc}")
            return False
        return True

    say("Quick iPhone check: apps, profiles, provisioning profiles and crash logs.")
    say("Keep the iPhone unlocked and connected. This takes about a minute.")
    done = {"apps": grab("apps list", ["apps", "list", "-t", "Any"], out / "apps.json"),
            "profiles": grab("profile list", ["profile", "list"], out / "profiles.json"),
            "provision": grab("provision list", ["provision", "list"], out / "provision.json"),
            "crashes": grab("crash pull", ["crash", "pull", str(crashes)], None)}
    if not any(done.values()):
        raise StepError("The iPhone answered none of the four quick commands. Check the cable, unlock "
                        f"the phone and trust this computer, then run ./sta ios-quick again. See {log}")

    apps = read_json(out / "apps.json") or {}
    info = {"apps": len(apps),
            "profiles": len((read_json(out / "profiles.json") or {}).get("ProfileMetadata") or {}),
            "provision": len(read_json(out / "provision.json") or []),
            "crashes": len(list(crashes.rglob("*.ips")))}
    for name, ok in done.items():
        if not ok:
            info[name] = f"failed: {name} returned no answer"
    case.state["ios_quick"] = info
    case.mark("ios-quick")
    say(f"ios-quick done: apps {info['apps']}, profiles {info['profiles']}, "
        f"provisioning {info['provision']}, crash logs {info['crashes']}.")



# ---------------------------------------------------------------- cleanup

def usb_permission_gone(serial: str) -> bool:
    """True when this computer can no longer drive the phone over USB: adb
    lists it as 'unauthorized', or not at all."""
    from sta.device import adb_devices
    return dict(adb_devices()).get(serial) != "device"


def cleanup(case: Case, verify_only: bool = False) -> None:
    case.require("review")
    if verify_only and case.platform == "ios":
        raise StepError("--verify is for Android. Run ./sta cleanup.")
    if case.platform == "ios":
        if case.state.get("ios", {}).get("we_enabled_encryption"):
            udid = case.state["device"]["udid"]
            say("Turning backup encryption off again, as it was before the check.")
            say("The iPhone may ask for its passcode.")
            run([pmd(), "backup2", "encryption", "--udid", udid, "off", read_password(case)],
                log=case.logs_dir / "ios-backup.log")
        forget_password(case)
        say("TELL THE USER: on the iPhone you can remove this computer from trusted computers with "
            "Settings > General > Transfer or Reset iPhone > Reset > Reset Location & Privacy.")
    else:
        serial = case.state["device"]["serial"]
        if not verify_only:
            say("TELL THE USER: on the phone, open Settings > System > Developer options,")
            say("tap 'Revoke USB debugging authorizations', then turn Developer options off.")
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                say("When the user has done it, with the phone still connected and unlocked, run:")
                say("  ./sta cleanup --verify")
                return
            input("Press Enter when it is done, with the phone still connected and unlocked: ")
        if not usb_permission_gone(serial):
            raise StepError("This computer can still use USB debugging on the phone: the permission was not "
                            "revoked.\nTELL THE USER: open Developer options and tap 'Revoke USB debugging "
                            "authorizations'. Then run ./sta cleanup --verify.")
        say("Checked: this computer can no longer use USB debugging on the phone.")
    case.mark("cleanup")
    say("Cleanup done. The case folder still holds personal data. "
        "When the case is closed, run ./sta purge to delete everything except the report.")
