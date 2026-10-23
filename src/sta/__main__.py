"""sta: guided phone check with MVT. Run `./sta next` to know what to do."""

import argparse
import datetime as dt
import os
import re
import shutil
import sys

from sta.common import CASES_DIR, CURRENT_FILE, SCHEMA_VERSION, Case, StepError, fail, now, run, say, which

# What the agent tells the person, and the command it runs, for each step.
GUIDE = {
    "detect": ("Connect the phone with a USB cable and unlock it.\n"
               "  Android: USB debugging must be on (./sta detect explains how if it is not).\n"
               "  iPhone: tap 'Trust' and type the passcode when the phone asks.",
               "./sta detect"),
    "ios-quick": ("Keep the iPhone unlocked and connected. This takes about a minute.\n"
                  "  It copies the app list, profiles, provisioning profiles and crash logs —\n"
                  "  no backup is needed. With them ./sta report --partial can already give a first result.",
                  "./sta ios-quick"),
    "update-kb": ("Nothing to do on the phone. This downloads the latest indicators.",
                  "./sta update-kb"),
    "ios-password": ("Keep the iPhone unlocked. It may ask for its passcode.",
                     "./sta ios-password"),
    "acquire": ("Keep the phone unlocked, on the table and connected. Do not use it until this ends.\n"
                "  Android: a 'Full backup' screen appears. Tap 'Back up my data', leave the password empty.\n"
                "  iPhone: it may ask for the passcode. This can take up to an hour.",
                "./sta acquire"),
    "sysdiagnose": ("Keep the iPhone unlocked and connected. When the command starts, press and release\n"
                    "  both volume buttons and the side button at the same time. The phone vibrates.\n"
                    "  It takes up to 10 minutes.",
                    "./sta sysdiagnose"),
    "decrypt": ("Nothing to do on the phone. You can disconnect it now.",
                "./sta decrypt"),
    "analyze": ("Nothing to do on the phone. You can disconnect it now.",
                "./sta analyze"),
    "check-apps": ("Nothing to do. This checks the installed apps.",
                   "./sta check-apps"),
    "triage": ("Nothing to do.", "./sta triage"),
    "report": ("Nothing to do.", "./sta report"),
    "review": ("Now we go through the findings that need the owner's explanation.",
               "./sta review"),
    "cleanup": ("Reconnect the iPhone if it is disconnected, and unlock it.",
                "./sta cleanup"),
    # Android cleanup only prints what to do on the phone: no cable needed.
    "cleanup-android": ("Nothing to connect. This shows how to remove the USB debugging permission.",
                        "./sta cleanup"),
}


def cmd_next(case: Case) -> None:
    pending = [s for s in case.steps if not case.done(s)]
    say(f"CASE: {case.state['case_id']}   PLATFORM: {case.platform or 'not detected yet'}")
    say(f"DONE: {', '.join(s for s in case.steps if case.done(s)) or 'nothing yet'}")
    if not pending:
        say("ALL STEPS DONE.")
        say(f"REPORT: {case.path / 'report.md'}")
        say("Tell the user where the report is and give the one-line result from its 'Result' section.")
        return
    step = pending[0]
    if "interview" not in case.state and not case.done("triage"):
        say("OPTIONAL: the operator can ask the owner a few questions first. It cannot be run by the agent.")
        say("  TELL THE USER: if you want, run ./sta interview in your own terminal, then come back.")
    tell, command = GUIDE.get(f"{step}-{case.platform}") or GUIDE[step]
    say(f"NEXT STEP: {step}")
    say(f"TELL THE USER:\n  {tell}")
    say(f"THEN RUN:\n  {command}")
    if step == "review":
        say("Then follow what ./sta review prints.")
    if (step == "acquire" and case.platform == "ios" and case.done("ios-quick")
            and case.state.get("ios_acquire_fails", 0) >= 2):
        say("The backup failed twice. If it will not work, an escape route:")
        say("  ./sta check-apps && ./sta triage && ./sta report --partial")
        say("That gives a PARTIAL report from the quick iPhone check (no MVT).")


def cmd_interview(case: Case) -> None:
    """The owner's answers stay on this computer, outside the folder the agent
    reads: the agent must neither see nor invent them."""
    from sta import interview
    operator_terminal("interview the owner")
    say("A few optional questions. Press Enter to skip any of them.")
    say("The answers stay on this computer and never appear in the report.")
    answers = interview.ask()
    interview.save(case, answers)
    say(f"Saved {len(answers)} answer(s). Go back to the agent and continue.")


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:30] or "case"


def operator_terminal(action: str) -> None:
    """Consent and purge are the operator's decisions, not the agent's. The
    agent's tools have no terminal, so these commands refuse to run without one.
    This stops an agent that follows its rules badly or a prompt injection that
    calls ./sta. It is not a wall against an agent with a free shell, which
    can fake a terminal: that is why the planned MCP mode has no shell at all."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise StepError(f"Only the operator can {action}, in a terminal.\n"
                        "TELL THE USER: open a terminal in this folder and run the command there.\n"
                        "After that, run ./sta next.")


def ask_yes_no(question: str, given: str | None) -> bool:
    if given:
        return given == "yes"
    while True:
        answer = input(f"{question} [yes/no]: ").strip().lower()
        if answer in ("yes", "no"):
            return answer == "yes"


def cmd_new_case(args) -> None:
    operator_terminal("open a case and record the owner's consent")
    say("The check copies data from the phone to this computer: the app list, settings, logs,")
    say("and on Android the SMS messages, on iPhone a full backup. The data stays on this computer.")
    if not ask_yes_no("Does the phone owner agree to this check?", args.consent):
        fail("No consent: no check. Nothing was saved.")
    network = ask_yes_no("May the check use the internet? It downloads indicator lists, and sends the "
                         "names of the installed apps and the store country to Google Play, Apple and "
                         "F-Droid to look them up.", args.network)
    virustotal = False
    if network and (os.environ.get("MVT_VT_API_KEY") or os.environ.get("VT_API_KEY")):
        virustotal = ask_yes_no("May the check send the fingerprints (SHA-256) of apps from outside a store "
                                "to VirusTotal? VirusTotal keeps them, linked to your API key.", args.virustotal)
    abusech = False
    if network and os.environ.get("STA_ABUSECH_API_KEY"):
        abusech = ask_yes_no("May the check send the SHA-256 of apps from outside a store, and the domain "
                             "names found inside those apps, to abuse.ch (MalwareBazaar and ThreatFox)? "
                             "abuse.ch logs the lookups.", args.abusech)
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    base = f"{dt.date.today().isoformat()}-{slug(args.alias)}"
    case_id, n = base, 2
    while (CASES_DIR / case_id).exists():
        case_id, n = f"{base}-{n}", n + 1
    path = CASES_DIR / case_id
    path.mkdir(mode=0o700)
    case = Case(path)
    case.state = {"schema": SCHEMA_VERSION, "case_id": case_id, "alias": args.alias, "created": now(),
                  "consent": {"given": True, "at": now(), "by": "operator terminal"},
                  "network": network, "virustotal": virustotal, "abusech": abusech, "country": args.country.lower(),
                  "platform": None, "steps": {}}
    case.save()
    CURRENT_FILE.write_text(case_id + "\n")
    say(f"Case {case_id} created in {path}.")
    say(f"Internet lookups: {'yes' if network else 'no'}. VirusTotal: {'yes' if virustotal else 'no'}. "
        f"abuse.ch: {'yes' if abusech else 'no'}.")
    say("Go back to the agent and continue.")


def cmd_use(case_id: str) -> None:
    if not (CASES_DIR / case_id / "state.json").exists():
        fail(f"No case {case_id}. Run ./sta cases.")
    CURRENT_FILE.write_text(case_id + "\n")
    say(f"Current case: {case_id}")


def cmd_cases() -> None:
    current = CURRENT_FILE.read_text().strip() if CURRENT_FILE.exists() else ""
    for path in sorted(CASES_DIR.glob("*/state.json")):
        mark = "*" if path.parent.name == current else " "
        say(f"{mark} {path.parent.name}")


def cmd_doctor() -> None:
    checks = [("mvt", "pipx install mvt"), ("mvt-android", "pipx install mvt"),
              ("mvt-ios", "pipx install mvt"), ("androidqf", "./install.sh"),
              ("adb", "android-tools / platform-tools"),
              ("pymobiledevice3", "pipx install pymobiledevice3"),
              ("apkid", "./install.sh")]
    ok = True
    for tool, hint in checks:
        path = which(tool)
        say(f"  {'OK ' if path else 'MISSING'}  {tool:16} {path or '-> ' + hint}")
        ok = ok and bool(path)
    # The manifest parser runs as `python -m sta.manifest` with this same
    # interpreter, so check the module here, not a command on the PATH: an old
    # container image has the command on the host but not the module inside.
    from sta import manifest
    parser = manifest.parser_available()
    say(f"  {'OK ' if parser else 'MISSING'}  {'pyaxmlparser':16} "
        f"{sys.executable if parser else '-> ./install.sh, or ./install.sh --docker to rebuild the image'}")
    ok = ok and parser
    for tool, hint in (("age", "seal --encrypt and export --age-recipient"),
                       ("saf", "reads the whole iPhone sysdiagnose"), ("ots", "timestamps the seal")):
        path = which(tool)
        say(f"  {'OK ' if path else 'OPTIONAL'}  {tool:16} {path or '-> not installed: ' + hint}")
    if sys.platform.startswith("linux"):
        usbmuxd = os.path.exists("/var/run/usbmuxd") or run(["pgrep", "-x", "usbmuxd"], check=False).returncode == 0
        say(f"  {'OK ' if usbmuxd else 'WARN   '}  usbmuxd          "
            f"{'running' if usbmuxd else 'not running (needed for iPhone; it starts when one is plugged in)'}")
    if not ok:
        fail("Some tools are missing. Run ./install.sh", 1)
    say("All tools found.")


def cmd_purge(case: Case, yes: bool) -> None:
    # The manifest stays as the record of what the case held when sealed.
    keep = {"state.json", "findings.json", "notes.json", "report.md", "MANIFEST.sha256", "MANIFEST.sha256.ots"}
    doomed = [p for p in case.path.iterdir() if p.name not in keep]
    if not yes:
        say("This deletes the phone data of this case and keeps only the report files:")
        for p in doomed:
            say(f"  {p}")
        if case.secrets_dir.exists():
            say(f"  {case.secrets_dir}")
        say("To confirm, the operator (not the agent) runs: ./sta purge --yes")
        return
    operator_terminal("delete the phone data")
    typed = input(f"This cannot be undone. Type the case name ({case.path.name}) to delete its phone data: ")
    if typed.strip() != case.path.name:
        fail("The name does not match. Nothing was deleted.")
    for p in doomed:
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    # Backup password and interview answers: phone data too.
    shutil.rmtree(case.secrets_dir, ignore_errors=True)
    case.state["purged"] = now()
    case.save()
    say(f"Purged. Kept: {', '.join(sorted(keep))}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="sta", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    nc = sub.add_parser("new-case", help="start a check for one phone")
    nc.add_argument("--alias", required=True, help="short name for the owner, no personal data needed")
    nc.add_argument("--consent", choices=["yes", "no"], help="the owner agrees (asked if missing)")
    nc.add_argument("--network", choices=["yes", "no"],
                    help="indicator downloads and store lookups, which send the installed app names "
                         "and the store country (asked if missing)")
    nc.add_argument("--virustotal", choices=["yes", "no"],
                    help="send the SHA-256 of apps from outside a store to VirusTotal (asked if missing)")
    nc.add_argument("--abusech", choices=["yes", "no"],
                    help="send the SHA-256 of apps from outside a store and the domains in their code "
                         "to abuse.ch (asked if missing, only when STA_ABUSECH_API_KEY is set)")
    nc.add_argument("--country", default=os.environ.get("STA_COUNTRY", "us"),
                    help="two-letter store country for lookups")
    sub.add_parser("next", help="say what to do now")
    sub.add_parser("status", help="show case state")
    sub.add_parser("cases", help="list cases")
    use = sub.add_parser("use", help="switch current case")
    use.add_argument("case_id")
    sub.add_parser("doctor", help="check installed tools")
    sub.add_parser("interview", help="operator only: a few optional questions to the owner, before detect")
    sub.add_parser("detect")
    up = sub.add_parser("update-kb")
    up.add_argument("--skip-fdroid", action="store_true")
    sub.add_parser("ios-password")
    acq = sub.add_parser("acquire")
    acq.add_argument("--no-sms", action="store_true", help="Android: skip the SMS backup")
    sub.add_parser("ios-quick", help="iPhone: apps, profiles, provisioning and crash logs in a minute (no backup)")
    sd = sub.add_parser("sysdiagnose", help="iPhone: pull a sysdiagnose for its shutdown.log")
    sd.add_argument("--skip", metavar="REASON", help="go on without it, and say why in the report")
    sub.add_parser("decrypt")
    sub.add_parser("analyze")
    sub.add_parser("check-apps")
    sub.add_parser("triage")
    rp = sub.add_parser("report")
    rp.add_argument("--partial", action="store_true",
                    help="accept a check without analyze (ios-quick only): the report warns that MVT did not run")
    rv = sub.add_parser("review")
    rv.add_argument("--done", action="store_true")
    note = sub.add_parser("note", help="record the owner's answer for a finding")
    note.add_argument("finding_id")
    note.add_argument("text")
    cl = sub.add_parser("cleanup")
    cl.add_argument("--verify", action="store_true",
                    help="Android: only check that this computer lost its USB debugging permission")
    se = sub.add_parser("seal", help="write MANIFEST.sha256 with the hash of every file in the case")
    se.add_argument("--encrypt", metavar="AGE_PUBLIC_KEY",
                    help="operator only: encrypt the phone data for this age public key and delete the originals")
    sub.add_parser("verify", help="compare the case with its seal")
    df = sub.add_parser("diff", help="follow-up check: what changed on the phone between two cases")
    df.add_argument("old_case")
    df.add_argument("new_case")
    ex = sub.add_parser("export", help="operator only: tar.gz for a specialist, no raw acquisition, no secrets")
    ex.add_argument("dest")
    ex.add_argument("--with-apks", action="store_true", help="add the APKs of apps with a red or amber finding")
    ex.add_argument("--age-recipient", metavar="AGE_PUBLIC_KEY", help="encrypt the export for this key")
    us = sub.add_parser("unseal", help="operator only: decrypt phone-data.tar.age back into the case")
    us.add_argument("--identity", required=True, help="the age private key file (keep it off this computer)")
    pg = sub.add_parser("purge", help="delete phone data, keep the report")
    pg.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    try:
        if args.cmd == "new-case":
            return cmd_new_case(args)
        if args.cmd == "cases":
            return cmd_cases()
        if args.cmd == "use":
            return cmd_use(args.case_id)
        if args.cmd == "doctor":
            return cmd_doctor()
        if args.cmd == "diff":
            from sta.diff import diff
            return diff(args.old_case, args.new_case, CASES_DIR)

        case = Case.current()
        if args.cmd not in ("next", "status") and not (args.cmd == "purge" and not args.yes):
            case.lock(args.cmd)
        if args.cmd == "next":
            cmd_next(case)
        elif args.cmd == "status":
            import json
            say(json.dumps(case.state, indent=2, default=str))
        elif args.cmd == "interview":
            cmd_interview(case)
        elif args.cmd == "detect":
            from sta.device import detect
            detect(case)
        elif args.cmd == "update-kb":
            from sta.kbupdate import update_kb
            update_kb(case, args.skip_fdroid)
        elif args.cmd == "ios-password":
            from sta.acquire import ios_password
            ios_password(case)
        elif args.cmd == "acquire":
            from sta.acquire import acquire_android, acquire_ios
            if case.platform != "ios":
                acquire_android(case, not args.no_sms)
            else:
                try:
                    acquire_ios(case)
                except StepError:
                    # next suggests `report --partial` after two failed backups.
                    case.state["ios_acquire_fails"] = case.state.get("ios_acquire_fails", 0) + 1
                    case.save()
                    raise
        elif args.cmd == "ios-quick":
            from sta.acquire import quick_ios
            quick_ios(case)
        elif args.cmd == "sysdiagnose":
            from sta.acquire import sysdiagnose_ios
            sysdiagnose_ios(case, args.skip)
        elif args.cmd == "decrypt":
            from sta.acquire import decrypt_ios
            decrypt_ios(case)
        elif args.cmd == "analyze":
            from sta.analyze import analyze
            analyze(case)
        elif args.cmd == "check-apps":
            from sta.checks import check_apps
            check_apps(case)
        elif args.cmd == "triage":
            from sta.report import triage
            triage(case)
        elif args.cmd == "report":
            from sta.report import report
            report(case, partial=args.partial)
        elif args.cmd == "review":
            from sta.report import review
            review(case, args.done)
        elif args.cmd == "note":
            from sta.report import add_note
            add_note(case, args.finding_id, args.text)
        elif args.cmd == "cleanup":
            from sta.acquire import cleanup
            cleanup(case, args.verify)
        elif args.cmd == "seal":
            from sta import evidence
            if args.encrypt:
                operator_terminal("encrypt the phone data and delete the originals")
            evidence.seal(case, args.encrypt)
        elif args.cmd == "verify":
            from sta import evidence
            if not evidence.verify(case):
                raise StepError("The case differs from its seal: see the lines above.")
        elif args.cmd == "export":
            from pathlib import Path

            from sta import evidence
            operator_terminal("export the case")
            evidence.export(case, Path(args.dest), args.with_apks, args.age_recipient)
        elif args.cmd == "unseal":
            from pathlib import Path

            from sta import evidence
            operator_terminal("decrypt the phone data")
            evidence.unseal(case, Path(args.identity))
        elif args.cmd == "purge":
            cmd_purge(case, args.yes)
        if args.cmd not in ("next", "status", "purge", "note", "interview", "verify", "export", "seal", "unseal"):
            say("\nNow run: ./sta next")
    except StepError as exc:
        fail(str(exc))
    except (EOFError, KeyboardInterrupt):
        fail("Stopped. Nothing more was done.", 1)
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
