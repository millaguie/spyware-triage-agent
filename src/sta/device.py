"""Find the connected phone and record what it is."""

import datetime as dt
import json

from sta.common import Case, StepError, run, say, which


def adb_devices() -> list[tuple[str, str]]:
    adb = which("adb")
    if not adb:
        return []
    out = run([adb, "devices"], check=False).stdout
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices


def ios_devices() -> list[dict]:
    pmd = which("pymobiledevice3")
    if not pmd:
        return []
    proc = run([pmd, "usbmux", "list", "--usb"], check=False)
    if proc.returncode != 0:
        proc = run([pmd, "usbmux", "list"], check=False)
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return [d for d in data if isinstance(d, dict)]


def getprop(serial: str, name: str) -> str:
    return run([which("adb"), "-s", serial, "shell", "getprop", name], check=False).stdout.strip()


def detect(case: Case) -> None:
    android = adb_devices()
    ios = ios_devices()
    total = len(android) + len(ios)

    if total == 0:
        raise StepError(
            "No phone found.\n"
            "TELL THE USER:\n"
            "  Android: open Settings > About phone, tap 'Build number' 7 times,\n"
            "           then Settings > System > Developer options > turn on 'USB debugging'.\n"
            "           Connect the cable and unlock the phone.\n"
            "  iPhone:  connect the cable, unlock the phone, tap 'Trust' and type the passcode.\n"
            "Then run ./sta detect again.")
    if total > 1:
        raise StepError("More than one phone is connected. Disconnect all phones except the one to check.")

    if android:
        serial, status = android[0]
        if status == "unauthorized":
            raise StepError(
                "The Android phone is connected but this computer is not authorized.\n"
                "TELL THE USER: unlock the phone and tap 'Allow' on the USB debugging prompt.\n"
                "Tick 'Always allow from this computer'. Then run ./sta detect again.")
        if status != "device":
            raise StepError(f"adb reports the phone as '{status}'. Reconnect the cable and run ./sta detect again.")
        patch = getprop(serial, "ro.build.version.security_patch")
        info = {
            "serial": serial,
            "manufacturer": getprop(serial, "ro.product.manufacturer"),
            "model": getprop(serial, "ro.product.model"),
            "android_version": getprop(serial, "ro.build.version.release"),
            "security_patch": patch,
            "security_patch_age_days": patch_age(patch),
        }
        case.state["platform"] = "android"
    else:
        dev = ios[0]
        udid = dev.get("Identifier") or dev.get("UniqueDeviceID") or dev.get("SerialNumber")
        pmd = which("pymobiledevice3")
        proc = run([pmd, "lockdown", "info", "--udid", udid], check=False)
        if proc.returncode != 0:
            raise StepError(
                "The iPhone is connected but not paired with this computer.\n"
                "TELL THE USER: unlock the iPhone, tap 'Trust' and type the passcode.\n"
                "Then run ./sta detect again.")
        try:
            lock = json.loads(proc.stdout)
        except json.JSONDecodeError:
            lock = {}
        info = {
            "udid": udid,
            "product_type": lock.get("ProductType") or dev.get("ProductType"),
            "ios_version": lock.get("ProductVersion") or dev.get("ProductVersion"),
            "build": lock.get("BuildVersion"),
        }
        case.state["platform"] = "ios"

    case.state["device"] = info
    case.mark("detect")
    say(f"Found {case.platform} phone:")
    for key, value in info.items():
        say(f"  {key}: {value}")


def patch_age(patch: str) -> int | None:
    try:
        return (dt.date.today() - dt.date.fromisoformat(patch)).days
    except ValueError:
        return None
