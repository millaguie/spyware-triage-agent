"""Read the AndroidManifest.xml inside an APK.

Classic stalkerware hides in the manifest: no launcher icon, a name like
'System Service', a BOOT_COMPLETED receiver, declared accessibility access.
pyaxmlparser is that manifest parser and nothing else (androguard drags in
ipython, networkx, pydot...).

A hostile APK can attack whatever parses it, so parse_apk() only runs in a
child process (`python -m sta.manifest <apk>`): inspect() starts it with a
60 s timeout and reads the JSON on its stdout. A crash or a hang stays inside
the child; the app is then recorded without a manifest (plus the reason) in
apk-scan.json. The child imports this module, so it must stay light: that is
why finding() and SYSTEM_WORDS are copies of checks.py instead of imports."""

import fnmatch
import json
import logging
import re
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO

from sta.common import KB_DIR

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAIN_ACTION = "android.intent.action.MAIN"
LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
BOOT_ACTION = "android.intent.action.BOOT_COMPLETED"
SMS_ACTION = "android.provider.Telephony.SMS_RECEIVED"
ACCESSIBILITY_ACTION = "android.accessibilityservice.AccessibilityService"
DEVICE_ADMIN_ACTION = "android.app.action.DEVICE_ADMIN_ENABLED"

SMS_PERMISSIONS = {"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"}

# A copy of checks.SYSTEM_WORDS: importing checks here would load yaml, vt and
# apkscan into the child process for no reason.
SYSTEM_WORDS = {"android", "system", "google", "update", "service", "services",
                "security", "samsung", "settings", "battery", "sync"}

# Apps whose name is exactly one of these are lying about what they are.
EXACT_SYSTEM_LABELS = {"Settings", "System", "Android System", "Sync Service",
                       "Update Service", "Google Services"}

# The surveillance set of the app-surveillance-permissions rule.
SURVEILLANCE_PERMISSIONS = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                            "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO",
                            "android.permission.ACCESS_BACKGROUND_LOCATION",
                            "android.permission.READ_CONTACTS", "android.permission.CAMERA",
                            "android.permission.SYSTEM_ALERT_WINDOW",
                            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"}

OLD_TARGET_SDK = 23  # below this, Android granted every permission at install time


def parser_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("pyaxmlparser") is not None


def finding(kind, severity, subject, detail, **evidence) -> dict:
    """Same shape as sta.checks.finding; copied to keep this module light."""
    return {"kind": kind, "severity": severity, "subject": subject,
            "detail": detail, "evidence": evidence}


def hidden_ok_packages() -> set:
    """Patterns from kb/hidden-ok.yaml: apps with no launcher icon by design
    (Chrome webapps, keyboards, watchfaces)."""
    path = KB_DIR / "hidden-ok.yaml"
    if not path.exists():
        return set()
    import yaml  # here, not at the top: keeps `python -m sta.manifest` cheap
    return {str(entry) for entry in (yaml.safe_load(path.read_text(encoding="utf-8")) or [])
            if isinstance(entry, str)}


def _matches(name: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _short(permission: str) -> str:
    return permission.removeprefix("android.permission.")


def launcher_activities(xml) -> set:
    """Components (activities and activity-aliases) whose manifest intent-filter
    asks for MAIN + LAUNCHER: what puts an icon on the home screen. The category
    never appears in dumpsys, so only the manifest settles 'this app has (had)
    an icon'. Names come out fully qualified, like disabled_components."""
    out = set()
    package = xml.get("package") or ""
    for item in list(xml.iter("activity")) + list(xml.iter("activity-alias")):
        name = item.get(ANDROID_NS + "name") or ""
        if not name:
            continue
        full = package + name if name.startswith(".") else name
        for flt in item.findall(".//intent-filter"):
            actions = {el.get(ANDROID_NS + "name") for el in flt.findall("action")}
            categories = {el.get(ANDROID_NS + "name") for el in flt.findall("category")}
            if MAIN_ACTION in actions and LAUNCHER_CATEGORY in categories:
                out.add(full)
    return out


def _filters(xml, tag: str) -> dict[str, dict]:
    """{component: {'action': [...], 'category': [...]}} for every component of
    this kind that declares at least one intent-filter."""
    out = {}
    for item in xml.iter(tag):
        name = item.get(ANDROID_NS + "name") or ""
        if not name:
            continue
        found = {}
        for kind in ("action", "category"):
            values = [el.get(ANDROID_NS + "name")
                      for flt in item.findall(".//intent-filter") for el in flt.findall(kind)]
            found[kind] = sorted(v for v in dict.fromkeys(values) if v)
        if any(found.values()):
            out[name[1:] if name.startswith(".") else name] = found
    return out


def parse_apk(path) -> dict:
    """What the manifest says, as JSON-safe values. Callable anywhere;
    inspect() calls it in a child process for a reason."""
    with redirect_stdout(StringIO()):  # some APKs make pyaxmlparser print 'res1 is not zero!'
        previous = logging.root.manager.disable
        logging.disable(logging.WARNING)  # the same noise on the logger
        try:
            from pyaxmlparser import APK

            apk = APK(str(path))
            xml = apk.get_android_manifest_xml()
            receivers, services = _filters(xml, "receiver"), _filters(xml, "service")
            return {
                "package": apk.get_package(),
                "label": apk.get_app_name(),
                "target_sdk": apk.get_target_sdk_version(),  # a string like '35'
                "main_activity": apk.get_main_activity(),
                "launcher": sorted(launcher_activities(xml)),
                "permissions_declared": sorted({p.get(ANDROID_NS + "name")
                                                for p in xml.iter("uses-permission")
                                                if p.get(ANDROID_NS + "name")}),
                "receivers_boot": sorted(r for r, f in receivers.items() if BOOT_ACTION in f["action"]),
                "receivers_sms": sorted(r for r, f in receivers.items() if SMS_ACTION in f["action"]),
                "device_admin_receivers": sorted(r for r, f in receivers.items()
                                                 if DEVICE_ADMIN_ACTION in f["action"]),
                # declaring accessibility is not having it: the real capability
                # finding (accessibility-service) comes from settings_secure.
                "services_accessibility": sorted(s for s, f in services.items()
                                                 if ACCESSIBILITY_ACTION in f["action"]),
            }
        finally:
            logging.disable(previous)


def inspect(apk_path) -> dict:
    """The manifest of this APK as a dict, or {'error': reason}. Never raises
    and never lets the parser's own output through: that is the point of
    running it in a separate process."""
    try:
        proc = subprocess.run([sys.executable, "-m", "sta.manifest", str(apk_path)],
                              capture_output=True, text=True, timeout=60,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return {"error": "the manifest parser could not be started or took over 60 s"}
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        lines = [line for line in (proc.stderr or proc.stdout).strip().splitlines() if line]
        return {"error": f"the manifest parser failed: {(lines[-1] if lines else 'no output')[:200]}"}
    if not isinstance(data, dict):
        return {"error": "the manifest parser answered something that is not an object"}
    return data


def _one_level_lower(severity: str) -> str:
    return {"red": "amber", "amber": "info"}[severity]


def manifest_findings(name, info, origin, granted: set | None, *, disabled=None,
                      device_admins=(), accessibility_enabled=False, hidden_ok=None,
                      battery_exempt=False) -> list[dict]:
    """Findings from one parsed manifest.

    `granted` and `disabled` are this package's dumpsys data (task 0.2).
    `disabled is None` means there are no package details for it: app-hidden
    can then only fall back to 'the manifest declares no launcher' (marked
    source: manifest, one severity level lower), and the SMS and surveillance
    rules count what the manifest demands instead of what was granted.
    `hidden_ok` is only an exception for app-hidden: keyboards have no icon by
    design, but a keyboard with boot-plus-SMS behaviour is still news.
    `battery_exempt` says somebody took this app out of battery saving (task
    3.3), so it is meant to keep running all the time."""
    if not info or info.get("error"):
        return []
    if hidden_ok is None:
        hidden_ok = hidden_ok_packages()
    dumpsys_known = disabled is not None
    sideloaded = origin in ("sideload", "adb")
    label = str(info.get("label") or "")
    launcher = set(info.get("launcher") or ())
    declared = list(info.get("permissions_declared") or [])
    granted = set(granted or ())
    permissions = granted if dumpsys_known else set(declared)
    ev = dict(package=name, origin=origin, label=label or None,
              target_sdk=info.get("target_sdk"), main_activity=info.get("main_activity"),
              has_launcher=bool(launcher), permissions_declared=sorted(declared),
              permissions_granted=sorted(granted),
              receivers_boot=bool(info.get("receivers_boot")),
              receivers_sms=bool(info.get("receivers_sms")),
              services_accessibility=list(info.get("services_accessibility") or []))
    out = []

    # app-hidden. Main signal: the icon exists in the manifest but its component
    # is disabled while the app runs. Second signal: the manifest has no
    # launcher at all. Since Android 10 the launcher shows an icon for almost
    # any app anyway, so that one gets one level less; with dumpsys data it
    # counts only for hand-installed apps (store apps without an icon are
    # keyboards, companions and the like).
    hidden = bool(launcher) and dumpsys_known and launcher <= set(disabled)
    fallback = not launcher and (not dumpsys_known or sideloaded)
    if (hidden or fallback) and not _matches(name, hidden_ok):
        sev = "red" if sideloaded else "amber"
        detail = (f"Its launcher screen ({', '.join(sorted(launcher))}) is switched off on the "
                  "phone, so it keeps running with no icon and nothing opens it." if hidden else
                  "Its manifest declares no launcher screen at all: the app has no icon and "
                  "only opens from links or from other apps.")
        out.append(finding("app-hidden", sev if hidden else _one_level_lower(sev), name, detail,
                           **({} if hidden else {"source": "manifest"}), **ev))

    # Store apps get info for the next three rules: on a real phone every
    # amber they gave there was a genuine app (Google components named
    # '... Services', one-time-code autofill, messengers and banks with camera,
    # microphone and contacts). The shape matters when the app came by hand.
    store_sev = "amber" if sideloaded else "info"

    # A label still '@7F...' is a resource id pyaxmlparser could not resolve
    # (split APKs): there is no name to judge.
    words = set(re.split(r"[^a-z0-9]+", label.lower())) - {""}
    if not label.startswith("@") and (len(words & SYSTEM_WORDS) >= 2 or label in EXACT_SYSTEM_LABELS):
        hidden_now = any(f["kind"] == "app-hidden" for f in out)
        out.append(finding("app-label-mimics-system", "red" if hidden_now else store_sev, name,
                           f"The app shows itself as «{label}», a name built to look like part "
                           "of the system.", **ev))

    if info.get("receivers_boot"):
        why = []
        sms_perms = sorted(permissions & SMS_PERMISSIONS)
        if sms_perms:
            why.append("it can read text messages (" + ", ".join(map(_short, sms_perms)) + ")")
        if info.get("receivers_sms"):
            why.append("it listens for incoming messages")
        if why:
            out.append(finding("app-boot-sms", store_sev, name,
                               "It wakes up when the phone starts and " + " and ".join(why) + ".", **ev))

    # An enabled accessibility service is already an accessibility-service
    # finding (from settings_secure); checks.py adds declared=True to its
    # evidence instead of this duplicate.
    if info.get("services_accessibility") and not accessibility_enabled:
        out.append(finding("app-accessibility-declared", "info", name,
                           f"It contains an accessibility service "
                           f"({', '.join(info['services_accessibility'])}): it could read the screen "
                           "and press buttons for the owner if that access were turned on. Now it is not.",
                           **ev))

    if info.get("device_admin_receivers"):
        admin = name in set(device_admins)
        out.append(finding("app-device-admin-declared", "amber" if admin else "info", name,
                           "It holds device administrator rights now." if admin else
                           "Its manifest is built to ask for device administrator rights: an app "
                           "hard to uninstall that can lock the phone. The rights are not granted now.", **ev))

    surveillance = sorted(SURVEILLANCE_PERMISSIONS & permissions)
    if len(surveillance) >= 3:
        detail = (f"{'Granted' if dumpsys_known else 'The manifest demands'} {len(surveillance)} "
                  "permissions that together can watch what the owner does: "
                  + ", ".join(map(_short, surveillance)) + ".")
        # An app somebody took out of battery saving is meant to stay awake
        # all the time; hand-installed and watching, that is the stalkerware shape.
        if battery_exempt:
            detail += " It is also exempt from battery saving, so the phone never puts it to sleep."
        out.append(finding("app-surveillance-permissions",
                           "red" if sideloaded and (len(surveillance) >= 5 or battery_exempt) else store_sev,
                           name, detail,
                           **({} if dumpsys_known else {"source": "manifest"}), **ev))

    try:  # the manifest holds a string; the dumpsys parse was already an int
        target = int(info.get("target_sdk"))
    except (TypeError, ValueError):
        target = None
    if target is not None and target < OLD_TARGET_SDK:
        out.append(finding("app-old-target-sdk", "amber" if sideloaded else "info", name,
                           f"It was built before Android 6 existed (targetSdk {target}), when every "
                           "permission was granted at install time without asking the owner.", **ev))
    return out


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m sta.manifest <apk>")
    print(json.dumps(parse_apk(sys.argv[1])))
