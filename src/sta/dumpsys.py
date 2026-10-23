"""Parsers for the concatenated `dumpsys <service>` output of androidqf.

The real dumpsys.txt is 67 MB with 385 sections, so every function here makes
one pass over the text it is given; nothing re-scans the whole file per
service. Formats verified against a real Pixel in docs/format-notes.md."""

import re

# A section header only counts when the line right before it is a separator of
# dashes: that is the only way a real dumpsys reaches a header, and it keeps a
# `DUMP OF SERVICE` line echoed inside a value from cutting a section. Long
# decorative hyphen runs exist in bodies, so a run alone must not split either.
HEADER = re.compile(r"^-{5,}$\n^DUMP OF SERVICE (\S+):$", re.M)

# '  Package [org.fdroid.fdroid] (d5d3538):' exactly; no other shape appears.
PACKAGE = re.compile(r"^  Package \[([^\]]+)\] \(([0-9a-f]+)\):$")

# '    User 0: ceDataInode=... installed=true hidden=false ... enabled=0 ...'
USER_HEAD = re.compile(r"^    User (\d+): (.*)$")

PERMISSION = re.compile(r"^(\S+): granted=true\b")
TARGET_SDK = re.compile(r"\btargetSdk=(\d+)")
ENTRY = re.compile(r"^\s+[0-9a-f]+ ([^\s/]+)/")

# '    Account {name=someone, type=bitfire.at.davdroid}' in `dumpsys account`.
ACCOUNT = re.compile(r"Account \{name=(.*?), type=(\S+)\}")

# A role block of `dumpsys role`: its name line and its optional holders line.
ROLE_NAME = re.compile(r"^\s+name=(\S+)$")
ROLE_HOLDERS = re.compile(r"^\s+holders=(.+)$")

# '  UserInfo{0:Owner:4c13} serialNo=0 isPrimary=true' and, a couple of lines
# below it, '    Flags: 19475 (ADMIN|FULL|INITIALIZED|MAIN|PRIMARY|SYSTEM)'.
# The name in the middle is personal: the patterns never capture it.
USER_INFO = re.compile(r"UserInfo\{(\d+):[^:]*:[0-9a-f]+\}")
USER_FLAGS = re.compile(r"\s+Flags: \d+ \(([A-Z_|]+)\)$")

# The package lines of a `dumpsys deviceidle` list: header at 2 spaces, one
# entry per line at 4.
EXEMPT_HEADER = "  Whitelist user apps:"
EXEMPT_ITEM = re.compile(r"^    (\S+)$")


def sections(text: str) -> dict[str, str]:
    """{'account': '...', 'device_policy': '...'}: the text of each DUMP OF SERVICE block."""
    found = list(HEADER.finditer(text))
    out = {}
    for number, match in enumerate(found):
        start = match.end() + 1  # after the newline that closes the header line
        stop = found[number + 1].start() if number + 1 < len(found) else len(text)
        out[match.group(1)] = text[start:stop]
    return out


def packages(section: str) -> dict[str, dict]:
    """{package: {first_install, last_update, installer, initiating, originating,
                  code_path, target_sdk, install_reason, flags: set, granted: set,
                  hidden, enabled, disabled_components: set, users: list}} for one
    `dumpsys package` section.

    Only the blocks between `Packages:` and `Hidden system packages:` count:
    below that marker PackageManager keeps stub copies of updated apps; if a
    name still appears twice above it, the block whose codePath is under
    /data/app (the live one) wins. Granted permissions are the `install
    permissions` plus the `runtime permissions` of user 0: a work profile
    (User 10 and up) says nothing about what the owner sees, so its users are
    only listed in `users`."""
    blocks: list[tuple[str, dict]] = []
    info: dict | None = None  # the block we are filling, or None before the first one
    user = None  # the User N sub-block we are inside, or None in the package-wide part
    mode = None  # 'permissions' | 'disabled' | None, from the last header line
    in_hidden = False
    for line in section.splitlines():
        if line == "Packages:":
            in_hidden = False
            continue
        if line == "Hidden system packages:":
            in_hidden, info = True, None
            continue
        if header := PACKAGE.match(line):
            if in_hidden:
                continue
            info = {"first_install": None, "last_update": None, "installer": None,
                    "initiating": None, "originating": None, "code_path": "",
                    "target_sdk": None, "install_reason": None, "flags": set(),
                    "granted": set(), "hidden": False, "enabled": None,
                    "disabled_components": set(), "users": []}
            blocks.append((header.group(1), info))
            user = mode = None
            continue
        if not info:
            continue
        if head := USER_HEAD.match(line):
            user = int(head.group(1))
            mode = None
            if user not in info["users"]:
                info["users"].append(user)
            if user == 0:  # these fields repeat per user; only the owner's count
                hidden = re.search(r"\bhidden=(\w+)", head.group(2))
                enabled = re.search(r"\benabled=(-?\d+)", head.group(2))
                info["hidden"] = bool(hidden) and hidden.group(1) == "true"
                info["enabled"] = int(enabled.group(1)) if enabled else None
            continue
        text = line.strip()
        if mode and not line.startswith(" "):  # an unindented line (a duration, a new
            mode = None                        # block) ends the permissions/component list
        if text.endswith(":"):  # sub-block header: permissions lists, components...
            mode = {"install permissions:": "permissions", "runtime permissions:": "permissions",
                    "disabledComponents:": "disabled"}.get(text)
            continue
        if mode == "permissions" and user in (None, 0):
            if perm := PERMISSION.match(text):
                info["granted"].add(perm.group(1))
            continue
        if mode == "disabled":
            # items are indented; the section's trailing duration line is not
            if user == 0 and text and line[:1] in (" ", "\t"):
                info["disabled_components"].add(text)
            continue
        if sdk := TARGET_SDK.search(text):
            info["target_sdk"] = int(sdk.group(1))
            continue
        key, sep, value = text.partition("=")
        if not sep or value == "null":
            continue
        if user is None and key in ("installerPackageName", "initiatingPackageName",
                                    "originatingPackageName"):
            info[{"installerPackageName": "installer", "initiatingPackageName": "initiating",
                  "originatingPackageName": "originating"}[key]] = value
        elif user is None and key == "lastUpdateTime":
            info["last_update"] = value
        elif user is None and key == "codePath":
            info["code_path"] = value
        elif user is None and key == "flags" and value.startswith("["):
            info["flags"] = set(value.strip("[] ").split())
        elif user == 0 and key == "installReason" and value.isdigit():
            info["install_reason"] = int(value)
        elif user == 0 and key == "firstInstallTime":
            info["first_install"] = value
    out: dict[str, dict] = {}
    for name, block in blocks:
        old = out.get(name)
        if old and old["code_path"].startswith("/data/app") \
                and not block["code_path"].startswith("/data/app"):
            continue  # a stub copy never replaces the live block
        out[name] = block
    return out


def for_json(details: dict[str, dict], exempt=()) -> dict:
    """The parsed package details as plain JSON values (sets become sorted
    lists), for `package-details.json` in the case folder.

    `exempt` is the battery-saving whitelist of task 3.3: each package says
    whether it is on it, and an exempt app with no block in the package section
    gets a stub entry that says only that, so one file carries the whole list."""
    out = {}
    for name, info in details.items():
        fields = {key: (sorted(value) if isinstance(value, set) else value)
                  for key, value in info.items() if key != "code_path"}
        fields["battery_exempt"] = name in exempt
        out[name] = fields
    for name in sorted(set(exempt) - set(details)):
        out[name] = {"battery_exempt": True}
    return out


def with_battery_exempt(details: dict[str, dict], exempt) -> dict[str, dict]:
    """Adds `battery_exempt` to every package of `details` (task 0.2 blocks) and
    a stub entry for each exempt app that has no block there, so the exemption
    list lives in one file for the timeline and the follow-up diff."""
    for name, info in details.items():
        info["battery_exempt"] = name in exempt
    for name in sorted(set(exempt) - set(details)):
        details[name] = {"battery_exempt": True}
    return details


def accounts(section: str) -> list[tuple[str, str]]:
    """[(name, type)] of every account in a `dumpsys account` section.

    The name is personal data (it is usually an email address): callers count
    it or hash it with the machine key and never store it. The lines after the
    account list (Accounts History, Active Sessions, RegisteredServicesCache)
    hold no `Account {name=...}` line, so one pass over the section is enough."""
    return [(match.group(1), match.group(2)) for match in ACCOUNT.finditer(section)]


def roles(section: str) -> dict[str, list[str]]:
    """{role name: [holder packages]} of a `dumpsys role` section.

    A role without a holder is not in the result. No real dumpsys has ever
    printed two holders on one line, so the separator is unknown: split on ';'
    and ',' to be safe."""
    out: dict[str, list[str]] = {}
    name = None
    for line in section.splitlines():
        if line.strip() == "{":
            name = None  # a new role block; user_states={ is not one of these
        elif found := ROLE_NAME.match(line):
            name = found.group(1)
        elif holders := ROLE_HOLDERS.match(line):
            packages = [pkg for pkg in re.split(r"[;,]", holders.group(1)) if pkg.strip()]
            if name and packages:
                out[name] = [pkg.strip() for pkg in packages]
    return out


def battery_exemptions(section: str) -> set[str]:
    """Packages under `Whitelist user apps:` of a `dumpsys deviceidle` section:
    apps somebody exempted from battery saving, so they can keep running. The
    other lists there (`... system apps`, `... app ids`) are system defaults and
    say nothing about the owner's choices."""
    out: set[str] = set()
    inside = False
    for line in section.splitlines():
        if line.startswith("  ") and not line.startswith("    "):
            inside = line == EXEMPT_HEADER  # the next 2-space header ends the list
        elif inside and (item := EXEMPT_ITEM.match(line)):
            out.add(item.group(1))
    return out


def users(section: str) -> list[dict]:
    """[{'id': 0, 'flags': {'ADMIN', 'FULL', ...}}] of a `dumpsys user` section.

    Only the id and the flags come out: the name between the braces is personal
    data, so it is never captured. The UserManager internals that fill the rest
    of the section print UserInfo lines too, without a `Flags:` line under them;
    requiring that line (as in the real dump) is what keeps those out."""
    out: list[dict] = []
    pending = None  # the UserInfo line we saw, waiting for its Flags line
    for line in section.splitlines():
        if head := USER_INFO.search(line):
            pending = {"id": int(head.group(1)), "flags": set()}  # no Flags yet: not a user
            continue
        if pending is not None and (flags := USER_FLAGS.match(line)):
            pending["flags"] = set(flags.group(1).split("|"))
            out.append(pending)
            pending = None
    return out


def main_activities(section: str) -> set[str]:
    """Packages with an entry under the first `android.intent.action.MAIN:` of
    the Activity Resolver Table (the activities one; MAIN appears again in the
    other resolver tables, so the table is cut at its end). The table never
    prints categories, so this only backs up the manifest's LAUNCHER check
    (task 1); it also still lists components the app disabled, so cross-check
    with `disabled_components` before concluding anything about a missing icon."""
    start = section.find("Activity Resolver Table:")
    if start == -1:
        return set()
    stop = section.find("\nReceiver Resolver Table:", start)
    table = section[start:stop if stop != -1 else len(section)]
    out: set[str] = set()
    collecting = False
    for line in table.splitlines():
        if line.strip() == "android.intent.action.MAIN:":
            collecting = True  # only the first one: any other line ends the list
        elif collecting and (entry := ENTRY.match(line)):
            out.add(entry.group(1))
        else:
            collecting = False
    return out
