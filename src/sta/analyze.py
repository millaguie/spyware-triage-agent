"""Run MVT on the acquisition."""

import os

from sta.common import Case, StepError, read_json, run, say, tail, which


def analyze(case: Case) -> None:
    out = case.results_dir
    out.mkdir(parents=True, exist_ok=True)
    env = {} if case.network else {"MVT_NETWORK_ACCESS_ALLOWED": "false"}
    log = case.logs_dir / "mvt-check.log"
    base = ["--disable-update-check", "--disable-indicator-update-check"]

    if case.platform == "android":
        case.require("acquire")
        tool = which("mvt-android")
        target = case.path / case.state["acquisition"]["path"]
        cmd = [tool, *base, "check-androidqf", "--non-interactive", "-o", str(out)]
        if case.network and os.environ.get("MVT_VT_API_KEY") and os.environ.get("STA_VT_ALL") == "1":
            # Every non-system APK hash (hundreds): needs a paid key, or a
            # long wait. check-apps already looks up the apps from outside a store.
            cmd += ["--virustotal", "--delay", os.environ.get("STA_VT_DELAY", "15")]
        cmd.append(str(target))
    elif case.platform == "ios":
        case.require("decrypt")
        tool = which("mvt-ios")
        cmd = [tool, *base, "check-backup", "-o", str(out), str(case.decrypted_dir)]
    else:
        raise StepError("Unknown platform. Run ./sta detect.")
    if not tool:
        raise StepError("MVT is not installed. Run ./install.sh")

    say("Running MVT. This takes 1 to 15 minutes.")
    proc = run(cmd, check=False, env=env, log=log)
    if proc.returncode != 0:
        raise StepError(f"MVT exited with {proc.returncode}. Last log lines:\n{tail(log)}")

    alerts = read_json(out / "alerts.json") or []
    levels: dict[str, int] = {}
    for alert in alerts:
        levels[alert.get("level", "?")] = levels.get(alert.get("level", "?"), 0) + 1
    case.mark("analyze", mvt_alerts=levels, virustotal="--virustotal" in cmd)
    say(f"MVT finished. Alerts by level: {levels or 'none'}")
