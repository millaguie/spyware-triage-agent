"""How MVT alerts become findings, and the kind/severity rewrites."""

import json

from sta import report
from sta.common import SCHEMA_VERSION


def alert(level, message, module="m", event=None, ioc=None):
    return {"level": level, "module": module, "message": message, "event_time": "",
            "event": event or {}, "matched_indicator": ioc}


def write_alerts(case, alerts):
    (case.path / "mvt-results").mkdir(exist_ok=True)
    (case.path / "mvt-results" / "alerts.json").write_text(json.dumps(alerts))


def test_levels_map_to_severity(case):
    write_alerts(case, [
        alert("CRITICAL", "ioc", ioc={"type": "domain", "value": "evil.example"}),
        alert("HIGH", "high"),
        alert("MEDIUM", "medium"),
        alert("LOW", "low"),
        alert("INFORMATIONAL", "info"),
    ])
    out = report.mvt_findings(case)
    assert [(f["kind"], f["severity"]) for f in out] == [
        ("mvt-ioc-match", "red"), ("mvt-high", "red"), ("mvt-medium", "amber"),
        ("mvt-low", "info"), ("mvt-low", "info")]
    assert "evil.example" in out[0]["evidence"]["matched_indicator"]


def test_message_rewrites(case):
    write_alerts(case, [
        alert("MEDIUM", "This phone has not received security updates for more than six months"),
        alert("MEDIUM", "Google Play Protect is disabled"),
        alert("MEDIUM", "Found an installed package related to rooting/jailbreaking"),
        alert("MEDIUM", "Package 'x' had risky permission 'Y' set to 'reject' at ..."),
        alert("MEDIUM", "Detected uninstall of package com.google.android.trichromelibrary_1 (vers 0)"),
        # a red alert is never downgraded by a message pattern
        alert("HIGH", "Google Play Protect is disabled"),
    ])
    out = [(f["kind"], f["severity"]) for f in report.mvt_findings(case)]
    assert out == [("outdated-os", "amber"), ("play-protect-off", "amber"), ("root-tools", "amber"),
                   ("mvt-low", "info"), ("mvt-low", "info"), ("mvt-high", "red")]


def test_watchdog_crash_is_info_only_on_release_builds(case):
    base = {"abort_message": "[Watchdog] thread hung", "signal_info": {"name": "SIGABRT"}}
    write_alerts(case, [
        alert("MEDIUM", "crash", "tombstones", {**base, "build_fingerprint": "g/a/a:17/x:user/release-keys"}),
        alert("MEDIUM", "crash", "tombstones", {**base, "build_fingerprint": "g/a/a:17/x:user/test-keys"}),
        alert("MEDIUM", "crash", "tombstones", {"abort_message": "", "signal_info": {"name": "SIGSEGV"},
                                                "build_fingerprint": "g/a/a:17/x:user/release-keys"}),
    ])
    out = [(f["kind"], f["severity"]) for f in report.mvt_findings(case)]
    assert out == [("crash-watchdog", "info"), ("mvt-medium", "amber"), ("mvt-medium", "amber")]


def test_subject_prefers_the_package(case):
    write_alerts(case, [alert("MEDIUM", "x", "mod", {"name": "com.a"}),
                        alert("MEDIUM", "x", "mod", {"package_name": "com.b"}),
                        alert("MEDIUM", "x", "mod", {"other": 1})])
    assert [f["subject"] for f in report.mvt_findings(case)] == ["com.a", "com.b", "mod"]


def test_group_alerts_counts_repeats():
    items = [{"kind": "k", "subject": "s", "severity": "info", "detail": "d", "evidence": {"n": i}}
             for i in range(3)]
    items.append({"kind": "k", "subject": "other", "severity": "info", "detail": "d", "evidence": {}})
    out = report.group_alerts(items)
    assert len(out) == 2
    assert out[0]["detail"] == "d (3 alerts like this)"
    assert [e["n"] for e in out[0]["evidence"]["more_events"]] == [1, 2]


def test_group_alerts_is_idempotent_on_the_detail():
    items = [{"kind": "k", "subject": "s", "severity": "info", "detail": "d (2 alerts like this)", "evidence": {}}
             for _ in range(2)]
    assert report.group_alerts(items)[0]["detail"] == "d (2 alerts like this)"


def test_acquisition_findings(case):
    case.state["acquisition"] = {"hash_check": "no hashes.csv", "incomplete_modules": [
        {"name": "backup", "status": "failed", "error": "timeout"}]}
    out = report.acquisition_findings(case)
    assert [(f["kind"], f["severity"]) for f in out] == [("acquisition-incomplete", "info"),
                                                         ("acquisition-integrity", "amber")]
    case.state["acquisition"] = {"hash_check": "ok", "hash_mismatches": ["a", "b"]}
    case.state["steps"]["update-kb"]["mvt_indicator_files"] = 0
    out = report.acquisition_findings(case)
    assert [(f["kind"], f["severity"]) for f in out] == [("acquisition-integrity", "amber"),
                                                         ("no-indicators", "amber")]


def test_every_kind_the_code_emits_is_in_the_kb(case):
    """A finding kind with no text would stop triage with an error; catch it here."""
    import re
    from pathlib import Path
    src = Path(report.__file__).parent
    emitted = set()
    for path in src.glob("*.py"):
        text = path.read_text()
        emitted |= set(re.findall(r'finding\(\s*"([a-z0-9-]+)"', text))
        emitted |= set(re.findall(r'"kind": "([a-z0-9-]+)"', text))
        emitted |= set(re.findall(r'kind, sev = (?:\()?"([a-z0-9-]+)"', text))
    emitted |= {k for _, k, _ in report.MVT_MESSAGE_KINDS}
    kb = report.load_kb()
    missing = emitted - set(kb)
    assert not missing, f"kinds without kb/findings.yaml entry: {sorted(missing)}"
    for kind, entry in kb.items():
        assert {"title", "explain", "action"} <= set(entry), kind


def test_schema_version_is_written(case):
    report.save_findings(case, [])
    report.save_notes(case, {})
    assert json.loads((case.path / "findings.json").read_text())["schema"] == SCHEMA_VERSION
    assert json.loads((case.path / "notes.json").read_text())["schema"] == SCHEMA_VERSION
