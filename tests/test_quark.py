"""Task 5.2: Quark-Engine on apps that already look bad (stubbed)."""

import json

from sta import apkscan, checks, quark


def test_behaviours_need_full_confidence():
    crimes = [{"crime": "Send SMS messages", "confidence": 100},
              {"crime": "Read sensitive data (SMS, call log)", "confidence": 100},
              {"crime": "Get the location of the device", "confidence": 100},
              {"crime": "Record audio from the microphone", "confidence": 80}]
    assert quark.behaviours(crimes) == ["get location", "read SMS", "send SMS"]


def test_confidence_reads_quarks_percent_strings():
    assert quark.confidence("100%") == 100 and quark.confidence(None) == 0


def test_quark_runs_only_on_flagged_apps(case, monkeypatch, tmp_path):
    monkeypatch.setattr(quark, "which", lambda name: "/bin/quark")
    asked = []

    def fake(apk, out, log):
        asked.append(apk.name)
        return [{"crime": t, "confidence": 100} for t in ("Send SMS", "Read SMS inbox", "Get GPS location")]

    monkeypatch.setattr(quark, "analyse", fake)
    targets = {"org.bad": [tmp_path / "bad.apk"], "org.fine": [tmp_path / "fine.apk"]}
    findings = [checks.finding("app-hidden", "red", "org.bad", "hidden"),
                checks.finding("sideloaded-app", "amber", "org.fine", "x")]
    raw = {}
    apkscan.quark_pass(case, targets, raw, findings)
    assert asked == ["bad.apk"]
    assert ("app-behaviour", "amber", "org.bad") in {(f["kind"], f["severity"], f["subject"]) for f in findings}
    assert raw["org.bad"]["quark"][0]["crime"] == "Send SMS"


def test_quark_json_is_read(tmp_path, monkeypatch):
    out = tmp_path / "r.json"
    out.write_text(json.dumps({"crimes": [{"crime": "Send SMS", "confidence": "100%"},
                                          {"crime": "Weak", "confidence": "40%"}]}))
    monkeypatch.setattr(quark, "which", lambda name: "/bin/quark")
    monkeypatch.setattr(quark, "run", lambda *a, **k: None)
    assert quark.analyse(tmp_path / "a.apk", out, tmp_path / "log") == [{"crime": "Send SMS", "confidence": 100}]
