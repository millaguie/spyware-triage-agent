"""Task 5.3: the full sysdiagnose through saf (stubbed: no real archive)."""

import json

from sta import saf


def parsed(tmp_path, processes=(), apps=None):
    folder = tmp_path / "parsed_data"
    folder.mkdir()
    (folder / "ps_everywhere.jsonl").write_text(
        "\n".join(json.dumps({"datetime": f"2026-10-0{n + 1}T10:00:00", "message": p, "data": {}})
                  for n, p in enumerate(processes)) + "\nnot json\n")
    if apps is not None:
        (folder / "apps.json").write_text(json.dumps(apps))
    return folder


def kinds(out):
    return {(f["kind"], f["severity"], f["subject"]) for f in out}


def test_a_process_from_a_spyware_folder_is_red(tmp_path):
    folder = parsed(tmp_path, ["/private/var/db/com.apple.xpc.roleaccountd.staging/bh",
                               "/usr/libexec/backboardd", "/private/var/db/com.apple.xpc.roleaccountd.staging/bh"])
    out = saf.findings(folder, None)
    assert kinds(out) == {("ios-suspicious-process-path", "red",
                           "/private/var/db/com.apple.xpc.roleaccountd.staging/bh")}
    assert len(out[0]["evidence"]["seen"]) == 2


def test_apps_missing_from_the_list(tmp_path):
    apps = {"com.example.listed": {"found": ["itunesstore"]},
            "com.example.gone": {"found": ["itunesstore"]},
            "com.example.watcher": {"found": ["accessibility-tcc"], "services": ["kTCCServiceMicrophone"]},
            "com.example.logonly": {"found": ["logarchive"]},
            "com.apple.Maps": {"found": ["itunesstore"]},
            "backboardd": {"found": ["accessibility-tcc"]}}
    out = saf.findings(parsed(tmp_path, apps=apps), {"com.example.listed"})
    assert kinds(out) == {("ios-app-not-listed", "info", "com.example.gone"),
                          ("ios-app-not-listed", "amber", "com.example.watcher")}


def test_no_app_list_no_app_comparison(tmp_path):
    out = saf.findings(parsed(tmp_path, apps={"com.example.gone": {"found": ["itunesstore"]}}), None)
    assert out == []


def test_without_saf_the_check_goes_on(case, monkeypatch, capsys):
    monkeypatch.setattr(saf, "which", lambda name: None)
    assert saf.analyse(case, case.path / "x.tar.gz") is None
    assert "not installed" in capsys.readouterr().out
