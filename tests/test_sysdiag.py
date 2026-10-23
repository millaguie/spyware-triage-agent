import io
import tarfile

import pytest

from sta import sysdiag

# In the real log the clients and the delay notices come first; the SIGTERM
# line with the timestamp closes the reboot.
CLEAN_REBOOT = """\
remaining client pid: 100 (/usr/libexec/trustd)
these clients are still here
SIGTERM: [1700000000] shutdown
SIGTERM: [1700086400] shutdown
"""

BAD_REBOOT = """\
remaining client pid: 100 (/usr/libexec/trustd)
remaining client pid: 433 (/private/var/db/com.apple.xpc.roleaccountd.staging/evil)
these clients are still here
these clients are still here
these clients are still here
SIGTERM: [1700000000] shutdown
remaining client pid: 433 (/private/var/db/com.apple.xpc.roleaccountd.staging/evil)
SIGTERM: [1700086400] shutdown
SIGTERM: [1700172800] shutdown
"""


def archive(tmp_path, text: str | None, name="x/shutdown.log"):
    path = tmp_path / "sysdiagnose_test.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        if text is not None:
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo("x/other.txt")
        info.size = 0
        tar.addfile(info, io.BytesIO(b""))
    return path


def test_parse_groups_lines_per_reboot():
    data = sysdiag.parse(BAD_REBOOT)
    assert [r["delays"] for r in data["reboots"]] == [3, 0, 0]
    assert data["reboots"][0]["at"] == "2023-11-14T22:13:20+00:00"
    assert data["reboots"][1]["clients"][0]["pid"] == "433"


def test_clean_log_only_says_how_many_reboots(tmp_path):
    findings, data = sysdiag.check(archive(tmp_path, CLEAN_REBOOT))
    assert [f["kind"] for f in findings] == []
    assert data["reboots"] == 2 and data["first"] == "2023-11-14T22:13:20+00:00"


def test_suspicious_path_is_red_and_delays_amber(tmp_path):
    findings, _ = sysdiag.check(archive(tmp_path, BAD_REBOOT))
    by = {f["kind"]: f for f in findings}
    assert by["ios-suspicious-process-path"]["severity"] == "red"
    assert by["ios-suspicious-process-path"]["subject"].startswith("/private/var/db/")
    assert len(by["ios-suspicious-process-path"]["evidence"]["reboots"]) == 2
    assert by["ios-shutdown-delay"]["severity"] == "amber"
    assert "1 of 3 reboots" in by["ios-shutdown-delay"]["detail"]


def test_single_reboot_is_flagged_as_little_evidence(tmp_path):
    findings, _ = sysdiag.check(archive(tmp_path, "SIGTERM: [1700000000]\n"))
    assert [f["kind"] for f in findings] == ["sysdiagnose-few-reboots"]


def test_missing_shutdown_log(tmp_path):
    findings, data = sysdiag.check(archive(tmp_path, None))
    assert [f["kind"] for f in findings] == ["sysdiagnose-no-shutdown-log"]
    assert data == {}


@pytest.mark.parametrize("client", ["/private/var/tmp/x", "/private/var/db/y"])
def test_both_suspicious_prefixes(tmp_path, client):
    text = f"remaining client pid: 1 ({client})\nSIGTERM: [1]\nSIGTERM: [2]\n"
    findings, _ = sysdiag.check(archive(tmp_path, text))
    assert any(f["kind"] == "ios-suspicious-process-path" for f in findings)
