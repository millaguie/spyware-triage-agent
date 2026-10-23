"""Task 5.4: follow-up checks of the same phone."""

import json

import pytest

from conftest import make_case
from sta import checks, diff, report
from sta.common import StepError


@pytest.fixture
def two_cases(sandbox, no_apkid):
    old = make_case(sandbox, "2026-01-01-first")
    new = make_case(sandbox, "2026-02-01-second")
    for case in (old, new):
        checks.check_apps(case)
    details = json.loads((new.path / "package-details.json").read_text())
    details["org.example.new"] = {"first_install": "2026-01-20 10:00:00", "last_update": "x", "granted": []}
    hidden = details["org.example.hidden"]
    hidden["granted"] = sorted(set(hidden["granted"]) | {"android.permission.CAMERA"})
    (new.path / "package-details.json").write_text(json.dumps(details))
    accounts = json.loads((new.path / "accounts.json").read_text())
    accounts["google_accounts"].append("f" * 64)
    (new.path / "accounts.json").write_text(json.dumps(accounts))
    for case in (old, new):
        report.triage(case)
    return old, new


def test_diff_reports_apps_permissions_accounts_and_findings(two_cases, sandbox):
    old, new = two_cases
    findings = report.load_findings(new)
    findings.append(checks.finding("app-hidden", "red", "org.example.new", "hidden"))
    report.save_findings(new, findings)
    diff.diff(old.path.name, new.path.name, sandbox / "cases")
    text = (new.path / f"diff-from-{old.path.name}.md").read_text()
    assert "- new: `org.example.new`" in text
    assert "`org.example.hidden`: CAMERA" in text
    assert "1 new Google account(s), 0 removed." in text
    assert "- new: red `app-hidden` on `org.example.new`" in text
    assert "@" not in text  # no account name, ever


def test_diff_needs_two_triaged_cases(sandbox):
    make_case(sandbox, "2026-01-01-a")
    make_case(sandbox, "2026-01-02-b")
    with pytest.raises(StepError, match="triage"):
        diff.diff("2026-01-01-a", "2026-01-02-b", sandbox / "cases")
    with pytest.raises(StepError, match="No case"):
        diff.diff("2026-01-01-a", "nope", sandbox / "cases")
