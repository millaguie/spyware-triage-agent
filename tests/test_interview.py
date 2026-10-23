"""Task 6.1-6.2: the owner's interview and the install timeline."""

import json
import stat

from sta import checks, interview, report
from sta.checks import finding


def answers_from(*replies):
    replies = iter(replies)
    return interview.ask(read=lambda prompt: next(replies))


def test_every_question_is_optional_and_bad_formats_are_asked_again():
    got = answers_from("2026-13", "2026-09", "", "maybe", "yes", "", "", "NO")
    assert got == {"since": "2026-09", "physical_access": "yes", "managed": "no"}


def test_answers_live_outside_the_case_and_state_holds_no_content(case):
    interview.save(case, {"since": "2026-09", "signs": "my ex knew where I was"})
    path = interview.path(case)
    assert not path.is_relative_to(case.path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert interview.load(case)["signs"] == "my ex knew where I was"
    state = json.loads((case.path / "state.json").read_text())
    assert state["interview"]["answered"] == 2 and "my ex" not in json.dumps(state)


def make(kind, severity, subject="org.x"):
    return finding(kind, severity, subject, "detail")


def test_physical_access_raises_what_a_person_holding_the_phone_does():
    items = [make("app-hidden", "amber"), make("accessibility-service", "amber"),
             make("sideloaded-app", "amber")]
    interview.adjust(items, {"physical_access": "yes"})
    assert [f["severity"] for f in items] == ["red", "red", "amber"]
    assert items[0]["evidence"]["context"] == ["physical access"]


def test_managed_answers_move_management_findings_both_ways():
    items = [make("device-owner", "amber"), make("work-profile", "info")]
    interview.adjust(items, {"managed": "no"})
    assert [f["severity"] for f in items] == ["red", "red"]
    items = [make("ios-mdm-profile", "amber"), make("device-owner", "amber")]
    interview.adjust(items, {"managed": "yes"})
    assert [f["severity"] for f in items] == ["info", "amber"]


def test_shared_account_raises_the_account_question():
    items = [make("accounts-review", "info", "phone accounts")]
    interview.adjust(items, {"shared_account": "yes"})
    assert items[0]["severity"] == "amber"


def test_since_range_covers_a_day_or_a_month():
    assert [str(d) for d in interview.since_range("2026-02")] == ["2026-02-01", "2026-02-28"]
    assert interview.since_range("2026-02-30") is None


def test_app_installed_near_the_worry_is_flagged_in_triage(case, no_apkid):
    """The fixture's dumpsys has org.example.hidden installed on 2026-10-10."""
    checks.check_apps(case)
    interview.save(case, {"since": "2026-10-01", "physical_access": "yes"})
    report.triage(case)
    found = {f["kind"]: f for f in report.load_findings(case) if f["subject"] == "org.example.hidden"}
    assert found["installed-near-suspicion"]["severity"] == "info"
    interview.save(case, {"since": "2025-01"})
    assert interview.near_suspicion(case, [], interview.load(case)) == []


def test_an_existing_finding_gets_the_flag_instead_of_a_new_one(case, no_apkid):
    checks.check_apps(case)
    items = [make("app-hidden", "amber", "org.example.hidden")]
    assert interview.near_suspicion(case, items, {"since": "2026-10"}) == []
    assert items[0]["severity"] == "red" and items[0]["evidence"]["installed_near_suspicion"] is True


def test_report_says_interview_done_and_shows_the_timeline_not_the_answers(case, no_apkid):
    checks.check_apps(case)
    interview.save(case, {"signs": "a secret sentence"})
    report.triage(case)
    report.build_report(case)
    text = (case.path / "report.md").read_text()
    assert "| Interview | done |" in text and "a secret sentence" not in text
    assert "## Install timeline" in text and "`org.example.hidden`" in text
