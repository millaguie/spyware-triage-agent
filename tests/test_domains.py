"""Task 4.6 and 4.4: domains inside app code against MVT's STIX indicators,
and the abuse.ch lookups. Synthetic dex bytes and STIX, no network."""

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from sta import abusech, apkscan, checks, domains

FIXTURES = Path(__file__).resolve().parent / "fixtures"
STIX = FIXTURES / "mvt-indicators" / "test.stix2"


def apk(path: Path, *strings: str) -> Path:
    """A zip with one classes.dex holding these strings among other bytes."""
    body = b"\x00dex\n035\x00" + b"\x00".join(s.encode() for s in strings) + b"\x00" * 64
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", body)
        archive.writestr("res/raw/notes.txt", "https://not-in-dex.example.xyz")
    return path


def test_dex_domains_skip_the_allowlist_and_other_files(tmp_path):
    path = apk(tmp_path / "a.apk", "https://evil-c2.example.xyz/api", "https://www.google.com/x",
               "Lcom/example/Foo;", "cdn.sub.amazonaws.com")
    assert domains.dex_domains(path, ["google.com", "amazonaws.com"]) == ["evil-c2.example.xyz"]


def test_broken_apk_gives_no_domains(tmp_path):
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a zip")
    assert domains.dex_domains(bad, []) == []


def test_stix_domains_take_the_malware_name():
    found = domains.stix_domains(STIX.parent)
    assert found["evil-c2.example.xyz"] == ("test.stix2", "TestSpy")
    assert found["tracker-spy.top"][0] == "test.stix2"


def test_a_subdomain_matches_its_parent_indicator():
    hits = domains.match(["api.tracker-spy.top", "fine.example.com"], {"tracker-spy.top": ("f", "n")})
    assert [h["domain"] for h in hits] == ["api.tracker-spy.top"]
    assert domains.match(["notevil-c2.example.xyz"], {"evil-c2.example.xyz": ("f", "n")}) == []


@pytest.fixture
def indicators(sandbox):
    folder = sandbox / "mvt" / "indicators"
    folder.mkdir(parents=True)
    shutil.copy(STIX, folder)
    return folder


def run_pass(tmp_path, strings, findings=None):
    path = apk(tmp_path / "x.apk", *strings)
    raw, found = {}, list(findings or [])
    out = apkscan.domain_pass({"org.example.app": [path]}, raw, found, set())
    return out, raw, found


def test_one_match_is_amber_and_domains_are_kept(tmp_path, indicators):
    out, raw, found = run_pass(tmp_path, ["https://evil-c2.example.xyz/api"])
    assert out == {"org.example.app": ["evil-c2.example.xyz"]}
    assert raw["org.example.app"]["domains"] == ["evil-c2.example.xyz"]
    assert [(f["kind"], f["severity"]) for f in found] == [("ioc-domain-in-app", "amber")]
    assert found[0]["evidence"]["indicator_name"] == "TestSpy"


def test_red_next_to_a_hidden_app(tmp_path, indicators):
    hidden = checks.finding("app-hidden", "red", "org.example.app", "hidden")
    _, _, found = run_pass(tmp_path, ["evil-c2.example.xyz"], [hidden])
    assert ("ioc-domain-in-app", "red") in {(f["kind"], f["severity"]) for f in found}


def test_many_matches_look_like_a_blocklist(tmp_path, indicators):
    many = {"type": "bundle", "objects": [
        {"type": "indicator", "id": f"i{n}", "pattern": f"[domain-name:value = 'bad{n}.example.top']"}
        for n in range(domains.MANY)]}
    (indicators / "many.stix2").write_text(json.dumps(many))
    _, _, found = run_pass(tmp_path, [f"bad{n}.example.top" for n in range(domains.MANY)])
    assert [(f["kind"], f["severity"]) for f in found] == [("ioc-domain-in-app", "info")]
    assert "blockers" in found[0]["detail"]


def test_no_indicators_no_finding(tmp_path, sandbox):
    out, _, found = run_pass(tmp_path, ["evil-c2.example.xyz"])
    assert out and found == []


class FakeCase:
    def __init__(self, path, network=True, consent=True):
        self.path, self.network = path, network
        self.state = {"abusech": consent}


def fake_post(answers):
    def post(url, body, key, content_type):
        if "mb-api" in url:
            return answers["bazaar"]
        return answers["threatfox"]
    return post


def test_abusech_needs_key_network_and_its_own_yes(tmp_path, monkeypatch):
    monkeypatch.setattr(abusech, "post", lambda *a: pytest.fail("must not ask"))
    targets = {"org.x": ["a" * 64]}
    assert abusech.check(FakeCase(tmp_path), targets, {}) == []  # no key
    monkeypatch.setenv("STA_ABUSECH_API_KEY", "k")
    assert abusech.check(FakeCase(tmp_path, network=False), targets, {}) == []
    assert abusech.check(FakeCase(tmp_path, consent=False), targets, {}) == []


def test_bazaar_and_threatfox_hits_are_red_and_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("STA_ABUSECH_API_KEY", "k")
    monkeypatch.setattr("time.sleep", lambda s: None)
    calls = []
    answers = {"bazaar": {"query_status": "ok", "data": [{"signature": "SpyNote", "tags": ["rat"]}]},
               "threatfox": {"query_status": "ok", "data": [
                   {"malware_printable": "SpyNote", "confidence_level": 75},
                   {"malware_printable": "Other", "confidence_level": 20}]}}

    def post(url, body, key, content_type):
        calls.append(url)
        return fake_post(answers)(url, body, key, content_type)

    monkeypatch.setattr(abusech, "post", post)
    case = FakeCase(tmp_path)
    out = abusech.check(case, {"org.x": ["A" * 64]}, {"org.x": ["c2.example.xyz"]})
    assert [(f["kind"], f["severity"]) for f in out] == [("known-malware", "red"), ("c2-domain", "red")]
    assert out[0]["evidence"]["source"] == "MalwareBazaar" and out[1]["evidence"]["malware"] == "SpyNote"
    abusech.check(case, {"org.x": ["A" * 64]}, {"org.x": ["c2.example.xyz"]})
    assert len(calls) == 2  # the second run answers from abusech.json


def test_low_confidence_and_unknown_give_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("STA_ABUSECH_API_KEY", "k")
    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr(abusech, "post", fake_post({
        "bazaar": {"query_status": "hash_not_found"},
        "threatfox": {"query_status": "ok", "data": [{"malware_printable": "X", "confidence_level": 10}]}}))
    assert abusech.check(FakeCase(tmp_path), {"org.x": ["a" * 64]}, {"org.x": ["d.example.top"]}) == []


def test_a_refused_key_stops_the_lookups(tmp_path, monkeypatch):
    monkeypatch.setenv("STA_ABUSECH_API_KEY", "bad")
    monkeypatch.setattr("time.sleep", lambda s: None)
    calls = []

    def refuse(*args):
        calls.append(1)
        raise abusech.Refused("abuse.ch answered 401")

    monkeypatch.setattr(abusech, "post", refuse)
    out = abusech.check(FakeCase(tmp_path), {"org.x": ["a" * 64, "b" * 64]}, {"org.x": ["d.example.top"]})
    assert out == [] and len(calls) == 1
    assert not (tmp_path / "abusech.json").exists()  # nothing cached from a refusal


def test_exodus_signatures_become_dex_prefixes():
    from sta import trackers
    api = {"trackers": {"1": {"name": "Teemo", "code_signature": "com.databerries.|com.geolocstation."},
                        "2": {"name": "No code", "code_signature": ""}}}
    assert trackers.reduce(api) == {"Teemo": ["Lcom/databerries/", "Lcom/geolocstation/"]}


def test_trackers_go_into_apk_scan_and_finding_evidence(tmp_path, sandbox):
    from sta import trackers
    (trackers.CACHE_DIR / trackers.TRACKERS_NAME).write_text(json.dumps(
        {"Firebase Analytics": ["Lcom/google/firebase/analytics/"], "Teemo": ["Lcom/databerries/"]}))
    path = apk(tmp_path / "t.apk", "Lcom/google/firebase/analytics/FirebaseAnalytics;")
    raw = {}
    apkscan.domain_pass({"org.example.app": [path]}, raw, [], set())
    assert raw["org.example.app"]["trackers"] == ["Firebase Analytics"]
