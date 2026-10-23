"""Task 4.1-4.3: exploited holes against the patch level, iOS releases, and
the IzzyOnDroid signers. All data is synthetic, built in the tests."""

import datetime as dt
import io
import json
import zipfile

from sta import checks, kbupdate, osinfo

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Android", "product": "Framework",
     "vulnerabilityName": "Android Framework EoP", "dateAdded": "2026-09-20"},
    # Listed by CISA long after its fix: dateAdded must not make it count.
    {"cveID": "CVE-2023-0002", "vendorProject": "Android", "product": "Kernel",
     "vulnerabilityName": "Old kernel bug", "dateAdded": "2026-10-01"},
    {"cveID": "CVE-2026-0003", "vendorProject": "Google", "product": "Pixel",
     "vulnerabilityName": "Pixel modem bug", "dateAdded": "2026-09-10"},
    {"cveID": "CVE-2026-0004", "vendorProject": "Google", "product": "Chromium V8",
     "vulnerabilityName": "V8 type confusion", "dateAdded": "2026-09-01"},
    {"cveID": "CVE-2026-0005", "vendorProject": "Android", "product": "Framework",
     "vulnerabilityName": "Not in OSV", "dateAdded": "2026-09-01"},
    {"cveID": "CVE-2026-1001", "vendorProject": "Apple", "product": "iOS and iPadOS",
     "vulnerabilityName": "Apple iOS WebKit bug", "dateAdded": "2026-08-01"},
    {"cveID": "CVE-2026-1002", "vendorProject": "Apple", "product": "macOS",
     "vulnerabilityName": "Apple macOS bug", "dateAdded": "2026-08-01"},
]}


def osv_zip(entries: dict[str, dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, entry in entries.items():
            archive.writestr(name, json.dumps(entry))
    return buf.getvalue()


def osv_entry(cve: str, *levels: str) -> dict:
    return {"id": f"ASB-A-{cve[-4:]}", "aliases": [cve],
            "affected": [{"ecosystem_specific": {"spl": level}} for level in levels]}


OSV = osv_zip({
    "a.json": osv_entry("CVE-2026-0001", "2026-10-01", "2026-11-01"),  # two branches: earliest wins
    "b.json": osv_entry("CVE-2023-0002", "2023-06-05"),
    "c.json": osv_entry("CVE-2026-0003", "2026-11-05"),
    "d.json": osv_entry("CVE-2026-0004", "2026-11-01"),
})


def android_device(patch="2026-09-05", maker="Google"):
    return {"security_patch": patch, "manufacturer": maker}


def test_android_kev_keeps_bulletin_products_with_a_known_fix():
    rows = {row["cve"]: row for row in osinfo.android_kev(KEV, OSV)}
    assert set(rows) == {"CVE-2026-0001", "CVE-2023-0002", "CVE-2026-0003"}  # no Chrome, no unknown fix
    assert rows["CVE-2026-0001"]["fixed_in"] == "2026-10-01"


def test_patch_is_compared_with_the_fix_not_with_date_added():
    out = osinfo.android_findings(android_device(), osinfo.android_kev(KEV, OSV))
    assert [(f["kind"], f["severity"]) for f in out] == [("outdated-os-exploited", "amber")]
    cves = {v["cveID"] for v in out[0]["evidence"]["vulnerabilities"]}
    assert cves == {"CVE-2026-0001", "CVE-2026-0003"}  # the 2023 one is fixed by a 2026 patch


def test_pixel_holes_only_count_on_a_pixel():
    out = osinfo.android_findings(android_device(maker="samsung"), osinfo.android_kev(KEV, OSV))
    assert {v["cveID"] for v in out[0]["evidence"]["vulnerabilities"]} == {"CVE-2026-0001"}


def test_an_up_to_date_patch_gives_nothing():
    assert osinfo.android_findings(android_device("2026-11-05"), osinfo.android_kev(KEV, OSV)) == []
    assert osinfo.android_findings({"security_patch": None}, osinfo.android_kev(KEV, OSV)) == []


def test_ios_kev_only_counts_ios():
    assert [row["cve"] for row in osinfo.ios_kev(KEV)] == ["CVE-2026-1001"]


RELEASES = [
    {"name": "27", "isMaintained": True, "latest": {"name": "27.0.1", "date": "2026-09-28"}},
    {"name": "26", "isMaintained": True, "latest": {"name": "26.7.1", "date": "2026-09-28"}},
    {"name": "18", "isMaintained": False, "latest": {"name": "18.7.9", "date": "2026-03-01"}},
]
TODAY = dt.date(2026, 10, 23)


def ios(version):
    return osinfo.ios_findings({"ios_version": version}, RELEASES, osinfo.ios_kev(KEV), TODAY)


def test_ios_behind_its_own_version_is_outdated():
    out = ios("26.1")
    assert [(f["kind"], f["severity"]) for f in out] == [("outdated-os", "amber")]
    ev = out[0]["evidence"]
    assert ev["latest_in_version"] == "26.7.1" and ev["days_since_latest"] == 25
    assert ev["kev_ios_count"] == 1 and "some may affect" in out[0]["detail"]


def test_newest_release_of_a_maintained_older_version_is_fine():
    assert ios("26.7.1") == [] and ios("27.0.1") == []


def test_unmaintained_version_is_outdated_even_on_its_last_release():
    out = ios("18.7.9")
    assert out and out[0]["evidence"]["maintained"] is False


def test_unknown_version_gives_nothing():
    assert ios("31.0") == [] and ios(None) == []


def test_signers_merge_both_repos_and_keep_a_failed_one(sandbox, monkeypatch):
    cache = kbupdate.CACHE_DIR
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "fdroid-signers.json").write_text(json.dumps({"org.old": ["OLD"]}))  # pre-Izzy format

    def index(*pairs):
        return {"packages": {name: {"versions": {"1": {"manifest": {"signer": {"sha256": [key]}}}}}
                             for name, key in pairs}}

    def fake_fetch(url, dest, **_):
        if "izzysoft" in url:
            raise OSError("mirror down")
        dest.write_text(json.dumps(index(("org.both", "aa"))))

    monkeypatch.setattr(kbupdate, "fetch", fake_fetch)
    assert kbupdate.refresh_signers() == ("ok", "failed: mirror down")
    signers = kbupdate.load_signers()
    assert signers["org.both"] == {"fdroid": ["AA"]}
    assert "org.old" not in signers  # F-Droid answered, so its old keys are replaced

    (cache / "fdroid-signers.json").write_text(json.dumps({"org.izzy": {"izzy": ["BB"]}}))
    assert kbupdate.refresh_signers()[1].startswith("failed")
    assert kbupdate.load_signers()["org.izzy"] == {"izzy": ["BB"]}  # Izzy failed: its keys stay


def test_sideloaded_app_signed_like_izzy_is_info():
    class Stores(checks.Stores):
        def __init__(self):
            self.signers = {"org.izzy.app": {"izzy": ["C" * 64]}}

        def on_play(self, package):
            return False

    out = checks.sideload_finding("org.izzy.app", "sideload", "org.fdroid.fdroid", "C" * 64, Stores(), {})
    assert (out["kind"], out["severity"]) == ("sideloaded-app", "info")
    assert "IzzyOnDroid" in out["detail"] and out["evidence"]["signature_repo"] == "IzzyOnDroid"
    other = checks.sideload_finding("org.izzy.app", "sideload", "x", "D" * 64, Stores(), {})
    assert other["kind"] == "sideloaded-store-app" and "IzzyOnDroid build" in other["detail"]


def test_check_android_reads_the_cached_kev_extract(case, no_apkid):
    """update-kb leaves kev-android.json in kb/cache; check-apps only reads it."""
    rows = [{"cve": "CVE-2026-0001", "name": "Android Framework EoP", "product": "Framework",
             "date_added": "2026-09-20", "fixed_in": "2026-11-01"}]
    (checks.CACHE_DIR / "kev-android.json").write_text(json.dumps(rows))
    found = [f for f in checks.check_android(case) if f["kind"] == "outdated-os-exploited"]
    assert len(found) == 1 and found[0]["evidence"]["security_patch"] == "2026-10-05"


def test_holes_without_a_fix_level_are_counted():
    assert osinfo.android_kev_total(KEV) - len(osinfo.android_kev(KEV, OSV)) == 1  # CVE-2026-0005
