"""Is the phone's operating system behind on exploited holes?

Three public sources, downloaded by update-kb into kb/cache/ (nothing about
the phone goes out):

- CISA KEV: vulnerabilities exploited in the wild. Its `dateAdded` is when
  CISA listed a hole, not when it was fixed, so it is never compared with the
  phone's patch or version.
- OSV, Android ecosystem: the Android security bulletins. Each entry gives
  `spl`, the security patch level that fixes it. That is what the phone's
  patch is compared with.
- endoflife.date: the newest release of each iOS and Android version."""

import io
import json
import re
import zipfile

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_ANDROID_URL = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
EOL_URL = "https://endoflife.date/api/v1/products/{}"

# KEV products patched by the monthly Android bulletin. Chrome and its parts
# (Skia, Dawn, V8) are updated through Play, not by the security patch.
ANDROID_PRODUCTS = {"Android Kernel", "Android OS", "Framework", "Kernel", "Pixel", "Runtime"}
EVIDENCE_LIMIT = 10


def android_kev(kev: dict, osv_zip: bytes) -> list[dict]:
    """KEV holes of Android with the patch level that fixes them.

    One hole can have several OSV entries (one per Android version branch);
    the earliest `spl` is kept, so a phone counts as exposed only when its patch
    is older than every fix. Holes OSV does not list are left out."""
    fixed: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(osv_zip)) as archive:
        for name in archive.namelist():
            entry = json.loads(archive.read(name))
            levels = [str(spl) for item in entry.get("affected", [])
                      if (spl := (item.get("ecosystem_specific") or {}).get("spl"))]
            if not levels:
                continue
            for alias in [entry.get("id", ""), *entry.get("aliases", [])]:
                if alias.startswith("CVE-"):
                    fixed[alias] = min([*levels, *([fixed[alias]] if alias in fixed else [])])
    out = []
    for vuln in kev.get("vulnerabilities", []):
        if vuln.get("vendorProject") not in ("Android", "Google") or vuln.get("product") not in ANDROID_PRODUCTS:
            continue
        if vuln["cveID"] in fixed:
            out.append({"cve": vuln["cveID"], "name": vuln.get("vulnerabilityName", ""),
                        "product": vuln["product"], "date_added": vuln.get("dateAdded", ""),
                        "fixed_in": fixed[vuln["cveID"]]})
    return sorted(out, key=lambda item: item["fixed_in"], reverse=True)


def android_kev_total(kev: dict) -> int:
    """Android holes in KEV that the bulletin patch should fix, with or without OSV data."""
    return sum(1 for v in kev.get("vulnerabilities", [])
               if v.get("vendorProject") in ("Android", "Google") and v.get("product") in ANDROID_PRODUCTS)


def ios_kev(kev: dict) -> list[dict]:
    """KEV holes that name iOS. KEV does not say which iOS version fixed them,
    so these are only counted, as context."""
    out = []
    for vuln in kev.get("vulnerabilities", []):
        text = f"{vuln.get('product', '')} {vuln.get('vulnerabilityName', '')} {vuln.get('shortDescription', '')}"
        if vuln.get("vendorProject") == "Apple" and re.search(r"\biOS\b", text):
            out.append({"cve": vuln["cveID"], "name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", "")})
    return out


def eol_releases(data: dict) -> list[dict]:
    """endoflife.date API v1: the list of release cycles, newest first."""
    return (data.get("result") or {}).get("releases") or []


def version_tuple(text: str | None) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text or ""))


def android_findings(device: dict, kev_android: list[dict]) -> list[dict]:
    from sta.checks import finding

    patch = device.get("security_patch") or ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", patch):
        return []
    # Pixel-only holes are fixed in the Pixel bulletin; other makers never had them.
    pixel = (device.get("manufacturer") or "").lower() == "google"
    open_holes = [item for item in kev_android
                  if item["fixed_in"] > patch and (pixel or item["product"] != "Pixel")]
    if not open_holes:
        return []
    return [finding("outdated-os-exploited", "amber", "Android security patch",
                    f"The phone's security patch ({patch}) is older than the fix for "
                    f"{len(open_holes)} vulnerabilit{'y' if len(open_holes) == 1 else 'ies'} that CISA "
                    "reports as exploited in the wild.",
                    security_patch=patch, count=len(open_holes),
                    vulnerabilities=[{"cveID": item["cve"], "vulnerabilityName": item["name"],
                                      "dateAdded": item["date_added"], "fixed_in": item["fixed_in"]}
                                     for item in open_holes[:EVIDENCE_LIMIT]])]


def ios_findings(device: dict, releases: list[dict], kev_ios: list[dict], today) -> list[dict]:
    """outdated-os when the iPhone is behind the newest release of its own iOS
    version, or its version gets no more updates. A phone on the newest release
    of an older version Apple still maintains is not outdated."""
    from sta.checks import finding

    installed = device.get("ios_version")
    have = version_tuple(installed)
    if not have or not releases:
        return []
    cycle = next((r for r in releases if version_tuple(r.get("name"))[:1] == have[:1]), None)
    if cycle is None:
        return []  # a version endoflife.date does not list yet: nothing to compare
    newest = releases[0]
    latest = cycle.get("latest") or {}
    behind = bool(latest.get("name")) and have < version_tuple(latest["name"])
    unmaintained = not cycle.get("isMaintained", True)
    if not (behind or unmaintained):
        return []
    since = None
    if latest.get("date"):
        try:
            import datetime as dt
            since = (today - dt.date.fromisoformat(latest["date"])).days
        except ValueError:
            pass
    why = (f"iOS {installed} is older than {latest['name']}, the newest release of iOS {cycle['name']}"
           if behind else f"iOS {cycle['name']} no longer gets updates")
    detail = (f"{why}. The newest iOS is {(newest.get('latest') or {}).get('name') or newest.get('name')}. "
              f"CISA lists {len(kev_ios)} iOS vulnerabilities as exploited in the wild; some may affect "
              "this version.")
    return [finding("outdated-os", "amber", "iOS version", detail,
                    installed=installed, latest_in_version=latest.get("name"),
                    latest_date=latest.get("date"), days_since_latest=since,
                    newest=(newest.get("latest") or {}).get("name"),
                    maintained=not unmaintained, kev_ios_count=len(kev_ios))]
