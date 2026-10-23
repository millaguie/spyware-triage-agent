"""VirusTotal lookups for apps from outside a store.

Only SHA-256 hashes go out, never the APKs. A free API key allows 4 lookups
a minute and 500 a day, so we look up only the apps that no store checked,
wait STA_VT_DELAY seconds (default 15) between lookups, and keep the answers
in the case so a second run asks nothing again. One engine out of seventy is
often a false positive; that is why a few detections are amber, not red."""

import json
import os
import time
import urllib.error
import urllib.request

from sta.common import read_json, say, write_json

API = "https://www.virustotal.com/api/v3/files/"
RED_FROM = 5  # malicious verdicts from this many engines or more


def api_key() -> str | None:
    return os.environ.get("MVT_VT_API_KEY") or os.environ.get("VT_API_KEY")


def lookup(sha256: str, key: str) -> dict | None:
    """Stats for a known file, {} if VirusTotal has never seen it.
    Raises PermissionError when the key is wrong or the quota is used up."""
    req = urllib.request.Request(API + sha256, headers={"x-apikey": key, "User-Agent": "spyware-triage-agent"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            attrs = json.load(resp)["data"]["attributes"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        if exc.code in (401, 403, 429):
            raise PermissionError(f"VirusTotal answered {exc.code}")
        return None
    except (urllib.error.URLError, TimeoutError):
        return None
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return {"stats": attrs.get("last_analysis_stats", {}),
            "label": label,
            "names": attrs.get("names", [])[:5]}


def check(case, targets: dict[str, list[str]]) -> list[dict]:
    """`targets` maps package name to the SHA-256 of its APK files."""
    from sta.checks import finding

    key = api_key()
    # Its own consent: VirusTotal keeps the hashes, linked to the operator's key.
    if not key or not case.network or not case.state.get("virustotal"):
        return []
    cache_file = case.path / "virustotal.json"
    cache = read_json(cache_file) or {}
    todo = sorted({h.lower() for hashes in targets.values() for h in hashes if h} - set(cache))
    delay = float(os.environ.get("STA_VT_DELAY", "15"))
    if todo:
        say(f"Looking up {len(todo)} APK hashes on VirusTotal (about {int(len(todo) * delay // 60) + 1} min)...")
    for number, sha in enumerate(todo):
        if number and delay:
            time.sleep(delay)
        try:
            result = lookup(sha, key)
        except PermissionError as exc:
            say(f"WARNING: {exc}. VirusTotal lookups stop here; the rest stay unchecked.")
            break
        if result is not None:
            cache[sha] = result
            write_json(cache_file, cache)

    findings = []
    for name, hashes in sorted(targets.items()):
        for sha in sorted({h.lower() for h in hashes if h}):
            result = cache.get(sha) or {}
            bad = result.get("stats", {}).get("malicious", 0)
            if not bad:
                continue
            total = sum((result.get("stats") or {}).values())
            findings.append(finding(
                "virustotal-detections", "red" if bad >= RED_FROM else "amber", name,
                f"{bad} of {total} antivirus engines on VirusTotal flag this APK"
                + (f" ({result['label']})." if result.get("label") else "."),
                package=name, sha256=sha, malicious=bad, engines=total, label=result.get("label"),
                link=f"https://www.virustotal.com/gui/file/{sha}"))
    unchecked = sum(1 for hashes in targets.values() for h in hashes if h and h.lower() not in cache)
    if unchecked:
        say(f"VirusTotal: {unchecked} APK hash(es) not checked. Run ./sta check-apps again later.")
    return findings
