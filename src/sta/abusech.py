"""abuse.ch lookups: MalwareBazaar for APK hashes, ThreatFox for domains.

Needs a free key (STA_ABUSECH_API_KEY) and its own yes in new-case, like
VirusTotal: abuse.ch logs what it is asked. Only apps from outside a store
are looked up: their SHA-256, and the domain names found inside their code.
That is the one lookup that sends more than package names, hashes and
versions, and the new-case question says so."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from sta.common import cached_fetch, say

BAZAAR = "https://mb-api.abuse.ch/api/v1/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
MIN_CONFIDENCE = 50  # ThreatFox's own scale, 0 to 100


class Refused(Exception):
    """abuse.ch said no (wrong key, quota): stop asking. Not an OSError on
    purpose, so cached_fetch lets it through instead of treating it as 'no answer'."""


def api_key() -> str | None:
    return os.environ.get("STA_ABUSECH_API_KEY")


def post(url: str, body: bytes, key: str, content_type: str) -> dict:
    req = urllib.request.Request(url, data=body, headers={
        "Auth-Key": key, "Content-Type": content_type, "User-Agent": "spyware-triage-agent"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 429):
            raise Refused(f"abuse.ch answered {exc.code}") from exc
        raise


def bazaar(sha256: str, key: str) -> dict | None:
    """{} when MalwareBazaar does not know the file, its summary when it does,
    None when the answer is not definite (not cached)."""
    data = post(BAZAAR, urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode(), key,
                "application/x-www-form-urlencoded")
    status = data.get("query_status")
    if status in ("hash_not_found", "no_results"):
        return {}
    if status != "ok" or not data.get("data"):
        return None
    item = data["data"][0]
    return {"signature": item.get("signature"), "tags": item.get("tags") or [],
            "first_seen": item.get("first_seen")}


def threatfox(domain: str, key: str) -> dict | None:
    data = post(THREATFOX, json.dumps({"query": "search_ioc", "search_term": domain}).encode(), key,
                "application/json")
    status = data.get("query_status")
    if status == "no_result":
        return {}
    if status != "ok":
        return None
    hits = [item for item in data.get("data") or []
            if int(item.get("confidence_level") or 0) >= MIN_CONFIDENCE]
    if not hits:
        return {}
    best = max(hits, key=lambda item: int(item.get("confidence_level") or 0))
    return {"malware": best.get("malware_printable") or best.get("malware"),
            "confidence": int(best.get("confidence_level") or 0), "first_seen": best.get("first_seen")}


def check(case, hashes: dict[str, list[str]], domains: dict[str, list[str]]) -> list[dict]:
    """`hashes` and `domains` map each app from outside a store to its APK
    SHA-256s and the domains in its code."""
    from sta.checks import finding

    key = api_key()
    if not key or not case.network or not case.state.get("abusech"):
        return []
    todo = sum(len({h for h in v if h}) for v in hashes.values()) + sum(len(v) for v in domains.values())
    if todo:
        say(f"Looking up {todo} APK hashes and domains on abuse.ch...")
    out = []
    for name, shas in sorted(hashes.items()):
        for sha in sorted({h.lower() for h in shas if h}):
            try:
                hit = cached_fetch(case, "abusech.json", f"bazaar:{sha}", lambda sha=sha: bazaar(sha, key))
            except Refused as exc:
                say(f"WARNING: {exc}. abuse.ch lookups stop here; the rest stay unchecked.")
                return out
            if hit:
                out.append(finding("known-malware", "red", name,
                                   f"MalwareBazaar knows this exact APK as «{hit.get('signature') or 'malware'}».",
                                   package=name, sha256=sha, source="MalwareBazaar", family=hit.get("signature"),
                                   tags=hit.get("tags"), link=f"https://bazaar.abuse.ch/sample/{sha}/"))
    for name, names in sorted(domains.items()):
        for domain in names:
            try:
                hit = cached_fetch(case, "abusech.json", f"threatfox:{domain}", lambda domain=domain: threatfox(domain, key))
            except Refused as exc:
                say(f"WARNING: {exc}. abuse.ch lookups stop here; the rest stay unchecked.")
                return out
            if hit:
                out.append(finding("c2-domain", "red", name,
                                   f"Code inside «{name}» contains the domain «{domain}», listed by ThreatFox "
                                   f"as a command-and-control server of «{hit.get('malware')}».",
                                   package=name, domain=domain, source="ThreatFox", **hit))
    return out
