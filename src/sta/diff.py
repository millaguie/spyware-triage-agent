"""Follow-up check: what changed on the same phone between two cases.

Compares what both cases still hold: package details and accounts (Android,
until purge), iPhone profiles, and the findings (always kept). The result is
diff-from-<older case>.md in the newer case. Accounts are compared by their
HMAC only, so the file says "1 new Google account", never which."""

from sta.common import Case, StepError, read_json, say


def finding_keys(case: Case) -> dict[tuple[str, str], dict]:
    from sta.report import load_findings
    return {(f["kind"], f["subject"]): f for f in load_findings(case)}


def ios_profiles(case: Case) -> set[str]:
    data = read_json(case.acquisition_dir / "ios-quick" / "profiles.json") or {}
    meta = data.get("ProfileMetadata") or {}
    return {str(m.get("PayloadDisplayName") or key) for key, m in meta.items()}


def compare(old: Case, new: Case) -> list[str]:
    lines = [f"# Changes from {old.path.name} to {new.path.name}", ""]
    if old.platform != new.platform:
        lines += [f"The two cases are of different platforms ({old.platform}, {new.platform}).", ""]

    a, b = read_json(old.path / "package-details.json"), read_json(new.path / "package-details.json")
    if a is not None and b is not None:
        added, removed = sorted(b.keys() - a.keys()), sorted(a.keys() - b.keys())
        updated = sorted(n for n in a.keys() & b.keys() if a[n].get("last_update") != b[n].get("last_update"))
        lines += ["## Apps", "", f"New: {len(added)} · Removed: {len(removed)} · Updated: {len(updated)}", ""]
        lines += [f"- new: `{n}` (installed {b[n].get('first_install') or '?'})" for n in added]
        lines += [f"- removed: `{n}`" for n in removed]
        lines += [f"- updated: `{n}` ({b[n].get('last_update')})" for n in updated]
        granted = []
        for n in sorted(a.keys() & b.keys()):
            extra = sorted(set(b[n].get("granted") or []) - set(a[n].get("granted") or []))
            if extra:
                granted.append(f"- `{n}`: {', '.join(p.removeprefix('android.permission.') for p in extra)}")
        if granted:
            lines += ["", "### Permissions granted since the first check", "", *granted]
        lines.append("")
    else:
        lines += ["App details are missing from one case (purged, or an iPhone): apps not compared.", ""]

    acc_a, acc_b = read_json(old.path / "accounts.json"), read_json(new.path / "accounts.json")
    if acc_a is not None and acc_b is not None:
        new_google = len(set(acc_b.get("google_accounts") or []) - set(acc_a.get("google_accounts") or []))
        gone_google = len(set(acc_a.get("google_accounts") or []) - set(acc_b.get("google_accounts") or []))
        types = {t: acc_b["by_type"].get(t, 0) - acc_a.get("by_type", {}).get(t, 0)
                 for t in set(acc_b.get("by_type", {})) | set(acc_a.get("by_type", {}))}
        lines += ["## Accounts", "", f"- {new_google} new Google account(s), {gone_google} removed."]
        lines += [f"- {t}: {'+' if d > 0 else ''}{d}" for t, d in sorted(types.items()) if d and t != "com.google"]
        lines.append("")

    pa, pb = ios_profiles(old), ios_profiles(new)
    if pa or pb:
        lines += ["## iPhone profiles", ""]
        lines += [f"- new: «{p}»" for p in sorted(pb - pa)] + [f"- removed: «{p}»" for p in sorted(pa - pb)]
        lines += ["- no change"] if pa == pb else []
        lines.append("")

    fa, fb = finding_keys(old), finding_keys(new)
    lines += ["## Findings", ""]
    for label, keys, source in (("new", fb.keys() - fa.keys(), fb), ("resolved", fa.keys() - fb.keys(), fa)):
        for key in sorted(keys, key=lambda k: (k[0], k[1])):
            f = source[key]
            lines.append(f"- {label}: {f['severity']} `{f['kind']}` on `{f['subject']}`")
    for key in sorted(fa.keys() & fb.keys()):
        if fa[key]["severity"] != fb[key]["severity"]:
            lines.append(f"- changed: `{key[0]}` on `{key[1]}` from {fa[key]['severity']} to {fb[key]['severity']}")
    if fa.keys() == fb.keys() and all(fa[k]["severity"] == fb[k]["severity"] for k in fa):
        lines.append("- no change")
    lines.append("")
    return lines


def diff(old_id: str, new_id: str, cases_dir) -> None:
    old, new = Case(cases_dir / old_id), Case(cases_dir / new_id)
    for case in (old, new):
        if "/" in case.path.name or not case.state_file.exists():
            raise StepError(f"No case {case.path.name}. ./sta cases lists them.")
    if "triage" not in old.state.get("steps", {}) or "triage" not in new.state.get("steps", {}):
        raise StepError("Both cases need triage done before they can be compared.")
    out = new.path / f"diff-from-{old.path.name}.md"
    out.write_text("\n".join(compare(old, new)), encoding="utf-8")
    say(f"Wrote {out}")
