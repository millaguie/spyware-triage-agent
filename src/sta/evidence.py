"""Chain of custody: seal a case, check it later, export it, encrypt it.

- seal: MANIFEST.sha256 lists the hash of every file in the case, in
  `sha256sum` format, so `sha256sum -c` works without this tool. With the
  OpenTimestamps client (`ots`) and network consent, `ots stamp` adds a proof
  of when it existed; only the manifest's hash goes out.
- verify: says which files changed, appeared or went missing since the seal.
- export: a tar.gz for a specialist (report, findings, results, manifest),
  never the raw acquisition or the secrets. Optionally encrypted with age.
- seal --encrypt: the phone data (acquisition/, decrypted/, mvt-results/)
  becomes one phone-data.tar.age for an age public key. The private key is
  never created or kept here: next to the data it would protect nothing."""

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from sta.common import Case, StepError, now, run, say, sha256_file, which

MANIFEST = "MANIFEST.sha256"
# Not covered by the manifest: the manifest itself, its timestamp proof, the
# lock, and state.json, which the seal itself changes.
UNSEALED = {MANIFEST, MANIFEST + ".ots", ".lock", "state.json"}
PHONE_DATA = ("acquisition", "decrypted", "mvt-results")
ENCRYPTED = "phone-data.tar.age"
EXPORT_FILES = ("report.md", "findings.json", "notes.json", "apk-scan.json", MANIFEST, MANIFEST + ".ots")


def case_files(case: Case) -> list[Path]:
    return sorted(p for p in case.path.rglob("*")
                  if p.is_file() and p.relative_to(case.path).parts[0] not in UNSEALED)


def manifest_lines(case: Case) -> list[str]:
    return [f"{sha256_file(p)}  {p.relative_to(case.path).as_posix()}" for p in case_files(case)]


def age_command() -> str:
    found = which("age")
    if not found:
        raise StepError("age is not installed. Install it (apt install age, brew install age, "
                        "pacman -S age) or run ./install.sh again.")
    return found


def check_recipient(recipient: str) -> None:
    if not recipient.startswith("age1") or len(recipient) < 50:
        raise StepError("That is not an age public key (it starts with age1). Create the key pair on "
                        "another device with `age-keygen -o key.txt`, keep key.txt there, and pass the "
                        "line 'Public key: age1...' here. The private key must not live on this computer.")


def encrypt_phone_data(case: Case, recipient: str) -> None:
    check_recipient(recipient)
    folders = [name for name in PHONE_DATA if (case.path / name).exists()]
    if not folders:
        raise StepError("There is no phone data left to encrypt in this case.")
    target = case.path / ENCRYPTED
    if target.exists():
        raise StepError(f"{ENCRYPTED} already exists. Run ./sta unseal first.")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in folders:
            tar.add(case.path / name, arcname=name)
    tmp = target.with_suffix(".tmp")
    subprocess.run([age_command(), "-r", recipient, "-o", str(tmp)], input=buf.getvalue(), check=True)
    tmp.replace(target)
    for name in folders:
        shutil.rmtree(case.path / name)
    say(f"Encrypted {', '.join(folders)} into {ENCRYPTED} and deleted the originals.")
    say("Only the holder of the private key for that public key can read it now.")


def seal(case: Case, recipient: str | None = None) -> None:
    if recipient:
        encrypt_phone_data(case, recipient)
    lines = manifest_lines(case)
    text = "\n".join(lines) + "\n"
    (case.path / MANIFEST).write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode()).hexdigest()
    stamped = False
    ots = which("ots")
    if ots and case.network:
        proc = run([ots, "stamp", str(case.path / MANIFEST)], check=False)
        stamped = proc.returncode == 0
        if stamped:
            say("OpenTimestamps proof requested. It completes in a few hours: then run "
                f"`ots upgrade {case.path / MANIFEST}.ots`.")
    elif not ots:
        say("No OpenTimestamps client (ots): the manifest has no timestamp proof. "
            "Optional: pipx install opentimestamps-client.")
    case.state["sealed"] = {"at": now(), "manifest_sha256": digest, "files": len(lines),
                            "timestamped": stamped, "encrypted": bool(recipient)}
    case.save()
    say(f"Sealed {len(lines)} files. {MANIFEST} sha256: {digest}")


def parse_manifest(lines: list[str]) -> dict[str, str]:
    """{path: sha256} from `sha256sum` lines."""
    out = {}
    for line in lines:
        if line:
            digest, name = line.split("  ", 1)
            out[name] = digest
    return out


def verify(case: Case) -> bool:
    path = case.path / MANIFEST
    if not path.exists():
        raise StepError("This case was never sealed. Run ./sta seal first.")
    sealed = parse_manifest(path.read_text(encoding="utf-8").splitlines())
    now_ = parse_manifest(manifest_lines(case))
    changed = sorted(n for n in sealed.keys() & now_.keys() if sealed[n] != now_[n])
    missing, added = sorted(sealed.keys() - now_.keys()), sorted(now_.keys() - sealed.keys())
    for label, names in (("CHANGED", changed), ("MISSING", missing), ("NEW", added)):
        for name in names:
            say(f"{label}: {name}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != (case.state.get("sealed") or {}).get("manifest_sha256"):
        say(f"WARNING: {MANIFEST} itself differs from the one recorded at seal time.")
        return False
    if changed or missing or added:
        return False
    say(f"OK: all {len(sealed)} files match the seal of {case.state['sealed']['at']}.")
    return True


def flagged_apks(case: Case) -> list[Path]:
    """APK files of apps with a red or amber finding (Android)."""
    from sta.apkscan import apk_files
    from sta.report import load_findings

    folder = case.acquisition_dir / "androidqf"
    names = sorted({f["subject"] for f in load_findings(case) if f["severity"] in ("red", "amber")})
    return [p for paths in apk_files(folder, names).values() for p in paths] if folder.exists() else []


def export(case: Case, dest: Path, with_apks: bool = False, recipient: str | None = None) -> None:
    if not (case.path / "report.md").exists():
        raise StepError("No report yet. Run ./sta report first.")
    if recipient:
        check_recipient(recipient)
    members: list[tuple[Path, str]] = [(case.path / name, name) for name in EXPORT_FILES
                                       if (case.path / name).exists()]
    for folder in ("mvt-results",):
        for p in sorted((case.path / folder).glob("*.json")) if (case.path / folder).exists() else []:
            members.append((p, f"{folder}/{p.name}"))
    if with_apks:
        members += [(p, f"apks/{p.name}") for p in flagged_apks(case)]
    # state.json without the phone's serial or UDID: the report leaves them out too.
    state = json.loads(json.dumps(case.state))
    for key in ("serial", "udid"):
        (state.get("device") or {}).pop(key, None)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        root = case.path.name
        for path, name in members:
            tar.add(path, arcname=f"{root}/{name}")
        data = json.dumps(state, indent=2, ensure_ascii=False).encode()
        info = tarfile.TarInfo(f"{root}/state.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    body = buf.getvalue()
    if recipient:
        body = subprocess.run([age_command(), "-r", recipient], input=body, check=True,
                              capture_output=True).stdout
    dest.write_bytes(body)
    dest.chmod(0o600)
    say(f"Exported {len(members) + 1} files to {dest}" + (" (encrypted with age)." if recipient else "."))
    say("It holds no raw acquisition and no secrets.")


def unseal(case: Case, identity: Path) -> None:
    target = case.path / ENCRYPTED
    if not target.exists():
        raise StepError(f"No {ENCRYPTED} in this case.")
    if not identity.exists():
        raise StepError(f"No identity file at {identity}.")
    proc = subprocess.run([age_command(), "-d", "-i", str(identity), str(target)], capture_output=True)
    if proc.returncode != 0:
        raise StepError(f"age could not decrypt it: {proc.stderr.decode(errors='replace').strip()}")
    with tarfile.open(fileobj=io.BytesIO(proc.stdout)) as tar:
        tar.extractall(case.path, filter="data")  # refuses absolute paths and ../
    target.unlink()
    say(f"Restored {', '.join(name for name in PHONE_DATA if (case.path / name).exists())}. "
        "The old seal no longer matches: run ./sta seal again when done.")
