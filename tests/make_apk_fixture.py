"""Build tests/fixtures/apks/org.schabi.newpipe.apk from a public APK.

Run by hand when the fixture needs a refresh:

    .venv/bin/python tests/make_apk_fixture.py <path-to-newpipe.apk>

The source must be the NewPipe (or F-Droid) APK of an acquisition: both are
open-source apps on public stores, so their AndroidManifest.xml is not personal
data. The fixture keeps ONLY the manifest and adds a 4 KB classes.dex of zeros;
pyaxmlparser parses that zip fine. resources.arsc is NOT copied (it is 5 MB),
so get_app_name() on the fixture returns the raw "@7f..." reference instead of
the resolved label; tests must compare against the reference, not "NewPipe".
"""

import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "fixtures" / "apks" / "org.schabi.newpipe.apk"


def main(src: Path) -> None:
    with zipfile.ZipFile(src) as zin:
        if "AndroidManifest.xml" not in zin.namelist():
            sys.exit(f"{src} has no AndroidManifest.xml (is it a real APK?)")
        manifest = zin.read("AndroidManifest.xml")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        zout.writestr("AndroidManifest.xml", manifest)
        zout.writestr("classes.dex", b"\x00" * 4096)
    shutil.move(tmp, OUT)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
