"""Build the conformance fixtures as one archive that anyone can rebuild
byte for byte, for a versioned release of the suite.

    python tools/fixture_archive.py VERSION [OUT_DIR]

writes OUT_DIR/fm-verify-fixtures-VERSION.tar (default OUT_DIR: dist/) and
prints its SHA-256. The archive holds fixtures/ as committed, under a top
directory fm-verify-fixtures-VERSION/: POSIX ustar entries in path order,
every timestamp 0, owner 0, modes 0644 and 0755. It is not compressed, so no
compressor's version changes its bytes: run it on the same commit and the
bytes are the same, and the release's published SHA-256 can be checked
without trusting whoever uploaded the file. Extract it and run
`fm-verify conformance fm-verify-fixtures-VERSION`.
"""

from __future__ import annotations

import hashlib
import io
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def build(version: str, fixtures: Path = FIXTURES) -> bytes:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("VERSION is MAJOR.MINOR.PATCH")
    top = f"fm-verify-fixtures-{version}"
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        paths = sorted(fixtures.rglob("*"), key=lambda p: p.relative_to(fixtures).as_posix())
        for p in [fixtures] + paths:
            if "__pycache__" in p.parts:
                continue
            rel = p.relative_to(fixtures).as_posix()
            info = tarfile.TarInfo(top if rel == "." else f"{top}/{rel}")
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            if p.is_dir():
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            elif p.is_file():
                data = p.read_bytes()
                info.size, info.mode = len(data), 0o644
                tar.addfile(info, io.BytesIO(data))
    return tar_bytes.getvalue()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or len(args) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    version = args[0]
    out_dir = Path(args[1]) if len(args) == 2 else ROOT / "dist"
    data = build(version)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"fm-verify-fixtures-{version}.tar"
    path.write_bytes(data)
    print(f"{hashlib.sha256(data).hexdigest()}  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
