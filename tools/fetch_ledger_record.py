"""Copy the Provenance Ledger's public anchor record into a directory.

    python tools/fetch_ledger_record.py OUT_DIR [--url URL]

Reads the record's listing (contract anchor-record/v0; default URL
https://fundingmachine-ledger.vercel.app/api/anchors, public, no login) and
fetches every file it names at the exact version it names
(``?path=P&sha256=H``). A file is kept only if its SHA-256 and size are the
listing's and the server's ``x-content-sha256`` header agrees; any
difference stops the copy with exit 1 and nothing is written. Network errors
are tried three times. OUT_DIR must not exist; it receives ``listing.json``
as fetched and the files under ``anchors/``, ready for

    fm-verify anchors OUT_DIR/anchors --all --headers HEADERS --roots ROOTS

This tool uses the network; the verifier does not. Fetch, then verify
offline.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

URL = "https://fundingmachine-ledger.vercel.app/api/anchors"


class RecordError(Exception):
    pass


def fetch(url: str, tries: int = 3) -> tuple[bytes, str | None]:
    """The body and its x-content-sha256 header; network errors are retried, nothing else is."""
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return r.read(), r.headers.get("x-content-sha256")
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == tries - 1:
                raise
            time.sleep(2 * 2 ** attempt)
    raise AssertionError("unreachable")


def safe_path(rel: object) -> PurePosixPath:
    p = PurePosixPath(rel) if isinstance(rel, str) else None
    if p is None or not rel or p.is_absolute() or ".." in p.parts or "\\" in rel or p.parts[0] in (".", ""):
        raise RecordError(f"the listing names a path that is not inside the record: {rel!r}")
    return p


def copy_record(out: Path, url: str = URL) -> dict:
    listing_raw, _ = fetch(url)
    listing = json.loads(listing_raw)
    if listing.get("contract") != "anchor-record/v0":
        raise RecordError(f"the listing's contract is {listing.get('contract')!r}, not anchor-record/v0")
    files: dict[PurePosixPath, bytes] = {}
    for entry in listing.get("files", []):
        rel = safe_path(entry.get("path"))
        data, header = fetch(f"{url}?path={urllib.parse.quote(str(rel), safe='')}&sha256={entry.get('sha256')}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry.get("sha256") or len(data) != entry.get("bytes") or header != digest:
            raise RecordError(f"{rel}: SHA-256 {digest} and {len(data)} bytes; the listing says {entry.get('sha256')} and "
                              f"{entry.get('bytes')} bytes, the server's header {header}")
        if rel in files:
            raise RecordError(f"the listing names {rel} twice")
        files[rel] = data
    out.mkdir(parents=True)
    (out / "listing.json").write_bytes(listing_raw)
    for rel, data in files.items():
        dest = out / "anchors" / Path(*rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return {"url": url, "listing_sha256": hashlib.sha256(listing_raw).hexdigest(), "files": len(files),
            "anchors": len(listing.get("anchors", []))}


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-") or len(argv) not in (1, 3) or (len(argv) == 3 and argv[1] != "--url"):
        print(__doc__, file=sys.stderr)
        return 64
    out = Path(argv[0])
    if out.exists():
        print(f"{out} exists; give a new directory", file=sys.stderr)
        return 64
    try:
        result = copy_record(out, argv[2] if len(argv) == 3 else URL)
    except (RecordError, urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as exc:
        print(f"not copied: {exc}", file=sys.stderr)
        return 1
    print(f"{result['files']} files of {result['anchors']} anchors copied into {out}, each matching the listing "
          f"(SHA-256 {result['listing_sha256']}) and the server's header")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
