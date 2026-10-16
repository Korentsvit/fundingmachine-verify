"""Copy Pyodide's packages for a page that serves everything itself.

    python fetch_packages.py SITE_DIR PACKAGE...

Reads SITE_DIR/pyodide-lock.json, downloads each package with everything it
depends on from Pyodide's own distribution for that version, and keeps a
file only if its SHA-256 is the one the lock file names.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

DIST = "https://cdn.jsdelivr.net/pyodide/v{version}/full/"


def closure(packages: dict, names: list[str]) -> list[str]:
    seen: list[str] = []
    todo = list(names)
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.append(name)
            todo += packages[name]["depends"]
    return sorted(seen)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    site = Path(argv[0])
    lock = json.loads((site / "pyodide-lock.json").read_text(encoding="utf-8"))
    base = DIST.format(version=lock["info"]["version"])
    for name in closure(lock["packages"], argv[1:]):
        entry = lock["packages"][name]
        with urllib.request.urlopen(base + entry["file_name"], timeout=60) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            print(f"{entry['file_name']}: SHA-256 differs from pyodide-lock.json", file=sys.stderr)
            return 1
        (site / entry["file_name"]).write_bytes(data)
        print(f"{entry['sha256']}  {entry['file_name']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
