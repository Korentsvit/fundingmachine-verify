"""Check that a host serves the anchors page exactly as tools/build_page.py built it.

    python tools/check_served_page.py URL SITE

URL is where the page is served (https://verify.fundingmachine.ai); SITE is the directory the build wrote. For `/`
and for every file SITE/SHA256SUMS names, and SHA256SUMS itself, the served bytes must have the SHA-256 SHA256SUMS
gives (index.html's for `/`), and every response must carry each header of SITE/_headers with exactly its value
(docs/HOSTED_PAGE.md, section 3: the policy on every response). Scripts must be served as JavaScript and the
WebAssembly module as application/wasm, or the browser refuses them.

Run right after a deploy, the address may still answer from before it: a path not yet served, or the previous
deployment's bytes. So when anything differs, the whole check runs again after 5, 10, 20, 30 and 45 seconds, about
two minutes in all, and only the last result counts. Each difference of that last check is printed; any fails the
run.
"""

from __future__ import annotations

import hashlib
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vercel_config import headers as site_headers  # noqa: E402

TYPES = {".mjs": "javascript", ".js": "javascript", ".wasm": "application/wasm", ".html": "text/html"}


def fetch(url: str) -> tuple[bytes, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "fm-verify-page-check"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(), {k.lower(): v for k, v in r.headers.items()}


def check(base: str, site: Path) -> list[str]:
    base = base.rstrip("/")
    sums = {}
    for line in (site / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        sums[name] = digest
    sums["SHA256SUMS"] = hashlib.sha256((site / "SHA256SUMS").read_bytes()).hexdigest()
    want = site_headers((site / "_headers").read_text(encoding="utf-8"))
    paths = [("/", "index.html")] + [(f"/{name}", name) for name in sorted(sums)]
    problems = []
    for path, name in paths:
        try:
            body, got = fetch(base + path)
        except (urllib.error.URLError, OSError) as e:
            problems.append(f"{path}: not served ({e})")
            continue
        if hashlib.sha256(body).hexdigest() != sums[name]:
            problems.append(f"{path}: {len(body)} bytes, not the {name} the build wrote")
        for h in want:
            value = got.get(h["key"].lower())
            if value != h["value"]:
                problems.append(f"{path}: {h['key']} is {value!r}, not the build's")
        kind = TYPES.get(Path(name).suffix)
        if kind and kind not in got.get("content-type", ""):
            problems.append(f"{path}: served as {got.get('content-type')!r}, not {kind}")
    return problems


WAITS = (5, 10, 20, 30, 45)


def check_until(base: str, site: Path, waits=WAITS, sleep=time.sleep) -> list[str]:
    """check(), again after each of `waits` seconds while anything differs; the problems of the last check."""
    problems = check(base, site)
    for wait in waits:
        if not problems:
            break
        print(f"{base}: {len(problems)} differences; checking again in {wait} s", file=sys.stderr)
        sleep(wait)
        problems = check(base, site)
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    base, site = argv[0], Path(argv[1])
    problems = check_until(base, site)
    for p in problems:
        print(p)
    n = len((site / "SHA256SUMS").read_text(encoding="utf-8").splitlines()) + 2
    print(f"{base}: {n} paths checked against {site}: " + ("each as built, with its headers" if not problems
                                                           else f"{len(problems)} differences"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
