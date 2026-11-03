"""Write vercel.json for a site built by tools/build_page.py, from that site's own _headers.

    python tools/vercel_config.py SITE

The build is host-neutral: _headers holds the headers every response must carry (docs/HOSTED_PAGE.md, section 3 and
11.4). Vercel does not read _headers, so this writes the same headers into SITE/vercel.json, for every path, and
nothing else: no build step, no rewrites, no redirects. The headers are read from _headers and not restated here, so
the two cannot drift apart. vercel.json is not in SHA256SUMS; the files the page serves are.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def headers(text: str) -> list[dict]:
    """The headers of the single `/*` block of a _headers file, in order."""
    lines = text.splitlines()
    if not lines or lines[0] != "/*":
        raise ValueError("_headers must begin with the one path /*")
    out = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if not line.startswith("  ") or ": " not in line:
            raise ValueError(f"not a header line under /*: {line!r}")
        key, value = line.strip().split(": ", 1)
        out.append({"key": key, "value": value})
    if not any(h["key"] == "Content-Security-Policy" for h in out):
        raise ValueError("_headers has no Content-Security-Policy")
    return out


def config(text: str) -> dict:
    return {"headers": [{"source": "/(.*)", "headers": headers(text)}]}


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    site = Path(argv[0])
    doc = config((site / "_headers").read_text(encoding="utf-8"))
    (site / "vercel.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"{site / 'vercel.json'}: {len(doc['headers'][0]['headers'])} headers on every path")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
