"""Differential fuzz of PDF attachment extraction against pypdf.

    python tools/differential_pdf.py [ROUNDS]

Changes the bytes of every PDF certificate fixture ROUNDS times each
(default 1000), deterministically, and takes certificate.json from each
changed file with this verifier's reader and with pypdf (strict=False, as a
viewer would read a damaged file). One may read a file the other refuses;
what must never happen is that both read it and take different
certificates, since then a viewer could show one while this verifier checks
another. The one difference allowed: where a stream's /Length is wrong and
both fall back to finding ``endstream``, pypdf keeps the end-of-line marker
before it, which the PDF specification (ISO 32000-1, 7.3.8.1) says is not
stream data and this reader drops; the JSON is the same.
"""

from __future__ import annotations

import io
import logging
import random
import sys
import warnings
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from fmverify import pdf  # noqa: E402
from tamper_audit import mutate_bytes  # noqa: E402


def run(rounds: int) -> dict:
    import pypdf

    logging.getLogger("pypdf").setLevel(logging.CRITICAL)
    totals: Counter = Counter()
    other: list[str] = []
    for path in sorted((ROOT / "fixtures" / "certificate").glob("pdf-*/certificate.pdf")):
        data = path.read_bytes()
        rng = random.Random(path.parent.name)
        for _ in range(rounds):
            changed, where = mutate_bytes(rng, data)
            if changed == data:
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    found = pypdf.PdfReader(io.BytesIO(changed), strict=False).attachments.get("certificate.json") or []
                theirs = found[0] if len(set(found)) == 1 else None
            except Exception:  # noqa: BLE001 - pypdf's own errors are many; any of them is "pypdf did not read it"
                theirs = None
            try:
                ours = pdf.extract(changed)
            except pdf.PdfError:
                ours = None
            if theirs is None or ours is None:
                totals["read by " + ("neither" if theirs is None and ours is None else "pypdf only" if ours is None else "this reader only")] += 1
            elif theirs == ours:
                totals["read alike"] += 1
            elif theirs.startswith(ours) and theirs[len(ours):] in (b"\n", b"\r", b"\r\n"):
                totals["read alike but the end-of-line before endstream"] += 1
            else:
                totals["read differently"] += 1
                other.append(f"{path.parent.name}: {where}: pypdf took {len(theirs)} bytes, this reader {len(ours)}")
    return {"totals": dict(totals), "other": other}


def main(argv: list[str]) -> int:
    result = run(int(argv[0]) if argv else 1000)
    for what, n in sorted(result["totals"].items(), key=lambda x: -x[1]):
        print(f"{n:6}  {what}")
    for o in result["other"]:
        print(f"DIFFERENT {o}")
    return 1 if result["other"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
