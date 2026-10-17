"""The Provenance Ledger conformance suite's two live cases, run on its public anchors mirror.

    git clone https://github.com/Korentsvit/fundingmachine-anchors mirror
    python tools/fetch_headers.py mirror/anchors headers.txt
    python tools/mirror_conformance.py mirror/anchors --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt

CS-42, every anchor verifies: each anchor's leaves, root, preimage and both RFC 3161 tokens hold, and its
OpenTimestamps proof holds against the headers given; the index and each anchor's link to the one before it hold.
An anchor whose OpenTimestamps proof is still pending at the calendars is reported pending: its other checks must
hold, and the proof's Bitcoin part is not yet there to check.

CS-43, a tampered leaf fails: in a copy of the newest confirmed anchor, one leaf's sha256 is changed in its
manifest.json; that anchor must be invalid, named, with the check that failed.

Prints one line per case and exits non-zero unless both conform. Nothing is fetched here: the mirror and the
headers are inputs.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fmverify import ledger_anchors  # noqa: E402
from fmverify.bitcoin import NETWORKS  # noqa: E402
from fmverify.cli import _certs, header_sources  # noqa: E402
from fmverify.verdict import Outcome, Status  # noqa: E402

PENDING = "ledger_anchor.ots"


def anchor_state(v) -> str:
    """confirmed, pending or failed: what one anchor's verdict says."""
    if v.outcome is not Outcome.VALID:
        return "failed"
    ots = next((c for c in v.checks if c.id == PENDING), None)
    if ots is not None and ots.status is Status.PASS:
        return "confirmed"
    others = [c for c in v.checks if c.id != PENDING and c.id != "ledger_anchor.policy"]
    if ots is not None and ots.status is Status.NOT_CHECKED and all(c.status is not Status.FAIL for c in others):
        return "pending"
    return "failed"


def cs42(anchors: Path, common: dict) -> tuple[bool, str, list[Path]]:
    whole = ledger_anchors.verify_all(anchors, **common)
    states, confirmed = {}, []
    for d in ledger_anchors.find_anchor_dirs(anchors):
        rel = d.relative_to(anchors).as_posix()
        states[rel] = anchor_state(ledger_anchors.verify_dir(d, **common))
        if states[rel] == "confirmed":
            confirmed.append(d)
    index = next((c for c in whole.checks if c.id == "anchor_set.index"), None)
    failed = sorted(k for k, s in states.items() if s == "failed")
    ok = not failed and index is not None and index.status is Status.PASS and bool(states)
    n = len(states)
    line = (f"CS-42 {'conforms' if ok else 'DOES NOT CONFORM'}: {n} anchors; "
            f"{len(confirmed)} confirmed in Bitcoin, {sum(s == 'pending' for s in states.values())} pending, {len(failed)} failed"
            + (f" ({', '.join(failed)})" if failed else "")
            + f"; index and links: {index.status.value if index else 'absent'}")
    return ok, line, confirmed


def cs43(anchor: Path, rel: str, common: dict) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / rel
        shutil.copytree(anchor, copy)
        manifest = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
        leaf = manifest["leaves"][0]
        target = leaf["descriptor"] if "descriptor" in leaf and "sha256" in leaf["descriptor"] else leaf
        old = target["sha256"]
        target["sha256"] = ("0" if old[0] != "0" else "1") + old[1:]
        (copy / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        v = ledger_anchors.verify_dir(copy, **common)
    failing = [c.id for c in v.checks if c.status is Status.FAIL]
    ok = v.outcome is Outcome.INVALID and bool(failing)
    return ok, (f"CS-43 {'conforms' if ok else 'DOES NOT CONFORM'}: anchor {rel} with its first leaf's sha256 changed is "
                f"{v.outcome.value}; failing: {', '.join(failing) or 'none'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("anchors", type=Path, help="the anchors/ directory of a checkout of the mirror")
    ap.add_argument("--headers", action="append", help="Bitcoin headers, HEIGHT HEX lines (repeatable)")
    ap.add_argument("--roots", action="append", help="PEM roots for the RFC 3161 authorities (repeatable)")
    a = ap.parse_args(argv)
    ns = argparse.Namespace(headers=a.headers, headers_chain=None, explorer=None, bitcoind=None, bitcoind_cookie=None,
                            min_work_bits=None, network="bitcoin-mainnet")
    common = dict(header_sources=header_sources(ns), network=NETWORKS["bitcoin-mainnet"], roots=_certs(a.roots, "--roots"),
                  extra_certs=[], crls=[])
    ok42, line42, confirmed = cs42(a.anchors, common)
    print(line42)
    if not confirmed:
        print("CS-43 not run: no confirmed anchor to tamper with")
        return 1
    newest = confirmed[-1]
    ok43, line43 = cs43(newest, newest.relative_to(a.anchors).as_posix(), common)
    print(line43)
    return 0 if ok42 and ok43 else 1


if __name__ == "__main__":
    sys.exit(main())
