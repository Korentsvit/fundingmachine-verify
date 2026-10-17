"""The anchors directory held in memory (``ledger-anchor-set``, what a browser page passes) gives the verdict the
command line gives for the same directory on disk."""

import base64
import json
from pathlib import Path

from fmverify import api, conformance, ledger_anchors
from fmverify.bitcoin import NETWORKS

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "ledger-anchors"


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and p.name != "expected.json"}


def _same(a: dict, b: dict) -> dict:
    strip = lambda v: {k: x for k, x in v.items() if k not in ("subject", "checked_at", "statement")}
    return strip(a) == strip(b)


def _sets():
    return sorted(p for p in FIX.iterdir() if p.name.startswith("set-"))


def test_every_set_fixture_alike_in_memory_and_on_disk():
    assert _sets()
    for case in _sets():
        exp = json.loads((case / "expected.json").read_text())
        common = dict(header_sources=conformance._sources(case, exp), network=NETWORKS[exp.get("network", "mainnet")],
                      roots=conformance._certs(case, exp.get("roots", [])), extra_certs=conformance._certs(case, exp.get("chain", [])))
        disk = ledger_anchors.verify_all(case, checked_at="T", **common).to_dict()
        memory = ledger_anchors.verify_set_files(_files(case), name="x", checked_at="T", **common).to_dict()
        assert _same(disk, memory), case.name
        assert memory["outcome"] == exp["outcome"], case.name
        # Without the headers and roots, still alike.
        assert _same(ledger_anchors.verify_all(case, checked_at="T").to_dict(),
                     ledger_anchors.verify_set_files(_files(case), checked_at="T").to_dict()), case.name


def test_the_api_kind_and_its_refusals():
    case = _sets()[0]
    req = {"kind": "ledger-anchor-set", "label": "fixture set",
           "files": {k: base64.b64encode(v).decode() for k, v in _files(case).items()}}
    answer = api.verify(req)
    assert answer["kind"] == "anchor-set" and answer["outcome"] in ("valid", "invalid", "indeterminate")
    assert answer["subject"] == "anchors under fixture set"
    for bad in ("../x/manifest.json", "/abs/manifest.json"):
        a = api.verify({"kind": "ledger-anchor-set", "files": {bad: ""}})
        assert "error" in a and "relative path" in a["error"]
    assert "error" in api.verify({"kind": "ledger-anchor-set", "files": []})


def test_bitcoin_heights():
    proofs = [base64.b64encode(p.read_bytes()).decode() for p in sorted(FIX.rglob("*.ots"))]
    got = api.bitcoin_heights(proofs)
    assert "heights" in got and got["heights"] == sorted(set(got["heights"]))
    assert "error" in api.bitcoin_heights(["bm90IGEgcHJvb2Y="])
    assert "error" in api.bitcoin_heights("x")
