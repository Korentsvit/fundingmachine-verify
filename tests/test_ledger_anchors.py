import json
from pathlib import Path

import pytest

from fmverify import jcs, ledger_anchors, merkle
from fmverify.cli import main
from fmverify.hashes import sha256

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CASE = FIX / "ledger-anchors" / "valid"


def test_leaves_sorted_by_utf16_code_units():
    a = {"kind": "decisions_fragment", "path": "docs/decisions.d/" + chr(0xFB33) + ".md", "ref": "main", "repo": "r/x", "sha256": "0" * 64}
    b = {"kind": "decisions_fragment", "path": "docs/decisions.d/" + chr(0x1F600) + ".md", "ref": "main", "repo": "r/x", "sha256": "0" * 64}
    leaves = ledger_anchors.sorted_leaves([a, b])
    # U+1F600 is the surrogate pair D83D DE00, which sorts before U+FB33 in UTF-16 (and after it by code point).
    assert leaves == [jcs.dumps(b), jcs.dumps(a)]


@pytest.mark.parametrize("n", [1, 2, 3, 6, 9])
def test_preimage_hashes_to_the_root(n):
    leaves = [b"leaf %d" % i for i in range(n)]
    pre = ledger_anchors.preimage_for(leaves)
    assert sha256(pre) == merkle.tree_hash(leaves)
    assert pre[0] == (0 if n == 1 else 1)


def test_manifest_descriptors_found_by_shape():
    man = json.loads((CASE / "manifest.json").read_text())
    found = ledger_anchors._descriptors(man)
    assert len(found) == 5 and all(set(d) == ledger_anchors.DESCRIPTOR_KEYS for d in found)


def test_cli(capsys):
    base = ["anchors", str(CASE), "--network", "regtest",
            "--headers-chain", str(FIX / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin"),
            "--roots", str(FIX / "rfc3161" / "pki" / "root.pem")]
    assert main(base + ["--repo", f"example/repository={FIX / 'ledger-anchors' / 'repo'}"]) == 0
    out = capsys.readouterr().out
    assert "The 5 files and entries the manifest lists are the leaves of root" in out
    assert main(base + ["--repo", "no-equals-sign"]) == 64
    assert main(["anchors", str(CASE), "--network", "regtest"]) == 2


def test_missing_preimage_is_not_this_layout(tmp_path):
    assert not ledger_anchors.is_layout(tmp_path)


def test_all_anchors_under_a_directory(capsys):
    base = ["anchors", str(FIX / "ledger-anchors"), "--all", "--network", "regtest",
            "--headers-chain", str(FIX / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin"),
            "--roots", str(FIX / "rfc3161" / "pki" / "root.pem"), "--json"]
    assert main(base) == 1  # the set includes the deliberately broken cases
    import json as _json

    doc = _json.loads(capsys.readouterr().out)
    assert doc["kind"] == "anchor-set"
    by_case = {c["id"].split(".", 1)[1]: c["status"] for c in doc["checks"]}
    assert by_case["valid"] == "pass" and by_case["descriptor-altered"] == "fail"
    n = len(ledger_anchors.find_anchor_dirs(FIX / "ledger-anchors"))
    assert n == 7 and f"of {n} anchors" in doc["statement"]
    assert ledger_anchors.find_anchor_dirs(FIX / "anchors") == []


def test_entry_of_several_lines_is_found():
    """docs/ANCHORING.md: an entry's hash covers its line or lines (a dated list
    item in Knowledge-goblin), without the trailing newline."""
    lines = ["# Log", "", "- 2026-10-16: a ruling", "  that runs onto a second line", "- 2026-10-17: another"]
    runs = ledger_anchors.entry_runs(lines)
    assert runs[sha256("\n".join(lines[2:4]).encode()).hex()] == (3, 4)
    assert runs[sha256(lines[4].encode()).hex()] == (5, 5)
    assert sha256(("\n".join(lines[2:4]) + "\n").encode()).hex() not in runs


def test_fragment_of_several_rows_found_assembled():
    rows = ["| 2026-10-16 | layer | First | Why | this pull request |", "| 2026-10-16 | layer | Second | Why | this pull request |"]
    fragment = ("\n".join(rows) + "\n").encode()
    log = ["# Log", "", "| Date | Layer | Ruling | Why | Pull request |", "| --- | --- | --- | --- | --- |",
           "| 2026-10-15 | other | Earlier | Why | #7 |"] + [r.replace("this pull request", "#12") for r in rows]
    (at, number) = ledger_anchors.assembled_runs(log)[sha256(fragment).hex()]
    assert at == (6, 7) and number == "#12"
    # A fragment whose rows already named their pull request is found as written.
    plain = ("\n".join(log[4:5]) + "\n").encode()
    assert ledger_anchors.assembled_runs(log)[sha256(plain).hex()] == ((5, 5), None)
    # Only an exact match counts: other spacing is not the same fragment.
    spaced = fragment.replace(b"| First |", b"|  First |")
    assert sha256(spaced).hex() not in ledger_anchors.assembled_runs(log)


def test_assembled_fragment_named_in_the_verdict():
    from fmverify.verdict import Status

    v = ledger_anchors.verify_dir(FIX / "ledger-anchors" / "checkout-assembled",
                                  repos={"example/repository": FIX / "ledger-anchors" / "repo-assembled"})
    c = next(c for c in v.checks if c.id == "ledger_anchor.checkout.example/repository")
    assert c.status is Status.WARN
    assert c.data["changed"] == ["docs/DECISIONS_LOG.md"]
    assert c.data["assembled"] == ["docs/decisions.d/2026-10-16-example.md (assembled: line 7 of docs/DECISIONS_LOG.md, "
                                   "pull request #3 written for 'this pull request')"]
    assert c.data["absent"] == []


def test_long_log_is_quick():
    import time

    log = [f"| 2026-10-{1 + i % 28:02d} | layer | Ruling number {i} with some words | Why it was taken, at some length | #{i} |"
           for i in range(5000)]
    t = time.perf_counter()
    ledger_anchors.entry_runs(log)
    ledger_anchors.assembled_runs(log)
    assert time.perf_counter() - t < 20
