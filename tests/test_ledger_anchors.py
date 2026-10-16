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
