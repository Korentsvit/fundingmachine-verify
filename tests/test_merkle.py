import pytest

from fmverify import merkle
from fmverify.verdict import Outcome

# The RFC 6962 test leaves and roots used by Certificate Transparency's
# reference implementations.
LEAVES = [bytes.fromhex(h) for h in ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
PATHS = {
    (0, 8): ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
             "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
             "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"],
    (5, 8): ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
             "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
             "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"],
    (2, 3): ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
    (0, 1): [],
}


def test_empty_tree():
    assert merkle.tree_hash([]).hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize("n", range(1, 9))
def test_roots(n):
    assert merkle.tree_hash(LEAVES[:n]).hex() == ROOTS[n - 1]


@pytest.mark.parametrize("key", PATHS)
def test_paths(key):
    index, size = key
    assert [p.hex() for p in merkle.inclusion_path(LEAVES[:size], index)] == PATHS[key]


def _proof(leaves, index):
    return {"scheme": "rfc9162-sha256", "leaf_index": index, "tree_size": len(leaves),
            "path": [p.hex() for p in merkle.inclusion_path(leaves, index)], "root": merkle.tree_hash(leaves).hex()}


@pytest.mark.parametrize("n", list(range(1, 34)) + [64, 65, 100])
def test_every_leaf_of_many_trees(n):
    leaves = [b"leaf %d" % i for i in range(n)]
    root = merkle.tree_hash(leaves)
    for i in range(n):
        path = merkle.inclusion_path(leaves, i)
        assert merkle.root_from_inclusion(merkle.leaf_hash(leaves[i]), i, n, path) == root
        v = merkle.verify_inclusion(leaves[i], _proof(leaves, i), expected_root=root)
        assert v.outcome is Outcome.VALID, v.to_text()


def test_wrong_index_fails():
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    proof = _proof(leaves, 1)
    proof["leaf_index"] = 0
    assert merkle.verify_inclusion(b"b", proof).outcome is Outcome.INVALID


def test_wrong_size_fails_or_errors():
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    for size in (4, 6, 9):
        proof = _proof(leaves, 4)
        proof["tree_size"] = size
        assert merkle.verify_inclusion(b"e", proof).outcome is Outcome.INVALID


def test_a_size_of_the_same_shape_verifies_so_the_position_is_the_proofs_claim():
    """Found by tools/tamper_audit.py: leaf 5's path in a tree of 7 also
    verifies as a tree of 8, so the verdict must not state the position as
    shown unless the size held with the root is given."""
    leaves = [b"%d" % i for i in range(7)]
    proof = _proof(leaves, 5)
    claimed = dict(proof, tree_size=8)
    v = merkle.verify_inclusion(b"5", claimed)
    assert v.outcome is Outcome.VALID and "as the proof states" in v.statement and "leaf 5 of" not in v.statement
    assert merkle.verify_inclusion(b"5", claimed, expected_size=7).outcome is Outcome.INVALID
    held = merkle.verify_inclusion(b"5", proof, expected_size=7)
    assert held.outcome is Outcome.VALID and held.statement.startswith("The leaf is leaf 5 of 7 ")


def test_reordered_leaves_change_root():
    leaves = [b"a", b"b", b"c"]
    proof = _proof(leaves, 0)
    proof["root"] = merkle.tree_hash([b"b", b"a", b"c"]).hex()
    assert merkle.verify_inclusion(b"a", proof).outcome is Outcome.INVALID


def test_inner_node_cannot_pose_as_leaf():
    leaves = [b"a", b"b", b"c", b"d"]
    inner = merkle.leaf_hash(b"a") + merkle.leaf_hash(b"b")
    proof = {"scheme": "rfc9162-sha256", "leaf_index": 0, "tree_size": 2,
             "path": [merkle.tree_hash(leaves[2:]).hex()], "root": merkle.tree_hash(leaves).hex()}
    assert merkle.verify_inclusion(inner, proof).outcome is Outcome.INVALID


def test_path_too_long_and_too_short():
    leaves = [b"a", b"b", b"c", b"d"]
    proof = _proof(leaves, 0)
    longer = dict(proof, path=proof["path"] + ["00" * 32])
    shorter = dict(proof, path=proof["path"][:-1])
    for p in (longer, shorter):
        v = merkle.verify_inclusion(b"a", p)
        assert v.outcome is Outcome.INVALID
        assert v.checks[-1].id == "merkle.proof"


def test_anchored_root_mismatch():
    leaves = [b"a", b"b"]
    v = merkle.verify_inclusion(b"a", _proof(leaves, 0), expected_root=b"\x11" * 32)
    assert v.outcome is Outcome.INVALID
    assert [c.id for c in v.checks if c.status.value == "fail"] == ["merkle.anchored_root"]


def test_explicit_scheme_warns():
    leaf, sibling = b"x", merkle.sha256(b"y")
    root = merkle.sha256(merkle.sha256(leaf) + sibling)
    proof = {"scheme": "explicit-sha256", "steps": [{"side": "right", "hash": sibling.hex()}], "root": root.hex()}
    v = merkle.verify_inclusion(leaf, proof)
    assert v.outcome is Outcome.VALID
    assert v.checks[0].status.value == "warn"
    assert any("same prefix" in r for r in v.checks[0].reasons)


def test_unknown_scheme_is_invalid():
    v = merkle.verify_inclusion(b"x", {"scheme": "sha1-pairs", "root": "00" * 32})
    assert v.outcome is Outcome.INVALID
    assert "not one this verifier knows" in v.checks[0].reasons[0]
