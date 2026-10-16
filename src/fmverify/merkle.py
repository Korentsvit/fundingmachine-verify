"""Merkle inclusion proofs.

Two schemes:

* ``rfc9162-sha256``: the tree of RFC 9162 (Certificate Transparency 2.0),
  section 2.1: leaf hash SHA-256(0x00 || leaf), node hash
  SHA-256(0x01 || left || right), and the inclusion proof algorithm of
  section 2.1.3.2, which binds the leaf's index and the tree's size. This is
  the scheme the verifier recommends.
* ``explicit-sha256``: a path of (side, hash) steps with the leaf and node
  prefixes stated in the proof. Accepted for formats that do not carry an
  index and size; the verdict warns when the prefixes give no domain
  separation between leaves and nodes, or when the path does not bind a
  position.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .hashes import sha256
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, Verdict, make_verdict

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class ProofError(ValueError):
    """A proof that cannot be evaluated: wrong lengths, impossible positions."""


def leaf_hash(leaf: bytes) -> bytes:
    return sha256(LEAF_PREFIX + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


def _split(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_hash(leaves: Sequence[bytes]) -> bytes:
    """MTH of RFC 9162 section 2.1.1 over the leaf data (not leaf hashes)."""
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(tree_hash(leaves[:k]), tree_hash(leaves[k:]))


def inclusion_path(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """PATH of RFC 9162 section 2.1.3.1: siblings from the leaf upward."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ProofError(f"index {index} outside a tree of {n} leaves")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(leaves[:k], index) + [tree_hash(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [tree_hash(leaves[:k])]


def root_from_inclusion(leaf_digest: bytes, index: int, size: int, path: Sequence[bytes]) -> bytes:
    """RFC 9162 section 2.1.3.2, steps 1 to 5, returning the computed root.

    Raises ProofError where the RFC says to fail the verification for a
    reason other than a root mismatch.
    """
    if size <= 0:
        raise ProofError(f"tree size {size} is not positive")
    if index < 0 or index >= size:
        raise ProofError(f"leaf index {index} is not below tree size {size}")
    for p in path:
        if len(p) != 32:
            raise ProofError(f"path entry is {len(p)} bytes, not 32")
    fn, sn, r = index, size - 1, leaf_digest
    for p in path:
        if sn == 0:
            raise ProofError("path is longer than the tree is deep")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ProofError("path is shorter than the tree is deep")
    return r


@dataclass
class ExplicitStep:
    side: str  # "left" or "right": where the sibling sits
    hash: bytes


def root_from_explicit(leaf: bytes, steps: Sequence[ExplicitStep], leaf_prefix: bytes, node_prefix: bytes) -> bytes:
    r = sha256(leaf_prefix + leaf)
    for step in steps:
        if step.side == "left":
            r = sha256(node_prefix + step.hash + r)
        elif step.side == "right":
            r = sha256(node_prefix + r + step.hash)
        else:
            raise ProofError(f"step side {step.side!r} is neither 'left' nor 'right'")
    return r


def _hex(b: bytes) -> str:
    return b.hex()


def verify_inclusion(
    leaf: bytes,
    proof: dict,
    expected_root: bytes | None = None,
    subject: str | None = None,
    checked_at: str | None = None,
) -> Verdict:
    """Check that ``leaf`` (the leaf data, before leaf hashing) is in the tree
    the proof describes, and that its root is the one given.

    ``proof`` holds ``scheme`` and, for ``rfc9162-sha256``, ``leaf_index``,
    ``tree_size``, ``path`` (hex strings, leaf upward) and ``root`` (hex); for
    ``explicit-sha256``, ``leaf_prefix``, ``node_prefix``, ``steps``
    (``{"side", "hash"}``) and ``root``. ``expected_root``, when given, is the
    root the caller holds from elsewhere (an anchored manifest): the proof's
    own root must equal it.
    """
    checks: list[Check] = []
    scheme = proof.get("scheme")
    subject = subject or f"leaf {sha256(leaf).hex()} (SHA-256 of the leaf data)"
    computed: bytes | None = None
    try:
        stated_root = bytes.fromhex(proof["root"])
        if len(stated_root) != 32:
            raise ProofError(f"stated root is {len(stated_root)} bytes, not 32")
        if scheme == "rfc9162-sha256":
            index, size = int(proof["leaf_index"]), int(proof["tree_size"])
            path = [bytes.fromhex(h) for h in proof["path"]]
            computed = root_from_inclusion(leaf_hash(leaf), index, size, path)
            position = f"leaf {index} of {size}"
            checks.append(
                Check(
                    "merkle.scheme",
                    Status.PASS,
                    "RFC 9162 tree: leaf and node hashes are domain-separated and the proof binds the leaf's position",
                    data={"scheme": scheme, "leaf_index": index, "tree_size": size, "path_length": len(path)},
                )
            )
        elif scheme == "explicit-sha256":
            leaf_prefix = bytes.fromhex(proof.get("leaf_prefix", ""))
            node_prefix = bytes.fromhex(proof.get("node_prefix", ""))
            steps = [ExplicitStep(s["side"], bytes.fromhex(s["hash"])) for s in proof["steps"]]
            computed = root_from_explicit(leaf, steps, leaf_prefix, node_prefix)
            position = "position given by the steps' sides"
            reasons = []
            if leaf_prefix == node_prefix:
                reasons.append(
                    "leaf and node hashes use the same prefix, so an inner node can be passed off as a leaf "
                    "(second-preimage on the tree structure)"
                )
            reasons.append("the proof states no tree size, so it cannot show the leaf's index within a known tree")
            checks.append(
                Check(
                    "merkle.scheme",
                    Status.WARN,
                    "explicit path scheme: weaker than RFC 9162",
                    reasons=reasons,
                    data={"scheme": scheme, "path_length": len(steps)},
                )
            )
        else:
            raise ProofError(f"scheme {scheme!r} is not one this verifier knows (rfc9162-sha256, explicit-sha256)")
    except (KeyError, ValueError, TypeError) as exc:
        reason = f"missing field {exc}" if isinstance(exc, KeyError) else str(exc)
        checks.append(Check("merkle.proof", Status.FAIL, "the proof could not be evaluated", reasons=[reason]))
        return make_verdict(
            "merkle-inclusion",
            subject,
            checks,
            {o: "The inclusion proof could not be evaluated." for o in Outcome},
            ANCHOR_LIMITS,
            checked_at,
        )

    if computed == stated_root:
        checks.append(
            Check(
                "merkle.root",
                Status.PASS,
                f"the path from the leaf reproduces the stated root {stated_root.hex()}",
                data={"computed_root": computed.hex()},
            )
        )
    else:
        checks.append(
            Check(
                "merkle.root",
                Status.FAIL,
                "the path from the leaf does not reproduce the stated root",
                reasons=[f"computed {computed.hex()}", f"stated {stated_root.hex()}"],
                data={"computed_root": computed.hex(), "stated_root": stated_root.hex()},
            )
        )
    if expected_root is not None:
        if expected_root == stated_root:
            checks.append(
                Check("merkle.anchored_root", Status.PASS, "the proof's root equals the root given from the anchored record")
            )
        else:
            checks.append(
                Check(
                    "merkle.anchored_root",
                    Status.FAIL,
                    "the proof's root differs from the root given from the anchored record",
                    reasons=[f"proof {stated_root.hex()}", f"anchored {expected_root.hex()}"],
                )
            )
    statements = {
        Outcome.VALID: f"The leaf is {position} in the Merkle tree with root {stated_root.hex()}.",
        Outcome.INVALID: "The leaf is not shown to be in a tree with the stated root.",
        Outcome.INDETERMINATE: "Inclusion could not be decided.",
    }
    return make_verdict(
        "merkle-inclusion", subject, checks, statements, ANCHOR_LIMITS[:2], checked_at
    )
