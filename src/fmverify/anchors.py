"""Anchor batches: a list of files, the Merkle root over them, and the
anchors over that root (an OpenTimestamps proof and RFC 3161 tokens).

The batch format is the verifier's proposal (``docs/INPUTS.md``) until the
Provenance Ledger session publishes its own; the reading of it is kept in
``load_batch`` so that another format needs only another loader.

What a batch verdict says:

* the listed files, in order, produce the stated root (RFC 9162), so no
  file was added, removed, changed or re-ordered after the root was made;
* each anchor over the root, with its own checks and reliance;
* optionally, how the files in a checkout compare with the listed digests.

A batch is ``valid`` when its root holds and at least one anchor over it is
valid with none invalid; the standing ruling anchor-everything asks for both
kinds, and the verdict warns when one is missing or unproven.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Sequence

from . import merkle, ots, rfc3161
from .bitcoin import MAINNET, HeaderSource, Network
from .hashes import sha256
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, Verdict, guarded, make_verdict, summarize

FORMAT = "fm-anchor-batch/0"
LEAF_ENCODINGS = {
    # The UTF-8 bytes of "<sha256 hex> <repository-relative path>": a leaf binds content and name.
    "sha256-path-v0": lambda digest, path: f"{digest.hex()} {path}".encode("utf-8"),
    # The 32-byte digest alone: binds content, not name.
    "sha256-v0": lambda digest, path: digest,
}


class BatchError(ValueError):
    pass


@dataclass
class Entry:
    path: str
    digest: bytes


@dataclass
class Batch:
    name: str
    tree: str
    leaf_encoding: str
    entries: list[Entry]
    root: bytes
    ots_files: list[tuple[str, bytes]]
    tsr_files: list[tuple[str, bytes]]

    def leaf(self, entry: Entry) -> bytes:
        return LEAF_ENCODINGS[self.leaf_encoding](entry.digest, entry.path)

    def leaves(self) -> list[bytes]:
        return [self.leaf(e) for e in self.entries]


def _safe_relative(path: str) -> str:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or not path or "\\" in path:
        raise BatchError(f"listed path {path!r} is not a plain repository-relative path")
    return path


def batch_from_doc(doc: dict, anchor_files: dict[str, bytes], name: str = "batch") -> Batch:
    """A batch from its parsed ``batch.json`` and the anchor files beside it, by file name."""
    if not isinstance(doc, dict):
        raise BatchError("batch.json does not hold an object")
    if doc.get("format") != FORMAT:
        raise BatchError(f"format {doc.get('format')!r}; this verifier reads {FORMAT}")
    if doc.get("tree") != "rfc9162-sha256":
        raise BatchError(f"tree {doc.get('tree')!r}; this verifier reads rfc9162-sha256")
    if doc.get("leaf_encoding") not in LEAF_ENCODINGS:
        raise BatchError(f"leaf encoding {doc.get('leaf_encoding')!r} is not one of {', '.join(LEAF_ENCODINGS)}")
    entries = []
    try:
        for item in doc["leaves"]:
            digest = bytes.fromhex(item["sha256"])
            if len(digest) != 32:
                raise BatchError(f"{item['path']}: digest is {len(digest)} bytes")
            entries.append(Entry(_safe_relative(item["path"]), digest))
        root = bytes.fromhex(doc["root"])
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, BatchError):
            raise
        raise BatchError(f"batch.json is missing or mangles a field: {exc}") from exc
    if not entries:
        raise BatchError("the batch lists no files")
    if len({e.path for e in entries}) != len(entries):
        raise BatchError("the batch lists a path twice")
    if len(root) != 32:
        raise BatchError("the root is not 32 bytes")
    for fname in [*doc.get("ots", []), *doc.get("rfc3161", [])]:
        if not isinstance(fname, str) or "/" in fname or "\\" in fname or fname.startswith("."):
            raise BatchError(f"anchor file {fname!r} is not a plain file name inside the batch directory")

    def pick(names: list[str], suffix: str) -> list[tuple[str, bytes]]:
        if not names:
            names = sorted(n for n in anchor_files if n.endswith(suffix))
        missing = [n for n in names if n not in anchor_files]
        if missing:
            raise BatchError(f"batch.json names anchor files that are not there: {', '.join(missing)}")
        return [(n, anchor_files[n]) for n in names]

    return Batch(name, doc["tree"], doc["leaf_encoding"], entries, root,
                 pick(list(doc.get("ots", [])), ".ots"), pick(list(doc.get("rfc3161", [])), ".tsr"))


def load_batch(directory: str | Path) -> Batch:
    d = Path(directory)
    try:
        doc = json.loads((d / "batch.json").read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BatchError(f"{d} holds no batch.json") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BatchError(f"batch.json is not JSON: {exc}") from exc
    files = {p.name: p.read_bytes() for p in d.iterdir() if p.is_file() and p.suffix in (".ots", ".tsr")}
    return batch_from_doc(doc, files, name=str(d))


def inclusion_proof(batch: Batch, path: str) -> dict:
    """An RFC 9162 inclusion proof for one listed file, as ``fm-verify merkle`` reads it."""
    index = next((i for i, e in enumerate(batch.entries) if e.path == path), None)
    if index is None:
        raise BatchError(f"{path} is not listed in the batch")
    leaves = batch.leaves()
    return {"scheme": "rfc9162-sha256", "leaf_index": index, "tree_size": len(leaves),
            "path": [h.hex() for h in merkle.inclusion_path(leaves, index)], "root": batch.root.hex(),
            "leaf": leaves[index].hex()}


@guarded("anchor-batch", "anchors.batch", "anchor batch")
def verify_batch(
    directory: "str | Path | Batch",
    repo_root: str | Path | None = None,
    files: Sequence[str | Path] = (),
    header_sources: Sequence[HeaderSource] = (),
    network: Network = MAINNET,
    roots=(),
    extra_certs=(),
    strict_files: bool = False,
    checked_at: str | None = None,
    held: dict[str, bytes] | None = None,
    crls=(),
) -> Verdict:
    """Check a batch (a directory, or a Batch already loaded).

    ``files`` are local files the caller holds, each named by the path it is
    listed under (relative to ``repo_root`` when given, else to the current
    directory); ``held`` gives the same in memory, listed path to content;
    ``repo_root`` alone compares every listed file with the checkout."""
    checks: list[Check] = []
    subject = f"anchor batch {directory.name if isinstance(directory, Batch) else directory}"
    try:
        batch = directory if isinstance(directory, Batch) else load_batch(directory)
    except BatchError as exc:
        checks.append(Check("anchors.batch", Status.FAIL, "the batch could not be read", reasons=[str(exc)]))
        return make_verdict("anchor-batch", subject, checks, {o: "The anchor batch could not be read." for o in Outcome},
                            ANCHOR_LIMITS, checked_at)
    n = len(batch.entries)
    checks.append(Check("anchors.batch", Status.PASS, f"{n} files listed, leaf encoding {batch.leaf_encoding}, root {batch.root.hex()}",
                        data={"files": n, "root": batch.root.hex(), "leaf_encoding": batch.leaf_encoding}))
    if batch.leaf_encoding == "sha256-v0":
        checks.append(Check("anchors.leaf_encoding", Status.WARN, "leaves hold digests only: the root binds the files' contents but not their names"))

    computed = merkle.tree_hash(batch.leaves())
    if computed == batch.root:
        checks.append(Check("anchors.root", Status.PASS, f"the {n} listed files, in order, produce the stated root"))
    else:
        checks.append(Check("anchors.root", Status.FAIL, "the listed files do not produce the stated root",
                            reasons=[f"computed {computed.hex()}", f"stated {batch.root.hex()}",
                                     "a file was added, removed, changed or re-ordered after the root was made"]))

    # Files the reader holds.
    base = Path(repo_root) if repo_root is not None else Path(".")
    listed = {e.path: e for e in batch.entries}
    named: dict[str, bytes] = dict(held or {})
    for f in files:
        rel = Path(f).as_posix() if repo_root is None else Path(f).resolve().relative_to(base.resolve()).as_posix()
        named[rel] = (base / rel).read_bytes() if repo_root is not None else Path(f).read_bytes()
    for rel, content in named.items():
        entry = listed.get(rel)
        if entry is None:
            checks.append(Check("anchors.file", Status.FAIL, f"{rel} is not listed in this batch"))
            continue
        actual = sha256(content)
        if actual == entry.digest:
            index = batch.entries.index(entry)
            checks.append(Check("anchors.file", Status.PASS, f"{rel} matches its listed digest (leaf {index} of {n})",
                                data={"path": rel, "sha256": actual.hex(), "proof": inclusion_proof(batch, rel)}))
        else:
            checks.append(Check("anchors.file", Status.FAIL, f"{rel} differs from the content anchored under its name",
                                reasons=[f"now {actual.hex()}", f"anchored {entry.digest.hex()}"]))
    if repo_root is not None and not named:
        same, changed, absent = [], [], []
        for e in batch.entries:
            p = base / e.path
            if not p.is_file():
                absent.append(e.path)
            elif sha256(p.read_bytes()) == e.digest:
                same.append(e.path)
            else:
                changed.append(e.path)
        data = {"matching": same, "changed": changed, "absent": absent}
        if changed:
            checks.append(Check("anchors.checkout", Status.FAIL if strict_files else Status.WARN,
                                f"{len(changed)} of {n} listed files in {base} differ from what was anchored",
                                reasons=[*changed[:20], *(["..."] if len(changed) > 20 else []),
                                         "the anchors cover the content as it was listed; compare with the checkout at the batch's commit"],
                                data=data))
        else:
            checks.append(Check("anchors.checkout", Status.PASS, f"{len(same)} of {n} listed files in {base} match what was anchored"
                                + (f"; {len(absent)} not present" if absent else ""), data=data))

    # Anchors over the root.
    subs: list[tuple[str, str, Verdict]] = []
    for fname, data in batch.ots_files:
        subs.append((f"anchors.ots.{fname}", f"the OpenTimestamps proof {fname}",
                     ots.verify(data, header_sources, digest=batch.root, network=network,
                                subject=f"root {batch.root.hex()}", checked_at=checked_at)))
    for fname, data in batch.tsr_files:
        subs.append((f"anchors.rfc3161.{fname}", f"the RFC 3161 token {fname}",
                     rfc3161.verify(data, digest=batch.root, roots=roots, extra_certs=extra_certs,
                                    subject=f"root {batch.root.hex()}", checked_at=checked_at, crls=crls)))
    valid = sum(1 for _, _, v in subs if v.outcome is Outcome.VALID)
    for cid, name, v in subs:
        checks.append(summarize(v, cid, name, valid))
    if not subs:
        checks.append(Check("anchors.present", Status.NOT_CHECKED, "the batch holds no anchor over its root"))
    kinds_valid = {v.kind for _, _, v in subs if v.outcome is Outcome.VALID}
    missing = [k for k in ("opentimestamps", "rfc3161") if k not in kinds_valid]
    if subs and missing:
        checks.append(Check("anchors.policy", Status.WARN,
                            "standing ruling anchor-everything asks for an OpenTimestamps anchor and an RFC 3161 token; "
                            f"not shown valid here: {', '.join(missing)}", required=False))

    anchored = [v.statement for _, _, v in subs if v.outcome is Outcome.VALID]
    statements = {
        Outcome.VALID: f"The {n} files listed in the batch are the leaves of Merkle root {batch.root.hex()}. " + " ".join(anchored),
        Outcome.INVALID: "The anchor batch does not hold: see the failing checks.",
        Outcome.INDETERMINATE: f"The batch's root {batch.root.hex()} holds, but no anchor over it could be shown valid.",
    }
    return make_verdict("anchor-batch", subject, checks, statements, ANCHOR_LIMITS, checked_at)
