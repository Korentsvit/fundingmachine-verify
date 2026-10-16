"""The Provenance Ledger's artefact anchors (docs/ANCHORING.md, v0 of
16 October 2026), checked without the Ledger's code.

An anchor directory holds ``manifest.json``, ``root.preimage`` (the bytes
whose SHA-256 is the root), ``root.preimage.ots`` and one
``root.preimage.<authority>.tsr`` per authority. The checks:

* ``root.preimage`` has the shape of a root node (0x01 || left || right) or
  of a one-leaf tree (0x00 || data), and its SHA-256 is the root;
* the leaves are the RFC 8785 JSON of each descriptor
  ``{kind, path, ref, repo, sha256}``, sorted by their canonical JSON in
  UTF-16 code unit order, and the RFC 9162 tree over them gives that root;
* the OpenTimestamps proof and every RFC 3161 token cover ``root.preimage``;
* optionally, each anchored file in a checkout the reader names still has
  the anchored hash.

The manifest's own schema (anchor-manifest/v0) is published with the
Ledger's anchoring job; until then the descriptors are found by their
documented shape, and the verdict says so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from . import jcs, merkle, ots, rfc3161
from .bitcoin import MAINNET, HeaderSource, Network
from .hashes import sha256
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, Verdict, guarded, make_verdict

DESCRIPTOR_KEYS = {"kind", "path", "ref", "repo", "sha256"}
KINDS = {"release_manifest", "standing_rulings", "decisions_log", "decisions_entry", "decisions_fragment"}


def is_layout(directory: str | Path) -> bool:
    d = Path(directory)
    return (d / "root.preimage").is_file()


def _descriptors(manifest: Any) -> list[dict]:
    """Every object in the manifest with exactly the descriptor's fields, or
    such an object under a ``descriptor`` key, in the order found."""
    found: list[dict] = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            if set(o) == DESCRIPTOR_KEYS:
                found.append(o)
                return
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(manifest)
    return found


def leaf_data(descriptor: dict) -> bytes:
    return jcs.dumps(descriptor)


def sorted_leaves(descriptors: Sequence[dict]) -> list[bytes]:
    return sorted((leaf_data(d) for d in descriptors), key=lambda b: b.decode("utf-8").encode("utf-16-be", "surrogatepass"))


def preimage_for(leaves: Sequence[bytes]) -> bytes:
    """The bytes whose SHA-256 is the RFC 9162 root over ``leaves``."""
    n = len(leaves)
    if n == 1:
        return merkle.LEAF_PREFIX + leaves[0]
    k = merkle._split(n)
    return merkle.NODE_PREFIX + merkle.tree_hash(leaves[:k]) + merkle.tree_hash(leaves[k:])


def _summarize(sub: Verdict, cid: str, what: str, valid_count: int) -> Check:
    if sub.outcome is Outcome.VALID:
        return Check(cid, Status.PASS, sub.statement, relies_on=sub.relies_on, data={"verdict": sub.to_dict()})
    if sub.outcome is Outcome.INVALID:
        return Check(cid, Status.FAIL, f"{what} does not hold",
                     reasons=[f"{c.id}: {c.summary}" for c in sub.checks if c.status is Status.FAIL], data={"verdict": sub.to_dict()})
    return Check(cid, Status.NOT_CHECKED, f"{what} could not be checked: {sub.statement}",
                 reasons=[f"{c.id}: {c.summary}" for c in sub.checks if c.status is Status.NOT_CHECKED and c.required],
                 required=valid_count == 0, data={"verdict": sub.to_dict()})


@guarded("ledger-anchor", "ledger_anchor.preimage", "anchor directory")
def verify_dir(
    directory: str | Path,
    repos: dict[str, str | Path] | None = None,
    header_sources: Sequence[HeaderSource] = (),
    network: Network = MAINNET,
    roots=(),
    extra_certs=(),
    crls=(),
    checked_at: str | None = None,
) -> Verdict:
    """``repos`` maps a repository name as descriptors give it
    (``Korentsvit/fundingmachine-core``) to a local checkout."""
    d = Path(directory)
    checks: list[Check] = []
    subject = f"Provenance Ledger anchor {d.name}"
    bad = {o: "The anchor does not hold: see the failing checks." for o in Outcome}
    try:
        preimage = (d / "root.preimage").read_bytes()
    except OSError as exc:
        checks.append(Check("ledger_anchor.preimage", Status.FAIL, "root.preimage cannot be read", reasons=[str(exc)]))
        return make_verdict("ledger-anchor", subject, checks, bad, ANCHOR_LIMITS, checked_at)
    root = sha256(preimage)
    shape_ok = (len(preimage) == 65 and preimage[0] == 1) or (len(preimage) >= 1 and preimage[0] == 0)
    if shape_ok:
        checks.append(Check("ledger_anchor.preimage", Status.PASS,
                            f"root.preimage has the shape of {'a root node' if preimage[0] == 1 else 'a one-leaf tree'}; its SHA-256 is {root.hex()}",
                            data={"root": root.hex()}))
    else:
        checks.append(Check("ledger_anchor.preimage", Status.FAIL, "root.preimage is neither 0x01 || left || right nor 0x00 || data"))

    # The manifest.
    descriptors: list[dict] = []
    stated_root = None
    try:
        manifest = jcs.loads((d / "manifest.json").read_text(encoding="utf-8"))
        descriptors = _descriptors(manifest)
        stated_root = manifest.get("root") if isinstance(manifest, dict) else None
    except FileNotFoundError:
        checks.append(Check("ledger_anchor.manifest", Status.NOT_CHECKED, "no manifest.json: the anchored files cannot be named",
                            reasons=["the proofs below still show when the root existed"]))
    except (jcs.JcsError, UnicodeDecodeError) as exc:
        checks.append(Check("ledger_anchor.manifest", Status.FAIL, "manifest.json is not JSON", reasons=[str(exc)]))
    if descriptors:
        problems = [f"descriptor {i} has kind {x.get('kind')!r}" for i, x in enumerate(descriptors) if x.get("kind") not in KINDS]
        problems += [f"descriptor {i} sha256 is not 64 hex characters" for i, x in enumerate(descriptors)
                     if not (isinstance(x.get("sha256"), str) and len(x["sha256"]) == 64)]
        leaves = sorted_leaves(descriptors)
        if len(set(leaves)) != len(leaves):
            problems.append("a descriptor is listed twice")
        computed = merkle.tree_hash(leaves)
        if computed != root:
            problems.append(f"the {len(leaves)} descriptors give the root {computed.hex()}, root.preimage gives {root.hex()}")
        if stated_root is not None and stated_root != root.hex():
            problems.append(f"the manifest states the root {stated_root}")
        if problems:
            checks.append(Check("ledger_anchor.leaves", Status.FAIL, "the manifest's descriptors do not give the anchored root", reasons=problems))
        else:
            checks.append(Check("ledger_anchor.leaves", Status.PASS,
                                f"the {len(leaves)} descriptors, as RFC 8785 JSON sorted in UTF-16 order, give the anchored root",
                                data={"leaves": len(leaves)}))
        checks.append(Check("ledger_anchor.manifest_schema", Status.INFO,
                            "descriptors found by their documented shape; the manifest's own schema (anchor-manifest/v0) was not checked",
                            required=False))

    # The proofs over root.preimage.
    subs: list[tuple[str, str, Verdict]] = []
    if (d / "root.preimage.ots").is_file():
        subs.append(("ledger_anchor.ots", "the OpenTimestamps proof",
                     ots.verify((d / "root.preimage.ots").read_bytes(), header_sources, file_bytes=preimage, network=network,
                                subject=f"root {root.hex()}", checked_at=checked_at)))
    for p in sorted(d.glob("root.preimage.*.tsr")):
        subs.append((f"ledger_anchor.rfc3161.{p.name}", f"the RFC 3161 token {p.name}",
                     rfc3161.verify(p.read_bytes(), file_bytes=preimage, roots=roots, extra_certs=extra_certs, crls=crls,
                                    subject=f"root {root.hex()}", checked_at=checked_at)))
    valid = sum(1 for _, _, v in subs if v.outcome is Outcome.VALID)
    for cid, what, v in subs:
        checks.append(_summarize(v, cid, what, valid))
    if not subs:
        checks.append(Check("ledger_anchor.proofs", Status.NOT_CHECKED, "the directory holds no proof over root.preimage"))
    kinds_valid = {v.kind for _, _, v in subs if v.outcome is Outcome.VALID}
    tsa_valid = sum(1 for _, _, v in subs if v.kind == "rfc3161" and v.outcome is Outcome.VALID)
    if subs and ("opentimestamps" not in kinds_valid or tsa_valid < 2):
        checks.append(Check("ledger_anchor.policy", Status.WARN,
                            "docs/ANCHORING.md anchors each root with OpenTimestamps and two RFC 3161 authorities; "
                            f"shown valid here: OpenTimestamps {'yes' if 'opentimestamps' in kinds_valid else 'no'}, RFC 3161 {tsa_valid}",
                            required=False))

    # Checkouts.
    for repo, path in (repos or {}).items():
        mine = [x for x in descriptors if x.get("repo") == repo and x.get("kind") != "release_manifest"]
        same, changed, absent = [], [], []
        base = Path(path)
        log_lines = None
        for x in mine:
            if x["kind"] == "decisions_entry":
                if log_lines is None:
                    log = base / "docs" / "DECISIONS_LOG.md"
                    log_lines = log.read_text(encoding="utf-8").splitlines() if log.is_file() else []
                hashes = {sha256(line.encode("utf-8")).hex() for line in log_lines}
                (same if x["sha256"] in hashes else absent).append(f"{x['path']} (an entry)")
                continue
            p = base / x["path"]
            if not p.is_file():
                absent.append(x["path"])
            elif sha256(p.read_bytes()).hex() == x["sha256"]:
                same.append(x["path"])
            else:
                changed.append(x["path"])
        data = {"matching": same, "changed": changed, "absent": absent}
        if changed:
            checks.append(Check(f"ledger_anchor.checkout.{repo}", Status.WARN,
                                f"{len(changed)} of {len(mine)} anchored files in {base} differ from what was anchored",
                                reasons=changed[:20] + ["an anchor covers the content as it was; a later edit is a new leaf in a later anchor"],
                                data=data))
        else:
            checks.append(Check(f"ledger_anchor.checkout.{repo}", Status.PASS,
                                f"{len(same)} of {len(mine)} anchored items found unchanged in {base}" + (f"; {len(absent)} not present" if absent else ""),
                                data=data))

    anchored = " ".join(v.statement for _, _, v in subs if v.outcome is Outcome.VALID)
    n = len(descriptors)
    named = f"The {n} files and entries the manifest lists are the leaves of root {root.hex()}. " if n else f"Root {root.hex()}: "
    statements = {
        Outcome.VALID: named + anchored,
        Outcome.INVALID: "The anchor does not hold: see the failing checks.",
        Outcome.INDETERMINATE: f"The anchor's root {root.hex()} could not be shown anchored: see the checks not run.",
    }
    return make_verdict("ledger-anchor", subject, checks, statements, ANCHOR_LIMITS, checked_at)


def read_index(path: str | Path) -> list[dict]:
    """anchors/index.jsonl: one JSON object per line."""
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def find_anchor_dirs(root: str | Path) -> list[Path]:
    """Every directory under ``root`` (itself included) holding root.preimage, in path order."""
    base = Path(root)
    return sorted(p.parent for p in base.rglob("root.preimage") if p.is_file())


@guarded("anchor-set", "anchor_set.read", "anchor set")
def verify_all(root: str | Path, checked_at: str | None = None, **kwargs) -> Verdict:
    """Verify every anchor directory under ``root``; one check per anchor."""
    dirs = find_anchor_dirs(root)
    checks: list[Check] = []
    outcomes = {o: 0 for o in Outcome}
    for d in dirs:
        v = verify_dir(d, checked_at=checked_at, **kwargs)
        outcomes[v.outcome] += 1
        rel = d.relative_to(Path(root)).as_posix() or "."
        status = {Outcome.VALID: Status.PASS, Outcome.INVALID: Status.FAIL, Outcome.INDETERMINATE: Status.NOT_CHECKED}[v.outcome]
        reasons = [f"{c.id}: {c.summary}" for c in v.checks if c.status in (Status.FAIL, Status.WARN)
                   or (c.status is Status.NOT_CHECKED and c.required)]
        checks.append(Check(f"anchor_set.{rel}", status, f"{rel}: {v.outcome.value}", reasons=reasons,
                            relies_on=v.relies_on, data={"verdict": v.to_dict()}))
    if not dirs:
        checks.append(Check("anchor_set.read", Status.NOT_CHECKED, f"no anchor directory (with root.preimage) under {root}"))
    n = len(dirs)
    statements = {
        Outcome.VALID: f"All {n} anchors under {root} hold.",
        Outcome.INVALID: (f"{outcomes[Outcome.INVALID]} of {n} anchors under {root} do not hold; "
                          f"{outcomes[Outcome.VALID]} hold and {outcomes[Outcome.INDETERMINATE]} could not be checked."),
        Outcome.INDETERMINATE: (f"{outcomes[Outcome.VALID]} of {n} anchors under {root} hold; "
                                f"{outcomes[Outcome.INDETERMINATE]} could not be checked."),
    }
    return make_verdict("anchor-set", f"anchors under {root}", checks, statements, ANCHOR_LIMITS, checked_at)
