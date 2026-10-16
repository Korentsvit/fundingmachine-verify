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

A manifest declaring ``anchor-manifest/v0`` (the Ledger's
``schemas/anchor-manifest-v0.schema.json``) is checked field by field: its
leaves in the order it lists them, each leaf hash, the size and root, the
sources it read, and what it states about each proof against the proof
itself. A manifest declaring no contract has its descriptors found by their
documented shape, and the verdict says so; another contract is not read.
Under a directory with ``index.jsonl``, ``verify_all`` also checks the index
and each anchor's link to the one before.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from . import der, jcs, merkle, ots, rfc3161
from .bitcoin import MAINNET, HeaderSource, Network
from .hashes import sha256
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, Verdict, guarded, make_verdict, utc

DESCRIPTOR_KEYS = {"kind", "path", "ref", "repo", "sha256"}
KINDS = {"release_manifest", "release_asset_manifest", "published_manifest", "standing_rulings", "decisions_log",
         "decisions_entry", "decisions_fragment"}
MANIFEST_CONTRACT = "anchor-manifest/v0"
NOT_IN_CHECKOUT = {"release_manifest", "release_asset_manifest"}  # read at a tag, or a release asset
ENTRY_LINES = 40  # the longest decisions entry, or fragment, looked for in a log, in lines
LOG_ROW = re.compile(r"^\| \d{4}-\d{2}-\d{2} \|.*\|$")
THIS_PR = "this pull request"


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


_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_MS_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def v0_problems(m: Any) -> list[str]:
    """Where a manifest departs from schemas/anchor-manifest-v0.schema.json of
    the Provenance Ledger (written out here, so no schema library is needed;
    the tests compare it with the published schema)."""
    out: list[str] = []

    def is_str(v: Any) -> bool:
        return isinstance(v, str)

    def is_int(v: Any) -> bool:
        return isinstance(v, int) and not isinstance(v, bool)

    def obj(v: Any, keys: set[str], where: str) -> bool:
        if not isinstance(v, dict):
            out.append(f"{where} is not an object")
            return False
        if set(v) != keys:
            missing, extra = sorted(keys - set(v)), sorted(set(v) - keys)
            out.append(f"{where}: " + "; ".join(([f"missing {', '.join(missing)}"] if missing else [])
                                                + ([f"unexpected {', '.join(extra)}"] if extra else [])))
            return False
        return True

    def want(ok: bool, what: str) -> None:
        if not ok:
            out.append(what)

    if not obj(m, {"contract", "created", "root", "size", "leaves", "sources", "previous", "proofs"}, "the manifest"):
        return out
    want(m["contract"] == MANIFEST_CONTRACT, "contract is not anchor-manifest/v0")
    want(is_str(m["created"]) and bool(_MS_TIME.fullmatch(m["created"])), "created is not a UTC time to the millisecond")
    want(is_str(m["root"]) and bool(_HEX64.fullmatch(m["root"])), "root is not 64 lower-case hex characters")
    want(is_int(m["size"]) and m["size"] >= 1, "size is not a whole number of at least 1")
    if not isinstance(m["leaves"], list) or not m["leaves"]:
        out.append("leaves is not a non-empty array")
    else:
        for i, leaf in enumerate(m["leaves"]):
            if not obj(leaf, {"leaf_hash", "descriptor"}, f"leaf {i}"):
                continue
            want(is_str(leaf["leaf_hash"]) and bool(_HEX64.fullmatch(leaf["leaf_hash"])), f"leaf {i}: leaf_hash is not 64 hex characters")
            dsc = leaf["descriptor"]
            if obj(dsc, DESCRIPTOR_KEYS, f"leaf {i} descriptor"):
                want(dsc["kind"] in KINDS, f"leaf {i}: kind {dsc['kind']!r} is not one of the schema's")
                want(is_str(dsc["repo"]) and bool(_REPO.fullmatch(dsc["repo"])), f"leaf {i}: repo is not OWNER/NAME")
                want(is_str(dsc["path"]) and len(dsc["path"]) >= 1, f"leaf {i}: path is empty")
                want(is_str(dsc["ref"]) and len(dsc["ref"]) >= 1, f"leaf {i}: ref is empty")
                want(is_str(dsc["sha256"]) and bool(_HEX64.fullmatch(dsc["sha256"])), f"leaf {i}: sha256 is not 64 hex characters")
    if not isinstance(m["sources"], list):
        out.append("sources is not an array")
    else:
        for i, src in enumerate(m["sources"]):
            if not obj(src, {"repo", "read", "reason", "default_branch", "head", "tags", "absent", "release_assets"}, f"source {i}"):
                continue
            want(is_str(src["repo"]), f"source {i}: repo is not a string")
            want(isinstance(src["read"], bool), f"source {i}: read is not true or false")
            want(src["reason"] is None or is_str(src["reason"]), f"source {i}: reason is neither null nor a string")
            want(is_str(src["default_branch"]), f"source {i}: default_branch is not a string")
            want(src["head"] is None or (is_str(src["head"]) and bool(_HEX40.fullmatch(src["head"]))), f"source {i}: head is not a commit id")
            if not isinstance(src["tags"], list):
                out.append(f"source {i}: tags is not an array")
            else:
                for j, t in enumerate(src["tags"]):
                    if obj(t, {"name", "commit"}, f"source {i} tag {j}"):
                        want(is_str(t["name"]) and is_str(t["commit"]) and bool(_HEX40.fullmatch(t["commit"])),
                             f"source {i} tag {j}: not a name and a commit id")
            want(isinstance(src["absent"], list) and all(is_str(a) for a in src["absent"]), f"source {i}: absent is not an array of paths")
            ra = src["release_assets"]
            if obj(ra, {"read", "reason", "count"}, f"source {i} release_assets"):
                want(isinstance(ra["read"], bool) and (ra["reason"] is None or is_str(ra["reason"])) and is_int(ra["count"]) and ra["count"] >= 0,
                     f"source {i} release_assets: read, reason or count has the wrong type")
    prev = m["previous"]
    if prev is not None and obj(prev, {"path", "root"}, "previous"):
        want(is_str(prev["path"]) and is_str(prev["root"]) and bool(_HEX64.fullmatch(prev["root"])), "previous: not a path and a root")
    proofs = m["proofs"]
    if obj(proofs, {"preimage", "opentimestamps", "rfc3161"}, "proofs"):
        want(proofs["preimage"] == "root.preimage", "proofs.preimage is not root.preimage")
        o = proofs["opentimestamps"]
        if obj(o, {"file", "accepted_by", "failed"}, "proofs.opentimestamps"):
            want(o["file"] == "root.preimage.ots", "proofs.opentimestamps.file is not root.preimage.ots")
            want(isinstance(o["accepted_by"], list) and len(o["accepted_by"]) >= 2 and all(is_str(c) for c in o["accepted_by"]),
                 "proofs.opentimestamps.accepted_by does not name at least two calendars")
            if not isinstance(o["failed"], list):
                out.append("proofs.opentimestamps.failed is not an array")
            else:
                for j, f in enumerate(o["failed"]):
                    if obj(f, {"calendar", "error"}, f"proofs.opentimestamps.failed {j}"):
                        want(is_str(f["calendar"]) and is_str(f["error"]), f"proofs.opentimestamps.failed {j}: not two strings")
        r = proofs["rfc3161"]
        if not isinstance(r, list) or len(r) < 2:
            out.append("proofs.rfc3161 does not list at least two tokens")
        else:
            for j, t in enumerate(r):
                if obj(t, {"authority", "url", "file", "gen_time", "serial", "policy"}, f"proofs.rfc3161 {j}"):
                    want(all(is_str(t[k]) for k in t), f"proofs.rfc3161 {j}: a field is not a string")
                    want(is_str(t["gen_time"]) and bool(_MS_TIME.fullmatch(t["gen_time"])), f"proofs.rfc3161 {j}: gen_time is not a UTC time to the millisecond")
                    want(is_str(t["serial"]) and bool(re.fullmatch(r"[0-9a-f]+", t["serial"])), f"proofs.rfc3161 {j}: serial is not lower-case hex")
    return out


def _token_statements(d: Path, manifest: dict) -> tuple[list[str], list[str], list[str]]:
    """Compare what a v0 manifest says about its proofs with the proofs:
    (contradictions, token files named and present, files named but absent)."""
    problems, named, missing = [], [], []
    proofs = manifest.get("proofs") if isinstance(manifest.get("proofs"), dict) else {}
    for t in proofs.get("rfc3161") or []:
        if not isinstance(t, dict) or not isinstance(t.get("file"), str):
            continue
        name = t["file"]
        if Path(name).name != name or not name.startswith("root.preimage."):
            problems.append(f"the manifest names the token file {name!r}, which is not a root.preimage file in this directory")
            continue
        f = d / name
        if not f.is_file():
            missing.append(name)
            continue
        named.append(name)
        try:
            tst = rfc3161.parse_token(f.read_bytes()).tst
        except (rfc3161.TokenError, der.DerError, ValueError):
            continue  # the token's own check reports it
        who = t.get("authority")
        try:
            stated = _dt.datetime.fromisoformat(str(t.get("gen_time")).replace("Z", "+00:00"))
            if abs((stated - tst.gen_time).total_seconds()) >= 0.001:
                problems.append(f"{who}: the manifest states genTime {t.get('gen_time')}, the token {utc(tst.gen_time)}")
        except ValueError:
            pass  # the schema check reports it
        try:
            if int(str(t.get("serial")), 16) != tst.serial:
                problems.append(f"{who}: the manifest states serial {t.get('serial')}, the token {tst.serial:x}")
        except ValueError:
            pass
        if t.get("policy") != tst.policy:
            problems.append(f"{who}: the manifest states policy {t.get('policy')}, the token {tst.policy}")
    o = proofs.get("opentimestamps")
    if isinstance(o, dict) and o.get("file") == "root.preimage.ots" and not (d / "root.preimage.ots").is_file():
        missing.append("root.preimage.ots")
    return problems, named, missing


def _sources_check(manifest: dict) -> Check:
    srcs = [s for s in manifest.get("sources") or [] if isinstance(s, dict)]
    unread = [f"{s.get('repo')}: not read ({s.get('reason') or 'no reason given'})" for s in srcs if s.get("read") is False]
    assets = [f"{s.get('repo')}: release assets not read ({(s.get('release_assets') or {}).get('reason') or 'no reason given'})"
              for s in srcs if s.get("read") is True and isinstance(s.get("release_assets"), dict) and s["release_assets"].get("read") is False]
    absent = sum(len(s.get("absent") or []) for s in srcs)
    data = {"sources": [s.get("repo") for s in srcs], "not_read": unread, "release_assets_not_read": assets, "absent_paths": absent}
    if unread:
        return Check("ledger_anchor.sources", Status.WARN,
                     f"{len(unread)} of {len(srcs)} sources were not read for this anchor: their artefacts are not in it",
                     reasons=unread + assets, required=False, data=data)
    return Check("ledger_anchor.sources", Status.INFO,
                 f"all {len(srcs)} sources were read" + (f"; {absent} configured paths were absent" if absent else "")
                 + (f"; {len(assets)} release asset listings were not read" if assets else ""),
                 reasons=assets, required=False, data=data)


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
    manifest: Any = None
    try:
        manifest = jcs.loads((d / "manifest.json").read_text(encoding="utf-8"))
        stated_root = manifest.get("root") if isinstance(manifest, dict) else None
    except FileNotFoundError:
        checks.append(Check("ledger_anchor.manifest", Status.NOT_CHECKED, "no manifest.json: the anchored files cannot be named",
                            reasons=["the proofs below still show when the root existed"]))
    except (jcs.JcsError, UnicodeDecodeError) as exc:
        checks.append(Check("ledger_anchor.manifest", Status.FAIL, "manifest.json is not JSON", reasons=[str(exc)]))
    contract = manifest.get("contract") if isinstance(manifest, dict) else None
    v0 = contract == MANIFEST_CONTRACT
    if manifest is not None and contract is not None and not v0:
        checks.append(Check("ledger_anchor.manifest_schema", Status.NOT_CHECKED,
                            f"the manifest's contract {contract!r} is not one this verifier reads ({MANIFEST_CONTRACT})",
                            reasons=["its leaves were not read; the proofs below still show when root.preimage existed"]))
    elif v0:
        schema = v0_problems(manifest)
        if schema:
            checks.append(Check("ledger_anchor.manifest_schema", Status.FAIL, "the manifest does not follow anchor-manifest/v0",
                                reasons=schema[:20] + ([f"and {len(schema) - 20} more"] if len(schema) > 20 else [])))
        else:
            checks.append(Check("ledger_anchor.manifest_schema", Status.PASS, "the manifest follows anchor-manifest/v0",
                                data={"created": manifest["created"]}))
        listed = [x for x in manifest.get("leaves") or [] if isinstance(x, dict) and isinstance(x.get("descriptor"), dict)]
        descriptors = [x["descriptor"] for x in listed]
        if listed:
            leaves = [leaf_data(x) for x in descriptors]
            problems = [f"leaf {i}: leaf_hash is not the hash of its descriptor" for i, x in enumerate(listed)
                        if x.get("leaf_hash") != merkle.leaf_hash(leaves[i]).hex()][:20]
            if manifest.get("size") != len(listed):
                problems.append(f"the manifest states {manifest.get('size')} leaves and lists {len(listed)}")
            if len(set(leaves)) != len(leaves):
                problems.append("a descriptor is listed twice")
            computed = merkle.tree_hash(leaves)
            if computed != root:
                problems.append(f"the {len(leaves)} leaves, in the manifest's order, give the root {computed.hex()}; root.preimage gives {root.hex()}")
            elif preimage_for(leaves) != preimage:
                problems.append("root.preimage hashes to the root but is not the root node of these leaves")
            if stated_root != root.hex():
                problems.append(f"the manifest states the root {stated_root}")
            if problems:
                checks.append(Check("ledger_anchor.leaves", Status.FAIL, "the manifest's leaves do not give the anchored root", reasons=problems))
            else:
                checks.append(Check("ledger_anchor.leaves", Status.PASS,
                                    f"the {len(leaves)} leaves, each the RFC 8785 JSON of its descriptor, give the anchored root, "
                                    "and root.preimage is their root node", data={"leaves": len(leaves)}))
            if leaves != sorted_leaves(descriptors):
                checks.append(Check("ledger_anchor.order", Status.WARN,
                                    "the leaves are not in the documented order (their canonical JSON sorted in UTF-16 code units)",
                                    reasons=["the root above is computed in the order the manifest lists them, as the Ledger's own verifier does"],
                                    required=False))
        checks.append(_sources_check(manifest))
        prev = manifest.get("previous")
        if isinstance(prev, dict):
            checks.append(Check("ledger_anchor.previous", Status.INFO,
                                f"the manifest links to the anchor before it, {prev.get('path')} (root {prev.get('root')}); "
                                "the link is checked when the whole set is verified (--all)", required=False, data={"previous": prev}))
        elif prev is None and "previous" in manifest:
            checks.append(Check("ledger_anchor.previous", Status.INFO, "the manifest says this is the first anchor", required=False))
    elif isinstance(manifest, (dict, list)):
        descriptors = _descriptors(manifest)
    if descriptors and not v0 and contract is None:
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
    if v0:
        stated, named, missing = _token_statements(d, manifest)
        if missing:
            checks.append(Check("ledger_anchor.files", Status.WARN, "the manifest names proofs this directory does not hold",
                                reasons=missing, required=False))
        if stated:
            checks.append(Check("ledger_anchor.statements", Status.FAIL, "the manifest misstates its own proofs", reasons=stated))
        elif named:
            checks.append(Check("ledger_anchor.statements", Status.PASS,
                                f"the manifest's genTime, serial and policy for each of its {len(named)} RFC 3161 tokens are the tokens' own"))
    kinds_valid = {v.kind for _, _, v in subs if v.outcome is Outcome.VALID}
    tsa_valid = sum(1 for _, _, v in subs if v.kind == "rfc3161" and v.outcome is Outcome.VALID)
    if subs and ("opentimestamps" not in kinds_valid or tsa_valid < 2):
        checks.append(Check("ledger_anchor.policy", Status.WARN,
                            "docs/ANCHORING.md anchors each root with OpenTimestamps and two RFC 3161 authorities; "
                            f"shown valid here: OpenTimestamps {'yes' if 'opentimestamps' in kinds_valid else 'no'}, RFC 3161 {tsa_valid}",
                            required=False))

    # Checkouts.
    for spec, path in (repos or {}).items():
        # OWNER/NAME: a checkout of the default branch, for every descriptor read there;
        # OWNER/NAME@REF: a checkout of a tag, for the descriptors read at that tag
        # (release manifests in the tagged tree; release assets, by name, in the same directory).
        repo, _, ref = spec.partition("@")
        if ref:
            mine = [x for x in descriptors if x.get("repo") == repo and x.get("ref") == ref]
        else:
            mine = [x for x in descriptors if x.get("repo") == repo and x.get("kind") not in NOT_IN_CHECKOUT]
        same, changed, absent, assembled = [], [], [], []
        base = Path(path)
        logs: dict[str, list[str]] = {}

        def log_lines(rel: str) -> list[str]:
            if rel not in logs:
                f = base / rel
                logs[rel] = f.read_text(encoding="utf-8").splitlines() if f.is_file() else []
            return logs[rel]

        for x in mine:
            if x["kind"] == "decisions_entry":
                at = entry_runs(log_lines(x["path"])).get(x["sha256"])
                if at:
                    same.append(f"{x['path']} (an entry, {_lines(at)})")
                else:
                    absent.append(f"{x['path']} (an entry)")
                continue
            rel = str(x.get("path", ""))
            rel = rel[len("release-asset:"):] if rel.startswith("release-asset:") else rel
            parts = PurePosixPath(rel).parts
            if not parts or PurePosixPath(rel).is_absolute() or ".." in parts:
                absent.append(f"{x.get('path')!r} (not a path inside the checkout; not read)")
                continue
            p = base.joinpath(*parts)
            if p.is_file():
                (same if sha256(p.read_bytes()).hex() == x["sha256"] else changed).append(x["path"])
                continue
            at = None
            if x["kind"] == "decisions_fragment":
                at = assembled_runs(log_lines("docs/DECISIONS_LOG.md")).get(x["sha256"])
            if at:
                (a, b), number = at
                assembled.append(f"{x['path']} (assembled: {_lines((a, b))} of docs/DECISIONS_LOG.md"
                                 + (f", pull request {number} written for '{THIS_PR}')" if number else ")"))
            else:
                absent.append(x["path"])
        data = {"matching": same, "assembled": assembled, "changed": changed, "absent": absent}
        if changed:
            checks.append(Check(f"ledger_anchor.checkout.{spec}", Status.WARN,
                                f"{len(changed)} of {len(mine)} anchored files in {base} differ from what was anchored",
                                reasons=changed[:20] + assembled[:20]
                                + ["an anchor covers the content as it was; a later edit is a new leaf in a later anchor"],
                                data=data))
        else:
            checks.append(Check(f"ledger_anchor.checkout.{spec}", Status.PASS,
                                f"{len(same)} of {len(mine)} anchored items found unchanged in {base}"
                                + (f"; {len(assembled)} fragments found assembled into the decisions log" if assembled else "")
                                + (f"; {len(absent)} not present" if absent else ""),
                                reasons=assembled[:20], data=data))

    anchored = " ".join(v.statement for _, _, v in subs if v.outcome is Outcome.VALID)
    n = len(descriptors)
    named = f"The {n} files and entries the manifest lists are the leaves of root {root.hex()}. " if n else f"Root {root.hex()}: "
    statements = {
        Outcome.VALID: named + anchored,
        Outcome.INVALID: "The anchor does not hold: see the failing checks.",
        Outcome.INDETERMINATE: f"The anchor's root {root.hex()} could not be shown anchored: see the checks not run.",
    }
    return make_verdict("ledger-anchor", subject, checks, statements, ANCHOR_LIMITS, checked_at)


def _lines(at: tuple[int, int]) -> str:
    return f"line {at[0]}" if at[0] == at[1] else f"lines {at[0]} to {at[1]}"


def _runs(texts: list[str], end: str = "") -> dict[str, tuple[int, int]]:
    """SHA-256 (hex) of every run of up to ENTRY_LINES consecutive texts,
    joined by newlines and followed by ``end``, mapped to its first and last
    position (from 1); the first run with a given hash wins."""
    found: dict[str, tuple[int, int]] = {}
    for i in range(len(texts)):
        h = hashlib.sha256()
        for j in range(i, min(len(texts), i + ENTRY_LINES)):
            h.update((("\n" if j > i else "") + texts[j]).encode("utf-8"))
            d = h.copy()
            d.update(end.encode("utf-8"))
            found.setdefault(d.hexdigest(), (i + 1, j + 1))
    return found


def entry_runs(lines: list[str]) -> dict[str, tuple[int, int]]:
    """docs/ANCHORING.md: a decisions entry's hash covers "its line or lines,
    UTF-8, without the trailing newline" (a table row in fundingmachine-core,
    a dated list item in Knowledge-goblin). The Ledger's collector removes
    white space at the end of each line, so runs are hashed both ways."""
    found = _runs([line.rstrip() for line in lines])
    for k, v in _runs(lines).items():
        found.setdefault(k, v)
    return found


def assembled_runs(lines: list[str]) -> dict[str, tuple[tuple[int, int], str | None]]:
    """For a decisions fragment removed from a checkout: fundingmachine-core's
    daily assembly (atlas/decisions.py) appends a fragment's rows to the log
    and writes the pull request number over a last cell reading "this pull
    request". Each run of consecutive log rows is hashed as a fragment holding
    those rows, as written and with the number put back to "this pull
    request". Only an exact SHA-256 match counts, so a match means the
    anchored fragment held exactly those rows."""
    rows = [(n + 1, line) for n, line in enumerate(lines) if LOG_ROW.match(line)]
    found: dict[str, tuple[tuple[int, int], str | None]] = {}
    # Runs of rows consecutive in the log.
    groups: list[list[tuple[int, str]]] = []
    for n, line in rows:
        if groups and groups[-1][-1][0] == n - 1:
            groups[-1].append((n, line))
        else:
            groups.append([(n, line)])
    for g in groups:
        for i in range(len(g)):
            for j in range(i, min(len(g), i + ENTRY_LINES)):
                run = [line for _, line in g[i:j + 1]]
                at = (g[i][0], g[j][0])
                last = run[-1].rsplit(" | ", 1)[-1][:-2].strip() if " | " in run[-1] else ""
                variants: list[tuple[list[str], str | None]] = [(run, None)]
                if re.fullmatch(r"#\d+", last):
                    back = [r[: r.rfind(" | ") + 3] + THIS_PR + " |" if r.endswith(f" | {last} |") else r for r in run]
                    variants.append((back, last))
                for texts, number in variants:
                    found.setdefault(sha256(("\n".join(texts) + "\n").encode("utf-8")).hex(), (at, number))
    return found


def read_index(path: str | Path) -> list[dict]:
    """anchors/index.jsonl: one JSON object per line."""
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


INDEX_KEYS = {"created", "root", "size", "path"}


def check_index(root: str | Path, dirs: Sequence[Path]) -> Check:
    """docs/ANCHORING.md: index.jsonl has one line per anchor (time, root,
    size, path), appended in order, and each manifest names the anchor before
    it as ``previous`` (null for the first). Checked: every line names an
    anchor here with that time, root and size; times increase; each link is
    to the line before; and every anchor directory here is listed."""
    base = Path(root)
    problems: list[str] = []
    try:
        lines = read_index(base / "index.jsonl")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return Check("anchor_set.index", Status.FAIL, "index.jsonl is not one JSON object per line", reasons=[str(exc)])
    listed: set[Path] = set()
    before: dict | None = None
    for i, line in enumerate(lines, 1):
        if not isinstance(line, dict) or set(line) != INDEX_KEYS:
            problems.append(f"line {i} is not an object with exactly {', '.join(sorted(INDEX_KEYS))}")
            before = None
            continue
        rel = line["path"]
        parts = PurePosixPath(rel).parts if isinstance(rel, str) else ()
        if not parts or PurePosixPath(rel).is_absolute() or ".." in parts:
            problems.append(f"line {i}: path {rel!r} is not a relative path inside the anchors directory")
            before = line
            continue
        d = base.joinpath(*parts)
        listed.add(d.resolve())
        try:
            m = jcs.loads((d / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, jcs.JcsError, UnicodeDecodeError):
            problems.append(f"line {i}: {rel} has no readable manifest.json")
            before = line
            continue
        if not isinstance(m, dict):
            m = {}
        for key in ("created", "root", "size"):
            if m.get(key) != line[key]:
                problems.append(f"line {i}: {key} is {line[key]!r}, the manifest at {rel} says {m.get(key)!r}")
        want = None if before is None else {"path": before.get("path"), "root": before.get("root")}
        if m.get("previous") != want:
            problems.append(f"line {i}: the manifest at {rel} links to {m.get('previous')!r}, the line before is {want!r}")
        if before is not None and isinstance(before.get("created"), str) and isinstance(line["created"], str) \
                and not line["created"] > before["created"]:
            problems.append(f"line {i}: created {line['created']} is not after the line before ({before['created']})")
        before = line
    unlisted = [d.relative_to(base).as_posix() for d in dirs if d.resolve() not in listed]
    data = {"lines": len(lines), "unlisted": unlisted}
    if problems:
        return Check("anchor_set.index", Status.FAIL, "index.jsonl and the anchors' links do not agree",
                     reasons=problems[:20] + unlisted[:5], data=data)
    if unlisted:
        return Check("anchor_set.index", Status.WARN,
                     f"index.jsonl lists {len(lines)} anchors, each linked to the one before; {len(unlisted)} anchor directories here are not listed",
                     reasons=unlisted[:20], data=data)
    return Check("anchor_set.index", Status.PASS,
                 f"index.jsonl lists all {len(lines)} anchors in time order, and each manifest links to the anchor before it",
                 data=data)


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
    if (Path(root) / "index.jsonl").is_file():
        checks.append(check_index(root, dirs))
    n = len(dirs)
    statements = {
        Outcome.VALID: f"All {n} anchors under {root} hold.",
        Outcome.INVALID: (f"{outcomes[Outcome.INVALID]} of {n} anchors under {root} do not hold; "
                          f"{outcomes[Outcome.VALID]} hold and {outcomes[Outcome.INDETERMINATE]} could not be checked."),
        Outcome.INDETERMINATE: (f"{outcomes[Outcome.VALID]} of {n} anchors under {root} hold; "
                                f"{outcomes[Outcome.INDETERMINATE]} could not be checked."),
    }
    return make_verdict("anchor-set", f"anchors under {root}", checks, statements, ANCHOR_LIMITS, checked_at)


def _anchor_order(base: Path, dirs: Sequence[Path]) -> list[tuple[str, Path, str | None]]:
    """Anchors in time order: index.jsonl's order where it lists them, then by
    the manifest's ``created``, then by path."""
    created: dict[Path, str | None] = {}
    for d in dirs:
        try:
            m = jcs.loads((d / "manifest.json").read_text(encoding="utf-8"))
            created[d] = m.get("created") if isinstance(m, dict) and isinstance(m.get("created"), str) else None
        except (OSError, jcs.JcsError, UnicodeDecodeError):
            created[d] = None
    position: dict[Path, int] = {}
    try:
        for i, line in enumerate(read_index(base / "index.jsonl")):
            if isinstance(line, dict) and isinstance(line.get("path"), str):
                parts = PurePosixPath(line["path"]).parts
                if parts and ".." not in parts and not PurePosixPath(line["path"]).is_absolute():
                    position.setdefault(base.joinpath(*parts).resolve(), i)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        pass
    ordered = sorted(dirs, key=lambda d: (position.get(d.resolve(), len(position)), created[d] or "", d.as_posix()))
    return [(d.relative_to(base).as_posix() or ".", d, created[d]) for d in ordered]


def _named(d: Path, digest: str) -> list[dict]:
    try:
        m = jcs.loads((d / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, jcs.JcsError, UnicodeDecodeError):
        return []
    if isinstance(m, dict) and m.get("contract") == MANIFEST_CONTRACT:
        descs = [x["descriptor"] for x in m.get("leaves") or [] if isinstance(x, dict) and isinstance(x.get("descriptor"), dict)]
    elif isinstance(m, dict) and "contract" in m:
        return []
    else:
        descs = _descriptors(m)
    return [x for x in descs if x.get("sha256") == digest]


@guarded("anchor-proof", "prove.search", "anchors for one content hash")
def prove(root: str | Path, digest: str, subject: str | None = None, checked_at: str | None = None, **kwargs) -> Verdict:
    """Which anchors under ``root`` name content with this SHA-256 (hex),
    earliest first, each verified; the statement rests on the earliest that
    holds. As the Ledger's ``anchor prove``, but checked here."""
    base = Path(root)
    digest = digest.lower()
    if not _HEX64.fullmatch(digest):
        raise ValueError("the content hash is not 64 hex characters")
    subject = subject or f"content with SHA-256 {digest}"
    order = _anchor_order(base, find_anchor_dirs(base))
    hits = [(rel, d, created, named) for rel, d, created in order for named in [_named(d, digest)] if named]
    checks = [Check("prove.search", Status.PASS if hits else Status.NOT_CHECKED,
                    f"{len(order)} anchors under {root} searched; {len(hits)} name this content",
                    reasons=[] if hits else ["no anchor here lists a descriptor with this SHA-256"])]
    results = [(rel, created, named, verify_dir(d, checked_at=checked_at, **kwargs)) for rel, d, created, named in hits]
    earliest = next((r for r in results if r[3].outcome is Outcome.VALID), None)

    def where(named: list[dict]) -> str:
        return "; ".join(f"{x.get('kind')} {x.get('repo')}:{x.get('path')} at {x.get('ref')}" for x in named)

    for rel, created, named, v in results:
        summary = f"{rel}" + (f" (created {created})" if created else "") + f": {v.outcome.value}; names it as {where(named)}"
        reasons = [f"{c.id}: {c.summary}" for c in v.checks if c.status in (Status.FAIL, Status.WARN)
                   or (c.status is Status.NOT_CHECKED and c.required)]
        data = {"descriptors": named, "verdict": v.to_dict()}
        if v.outcome is Outcome.VALID:
            first = earliest is not None and rel == earliest[0]
            checks.append(Check(f"prove.{rel}", Status.PASS, summary + (" (the earliest that holds)" if first else ""), reasons=reasons,
                                relies_on=v.relies_on if first else [], data=data))
        elif v.outcome is Outcome.INVALID:
            checks.append(Check(f"prove.{rel}", Status.FAIL if earliest is None else Status.WARN, summary, reasons=reasons,
                                required=earliest is None, data=data))
        else:
            checks.append(Check(f"prove.{rel}", Status.NOT_CHECKED, summary, reasons=reasons, required=earliest is None, data=data))
    if earliest is not None:
        rel, created, named, v = earliest
        valid = (f"The content with SHA-256 {digest} is named in {len(hits)} anchor{'s' if len(hits) != 1 else ''}; the earliest "
                 f"that holds is {rel}, as {where(named)}. {v.statement}")
    else:
        valid = ""
    statements = {
        Outcome.VALID: valid,
        Outcome.INVALID: "No anchor naming this content holds, and at least one fails: see the failing checks.",
        Outcome.INDETERMINATE: ("No anchor here names this content." if not hits else
                                "Anchors name this content, but none could be shown to hold: see the checks not run."),
    }
    return make_verdict("anchor-proof", subject, checks, statements, ANCHOR_LIMITS, checked_at)
