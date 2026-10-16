"""Build the fixtures from committed inputs, offline.

    python tools/make_fixtures.py

Inputs: fixtures/bitcoin/mainnet/headers-sparse.txt and coinbase-840000.json
(captured by tools/fetch_mainnet.py). Outputs: contiguous header files, a
regtest header chain, a test PKI (tools/tsa_fixtures.py), and one directory
per case under fixtures/ots/ and fixtures/rfc3161/, each
with an ``expected.json`` naming the outcome the verifier must reach. The
build is deterministic: running it twice gives the same bytes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fmverify import ots  # noqa: E402

sys.path.insert(0, str(ROOT / "tools"))
import chain_fixtures  # noqa: E402
import pdf_fixtures  # noqa: E402
import tsa_fixtures  # noqa: E402
from fmverify.bitcoin import parse_header  # noqa: E402

FIX = ROOT / "fixtures"
MAIN = FIX / "bitcoin" / "mainnet"
REG = FIX / "bitcoin" / "regtest"
CASES = FIX / "ots"

SHA256 = ots.Op(0x08)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def append(arg: bytes) -> ots.Op:
    return ots.Op(0xF0, arg)


def prepend(arg: bytes) -> ots.Op:
    return ots.Op(0xF1, arg)


def bitcoin_attestation(height: int) -> ots.Attestation:
    return ots.Attestation(ots.TAG_BITCOIN, ots._varuint(height))


def pending_attestation(uri: str) -> ots.Attestation:
    return ots.Attestation(ots.TAG_PENDING, ots._varbytes(uri.encode("ascii")))


def chain(msg: bytes, ops: list[ots.Op], end) -> ots.Timestamp:
    """A single path of operations from ``msg`` ending in ``end`` (an
    attestation or a ready Timestamp's entries)."""
    if not ops:
        ts = ots.Timestamp(msg)
        ts.entries = end if isinstance(end, list) else [end]
        return ts
    op = ops[0]
    return ots.Timestamp(msg, [(op, chain(op.apply(msg), ops[1:], end))])


def run(msg: bytes, ops: list[ots.Op]) -> bytes:
    for op in ops:
        msg = op.apply(msg)
    return msg


def merkle_ops(branch_internal: list[bytes], pos: int) -> list[ots.Op]:
    out: list[ots.Op] = []
    for sibling in branch_internal:
        out += [append(sibling) if pos % 2 == 0 else prepend(sibling), SHA256, SHA256]
        pos //= 2
    return out


def read_sparse(path: Path) -> dict[int, bytes]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            h, hexs = line.split()
            out[int(h)] = bytes.fromhex(hexs)
    return out


def write_case(name: str, proof: bytes, expected: dict, files: dict[str, bytes]) -> None:
    d = CASES / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "proof.ots").write_bytes(proof)
    for fname, data in files.items():
        (d / fname).write_bytes(data)
    (d / "expected.json").write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")


def mine_regtest(prev: bytes, merkle_root: bytes, time: int) -> bytes:
    bits = 0x207FFFFF
    target = 0x7FFFFF << (8 * (0x20 - 3))
    for nonce in range(1 << 32):
        h = struct.pack("<i", 4) + prev + merkle_root + struct.pack("<III", time, bits, nonce)
        if int.from_bytes(sha256d(h), "little") <= target:
            return h
    raise RuntimeError("no nonce")


SAMPLE_REPO = {
    "docs/RULINGS-example.md": b"# Example rulings\n\nA synthetic document for the verifier's fixtures. It is not a FundingMachine ruling.\n",
    "docs/decisions.d/2026-10-16-example.md": b"| 2026-10-16 | example | A synthetic decision row | Fixture only | none |\n",
    "manifests/example-release.json": b'{"release": "example", "files": 3}\n',
    "data/example.csv": b"id,value\n1,10\n2,20\n",
}


def build_anchors() -> None:
    """Anchor batches over a synthetic repository: a regtest OpenTimestamps
    proof and a test-authority RFC 3161 token over each batch root."""
    out = FIX / "anchors"
    if out.exists():
        shutil.rmtree(out)
    for rel, data in SAMPLE_REPO.items():
        (out / "repo" / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / "repo" / rel).write_bytes(data)
    changed = dict(SAMPLE_REPO)
    changed["docs/RULINGS-example.md"] = SAMPLE_REPO["docs/RULINGS-example.md"].replace(b"synthetic", b"edited")
    del changed["data/example.csv"]
    for rel, data in changed.items():
        (out / "repo-changed" / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / "repo-changed" / rel).write_bytes(data)

    from fmverify import merkle

    entries = [{"path": rel, "sha256": sha256(SAMPLE_REPO[rel]).hex()} for rel in sorted(SAMPLE_REPO)]

    def leaves(items):
        return [f"{e['sha256']} {e['path']}".encode() for e in items]

    root = merkle.tree_hash(leaves(entries))
    other_root = sha256(b"some other batch root")

    # A regtest chain whose block 4 commits to the root through calendar- and transaction-shaped operations.
    path_ops = [append(sha256(b"anchor nonce")[:16]), SHA256, prepend(sha256(b"anchor calendar sibling")), SHA256,
                prepend(bytes.fromhex("0100000001") + bytes(36) + bytes.fromhex("00ffffffff01") + bytes(8) + bytes.fromhex("226a20")),
                append(bytes(4)), SHA256, SHA256] + merkle_ops([sha256d(b"anchor block sibling")], 1)
    commitment = run(root, path_ops)
    prev, headers = bytes(32), []
    for height in range(7):
        h = mine_regtest(prev, commitment if height == 4 else sha256d(b"anchor regtest %d" % height), 1760100000 + 600 * height)
        headers.append(h)
        prev = sha256d(h)
    (REG / "anchors-headers-0-6.bin").write_bytes(b"".join(headers))

    def ots_over(digest: bytes, ops, end) -> bytes:
        return ots.DetachedTimestamp(SHA256, chain(digest, ops, end)).serialize()

    good_ots = ots_over(root, path_ops, bitcoin_attestation(4))
    pending_ots = ots_over(root, path_ops[:2], pending_attestation("https://calendar.example.org"))
    other_ots = ots_over(other_root, path_ops[:2], pending_attestation("https://calendar.example.org"))

    tsa_k, tsa_cert, ica = tsa_fixtures.test_authority()

    def tsr(value: bytes, **kw) -> bytes:
        return tsa_fixtures.token(tsa_k, tsa_cert, [tsa_cert, ica], b"", serial=2001, sig="rsa", imprint_value=value, **kw)

    good_tsr = tsr(root)
    import datetime as _dt

    backdated_tsr = tsr(root, tamper_gen_time=_dt.datetime(2026, 9, 1, tzinfo=_dt.timezone.utc))
    common = {"network": "regtest", "headers_chain": [{"path": "../../bitcoin/regtest/anchors-headers-0-6.bin", "start": 0}],
              "roots": ["../../rfc3161/pki/root.pem"]}

    def batch(name, items, batch_root, ots_bytes, tsr_bytes, expected):
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        doc = {"format": "fm-anchor-batch/0", "tree": "rfc9162-sha256", "leaf_encoding": "sha256-path-v0",
               "leaves": items, "root": batch_root.hex(), "ots": ["root.ots"], "rfc3161": ["root.test-tsa.tsr"]}
        (d / "batch.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        (d / "root.ots").write_bytes(ots_bytes)
        (d / "root.test-tsa.tsr").write_bytes(tsr_bytes)
        (d / "expected.json").write_text(json.dumps({**common, **expected}, indent=1) + "\n", encoding="utf-8")

    batch("batch-valid", entries, root, good_ots, good_tsr,
          {"description": "Four files, an anchored root, a confirmed OpenTimestamps proof and a test-authority token",
           "repo_root": "../repo", "outcome": "valid"})
    batch("checkout-changed", entries, root, good_ots, good_tsr,
          {"description": "The same batch against a checkout where one file was edited and one removed: the anchors still hold for what was listed",
           "repo_root": "../repo-changed", "outcome": "valid", "warning": ["anchors.checkout"]})
    batch("named-file-changed", entries, root, good_ots, good_tsr,
          {"description": "A reader holds the edited file and asks whether it is the anchored one",
           "repo_root": "../repo-changed", "files": ["docs/RULINGS-example.md"], "outcome": "invalid", "failing": ["anchors.file"]})
    swapped = [entries[1], entries[0]] + entries[2:]
    batch("batch-reordered", swapped, root, good_ots, good_tsr,
          {"description": "Two listed files swapped after the root was made", "outcome": "invalid", "failing": ["anchors.root"]})
    batch("batch-file-removed", entries[:-1], root, good_ots, good_tsr,
          {"description": "One listed file dropped after the root was made", "outcome": "invalid", "failing": ["anchors.root"]})
    batch("ots-pending", entries, root, pending_ots, good_tsr,
          {"description": "The OpenTimestamps proof is still pending; the token holds", "outcome": "valid", "warning": ["anchors.policy"]})
    batch("tsa-back-dated", entries, root, good_ots, backdated_tsr,
          {"description": "The token's time moved a month earlier after signing", "outcome": "invalid",
           "failing": ["anchors.rfc3161.root.test-tsa.tsr"]})
    batch("ots-other-root", entries, root, other_ots, good_tsr,
          {"description": "The OpenTimestamps proof covers a different root", "outcome": "invalid",
           "failing": ["anchors.ots.root.ots"]})


LEDGER_REPO = {
    "docs/STANDING_RULINGS.md": b"# Standing rulings (synthetic)\n\nA made-up rulings file for the verifier's fixtures; it is no FundingMachine ruling.\n",
    "docs/DECISIONS_LOG.md": (b"# Decisions log (synthetic)\n\n| Date | Layer | Ruling | Why | Pull request |\n| --- | --- | --- | --- | --- |\n"
                              b"| 2026-10-15 | example | A made-up first row | Fixture only | #1 |\n"
                              b"| 2026-10-16 | example | A made-up second row | Fixture only | #2 |\n"),
    "docs/decisions.d/2026-10-16-example.md": b"| 2026-10-16 | example | A made-up fragment row | Fixture only | this pull request |\n",
}


def build_ledger_anchors() -> None:
    """Anchors in the Provenance Ledger's layout (docs/ANCHORING.md v0) over a
    synthetic repository: descriptor leaves, root.preimage, a regtest
    OpenTimestamps proof and two test authorities' tokens."""
    import datetime as _dt

    from fmverify import ledger_anchors

    out = FIX / "ledger-anchors"
    if out.exists():
        shutil.rmtree(out)
    repo = "example/repository"
    for rel, data in LEDGER_REPO.items():
        (out / "repo" / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / "repo" / rel).write_bytes(data)
    changed = dict(LEDGER_REPO)
    changed["docs/STANDING_RULINGS.md"] = LEDGER_REPO["docs/STANDING_RULINGS.md"] + b"\nA ruling added later.\n"
    for rel, data in changed.items():
        (out / "repo-later" / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / "repo-later" / rel).write_bytes(data)
    # The day after: the fragment assembled into the log, as fundingmachine-core's
    # atlas/decisions.py does it (rows appended, the pull request number written in).
    assembled = {k: v for k, v in LEDGER_REPO.items() if "decisions.d" not in k}
    assembled["docs/DECISIONS_LOG.md"] += LEDGER_REPO["docs/decisions.d/2026-10-16-example.md"].replace(b"this pull request", b"#3")
    for rel, data in assembled.items():
        (out / "repo-assembled" / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / "repo-assembled" / rel).write_bytes(data)

    def desc(kind: str, path: str, digest: bytes) -> dict:
        return {"kind": kind, "path": path, "ref": "main", "repo": repo, "sha256": digest.hex()}

    entries = [line for line in LEDGER_REPO["docs/DECISIONS_LOG.md"].decode().splitlines() if line.startswith("| 2026")]
    descriptors = [desc("standing_rulings", "docs/STANDING_RULINGS.md", sha256(LEDGER_REPO["docs/STANDING_RULINGS.md"])),
                   desc("decisions_log", "docs/DECISIONS_LOG.md", sha256(LEDGER_REPO["docs/DECISIONS_LOG.md"])),
                   desc("decisions_fragment", "docs/decisions.d/2026-10-16-example.md", sha256(LEDGER_REPO["docs/decisions.d/2026-10-16-example.md"]))]
    descriptors += [desc("decisions_entry", "docs/DECISIONS_LOG.md", sha256(e.encode())) for e in entries]
    leaves = ledger_anchors.sorted_leaves(descriptors)
    preimage = ledger_anchors.preimage_for(leaves)
    root = sha256(preimage)
    from fmverify import merkle

    assert merkle.tree_hash(leaves) == root

    # Regtest block 2 commits to SHA-256(root.preimage) = root.
    path_ops = [append(sha256(b"ledger anchor nonce")[:16]), SHA256,
                prepend(bytes.fromhex("0100000001") + bytes(36) + bytes.fromhex("00ffffffff01") + bytes(8) + bytes.fromhex("226a20")),
                append(bytes(4)), SHA256, SHA256]
    prev, headers = bytes(32), []
    for height in range(5):
        h = mine_regtest(prev, run(root, path_ops) if height == 2 else sha256d(b"ledger regtest %d" % height), 1760300000 + 600 * height)
        headers.append(h)
        prev = sha256d(h)
    (REG / "ledger-anchor-headers-0-4.bin").write_bytes(b"".join(headers))
    good_ots = ots.DetachedTimestamp(SHA256, chain(root, path_ops, bitcoin_attestation(2))).serialize()

    gen = _dt.datetime(2026, 10, 17, 8, 4, 12, tzinfo=_dt.timezone.utc)
    rsa_k, rsa_cert, ica = tsa_fixtures.test_authority()
    ec_k, ec_cert, second_root = tsa_fixtures.test_authority_second()
    (out / "pki").mkdir(parents=True)
    (out / "pki" / "second-root.pem").write_bytes(tsa_fixtures.pem(second_root))
    tsr_a = tsa_fixtures.token(rsa_k, rsa_cert, [rsa_cert, ica], preimage, serial=4001, sig="rsa", gen_time=gen)
    tsr_b = tsa_fixtures.token(ec_k, ec_cert, [ec_cert], preimage, serial=4002, sig="ecdsa", gen_time=gen)

    from fmverify import rfc3161 as _rfc3161

    def token_entry(authority: str, slug: str, data: bytes) -> dict:
        # As the Ledger's src/anchor/tsa.ts states them: genTime to the millisecond,
        # the serial as the hex of the DER integer's bytes, the policy in dotted form.
        tst = _rfc3161.parse_token(data).tst
        n = tst.serial
        raw = n.to_bytes(n.bit_length() // 8 + 1, "big")
        return {"authority": authority, "url": f"http://tsa.example/{slug}", "file": f"root.preimage.{slug}.tsr",
                "gen_time": tst.gen_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{tst.gen_time.microsecond // 1000:03d}Z",
                "serial": raw.hex(), "policy": tst.policy}

    source = {"repo": repo, "read": True, "reason": None, "default_branch": "main",
              "head": hashlib.sha1(b"synthetic head").hexdigest(), "tags": [], "absent": [],
              "release_assets": {"read": True, "reason": None, "count": 0}}
    proofs = {"preimage": "root.preimage",
              "opentimestamps": {"file": "root.preimage.ots", "accepted_by": ["https://a.calendar.example", "https://b.calendar.example"],
                                 "failed": []},
              "rfc3161": [token_entry("FM Verify Test TSA RSA", "test-rsa", tsr_a), token_entry("FM Verify Second Test TSA", "test-p256", tsr_b)]}

    def manifest(descs: list[dict], order: str = "sorted", created: str = "2026-10-17T08:04:11.000Z", previous: dict | None = None,
                 sources: list | None = None, prf: dict | None = None) -> dict:
        """anchor-manifest/v0, as the Ledger's src/anchor/anchor.ts writes it."""
        ls = ledger_anchors.sorted_leaves(descs)
        if order == "reversed":
            ls = ls[::-1]
        return {"contract": "anchor-manifest/v0", "created": created, "root": merkle.tree_hash(ls).hex(), "size": len(ls),
                "leaves": [{"leaf_hash": merkle.leaf_hash(x).hex(), "descriptor": json.loads(x)} for x in ls],
                "sources": sources if sources is not None else [source], "previous": previous,
                "proofs": prf if prf is not None else proofs}

    common = {"network": "regtest", "headers_chain": [{"path": "../../bitcoin/regtest/ledger-anchor-headers-0-4.bin", "start": 0}],
              "roots": ["../../rfc3161/pki/root.pem", "../pki/second-root.pem"]}

    def case(name: str, expected: dict, man: dict | None = None, pre: bytes = preimage, ots_bytes: bytes | None = good_ots,
             tokens: dict | None = None) -> None:
        d = out / name
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps(man if man is not None else manifest(descriptors), indent=1) + "\n", encoding="utf-8")
        (d / "root.preimage").write_bytes(pre)
        if ots_bytes is not None:
            (d / "root.preimage.ots").write_bytes(ots_bytes)
        for tname, data in (tokens if tokens is not None else {"test-rsa": tsr_a, "test-p256": tsr_b}).items():
            (d / f"root.preimage.{tname}.tsr").write_bytes(data)
        (d / "expected.json").write_text(json.dumps({**common, **expected}, indent=1) + "\n", encoding="utf-8")

    case("valid", {"description": "Five leaves (three files, two log entries) from one repository, an OpenTimestamps proof and two authorities' tokens",
                   "repos": {repo: "../repo"}, "outcome": "valid"})
    case("checkout-later", {"description": "The same anchor against a checkout where the rulings file grew since: a warning",
                            "repos": {repo: "../repo-later"}, "outcome": "valid", "warning": ["ledger_anchor.checkout.example/repository"]})
    case("checkout-assembled", {"description": ("The same anchor against a checkout where the fragment was since assembled into the log: "
                                                "the log changed (a warning) and the fragment is found as the log's new row"),
                                "repos": {repo: "../repo-assembled"}, "outcome": "valid", "warning": ["ledger_anchor.checkout.example/repository"]})
    altered = [dict(x) for x in descriptors]
    altered[0]["sha256"] = sha256(b"something else").hex()
    case("descriptor-altered", {"description": "A descriptor's hash changed after anchoring", "outcome": "invalid",
                                "failing": ["ledger_anchor.leaves"]}, man=manifest(altered))
    case("descriptor-dropped", {"description": "A descriptor removed after anchoring", "outcome": "invalid",
                                "failing": ["ledger_anchor.leaves"]}, man=manifest(descriptors[:-1]))
    case("one-authority", {"description": "Only one of the two tokens the manifest names is in the directory: valid, with warnings",
                           "outcome": "valid", "warning": ["ledger_anchor.files", "ledger_anchor.policy"]}, tokens={"test-rsa": tsr_a})
    other_pre = ledger_anchors.preimage_for(ledger_anchors.sorted_leaves(descriptors[:-1]))
    case("proofs-over-another-root", {"description": "The proofs cover another root's preimage", "outcome": "invalid",
                                      "failing": ["ledger_anchor.leaves", "ledger_anchor.ots",
                                                  "ledger_anchor.rfc3161.root.preimage.test-p256.tsr",
                                                  "ledger_anchor.rfc3161.root.preimage.test-rsa.tsr"]}, pre=other_pre)
    wrong_hash = manifest(descriptors)
    wrong_hash["leaves"][1]["leaf_hash"] = sha256(b"not this leaf").hex()
    case("leaf-hash-wrong", {"description": "A leaf hash in the manifest is not the hash of its descriptor", "outcome": "invalid",
                             "failing": ["ledger_anchor.leaves"]}, man=wrong_hash)
    case("leaves-unsorted", {"description": ("The leaves listed out of the documented order: in that order they give another root "
                                             "(a failure), and the order itself is a warning"), "outcome": "invalid",
                             "failing": ["ledger_anchor.leaves"], "warning": ["ledger_anchor.order"]},
         man=manifest(descriptors, order="reversed"))
    misstated = json.loads(json.dumps(proofs))
    misstated["rfc3161"][0]["gen_time"] = "2026-10-17T07:04:12.000Z"
    case("manifest-misstates-token", {"description": "The manifest states a genTime an hour before the token's own", "outcome": "invalid",
                                      "failing": ["ledger_anchor.statements"]}, man=manifest(descriptors, prf=misstated))
    extra = manifest(descriptors)
    extra["note"] = "a field the schema does not have"
    case("schema-violation", {"description": "A manifest with a field anchor-manifest/v0 does not have", "outcome": "invalid",
                              "failing": ["ledger_anchor.manifest_schema"]}, man=extra)
    misnamed = json.loads(json.dumps(proofs))
    misnamed["rfc3161"][0]["authority"] = "DigiCert"
    case("authority-misnamed", {"description": "The manifest names DigiCert for a token another authority signed: a warning",
                                "outcome": "valid", "warning": ["ledger_anchor.authorities"]}, man=manifest(descriptors, prf=misnamed))
    p256_k, p256_cert, _ = tsa_fixtures.test_authority_p256()
    same_org = tsa_fixtures.token(p256_k, p256_cert, [p256_cert, ica], preimage, serial=4005, sig="ecdsa", gen_time=gen)
    not_independent = {**proofs, "rfc3161": [proofs["rfc3161"][0], token_entry("FM Verify Test TSA P-256", "test-p256", same_org)]}
    case("authorities-not-independent", {"description": "Both tokens from one organisation under one root: valid, with a warning",
                                         "outcome": "valid", "warning": ["ledger_anchor.independence"]},
         man=manifest(descriptors, prf=not_independent), tokens={"test-rsa": tsr_a, "test-p256": same_org})
    unread = {**source, "repo": "example/private", "read": False, "reason": "no read token", "head": None,
              "release_assets": {"read": False, "reason": "no read token", "count": 0}}
    case("source-not-read", {"description": "One of two sources could not be read: valid for what it covers, with a warning",
                             "outcome": "valid", "warning": ["ledger_anchor.sources"]}, man=manifest(descriptors, sources=[source, unread]))
    later = manifest(descriptors)
    later["contract"] = "anchor-manifest/v1"
    case("unknown-contract", {"description": "A manifest contract this verifier does not read: indeterminate", "outcome": "indeterminate"},
         man=later)
    case("unversioned", {"description": "A manifest with no contract: descriptors found by their documented shape", "outcome": "valid"},
         man={"leaves": [{"descriptor": json.loads(x)} for x in ledger_anchors.sorted_leaves(descriptors)]})

    # Sets: an anchors directory with index.jsonl and two anchors, the second linked to the first.
    second_descs = descriptors + [desc("decisions_fragment", "docs/decisions.d/2026-10-17-example.md", sha256(b"| 2026-10-17 | later |\n"))]
    second_leaves = ledger_anchors.sorted_leaves(second_descs)
    second_pre = ledger_anchors.preimage_for(second_leaves)
    second_root = sha256(second_pre)
    gen2 = gen + _dt.timedelta(hours=1)
    tsr_a2 = tsa_fixtures.token(rsa_k, rsa_cert, [rsa_cert, ica], second_pre, serial=4003, sig="rsa", gen_time=gen2)
    tsr_b2 = tsa_fixtures.token(ec_k, ec_cert, [ec_cert], second_pre, serial=4004, sig="ecdsa", gen_time=gen2)
    pending = ots.DetachedTimestamp(SHA256, ots.Timestamp(second_root, [ots.Attestation(ots.TAG_PENDING, ots._varbytes(b"https://a.calendar.example"))]))
    proofs2 = {**proofs, "rfc3161": [token_entry("FM Verify Test TSA RSA", "test-rsa", tsr_a2),
                                     token_entry("FM Verify Second Test TSA", "test-p256", tsr_b2)]}
    first_rel, second_rel = "2026/10/17/080411Z", "2026/10/17/090411Z"
    m1 = manifest(descriptors)
    m2 = manifest(second_descs, created="2026-10-17T09:04:11.000Z", previous={"path": first_rel, "root": m1["root"]}, prf=proofs2)

    def anchor_set(name: str, expected: dict, second: dict, lines: list[dict]) -> None:
        d = out / name
        for rel, man, pre, ots_b, toks in ((first_rel, m1, preimage, good_ots, {"test-rsa": tsr_a, "test-p256": tsr_b}),
                                           (second_rel, second, second_pre, pending.serialize(), {"test-rsa": tsr_a2, "test-p256": tsr_b2})):
            a = d.joinpath(*rel.split("/"))
            a.mkdir(parents=True)
            (a / "manifest.json").write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
            (a / "root.preimage").write_bytes(pre)
            (a / "root.preimage.ots").write_bytes(ots_b)
            for tname, data in toks.items():
                (a / f"root.preimage.{tname}.tsr").write_bytes(data)
        (d / "index.jsonl").write_text("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in lines), encoding="utf-8")
        (d / "expected.json").write_text(json.dumps({**common, "all": True, **expected}, indent=1) + "\n",
                                         encoding="utf-8")

    line1 = {"created": m1["created"], "root": m1["root"], "size": m1["size"], "path": first_rel}
    line2 = {"created": m2["created"], "root": m2["root"], "size": m2["size"], "path": second_rel}
    anchor_set("set-valid", {"description": ("Two anchors an hour apart, listed in index.jsonl, the second linked to the first; "
                                             "its OpenTimestamps proof still pending"), "outcome": "valid"}, m2, [line1, line2])
    broken = {**m2, "previous": {"path": first_rel, "root": sha256(b"another root").hex()}}
    anchor_set("set-broken-link", {"description": "The second anchor links to a root the first does not have", "outcome": "invalid",
                                   "failing": ["anchor_set.index"]}, broken, [line1, line2])
    anchor_set("set-unlisted", {"description": "index.jsonl lists only the first anchor: a warning", "outcome": "valid",
                                "warning": ["anchor_set.index"]}, m2, [line1])

    def prove_case(name: str, content: bytes, expected: dict) -> None:
        d = out / name
        d.mkdir(parents=True)
        (d / "expected.json").write_text(json.dumps({**common, "anchors": "../set-valid", "prove_sha256": sha256(content).hex(), **expected},
                                                    indent=1) + "\n", encoding="utf-8")

    prove_case("prove-earliest", LEDGER_REPO["docs/decisions.d/2026-10-16-example.md"],
               {"description": "A fragment named in both anchors of set-valid: the earliest, 080411Z, holds", "outcome": "valid"})
    prove_case("prove-later-only", b"| 2026-10-17 | later |\n",
               {"description": "Content named only in the second anchor, whose OpenTimestamps proof is pending: its tokens hold",
                "outcome": "valid"})
    prove_case("prove-nowhere", b"never anchored\n",
               {"description": "Content no anchor names: indeterminate", "outcome": "indeterminate"})


def build_merkle() -> None:
    """Inclusion proofs: RFC 9162 and the explicit scheme, and their failures."""
    from fmverify import merkle

    out = FIX / "merkle"
    if out.exists():
        shutil.rmtree(out)
    leaves = [b"FundingMachine verifier fixture leaf %d\n" % i for i in range(7)]
    root = merkle.tree_hash(leaves)

    def proof(i: int, size: int = 7) -> dict:
        return {"scheme": "rfc9162-sha256", "leaf_index": i, "tree_size": size,
                "path": [h.hex() for h in merkle.inclusion_path(leaves[:size], i)], "root": merkle.tree_hash(leaves[:size]).hex()}

    def case(name: str, p: dict, leaf: bytes, expected: dict) -> None:
        d = out / name
        d.mkdir(parents=True)
        (d / "proof.json").write_text(json.dumps(p, indent=1) + "\n", encoding="utf-8")
        (d / "leaf.txt").write_bytes(leaf)
        (d / "expected.json").write_text(json.dumps({"leaf_file": "leaf.txt", **expected}, indent=1) + "\n", encoding="utf-8")

    case("rfc9162-valid", proof(5), leaves[5], {"description": "Leaf 5 of a tree of 7", "root": root.hex(), "outcome": "valid"})
    case("rfc9162-wrong-leaf", proof(5), leaves[4], {"description": "Another leaf with leaf 5's path", "outcome": "invalid",
                                                    "failing": ["merkle.root"]})
    case("rfc9162-wrong-index", dict(proof(5), leaf_index=4), leaves[5], {"description": "The right path under the wrong index",
                                                                          "outcome": "invalid", "failing": ["merkle.root"]})
    case("rfc9162-other-root", proof(5), leaves[5], {"description": "A valid proof, but not under the anchored root given",
                                                    "root": merkle.tree_hash(leaves[:6]).hex(), "outcome": "invalid",
                                                    "failing": ["merkle.anchored_root"]})
    case("rfc9162-path-too-long", dict(proof(5), path=proof(5)["path"] + ["00" * 32]), leaves[5],
         {"description": "A path longer than the tree is deep", "outcome": "invalid", "failing": ["merkle.proof"]})
    sibling = sha256(b"sibling")
    case("explicit-valid", {"scheme": "explicit-sha256", "leaf_prefix": "00", "node_prefix": "01",
                            "steps": [{"side": "right", "hash": sibling.hex()}],
                            "root": sha256(b"\x01" + sha256(b"\x00" + leaves[0]) + sibling).hex()}, leaves[0],
         {"description": "The explicit scheme with domain separation: valid, with a warning that it binds no position",
          "outcome": "valid", "warning": ["merkle.scheme"]})


def build_roots() -> None:
    """A tenant's hourly root records as a chain, and ways to break it."""
    import base64
    import copy

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from fmverify import jcs
    from fmverify.base58 import ed25519_did_key

    out = FIX / "roots"
    if out.exists():
        shutil.rmtree(out)
    tenant = Ed25519PrivateKey.from_private_bytes(sha256(b"fm-verify test tenant key"))
    other = Ed25519PrivateKey.from_private_bytes(sha256(b"fm-verify test other key"))

    def raw(k) -> bytes:
        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(rec: dict, k) -> dict:
        rec = {x: y for x, y in rec.items() if x != "sig"}
        msg = ("ledger-root/v0:" + sha256(jcs.dumps(rec)).hex()).encode()
        return {**rec, "sig": base64.urlsafe_b64encode(k.sign(msg)).rstrip(b"=").decode()}

    def chain(hours: list[int], key=tenant) -> list[dict]:
        recs, prev = [], "0" * 64
        for i, h in enumerate(hours):
            rec = sign({"contract": "ledger-root/v0", "tenant_id": "fixture",
                        "window": {"start": f"2026-10-16T{h:02d}:00:00.000Z", "end": f"2026-10-16T{h + 1:02d}:00:00.000Z"},
                        "size": 3 + i, "root": sha256(b"hour %d" % h).hex(), "prev_root": prev, "key_id": sha256(raw(tenant)).hex()}, key)
            recs.append(rec)
            prev = sha256(jcs.dumps(rec)).hex()
        return recs

    good = chain([8, 9, 11, 12, 15])
    did = ed25519_did_key(raw(tenant))

    def case(name: str, recs: list[dict], expected: dict) -> None:
        d = out / name
        d.mkdir(parents=True)
        (d / "roots.json").write_text(json.dumps({"records": recs}, indent=1) + "\n", encoding="utf-8")
        (d / "expected.json").write_text(json.dumps({"key": did, **expected}, indent=1) + "\n", encoding="utf-8")

    case("valid", good, {"description": "Five hours with events (10, 13 and 14 had none), linked and signed", "outcome": "valid"})
    case("hour-dropped", good[:2] + good[3:], {"description": "The record of 11:00 removed", "outcome": "invalid", "failing": ["roots.links"]})
    case("re-ordered", [good[0], good[2], good[1]] + good[3:], {"description": "Two records swapped", "outcome": "invalid", "failing": ["roots.links"]})
    altered = copy.deepcopy(good)
    altered[2]["size"] += 1
    case("record-altered", altered, {"description": "One record's size changed after signing", "outcome": "invalid",
                                     "failing": ["roots.links", "roots.signatures"]})
    case("signed-by-another-key", chain([8, 9, 11, 12, 15], key=other),
         {"description": "Records naming the tenant key, signed by another", "outcome": "invalid", "failing": ["roots.signatures"]})
    case("from-the-middle", good[2:], {"description": "A later stretch of the chain: valid, with a note that earlier records were not given",
                                       "outcome": "valid"})


def build_certificates(writer, prefix: str = "", headers_name: str = "certificate-headers-0-5.bin", fresh: bool = True,
                       core_only: bool = False) -> None:
    """ledger-certificate/v0 credentials, issued here from the Provenance Ledger
    session's published documents with this repository's own test keys, over
    a fixture chain of tools/chain_fixtures.py. With ``core_only``, only the
    valid cases and the overstated map, named with ``prefix``."""
    import base64
    import copy
    import datetime as _dt

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from fmverify import jcs, ledger_events, merkle
    from fmverify.base58 import b58encode, ed25519_did_key
    from fmverify.certificate import ORIGINS, SCOPE_STATEMENT, percentages

    out = FIX / "certificate"
    if fresh and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    def key(seed: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(sha256(seed.encode()))

    def raw(k) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    tenant, other = key("fm-verify test tenant key"), key("fm-verify test other key")
    did = ed25519_did_key(raw(tenant))

    # The hour: the fixture chain's events, accepted in order; the sign event is the last.
    chain_events = writer.events
    events = [bytes.fromhex(chain_fixtures.event_hash(e)) for e in chain_events]
    signed_index = len(events) - 1
    result = ledger_events.validate_chain(chain_events)
    assert result.ok, result.message
    amap = ledger_events.authorship_map(result.state, len(chain_events), result.head)
    sign_ev, genesis = chain_events[-1], chain_events[0]["payload"]["genesis"]

    def record_for(k, root_bytes: bytes, tenant_id: str = "fixture", signer=None) -> dict:
        rec = {"contract": "ledger-root/v0", "tenant_id": tenant_id,
               "window": {"start": "2026-10-16T08:00:00.000Z", "end": "2026-10-16T09:00:00.000Z"},
               "size": len(events), "root": root_bytes.hex(), "prev_root": "0" * 64, "key_id": sha256(raw(k)).hex()}
        msg = ("ledger-root/v0:" + sha256(jcs.dumps(rec)).hex()).encode()
        rec["sig"] = b64url((signer or k).sign(msg))
        return rec

    hour_root = merkle.tree_hash(events)
    record = record_for(tenant, hour_root)
    other_record = record_for(other, sha256(b"another tenant's hour"), tenant_id="other")
    anchor_leaves = [sha256(jcs.dumps(record)), sha256(jcs.dumps(other_record))]  # sorted by tenant_id: fixture, other
    anchor_root = merkle.tree_hash(anchor_leaves)

    # The anchor: a regtest block 3 commits to the anchored root; the test authority signs it.
    path_ops = [append(sha256(b"certificate anchor nonce")[:16]), SHA256, prepend(sha256(b"certificate calendar sibling")), SHA256,
                prepend(bytes.fromhex("0100000001") + bytes(36) + bytes.fromhex("00ffffffff01") + bytes(8) + bytes.fromhex("226a20")),
                append(bytes(4)), SHA256, SHA256] + merkle_ops([sha256d(b"certificate block sibling")], 0)
    prev, headers = bytes(32), []
    for height in range(6):
        h = mine_regtest(prev, run(anchor_root, path_ops) if height == 3 else sha256d(b"certificate regtest %d" % height),
                         1760200000 + 600 * height)
        headers.append(h)
        prev = sha256d(h)
    (REG / headers_name).write_bytes(b"".join(headers))
    ots_proof = ots.DetachedTimestamp(SHA256, chain(anchor_root, path_ops, bitcoin_attestation(3))).serialize()

    tsa_k, tsa_cert, ica = tsa_fixtures.test_authority()
    gen_time = _dt.datetime(2026, 10, 16, 9, 5, 0, tzinfo=_dt.timezone.utc)

    def tsr(value: bytes) -> bytes:
        return tsa_fixtures.token(tsa_k, tsa_cert, [tsa_cert, ica], b"", serial=3001, sig="rsa", imprint_value=value, gen_time=gen_time)

    def anchor_block(token: bytes, ots_status: str = "bitcoin", ots_block=3, gen_time_text: str = "2026-10-16T09:05:00Z") -> dict:
        return {"contract": "ledger-anchor/v0", "root": anchor_root.hex(), "size": 2, "leaf_index": 0,
                "audit_path": [h.hex() for h in merkle.inclusion_path(anchor_leaves, 0)],
                "opentimestamps": {"proof_b64": base64.b64encode(ots_proof).decode(), "status": ots_status, "bitcoin_block": ots_block},
                "rfc3161": [{"authority": "FM Verify Test TSA RSA", "url": "http://tsa.example.org", "token_b64": base64.b64encode(token).decode(),
                             "gen_time": gen_time_text}]}

    exported = chain_fixtures.EXPORTED
    used_tools = sorted({(e["actor"]["tool_name"], e["actor"]["model_id"]) for e in chain_events if e["actor"]["kind"] == "tool"},
                        key=lambda t: (t[0], t[1] or ""))
    st = result.state
    bound = {e["payload"]["binding_id"]: e for e in chain_events if e["type"] == "evidence.bind"}
    subject = {
        "type": "DocumentWritingRecord", "contract": "ledger-certificate/v0", "scope_statement": SCOPE_STATEMENT,
        "tenant_id": st.tenant_id, "doc_id": st.doc_id,
        "document": {"exported_sha256": sign_ev["payload"]["exported"]["sha256"], "media_type": sign_ev["payload"]["exported"]["media_type"],
                     "byte_length": sign_ev["payload"]["exported"]["byte_length"], "doc_hash": sign_ev["doc_hash"],
                     "key_commitment": genesis["key_commitment"]},
        "signed": {"seq": sign_ev["seq"], "event_hash": events[signed_index].hex(), "ts": sign_ev["ts"],
                   "actor_id": sign_ev["actor"]["id"], "declaration_hash": sign_ev["payload"]["declaration_hash"]},
        "chain": {"first_event_hash": events[0].hex(), "events": len(chain_events),
                  "sessions": [{"session_id": sid, "key_id": v["key_id"], "public_key": v["public_key"], "client": v["client"],
                                "opened_seq": v["opened_seq"], "closed_seq": v["closed_seq"]} for sid, v in st.sessions.items()]},
        "authorship": {"contract": "authorship-map/v0", "map_sha256": sha256(jcs.dumps(amap)).hex(), "unit": "unicode_code_point",
                       **{k: amap[k] for k in ("document", "sections", "fidelity", "activity")}},
        "tools": [{"tool_name": name, "model_id": model} for name, model in used_tools],
        "evidence": {"statements": len(st.statements), "statements_with_evidence": len(set(st.bindings.values())),
                     "bindings": [{"binding_id": b, "statement_id": owner, "bound_seq": bound[b]["seq"],
                                   **{k: bound[b]["payload"][k] for k in ("source", "date", "licence", "page_hash", "quoted_span")}}
                                  for b, owner in sorted(st.bindings.items(), key=lambda kv: bound[kv[0]]["seq"])]},
        "ledger_root": {"record": record, "leaf_index": signed_index,
                        "audit_path": [h.hex() for h in merkle.inclusion_path(events, signed_index)], "anchor": anchor_block(tsr(anchor_root))},
    }

    def issue(subj: dict, signer=tenant, vm_did: str | None = None) -> dict:
        cred = {"@context": ["https://www.w3.org/ns/credentials/v2"], "id": "urn:uuid:3c2f1e0d-0000-4000-8000-00000000c0de",
                "type": ["VerifiableCredential", "ProvenanceCertificate"], "issuer": {"id": did, "name": "Provenance Ledger"},
                "validFrom": "2026-10-16T09:10:00.000Z", "credentialSubject": subj}
        vm = vm_did or did
        config = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2026-10-16T09:10:00.000Z",
                  "verificationMethod": f"{vm}#{vm[len('did:key:'):]}", "proofPurpose": "assertionMethod", "@context": cred["@context"]}
        sig = signer.sign(sha256(jcs.dumps(config)) + sha256(jcs.dumps(cred)))
        cred["proof"] = {**config, "proofValue": "z" + b58encode(sig)}
        return cred

    common = {"network": "regtest", "headers_chain": [{"path": f"../../bitcoin/regtest/{headers_name}", "start": 0}],
              "roots": ["../../rfc3161/pki/root.pem"]}

    def case(name: str, cred: dict, expected: dict, file_bytes: bytes | None = exported, events_doc: list | None = None) -> None:
        d = out / (prefix + name)
        d.mkdir()
        (d / "certificate.json").write_text(json.dumps(cred, indent=1) + "\n", encoding="utf-8")
        exp = {**common, **expected}
        if events_doc is not None:
            (d / "events.json").write_text(json.dumps({"contract": events_doc[-1]["contract"], "events": events_doc}, indent=1) + "\n",
                                           encoding="utf-8")
            exp["events"] = "events.json"
        if file_bytes is not None:
            (d / "exported.txt").write_bytes(file_bytes)
            exp["file"] = "exported.txt"
        (d / "expected.json").write_text(json.dumps(exp, indent=1) + "\n", encoding="utf-8")

    def variant(**changes) -> dict:
        subj = copy.deepcopy(subject)
        for path, value in changes.items():
            target = subj
            keys = path.split("__")
            for k in keys[:-1]:
                target = target[int(k)] if k.isdigit() else target[k]
            target[keys[-1]] = value
        return subj

    case("valid-anchored", issue(subject), {"description": "Anchored certificate, the exported file presented", "outcome": "valid"})
    case("valid-with-chain", issue(subject), {"description": "Anchored certificate, the exported file and the event chain presented: all seven steps run",
                                              "outcome": "valid"}, events_doc=chain_events)
    inflated = copy.deepcopy(amap)
    source = "tool_generated" if amap["document"]["counts"]["tool_generated"] else "imported"
    moved = inflated["document"]["counts"][source]
    inflated["document"]["counts"]["human_typed"] += moved
    inflated["document"]["counts"][source] = 0
    inflated["document"]["percent"] = percentages(inflated["document"]["counts"], ORIGINS, inflated["document"]["total"])
    case("authorship-overstated", issue(variant(authorship={**subject["authorship"], "document": inflated["document"],
                                                            "map_sha256": sha256(jcs.dumps(inflated)).hex()})),
         {"description": ("The issuer signed a document total crediting the tool's text to the person; only the chain shows it"
                          if source == "tool_generated" else
                          "The issuer signed a document total crediting text changed while capture was off to the person; only the chain shows it"),
          "outcome": "invalid", "failing": ["certificate.authorship_map"]}, events_doc=chain_events)
    if core_only:
        return
    case("tools-omitted", issue(variant(tools=[])),
         {"description": "The issuer signed a certificate naming no tool, where the chain records one", "outcome": "invalid",
          "failing": ["certificate.chain_statements"]}, events_doc=chain_events)
    other_chain = chain_fixtures.Writer("fm-verify other chain")
    other_chain.open("s1", ("st-1", "approach", None))
    other_chain.insert("s1", "st-1", 0, "A different document.")
    other_chain.sign("s1", exported)
    case("chain-of-another-document", issue(subject),
         {"description": "The events presented are another document's", "outcome": "invalid", "failing": ["certificate.chain"]},
         events_doc=other_chain.events)
    case("valid-not-anchored", issue(variant(ledger_root__anchor=None)),
         {"description": "Issued before the hour was anchored: steps 4 and 5 run, step 6 cannot", "outcome": "valid"})
    case("wrong-file", issue(subject), {"description": "The file presented is not the exported document", "outcome": "invalid",
                                        "failing": ["certificate.file"]}, file_bytes=exported.replace(b"exported", b"edited"))
    tampered = issue(subject)
    tampered["credentialSubject"]["doc_id"] = "0b7d1c52-5f1e-4c47-9a0e-6d1f6d3f2a11"
    case("tampered-after-signing", tampered, {"description": "The document id changed after the issuer signed", "outcome": "invalid",
                                              "failing": ["certificate.proof"]})
    case("signed-by-another-key", issue(subject, signer=other), {"description": "The issuer is named, but another key signed",
                                                                  "outcome": "invalid", "failing": ["certificate.proof"]})
    case("scope-statement-altered", issue(variant(scope_statement=SCOPE_STATEMENT.replace("does not detect AI", "detects no AI"))),
         {"description": "The issuer signed an altered scope statement", "outcome": "invalid", "failing": ["certificate.scope_statement"]})
    bad_percent = copy.deepcopy(subject["authorship"]["document"]["percent"])
    bad_percent["human_typed"], bad_percent["imported"] = "65.0", "17.0"
    case("percentages-inconsistent", issue(variant(authorship__document__percent=bad_percent)),
         {"description": "The issuer signed percentages that do not follow from the counts", "outcome": "invalid",
          "failing": ["certificate.authorship_arithmetic"]})
    wrong_record = record_for(tenant, hour_root, signer=other)
    case("root-record-wrong-signer", issue(variant(ledger_root__record=wrong_record, ledger_root__anchor=None)),
         {"description": "The hourly root record is signed by a key other than the issuer's", "outcome": "invalid",
          "failing": ["certificate.root_record"]})
    case("inclusion-wrong", issue(variant(ledger_root__leaf_index=17)),
         {"description": "The issuer signed a wrong position for the sign event", "outcome": "invalid", "failing": ["certificate.inclusion"]})
    case("anchor-time-earlier-than-token", issue(variant(ledger_root__anchor=anchor_block(tsr(anchor_root), gen_time_text="2026-10-16T07:00:00Z"))),
         {"description": "The certificate states an earlier time than the authority's token", "outcome": "invalid",
          "failing": ["certificate.rfc3161.0.gen_time"]})
    case("anchor-token-over-other-root", issue(variant(ledger_root__anchor=anchor_block(tsr(sha256(b"some other root")))))  ,
         {"description": "The authority's token covers a different root", "outcome": "invalid", "failing": ["certificate.rfc3161.0"]})
    case("ots-status-overstated", issue(variant(ledger_root__anchor=anchor_block(tsr(anchor_root), ots_block=99))),
         {"description": "The certificate names a Bitcoin block the proof does not hold", "outcome": "invalid",
          "failing": ["certificate.opentimestamps.status"]})
    def pdf_case(name: str, data: bytes, expected: dict) -> None:
        d = out / name
        d.mkdir()
        (d / "certificate.pdf").write_bytes(data)
        (d / "exported.txt").write_bytes(exported)
        exp = {**common, "certificate": "certificate.pdf", "file": "exported.txt", **expected}
        (d / "expected.json").write_text(json.dumps(exp, indent=1) + "\n", encoding="utf-8")

    good_json = (json.dumps(issue(subject), indent=1) + "\n").encode()
    pdf_case("pdf-classic", pdf_fixtures.classic(good_json),
             {"description": "The PDF form: certificate.json embedded, uncompressed", "outcome": "valid"})
    pdf_case("pdf-compressed", pdf_fixtures.compressed(good_json),
             {"description": "The PDF form, PDF 1.5: the file specification in an object stream, the embedded file deflated",
              "outcome": "valid"})
    other_json = (json.dumps(issue(variant(tools=[])), indent=1) + "\n").encode()
    pdf_case("pdf-two-attachments", pdf_fixtures.classic(good_json, [("certificate.json", good_json), ("certificate.json", other_json)]),
             {"description": "Two different embedded files both named certificate.json: refused", "outcome": "invalid",
              "failing": ["certificate.pdf"]})
    tampered_json = good_json.replace(b'"ledger-certificate/v0"', b'"ledger-certificate/v0" ', 1).replace(
        subject["doc_id"].encode(), subject["doc_id"][:-1].encode() + b"0", 1)
    pdf_case("pdf-updated-attachment", pdf_fixtures.with_update(pdf_fixtures.classic(good_json), tampered_json),
             {"description": "An incremental update replaces the embedded certificate with an altered one: the current one is checked, and fails",
              "outcome": "invalid", "failing": ["certificate.proof"]})
    pdf_case("pdf-no-attachment", pdf_fixtures.classic(good_json, []),
             {"description": "A PDF carrying no certificate.json", "outcome": "invalid", "failing": ["certificate.pdf"]})

    case("unknown-version", issue(variant(contract="ledger-certificate/v9")),
         {"description": "A contract version this verifier does not know: not verified", "outcome": "indeterminate"})


def main() -> None:
    # Mainnet: contiguous header files cut from the sparse capture.
    sparse = read_sparse(MAIN / "headers-sparse.txt")
    for lo, hi in [(0, 19), (839990, 840009)]:
        (MAIN / f"headers-{lo}-{hi}.bin").write_bytes(b"".join(sparse[h] for h in range(lo, hi + 1)))

    # Mainnet: a real proof built from public chain data only. The "file" is
    # the single SHA-256 of block 840000's coinbase transaction (32 bytes), so
    # the proof's file hash gives the txid, and the Merkle branch leads to the
    # block's Merkle root.
    cb = json.loads((MAIN / "coinbase-840000.json").read_text(encoding="utf-8"))
    subject = bytes.fromhex(cb["tx_sha256_single"])
    digest = sha256(subject)
    assert digest[::-1].hex() == cb["txid"]
    branch = [bytes.fromhex(h)[::-1] for h in cb["merkle_branch_display"]]
    ops = merkle_ops(branch, cb["pos"])
    header = parse_header(sparse[840000])
    assert run(digest, ops) == header.merkle_root
    mainnet_proof = ots.DetachedTimestamp(SHA256, chain(digest, ops, bitcoin_attestation(840000))).serialize()
    sparse_path = "../../bitcoin/mainnet/headers-sparse.txt"
    window_path = "../../bitcoin/mainnet/headers-839990-840009.bin"
    write_case("mainnet-840000-sparse", mainnet_proof,
               {"description": "Real proof from public chain data, checked against a sparse headers file",
                "network": "mainnet", "file": "subject.bin", "headers": [sparse_path], "outcome": "valid"},
               {"subject.bin": subject})
    write_case("mainnet-840000-chain", mainnet_proof,
               {"description": "The same proof, checked against a contiguous header window starting at 839990",
                "network": "mainnet", "file": "subject.bin", "headers_chain": [{"path": window_path, "start": 839990}],
                "outcome": "valid"},
               {"subject.bin": subject})
    write_case("mainnet-840000-no-headers", mainnet_proof,
               {"description": "No header source given: the anchor cannot be checked",
                "network": "mainnet", "file": "subject.bin", "outcome": "indeterminate"},
               {"subject.bin": subject})
    write_case("mainnet-840000-wrong-file", mainnet_proof,
               {"description": "The file presented is not the one the proof covers",
                "network": "mainnet", "file": "subject.bin", "headers": [sparse_path], "outcome": "invalid",
                "failing": ["ots.subject"]},
               {"subject.bin": sha256(b"not the coinbase")})

    # Mainnet: a forged header. The proof commits to a made-up root; the
    # header file carries block 840000's header with that root swapped in,
    # which breaks its proof of work. The verifier cannot vouch for it.
    forged_ops = [append(sha256(b"forged sibling")), SHA256]
    fake_digest = sha256(b"forged subject")
    forged_commitment = run(fake_digest, forged_ops)
    raw = bytearray(sparse[840000])
    raw[36:68] = forged_commitment
    write_case("mainnet-forged-header", ots.DetachedTimestamp(SHA256, chain(fake_digest, forged_ops, bitcoin_attestation(840000))).serialize(),
               {"description": "A header at height 840000 altered to match the proof; it no longer meets its proof of work",
                "network": "mainnet", "file": "subject.bin", "headers": ["headers.txt"], "outcome": "indeterminate"},
               {"subject.bin": b"forged subject", "headers.txt": f"840000 {bytes(raw).hex()}\n".encode()})

    # Regtest: a calendar-shaped proof with a fork (one branch pending, one
    # anchored), the anchoring transaction, and the block's Merkle branch.
    REG.mkdir(parents=True, exist_ok=True)
    text = b"FundingMachine verifier fixture: an anchored document\n"
    d0 = sha256(text)
    nonce = sha256(b"fixture nonce")[:16]
    common = [append(nonce), SHA256]
    m1 = run(d0, common)
    cal = [prepend(sha256(b"calendar sibling 1")), SHA256, append(sha256(b"calendar sibling 2")), SHA256]
    tx_prefix = bytes.fromhex("0100000001") + sha256(b"prevout") + bytes.fromhex("00000000") + bytes.fromhex("00ffffffff01") + bytes(8) + bytes.fromhex("22") + bytes.fromhex("6a20")
    tx_suffix = bytes.fromhex("00000000")
    txops = [prepend(tx_prefix), append(tx_suffix), SHA256, SHA256]
    block_sibling = sha256d(b"another transaction")
    mops = merkle_ops([block_sibling, sha256d(b"a third subtree")], 0)
    anchored_ops = cal + txops + mops
    root5 = run(m1, anchored_ops)

    prev = bytes(32)
    reg_headers = []
    for height in range(0, 12):
        root = root5 if height == 5 else sha256d(b"regtest block %d" % height)
        h = mine_regtest(prev, root, 1760000000 + 600 * height)
        reg_headers.append(h)
        prev = sha256d(h)
    (REG / "headers-0-11.bin").write_bytes(b"".join(reg_headers))
    reg_chain = [{"path": "../../bitcoin/regtest/headers-0-11.bin", "start": 0}]

    def regtest_proof(height: int, cal_ops=cal, with_pending=True) -> bytes:
        anchored = chain(m1, cal_ops + txops + mops, bitcoin_attestation(height))
        fork = ots.Timestamp(m1)
        if with_pending:
            fork.entries.append(pending_attestation("https://calendar.example.org"))
        fork.entries += anchored.entries
        return ots.DetachedTimestamp(SHA256, chain(d0, common, fork.entries)).serialize()

    write_case("regtest-valid", regtest_proof(5),
               {"description": "Calendar-shaped proof with a pending branch and a branch anchored in regtest block 5",
                "network": "regtest", "file": "document.txt", "headers_chain": reg_chain, "outcome": "valid"},
               {"document.txt": text})
    write_case("regtest-tampered-file", regtest_proof(5),
               {"description": "One character of the document changed after anchoring",
                "network": "regtest", "file": "document.txt", "headers_chain": reg_chain, "outcome": "invalid",
                "failing": ["ots.subject"]},
               {"document.txt": text.replace(b"anchored", b"Anchored")})
    tampered_cal = [prepend(sha256(b"calendar sibling X")), SHA256] + cal[2:]
    write_case("regtest-tampered-proof", regtest_proof(5, cal_ops=tampered_cal),
               {"description": "One operation in the proof altered: the path no longer reaches the block's Merkle root",
                "network": "regtest", "file": "document.txt", "headers_chain": reg_chain, "outcome": "invalid",
                "failing": ["ots.bitcoin.5"]},
               {"document.txt": text})
    write_case("regtest-back-dated", regtest_proof(2),
               {"description": "The attestation's block height changed from 5 to the earlier block 2",
                "network": "regtest", "file": "document.txt", "headers_chain": reg_chain, "outcome": "invalid",
                "failing": ["ots.bitcoin.2"]},
               {"document.txt": text})
    pending_only = ots.DetachedTimestamp(SHA256, chain(d0, common, pending_attestation("https://calendar.example.org"))).serialize()
    write_case("regtest-pending-only", pending_only,
               {"description": "Only a pending attestation: not yet anchored",
                "network": "regtest", "file": "document.txt", "headers_chain": reg_chain, "outcome": "indeterminate"},
               {"document.txt": text})
    good = regtest_proof(5)
    write_case("regtest-truncated", good[:-5],
               {"description": "The proof file cut short", "network": "regtest", "file": "document.txt",
                "headers_chain": reg_chain, "outcome": "invalid", "failing": ["ots.parse"]},
               {"document.txt": text})
    write_case("regtest-trailing-bytes", good + b"\x00",
               {"description": "A byte appended after the proof ends", "network": "regtest", "file": "document.txt",
                "headers_chain": reg_chain, "outcome": "invalid", "failing": ["ots.parse"]},
               {"document.txt": text})

    tsa_fixtures.build(FIX)
    build_anchors()
    build_ledger_anchors()
    writer = chain_fixtures.build(FIX)
    build_certificates(writer)
    build_certificates(chain_fixtures.v01_chain(close=False), prefix="v01-", headers_name="certificate-v01-headers-0-5.bin", fresh=False,
                       core_only=True)
    build_roots()
    build_merkle()

    manifest = {}
    for p in sorted(FIX.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS":
            manifest[p.relative_to(FIX).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    (FIX / "SHA256SUMS").write_text("".join(f"{h}  {name}\n" for name, h in manifest.items()), encoding="utf-8")


if __name__ == "__main__":
    main()
