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


def build_certificates() -> None:
    """ledger-certificate/v0 credentials, issued here from the Provenance Ledger
    session's published documents with this repository's own test keys."""
    import base64
    import copy
    import datetime as _dt

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from fmverify import jcs, merkle
    from fmverify.base58 import b58encode, ed25519_did_key
    from fmverify.certificate import FIDELITIES, ORIGINS, SCOPE_STATEMENT, percentages

    out = FIX / "certificate"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    def key(seed: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(sha256(seed.encode()))

    def raw(k) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    tenant, other = key("fm-verify test tenant key"), key("fm-verify test other key")
    did = ed25519_did_key(raw(tenant))

    # The hour: 20 accepted events; the sign event is the 19th.
    events = [sha256(b"fm-verify fixture event %d" % i) for i in range(20)]
    signed_index = 18

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
    (REG / "certificate-headers-0-5.bin").write_bytes(b"".join(headers))
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

    exported = b"FundingMachine verifier fixture: an exported document, as signed.\n"
    counts = {"human_typed": 120, "imported": 30, "tool_generated": 25, "tool_edited": 9}
    fidelity = {"live": 118, "snapshot_diff": 30, "tool_report": 36, "reconstructed": 0, "declared": 0}
    sec_a = {"human_typed": 70, "imported": 30, "tool_generated": 25, "tool_edited": 9}
    sec_b = {"human_typed": 50, "imported": 0, "tool_generated": 0, "tool_edited": 0}

    def block(c: dict, keys: list[str]) -> dict:
        total = sum(c.values())
        return {"total": total, "counts": dict(c), "percent": percentages(c, keys, total)}

    subject = {
        "type": "DocumentWritingRecord", "contract": "ledger-certificate/v0", "scope_statement": SCOPE_STATEMENT,
        "tenant_id": "fixture", "doc_id": "0b7d1c52-5f1e-4c47-9a0e-6d1f6d3f2a10",
        "document": {"exported_sha256": sha256(exported).hex(), "media_type": "text/plain", "byte_length": len(exported),
                     "doc_hash": sha256(b"keyed document hash stand-in").hex(), "key_commitment": sha256(b"document key stand-in").hex()},
        "signed": {"seq": signed_index + 1, "event_hash": events[signed_index].hex(), "ts": "2026-10-16T08:41:12.000Z",
                   "actor_id": "person:0f1x", "declaration_hash": sha256(b"declaration stand-in").hex()},
        "chain": {"first_event_hash": events[0].hex(), "events": signed_index + 1,
                  "sessions": [{"session_id": "5f9d1d0e-7a7b-4c2e-8d1e-3b1c2a4f5e60", "key_id": sha256(b"session key").hex(),
                                "public_key": b64url(sha256(b"session public key")), "client": {"name": "fixture-writer", "version": "0.1.0"},
                                "opened_seq": 1, "closed_seq": None}]},
        "authorship": {"contract": "authorship-map/v0", "map_sha256": sha256(b"authorship map stand-in").hex(), "unit": "unicode_code_point",
                       "document": block(counts, ORIGINS),
                       "sections": [{"section_id": "approach", "section_ref": "call:example/approach", "statements": 2, **block(sec_a, ORIGINS)},
                                    {"section_id": "team", "section_ref": None, "statements": 1, **block(sec_b, ORIGINS)}],
                       "fidelity": block(fidelity, FIDELITIES),
                       "activity": {"inserted": {"human_typed": 131, "imported": 30, "tool_generated": 40, "tool_edited": 9}, "deleted": 26}},
        "tools": [{"tool_name": "Example Assistant", "model_id": None}],
        "evidence": {"statements": 3, "statements_with_evidence": 1,
                     "bindings": [{"binding_id": "2d8f4c1e-9b3a-4f6d-8e2c-1a5b7c9d0e3f", "statement_id": "st-2", "bound_seq": 11,
                                   "source": {"ref": "url:https://example.org/source", "visibility": "public"},
                                   "date": {"kind": "retrieved", "value": "2026-10-15"}, "licence": "CC-BY-4.0",
                                   "page_hash": sha256(b"page").hex(), "quoted_span": {"quote_hash": sha256(b"quote").hex(), "locator": "paragraph 2"}}]},
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

    common = {"network": "regtest", "headers_chain": [{"path": "../../bitcoin/regtest/certificate-headers-0-5.bin", "start": 0}],
              "roots": ["../../rfc3161/pki/root.pem"]}

    def case(name: str, cred: dict, expected: dict, file_bytes: bytes | None = exported) -> None:
        d = out / name
        d.mkdir()
        (d / "certificate.json").write_text(json.dumps(cred, indent=1) + "\n", encoding="utf-8")
        exp = {**common, **expected}
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
    build_certificates()

    manifest = {}
    for p in sorted(FIX.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS":
            manifest[p.relative_to(FIX).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    (FIX / "SHA256SUMS").write_text("".join(f"{h}  {name}\n" for name, h in manifest.items()), encoding="utf-8")


if __name__ == "__main__":
    main()
