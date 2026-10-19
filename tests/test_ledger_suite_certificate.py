"""The Provenance Ledger suite's certificate cases that its recipes let a verifier derive itself (its
validation-conformance/v0, CS-03, CS-08, CS-11 and CS-12), from its fixture in its own repository (not copied here).

* CS-03 and CS-08: the exported file is the bytes its fixture script signs (scripts/fixtures.ts), checked against
  the certificate's exported_sha256 before use; CS-08 changes one byte.
* CS-11 and CS-12: the certificate with an anchor (a pending OpenTimestamps proof and two RFC 3161 tokens for the
  anchored root, from this repository's test authorities), re-signed with the fixture's issuer key, which is a
  published test vector (RFC 8032 section 7.1, keys.json "tenant"). CS-12 gives one token for another digest.
"""

import base64
import copy
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from fmverify import certificate, jcs, merkle, ots, pki  # noqa: E402
from fmverify.verdict import Outcome, Status  # noqa: E402

LEDGER = Path(os.environ["FM_LEDGER_REPO"]) if os.environ.get("FM_LEDGER_REPO") else None
CERT = Path("fixtures/certificate/v0/basic.certificate.json")
pytestmark = pytest.mark.skipif(
    LEDGER is None or not (LEDGER / CERT).is_file(),
    reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger holding its certificate fixture")


def _cert() -> dict:
    return json.loads((LEDGER / CERT).read_text(encoding="utf-8"))


def _status(v) -> dict:
    return {c.id: c.status for c in v.checks}


def _exported() -> bytes:
    script = (LEDGER / "scripts" / "fixtures.ts").read_text(encoding="utf-8")
    data = re.search(r'w\.sign\([^\n]*?bytes: Buffer\.from\("([^"]*)"\)', script).group(1).encode()
    doc = _cert()["credentialSubject"]["document"]
    assert hashlib.sha256(data).hexdigest() == doc["exported_sha256"] and len(data) == doc["byte_length"], \
        "the Ledger's fixture script no longer signs the exported file its certificate names"
    return data


def test_cs03_the_certificate_with_the_exported_file():
    v = certificate.verify((LEDGER / CERT).read_bytes(), exported_file=_exported())
    s = _status(v)
    for check in ("proof", "scope_statement", "file", "root_record", "inclusion"):
        assert s[f"certificate.{check}"] is Status.PASS, check
    assert s["certificate.anchor"] is Status.NOT_CHECKED  # anchor is null
    assert s["certificate.chain"] is Status.NOT_CHECKED
    assert v.outcome is Outcome.VALID


def test_cs08_an_exported_file_that_differs_by_one_byte():
    data = bytearray(_exported())
    data[0] ^= 1
    v = certificate.verify((LEDGER / CERT).read_bytes(), exported_file=bytes(data))
    s = _status(v)
    assert s["certificate.file"] is Status.FAIL
    for check in ("proof", "scope_statement", "root_record", "inclusion"):
        assert s[f"certificate.{check}"] is Status.PASS, check
    assert s["certificate.anchor"] is Status.NOT_CHECKED and s["certificate.chain"] is Status.NOT_CHECKED
    assert v.outcome is Outcome.INVALID


def _anchored(second_token_for_another_digest: bool) -> tuple[bytes, list]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import make_fixtures as mf
    import tsa_fixtures as tf
    from fmverify.base58 import b58encode

    cert = _cert()
    keys = json.loads((LEDGER / "fixtures" / "ledger-event" / "v0" / "keys.json").read_text(encoding="utf-8"))
    issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["ed25519"]["tenant"]["seed_hex"]))
    record = cert["credentialSubject"]["ledger_root"]["record"]
    assert cert["credentialSubject"]["ledger_root"]["anchor"] is None
    other = {"contract": "ledger-root/v0", "tenant_id": "zz-another-tenant", "root": hashlib.sha256(b"another hour").hexdigest()}
    leaves = [hashlib.sha256(jcs.dumps(record)).digest(), hashlib.sha256(jcs.dumps(other)).digest()]
    root = merkle.tree_hash(leaves)
    pending = ots.DetachedTimestamp(mf.SHA256, mf.chain(root, [mf.append(b"cs-11 nonce"), mf.SHA256],
                                                      mf.pending_attestation("https://alice.btc.calendar.opentimestamps.org")))
    gen = dt.datetime(2026, 10, 16, 9, 5, 0, tzinfo=dt.timezone.utc)
    k1, c1, ica = tf.test_authority()
    k2, c2, root2 = tf.test_authority_second()
    t1 = tf.token(k1, c1, [c1, ica], b"", serial=1101, sig="rsa", imprint_value=root, gen_time=gen)
    t2 = tf.token(k2, c2, [c2], b"", serial=1201, sig="ecdsa", gen_time=gen,
                  imprint_value=hashlib.sha256(b"not the anchored root").digest() if second_token_for_another_digest else root)
    cert["credentialSubject"]["ledger_root"]["anchor"] = {
        "contract": "ledger-anchor/v0", "root": root.hex(), "size": 2, "leaf_index": 0,
        "audit_path": [h.hex() for h in merkle.inclusion_path(leaves, 0)],
        "opentimestamps": {"proof_b64": base64.b64encode(pending.serialize()).decode(), "status": "pending", "bitcoin_block": None},
        "rfc3161": [{"authority": "FM Verify Test TSA RSA", "url": "http://tsa.example.org",
                     "token_b64": base64.b64encode(t1).decode(), "gen_time": "2026-10-16T09:05:00Z"},
                    {"authority": "FM Verify Second Test TSA", "url": "http://tsa2.example.org",
                     "token_b64": base64.b64encode(t2).decode(), "gen_time": "2026-10-16T09:05:00Z"}]}
    # eddsa-jcs-2022, as the issuer signed it: the proof's own configuration (with the document's @context), then the
    # document without its proof.
    proof = cert.pop("proof")
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    config.setdefault("@context", cert["@context"])
    sig = issuer.sign(hashlib.sha256(jcs.dumps(config)).digest() + hashlib.sha256(jcs.dumps(cert)).digest())
    cert["proof"] = {**{k: v for k, v in proof.items() if k != "proofValue"}, "proofValue": "z" + b58encode(sig)}
    roots = pki.load_certificates((ROOT / "fixtures" / "rfc3161" / "pki" / "root.pem").read_bytes() + tf.pem(root2))
    return json.dumps(cert).encode(), roots


def test_resigning_with_the_published_key_gives_the_fixtures_own_proof():
    """The derivation's signing is the issuer's: unchanged, the certificate re-signed is the fixture byte for byte."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from fmverify.base58 import b58encode

    cert = _cert()
    keys = json.loads((LEDGER / "fixtures" / "ledger-event" / "v0" / "keys.json").read_text(encoding="utf-8"))
    issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["ed25519"]["tenant"]["seed_hex"]))
    body = copy.deepcopy(cert)
    proof = body.pop("proof")
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    config.setdefault("@context", body["@context"])
    sig = issuer.sign(hashlib.sha256(jcs.dumps(config)).digest() + hashlib.sha256(jcs.dumps(body)).digest())
    assert "z" + b58encode(sig) == cert["proof"]["proofValue"]


def test_cs11_an_anchored_certificate():
    data, roots = _anchored(False)
    v = certificate.verify(data, roots=roots)
    s = _status(v)
    for check in ("proof", "scope_statement", "root_record", "inclusion", "anchor_inclusion", "rfc3161.0", "rfc3161.1"):
        assert s[f"certificate.{check}"] is Status.PASS, check
    # The OpenTimestamps proof is pending: not checked against Bitcoin, and it does not fail the step.
    assert s["certificate.opentimestamps"] is Status.NOT_CHECKED
    assert s["certificate.file"] is Status.NOT_CHECKED and s["certificate.chain"] is Status.NOT_CHECKED
    assert v.outcome is Outcome.VALID


def test_cs12_an_rfc3161_token_for_another_digest():
    data, roots = _anchored(True)
    v = certificate.verify(data, roots=roots)
    s = _status(v)
    assert s["certificate.rfc3161.1"] is Status.FAIL and s["certificate.rfc3161.0"] is Status.PASS
    for check in ("proof", "scope_statement", "root_record", "inclusion", "anchor_inclusion"):
        assert s[f"certificate.{check}"] is Status.PASS, check
    assert v.outcome is Outcome.INVALID
