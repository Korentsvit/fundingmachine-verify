"""The Provenance Ledger suite's record certificate cases on its test vector (its validation-conformance/v0, CS-71,
and CS-61 to CS-69 derived from it as each recipe says), from fixtures/record-certificate/v0 in a checkout of its
repository (not copied here).

The vector is synthetic: its issuer, root record and acceptance record are signed with keys.json "tenant" (RFC 8032
section 7.1 TEST 3), its tokens come from two test authorities whose roots it carries, and its block is a regtest
header (headers.txt). The derived cases are re-signed with the same published key; re-signing the vector unchanged
gives its own certificate.sig.
"""

import base64
import copy
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from fmverify import jcs, ledger_events, merkle, ots, pki, record_certificate  # noqa: E402
from fmverify.bitcoin import REGTEST, HeaderSet  # noqa: E402
from fmverify.verdict import Outcome, Status  # noqa: E402

LEDGER = Path(os.environ["FM_LEDGER_REPO"]) if os.environ.get("FM_LEDGER_REPO") else None
VEC = Path("fixtures/record-certificate/v0")
pytestmark = pytest.mark.skipif(
    LEDGER is None or not (LEDGER / VEC / "certificate.json").is_file(),
    reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger holding its record certificate test vector")


def _vec(name: str) -> bytes:
    return (LEDGER / VEC / name).read_bytes()


def _issuer():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keys = json.loads((LEDGER / "fixtures/ledger-event/v0/keys.json").read_text(encoding="utf-8"))["ed25519"]
    return (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["tenant"]["seed_hex"])),
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["session_1"]["seed_hex"])))


def _run(cert, sig=None, extra_roots: bytes = b"", headers: bool = True) -> dict:
    issuer, _ = _issuer()
    body = jcs.dumps(cert) if isinstance(cert, dict) else cert
    roots = pki.load_certificates(_vec("test-tsa-one.pem") + _vec("test-tsa-two.pem") + extra_roots)
    sources = [HeaderSet.parse(_vec("headers.txt").decode("utf-8"), REGTEST, name="headers.txt")] if headers else []
    v = record_certificate.verify(body, sig if sig is not None else issuer.sign(body), header_sources=sources,
                                  network=REGTEST, roots=roots)
    return v


def _rows(v) -> dict:
    return {c.id.split(".", 1)[1]: c.status for c in v.checks}


def _changed(**paths) -> dict:
    c = jcs.loads(_vec("certificate.json").decode("utf-8"))
    for path, value in paths.items():
        t, keys = c, path.split("__")
        for k in keys[:-1]:
            t = t[int(k)] if k.isdigit() else t[k]
        t[keys[-1]] = value
    return c


PASS_ALL = ("form", "schema", "signature", "scope_statement", "head_to_root", "root_record", "record_to_anchor",
            "rfc3161.0", "rfc3161.1", "opentimestamps", "block_header", "bitcoin_block")


def _only(v, failing: set) -> None:
    rows = _rows(v)
    for check in PASS_ALL:
        assert rows[check] is (Status.FAIL if check in failing else Status.PASS), (check, rows[check])
    assert v.outcome is (Outcome.INVALID if failing else Outcome.VALID)


def test_cs71_the_test_vector():
    issuer, _ = _issuer()
    assert issuer.sign(_vec("certificate.json")) == _vec("certificate.sig"), "the published key is not the vector's issuer"
    _only(_run(_vec("certificate.json"), _vec("certificate.sig")), set())
    v = _run(_vec("certificate.json"), _vec("certificate.sig"), headers=False)
    assert _rows(v)["bitcoin_block"] is Status.NOT_CHECKED and v.outcome is Outcome.INDETERMINATE


def test_cs61_one_byte_changed():
    body = bytearray(_vec("certificate.json"))
    at = body.index(b"urn:uuid:") + len(b"urn:uuid:")
    body[at] = ord("f") if body[at] != ord("f") else ord("e")
    _only(_run(bytes(body), _vec("certificate.sig")), {"signature"})


def test_cs62_a_scope_statement_not_the_contracts():
    c = _changed()
    _only(_run(_changed(scope_statement=c["scope_statement"].replace("does not detect AI", "detects no AI"))),
          {"scope_statement"})


def test_cs63_inclusion_steps_of_another_leaf():
    c = _changed()
    _only(_run(_changed(hour__leaf_index=c["hour"]["leaf_index"] - 1)), {"head_to_root"})


def test_cs64_a_root_record_signed_by_another_key():
    _, other = _issuer()
    c = _changed()
    rec = jcs.loads(base64.b64decode(c["hour"]["root_record_b64"]).decode("utf-8"))
    unsigned = {k: v for k, v in rec.items() if k != "sig"}
    sig = other.sign(("ledger-root/v0:" + hashlib.sha256(jcs.dumps(unsigned)).hexdigest()).encode())
    stranger = jcs.dumps({**unsigned, "sig": base64.urlsafe_b64encode(sig).rstrip(b"=").decode()})
    _only(_run(_changed(hour__root_record_b64=base64.b64encode(stranger).decode(),
                        hour__root_record_sha256=hashlib.sha256(stranger).hexdigest())), {"root_record", "record_to_anchor"})


def test_cs65_a_token_for_another_digest():
    import tsa_fixtures as tf

    c = _changed()
    k, c1, ica = tf.test_authority()
    wrong = tf.token(k, c1, [c1, ica], b"", serial=6501, sig="rsa", imprint_value=hashlib.sha256(b"another").digest(),
                     gen_time=dt.datetime.fromisoformat(c["anchor"]["rfc3161"][1]["gen_time"].replace("Z", "+00:00")))
    tokens = [c["anchor"]["rfc3161"][0], {**c["anchor"]["rfc3161"][1], "token_b64": base64.b64encode(wrong).decode()}]
    _only(_run(_changed(anchor__rfc3161=tokens), extra_roots=(ROOT / "fixtures/rfc3161/pki/root.pem").read_bytes()),
          {"rfc3161.1"})


def test_cs66_a_token_time_written_another_way():
    c = _changed()
    plain = [dict(t, gen_time=t["gen_time"].replace(".000Z", "Z")) for t in c["anchor"]["rfc3161"]]
    assert plain != c["anchor"]["rfc3161"]
    _only(_run(_changed(anchor__rfc3161=plain)), set())


def test_cs67_an_operation_that_is_not_a_sha256_step():
    import make_fixtures as mf

    c = _changed()
    root, ops = bytes.fromhex(c["anchor"]["root"]), []
    for s in c["anchor"]["bitcoin"]["anchor_to_merkle_root"]:
        ops += ([mf.prepend(bytes.fromhex(s["prepend"]))] if s["prepend"] else []) + \
               ([mf.append(bytes.fromhex(s["append"]))] if s["append"] else []) + [mf.SHA256]
    assert mf.run(root, ops).hex() == c["anchor"]["bitcoin"]["merkle_root"]
    bent = ots.DetachedTimestamp(mf.SHA256, mf.chain(root, [ots.Op(0xF2), ots.Op(0xF2)] + ops,
                                                    mf.bitcoin_attestation(c["anchor"]["bitcoin"]["height"]))).serialize()
    _only(_run(_changed(anchor__opentimestamps_b64=base64.b64encode(bent).decode())), {"opentimestamps"})


def test_cs68_a_block_time_the_header_does_not_carry():
    _only(_run(_changed(anchor__bitcoin__time="2026-10-20T01:00:00.000Z")), {"block_header"})


def test_cs69_a_contract_version_unknown():
    v = _run(_changed(contract="record-certificate/v0.9"))
    assert v.outcome is Outcome.INDETERMINATE and _rows(v)["contract"] is Status.NOT_CHECKED
    assert "signature" not in _rows(v)


def test_the_hour_is_the_basic_chains_events():
    """The vector's hour holds the basic chain's 20 events, so CS-63's other leaf is a real leaf of it."""
    chain = json.loads((LEDGER / "fixtures/ledger-event/v0/valid/basic.chain.json").read_text(encoding="utf-8"))
    events = chain["events"] if isinstance(chain, dict) else chain
    leaves = [bytes.fromhex(ledger_events.event_hash(e)) for e in events]
    assert merkle.tree_hash(leaves).hex() == _changed()["hour"]["root"]
    assert copy.deepcopy(_changed()) == _changed()
