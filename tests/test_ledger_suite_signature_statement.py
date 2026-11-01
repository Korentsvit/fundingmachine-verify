"""Ruling 17 in the signed JSON: the Provenance Ledger's fixtures for ledger-certificate/v0.2 and record-certificate/v0.1
(its fixtures/certificate/v0.2 and fixtures/record-certificate/v0.1, read from a checkout of its repository, not copied
here), verified as published and with one statement changed, re-signed with the fixtures' issuer key, a published test
vector (RFC 8032 section 7.1, keys.json "tenant").
"""

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from fmverify import certificate, jcs, pki, record_certificate
from fmverify.bitcoin import REGTEST, HeaderSet
from fmverify.verdict import Outcome, Status

LEDGER = Path(os.environ["FM_LEDGER_REPO"]) if os.environ.get("FM_LEDGER_REPO") else None
V02 = Path("fixtures/certificate/v0.2")
REC = Path("fixtures/record-certificate/v0.1")
pytestmark = pytest.mark.skipif(
    LEDGER is None or not (LEDGER / V02 / "basic.certificate.json").is_file() or not (LEDGER / REC / "certificate.json").is_file(),
    reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger holding its v0.2 and record v0.1 fixtures")


def _issuer():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keys = json.loads((LEDGER / "fixtures/ledger-event/v0/keys.json").read_text(encoding="utf-8"))["ed25519"]
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["tenant"]["seed_hex"]))


def _status(v) -> dict:
    return {c.id: c.status for c in v.checks}


def _failing(v) -> set:
    return {c.id for c in v.checks if c.status is Status.FAIL}


def _resigned(cert: dict) -> bytes:
    """eddsa-jcs-2022 as the issuer signs: the proof's configuration, then the document without its proof."""
    from fmverify.base58 import b58encode

    body = copy.deepcopy(cert)
    proof = body.pop("proof")
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    config.setdefault("@context", body["@context"])
    sig = _issuer().sign(hashlib.sha256(jcs.dumps(config)).digest() + hashlib.sha256(jcs.dumps(body)).digest())
    body["proof"] = {**config, "proofValue": "z" + b58encode(sig)}
    return json.dumps(body).encode()


def _ledger(name: str) -> dict:
    return json.loads((LEDGER / V02 / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name, meaning", [("basic.certificate.json", None), ("resync.certificate.json", "authorship")])
def test_the_v0_2_fixtures_as_published(name, meaning):
    v = certificate.verify((LEDGER / V02 / name).read_bytes())
    s = _status(v)
    assert v.outcome is Outcome.VALID, v.to_text()
    assert s["certificate.contract"] is s["certificate.proof"] is s["certificate.signature_statement"] is s["certificate.meaning"] is Status.PASS
    assert "certificate.unknown_fields" not in s
    assert _ledger(name)["credentialSubject"]["signed"].get("meaning") == meaning


def test_resigning_the_v0_2_fixture_gives_its_own_proof():
    cert = _ledger("basic.certificate.json")
    assert json.loads(_resigned(cert))["proof"]["proofValue"] == cert["proof"]["proofValue"]


@pytest.mark.parametrize("member, value", [("signature_meaning", "the signer approves this document."),
                                           ("eidas_statement", "This certificate is a qualified electronic signature under eIDAS.")])
def test_a_v0_2_statement_changed_and_re_signed(member, value):
    cert = _ledger("basic.certificate.json")
    cert["credentialSubject"][member] = value
    v = certificate.verify(_resigned(cert))
    assert _failing(v) == {"certificate.signature_statement"} and v.outcome is Outcome.INVALID


def test_a_v0_2_meaning_without_its_name_hash():
    cert = _ledger("resync.certificate.json")
    del cert["credentialSubject"]["signed"]["signer_name_hash"]
    v = certificate.verify(_resigned(cert))
    assert _failing(v) == {"certificate.meaning"}


def _record(cert: dict | None = None) -> tuple:
    body = jcs.dumps(cert) if cert is not None else (LEDGER / REC / "certificate.json").read_bytes()
    sig = _issuer().sign(body) if cert is not None else (LEDGER / REC / "certificate.sig").read_bytes()
    roots = pki.load_certificates((LEDGER / REC / "test-tsa-one.pem").read_bytes() + (LEDGER / REC / "test-tsa-two.pem").read_bytes())
    sources = [HeaderSet.parse((LEDGER / REC / "headers.txt").read_text(encoding="utf-8"), REGTEST, name="headers.txt")]
    return record_certificate.verify(body, sig, header_sources=sources, network=REGTEST, roots=roots)


def _record_json() -> dict:
    return jcs.loads((LEDGER / REC / "certificate.json").read_text(encoding="utf-8"))


def test_the_record_v0_1_fixture_as_published():
    v = _record()
    assert v.outcome is Outcome.VALID, v.to_text()
    assert _status(v)["record_certificate.signature_statement"] is Status.PASS
    assert _issuer().sign((LEDGER / REC / "certificate.json").read_bytes()) == (LEDGER / REC / "certificate.sig").read_bytes()


def test_a_record_v0_1_statement_changed_and_re_signed():
    c = _record_json()
    c["signature_meaning"] = "the signer approves this document."
    v = _record(c)
    assert _failing(v) == {"record_certificate.signature_statement"} and v.outcome is Outcome.INVALID


def test_a_record_v0_1_without_its_statements_or_a_v0_with_them():
    c = _record_json()
    without = {k: v for k, v in c.items() if k not in ("signature_meaning", "eidas_statement")}
    assert _failing(_record(without)) == {"record_certificate.schema"}
    assert _failing(_record({**c, "contract": "record-certificate/v0"})) == {"record_certificate.schema"}


def _invalid(kind: Path) -> list:
    path = LEDGER / kind / "invalid" / "expect.json"
    return json.loads(path.read_text(encoding="utf-8"))["cases"] if path.is_file() else []


def test_the_ledgers_invalid_v0_2_certificates():
    """Its fixtures/certificate/v0.2/invalid (from 520d397): each not valid, with the chain it names where only the chain
    shows the fault; a v0.1 certificate carrying the statements fails certificate.signature_statement."""
    cases = _invalid(V02)
    if not cases:
        pytest.skip("this checkout of the Ledger has no fixtures/certificate/v0.2/invalid")
    for c in cases:
        chain = json.loads((LEDGER / c["chain"]).read_text(encoding="utf-8"))
        v = certificate.verify((LEDGER / V02 / "invalid" / c["file"]).read_bytes(), events=chain["events"] if isinstance(chain, dict) else chain)
        assert v.outcome is Outcome.INVALID, (c["name"], v.to_text())
        if not c["schema_v0_2"] and c["name"] != "meaning-without-name-hash":
            assert "certificate.signature_statement" in _failing(v), c["name"]


def test_the_ledgers_invalid_record_v0_1_certificates():
    """Its fixtures/record-certificate/v0.1/invalid: each not valid, by the statements (the Ledger's "signature statement")
    or, where a member is missing or extra, by the version's schema."""
    cases = _invalid(REC)
    if not cases:
        pytest.skip("this checkout of the Ledger has no fixtures/record-certificate/v0.1/invalid")
    roots = pki.load_certificates((LEDGER / REC / "test-tsa-one.pem").read_bytes() + (LEDGER / REC / "test-tsa-two.pem").read_bytes())
    sources = [HeaderSet.parse((LEDGER / REC / "headers.txt").read_text(encoding="utf-8"), REGTEST, name="headers.txt")]
    for c in cases:
        d = LEDGER / REC / "invalid"
        v = record_certificate.verify((d / c["file"]).read_bytes(), (d / c["file"].replace(".json", ".sig")).read_bytes(),
                                      header_sources=sources, network=REGTEST, roots=roots)
        assert v.outcome is Outcome.INVALID and _failing(v) in ({"record_certificate.signature_statement"}, {"record_certificate.schema"}), \
            (c["name"], _failing(v))
