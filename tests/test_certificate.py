import base64
import json
import os
from pathlib import Path

import pytest

from fmverify import api, certificate
from fmverify.cli import main
from fmverify.verdict import Outcome, Status

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CASE = FIX / "certificate" / "valid-anchored"
BASE = ["--network", "regtest", "--headers-chain", str(FIX / "bitcoin" / "regtest" / "certificate-headers-0-5.bin"),
        "--roots", str(FIX / "rfc3161" / "pki" / "root.pem")]


def test_percentages_rule_from_the_document():
    # docs/AUTHORSHIP_MAP.md: 48, 25, 23 and 10 out of 106 give 45.3, 23.6, 21.7, 9.4
    counts = {"human_typed": 48, "imported": 25, "tool_generated": 23, "tool_edited": 10}
    assert certificate.percentages(counts, certificate.ORIGINS, 106) == {
        "human_typed": "45.3", "imported": "23.6", "tool_generated": "21.7", "tool_edited": "9.4"}
    assert certificate.percentages(dict.fromkeys(certificate.ORIGINS, 0), certificate.ORIGINS, 0)["imported"] == "0.0"
    third = certificate.percentages({"a": 1, "b": 1, "c": 1}, ["a", "b", "c"], 3)
    assert third == {"a": "33.4", "b": "33.3", "c": "33.3"}  # the tie goes to the key listed first


def test_valid_statement_scope():
    v = certificate.verify_file(CASE / "certificate.json", CASE / "exported.txt",
                                header_sources=[], roots=[])
    # Without headers or roots the anchor cannot be shown valid, which holds the certificate back.
    assert v.outcome is Outcome.INDETERMINATE
    assert any(c.id == "certificate.chain" and c.status is Status.NOT_CHECKED for c in v.checks)


def test_cli(capsys):
    assert main(["certificate", str(CASE / "certificate.json"), "--file", str(CASE / "exported.txt"), *BASE]) == 0
    out = capsys.readouterr().out
    assert out.startswith("VALID: ") and "The event chain itself was not checked." in out
    assert main(["certificate", str(FIX / "certificate" / "wrong-file" / "certificate.json"),
                 "--file", str(FIX / "certificate" / "wrong-file" / "exported.txt"), *BASE]) == 1
    assert main(["certificate", str(FIX / "certificate" / "unknown-version" / "certificate.json"), *BASE]) == 2


def test_api():
    req = {"kind": "certificate", "network": "regtest", "certificate": json.loads((CASE / "certificate.json").read_text()),
           "file": base64.b64encode((CASE / "exported.txt").read_bytes()).decode(),
           "headers": [{"kind": "chain", "data": base64.b64encode((FIX / "bitcoin" / "regtest" / "certificate-headers-0-5.bin").read_bytes()).decode()}],
           "roots": [(FIX / "rfc3161" / "pki" / "root.pem").read_text()]}
    assert api.verify(req)["outcome"] == "valid"
    assert "certificate must be" in api.verify({"kind": "certificate", "certificate": "x"})["error"]


def test_malformed_and_duplicate_members():
    assert certificate.verify(b"not json").outcome is Outcome.INVALID
    assert certificate.verify(b'{"credentialSubject": {}, "credentialSubject": {}}').checks[0].id == "certificate.parse"


def test_unknown_fields_are_reported():
    cred = json.loads((FIX / "certificate" / "valid-not-anchored" / "certificate.json").read_text())
    cred["credentialSubject"]["surprise"] = 1
    v = certificate.verify(json.dumps(cred).encode())
    warn = next(c for c in v.checks if c.id == "certificate.unknown_fields")
    assert warn.status is Status.WARN and warn.reasons == ["credentialSubject.surprise"]
    assert v.outcome is Outcome.INVALID  # the field was added after signing


LEDGER = os.environ.get("FM_LEDGER_REPO")


@pytest.mark.skipif(not LEDGER, reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger to cross-check its fixture")
def test_the_ledger_sessions_own_fixture():
    """The Provenance Ledger session's fixture, read from its own repository
    (not copied here): an independent issuer and this verifier must agree."""
    path = Path(LEDGER) / "fixtures" / "certificate" / "v0" / "basic.certificate.json"
    v = certificate.verify_file(path)
    assert v.outcome is Outcome.VALID, v.to_text()
    passed = {c.id for c in v.checks if c.status is Status.PASS}
    assert {"certificate.proof", "certificate.root_record", "certificate.inclusion", "certificate.authorship_arithmetic"} <= passed
    cred = json.loads(path.read_text())
    cred["credentialSubject"]["authorship"]["document"]["counts"]["human_typed"] += 1
    assert certificate.verify(json.dumps(cred).encode()).outcome is Outcome.INVALID


# Every step of docs/CERTIFICATE.md (Verifying offline) is reported on its own,
# whether it ran or not, and a failed proof hides none of the others (the
# Provenance Ledger's validation-conformance/v0, CS-04 to CS-07, CS-15, CS-50).
STEP_IDS = {
    "proof": {"certificate.proof"}, "scope": {"certificate.scope_statement"}, "file": {"certificate.file"},
    "root": {"certificate.root_record"}, "inclusion": {"certificate.inclusion"},
    "anchor": {"certificate.anchor", "certificate.anchor_inclusion"}, "chain": {"certificate.chain"},
}


def _steps(v):
    ids = {c.id for c in v.checks}
    return {step for step, want in STEP_IDS.items() if ids & want}


def test_every_step_is_reported_for_every_certificate_read():
    seen = 0
    for case in sorted((FIX / "certificate").iterdir()):
        source = case / "certificate.json" if (case / "certificate.json").exists() else case / "certificate.pdf"
        v = certificate.verify(source.read_bytes())
        if any(c.id in ("certificate.parse", "certificate.contract", "certificate.pdf") and c.status is not Status.PASS for c in v.checks):
            continue  # not read as a certificate of this version: no step can run
        assert _steps(v) == set(STEP_IDS), case.name
        seen += 1
    assert seen >= 20


def test_a_failed_proof_hides_no_other_step():
    v = certificate.verify((FIX / "certificate" / "tampered-after-signing" / "certificate.json").read_bytes())
    status = {c.id: c.status for c in v.checks}
    assert status["certificate.proof"] is Status.FAIL and v.outcome is Outcome.INVALID
    assert status["certificate.root_record"] is Status.PASS and status["certificate.inclusion"] is Status.PASS
    root = next(c for c in v.checks if c.id == "certificate.root_record")
    assert any("own proof does not verify" in r for r in root.reasons)


def test_an_issuer_that_is_not_the_proofs_key_fails_the_root_too():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from fmverify.base58 import ed25519_did_key

    cred = json.loads((FIX / "certificate" / "valid-not-anchored" / "certificate.json").read_text())
    other = Ed25519PrivateKey.from_private_bytes(bytes(32)).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    cred["issuer"]["id"] = ed25519_did_key(other)
    v = certificate.verify(json.dumps(cred).encode())
    failing = [c.id for c in v.checks if c.status is Status.FAIL]
    assert "certificate.proof" in failing and "certificate.root_record" in failing
    assert next(c for c in v.checks if c.id == "certificate.inclusion").status is Status.PASS


def test_no_root_yet_reports_steps_4_to_6_each_as_not_run():
    v = certificate.verify((FIX / "certificate" / "valid-no-root-yet" / "certificate.json").read_bytes())
    rows = {c.id: c for c in v.checks if c.id in ("certificate.root_record", "certificate.inclusion", "certificate.anchor")}
    assert set(rows) == {"certificate.root_record", "certificate.inclusion", "certificate.anchor"}
    assert all(c.status is Status.NOT_CHECKED and "did not run" in c.summary for c in rows.values())
    assert v.outcome is Outcome.VALID


def test_the_text_output_prints_the_scope_statement():
    # validation-conformance/v0 CS-51: the output prints the scope statement as the certificate carries it.
    case = FIX / "certificate" / "valid-not-anchored"
    statement = json.loads((case / "certificate.json").read_text())["credentialSubject"]["scope_statement"]
    assert statement in certificate.verify((case / "certificate.json").read_bytes()).to_text()
