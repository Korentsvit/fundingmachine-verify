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
