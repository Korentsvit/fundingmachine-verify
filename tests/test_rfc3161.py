import json
from pathlib import Path

import pytest

from fmverify import pki, rfc3161
from fmverify.cli import main
from fmverify.verdict import Outcome, Status

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "rfc3161"
CASES = sorted(p for p in FIX.iterdir() if p.is_dir() and p.name != "pki")


def _certs(case: Path, paths):
    return [c for p in paths for c in pki.load_certificates((case / p).read_bytes())]


def run_case(case: Path):
    exp = json.loads((case / "expected.json").read_text())
    v = rfc3161.verify_file(case / "token.tsr", case / exp["file"], roots=_certs(case, exp.get("roots", [])),
                            extra_certs=_certs(case, exp.get("chain", [])))
    return exp, v


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_fixture_case(case):
    exp, v = run_case(case)
    assert v.outcome.value == exp["outcome"], v.to_text()
    assert [c.id for c in v.checks if c.status is Status.FAIL] == exp.get("failing", []), v.to_text()
    assert v.statement and v.does_not_establish


def test_valid_statement_and_reliance():
    _, v = run_case(FIX / "valid-rsa")
    assert "2026-10-16T06:00:00.125000Z" in v.statement and "accuracy 1 s" in v.statement
    assert any("compare the fingerprint" in r for r in v.relies_on)
    assert any("not revoked" in r for r in v.relies_on)
    rev = next(c for c in v.checks if c.id == "rfc3161.revocation")
    assert rev.status is Status.NOT_CHECKED and not rev.required


def test_no_roots_names_where_the_chain_leads():
    _, v = run_case(FIX / "no-roots")
    chain = next(c for c in v.checks if c.id == "rfc3161.chain")
    assert "FM Verify Test Issuing CA" in chain.reasons[0] and "issued by CN=FM Verify Test Root CA" in chain.reasons[0]


def test_trusting_the_signer_directly_is_allowed_and_stated():
    case = FIX / "valid-rsa"
    signer = pki.load_certificates((FIX / "pki" / "tsa-rsa.pem").read_bytes())
    v = rfc3161.verify_file(case / "token.tsr", case / "document.txt", roots=signer)
    assert v.outcome is Outcome.VALID
    assert "FM Verify Test TSA RSA" in next(c for c in v.checks if c.id == "rfc3161.chain").summary


def test_digest_instead_of_file():
    case = FIX / "valid-rsa"
    roots = _certs(case, ["../pki/root.pem"])
    token = (case / "token.tsr").read_bytes()
    import hashlib

    good = hashlib.sha256((case / "document.txt").read_bytes()).digest()
    assert rfc3161.verify(token, digest=good, roots=roots).outcome is Outcome.VALID
    assert rfc3161.verify(token, digest=b"\x00" * 32, roots=roots).outcome is Outcome.INVALID
    other_alg = rfc3161.verify(token, digest=b"\x00" * 64, digest_alg="sha512", roots=roots)
    assert other_alg.outcome is Outcome.INDETERMINATE


def test_bare_token_without_response_wrapper():
    from fmverify import der

    case = FIX / "valid-rsa"
    bare = der.parse((case / "token.tsr").read_bytes()).children()[1].raw
    v = rfc3161.verify(bare, file_bytes=(case / "document.txt").read_bytes(), roots=_certs(case, ["../pki/root.pem"]))
    assert v.outcome is Outcome.VALID


def test_garbage_is_invalid_not_a_crash():
    for blob in (b"", b"\x30\x00", b"\x30\x03\x02\x01\x00", b"not der at all"):
        v = rfc3161.verify(blob)
        assert v.outcome is Outcome.INVALID and v.checks[0].id == "rfc3161.parse"


def test_cli(capsys):
    case = FIX / "valid-p256-chain-supplied"
    argv = ["rfc3161", str(case / "token.tsr"), "--file", str(case / "document.txt"),
            "--roots", str(FIX / "pki" / "root.pem"), "--chain", str(FIX / "pki" / "chain-p256.pem")]
    assert main(argv) == 0
    assert main(argv[:-2]) == 2
    capsys.readouterr()
    assert main(argv + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "valid"
    assert main(["rfc3161", str(case / "token.tsr"), "--roots", "/nonexistent.pem"]) == 64
    assert main(["rfc3161", str(case / "token.tsr"), "--digest", "00", "--digest-alg", "md5"]) == 64
