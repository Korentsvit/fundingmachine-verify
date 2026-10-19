import json
from pathlib import Path

import pytest

from fmverify import pki, rfc3161
from fmverify.cli import main
from fmverify.verdict import Outcome, Status

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "rfc3161"
CASES = sorted(p for p in FIX.iterdir() if (p / "expected.json").is_file())


def _certs(case: Path, paths):
    return [c for p in paths for c in pki.load_certificates((case / p).read_bytes())]


def run_case(case: Path):
    exp = json.loads((case / "expected.json").read_text())
    crls = [c for p in exp.get("crls", []) for c in pki.load_crls((case / p).read_bytes())]
    v = rfc3161.verify_file(case / "token.tsr", case / exp["file"], roots=_certs(case, exp.get("roots", [])),
                            extra_certs=_certs(case, exp.get("chain", [])), crls=crls)
    return exp, v


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_fixture_case(case):
    exp, v = run_case(case)
    assert v.outcome.value == exp["outcome"], v.to_text()
    assert [c.id for c in v.checks if c.status is Status.FAIL] == exp.get("failing", []), v.to_text()
    assert set(exp.get("warning", [])) <= {c.id for c in v.checks if c.status is Status.WARN}, v.to_text()
    assert v.statement and v.does_not_establish


def test_valid_statement_and_reliance():
    _, v = run_case(FIX / "valid-rsa")
    assert "2026-10-16T06:00:00.125Z" in v.statement and "accuracy 1 s" in v.statement
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


def test_revocation_statuses():
    def rev(name):
        return next(c for c in run_case(FIX / name)[1].checks if c.id == "rfc3161.revocation")

    assert rev("crl-clean").status is Status.PASS
    assert "revoked later (superseded" in " ".join(rev("crl-superseded-later").reasons)
    assert rev("crl-stale").status is Status.NOT_CHECKED and "issued before" in " ".join(rev("crl-stale").reasons)
    assert "key compromise" in rev("crl-key-compromise").reasons[0]


def test_crl_for_the_issuing_ca_only_leaves_the_rest_open():
    case = FIX / "valid-rsa"
    crls = pki.load_crls((FIX / "crl" / "ica-clean.pem").read_bytes())
    v = rfc3161.verify_file(case / "token.tsr", case / "document.txt", roots=_certs(case, ["../pki/root.pem"]), crls=crls)
    r = next(c for c in v.checks if c.id == "rfc3161.revocation")
    assert v.outcome is Outcome.VALID and r.status is Status.NOT_CHECKED
    assert any("no CRL from its issuer" in x and "Issuing CA" in x for x in r.reasons)


def test_crl_cli(capsys):
    case = FIX / "valid-rsa"
    base = ["rfc3161", str(case / "token.tsr"), "--file", str(case / "document.txt"), "--roots", str(FIX / "pki" / "root.pem")]
    assert main(base + ["--crl", str(FIX / "crl" / "root-clean.pem"), "--crl", str(FIX / "crl" / "ica-clean.pem")]) == 0
    assert main(base + ["--crl", str(FIX / "crl" / "ica-key-compromise.pem")]) == 1
    assert main(base + ["--crl", str(FIX / "pki" / "root.pem")]) == 64


SHA256_ALG = bytes.fromhex("300d06096086480165030402010500")


def _edited(old: bytes, new: bytes) -> bytes:
    data = (FIX / "valid-rsa" / "token.tsr").read_bytes()
    at = data.index(old)  # the first occurrence: SignedData's digestAlgorithms, or ContentInfo's [0]
    return data[:at] + new + data[at + len(old):]


def _roots():
    return pki.load_certificates((FIX / "pki" / "root.pem").read_bytes())


def test_digest_algorithms_without_the_signers_is_a_warning():
    """Found by tools/tamper_audit.py: digestAlgorithms was never read, so a
    change there went unseen; OpenSSL refuses such a token."""
    token = _edited(SHA256_ALG, SHA256_ALG[:-3] + b"\x02\x05\x00")  # sha384 listed instead
    v = rfc3161.verify(token, roots=_roots())
    row = next(c for c in v.checks if c.id == "rfc3161.digest_algorithms")
    assert v.outcome is Outcome.VALID and row.status is Status.WARN and "OpenSSL refuses" in row.reasons[0]
    assert not any(c.id == "rfc3161.digest_algorithms" for c in rfc3161.verify((FIX / "valid-rsa" / "token.tsr").read_bytes(),
                                                                                roots=_roots()).checks)


def test_hash_parameters_other_than_null_are_a_warning():
    """Found by a differential fuzz against OpenSSL: such parameters are not
    what RFC 5754 allows, but the hash is the one the identifier names, and
    OpenSSL ignores them; a warning says where they are."""
    v = rfc3161.verify(_edited(SHA256_ALG, SHA256_ALG[:-2] + b"\x04\x00"), roots=_roots())
    row = next(c for c in v.checks if c.id == "rfc3161.hash_parameters")
    assert v.outcome is Outcome.VALID and row.status is Status.WARN and "SignedData's digestAlgorithms" in row.reasons[0]
    data = (FIX / "valid-rsa" / "token.tsr").read_bytes()
    signer = data.rindex(SHA256_ALG)  # the last: the signer's digest algorithm
    edited = data[:signer] + SHA256_ALG[:-2] + b"\x04\x00" + data[signer + len(SHA256_ALG):]
    row = next(c for c in rfc3161.verify(edited, roots=_roots()).checks if c.id == "rfc3161.hash_parameters")
    assert "the signer's digest algorithm" in row.reasons[0]


def test_content_info_must_be_a_sequence():
    """Found by the same differential fuzz: another tag where ContentInfo's
    SEQUENCE belongs was read as if it were one; OpenSSL refuses it."""
    data = (FIX / "valid-rsa" / "token.tsr").read_bytes()
    at = data.index(bytes.fromhex("06092a864886f70d010702")) - 4  # ContentInfo's header: 30 82 LL LL
    assert data[at] == 0x30
    v = rfc3161.verify(data[:at] + b"\x31" + data[at + 1:], roots=_roots())
    assert v.outcome is Outcome.INVALID and "ContentInfo" in v.checks[0].reasons[0]


def test_signed_data_must_be_a_sequence():
    """Found by the differential fuzz at release scale (4,000 rounds a token):
    SignedData under another tag was read as if it were the SEQUENCE; OpenSSL
    refuses it."""
    for case in ("valid-rsa", "valid-p256-chain-supplied"):
        data = (FIX / case / "token.tsr").read_bytes()
        oid = bytes.fromhex("06092a864886f70d010702")  # id-signedData, then [0] EXPLICIT, then SignedData
        at = data.index(oid) + len(oid) + 4  # [0]'s header: a0 82 LL LL
        assert data[at - 4] == 0xA0 and data[at] == 0x30
        for tag in (0xA2, 0x78, 0x31):
            v = rfc3161.verify(data[:at] + bytes([tag]) + data[at + 1:], roots=_roots())
            assert v.outcome is Outcome.INVALID and "SignedData" in v.checks[0].reasons[0], (case, tag)


def test_content_info_content_must_be_explicit_zero():
    data = (FIX / "valid-rsa" / "token.tsr").read_bytes()
    oid = bytes.fromhex("06092a864886f70d010702")  # id-signedData, then [0] EXPLICIT
    at = data.index(oid) + len(oid)
    assert data[at] == 0xA0
    v = rfc3161.verify(data[:at] + b"\xa1" + data[at + 1:], roots=_roots())
    assert v.outcome is Outcome.INVALID and "[0] EXPLICIT" in v.checks[0].reasons[0]
