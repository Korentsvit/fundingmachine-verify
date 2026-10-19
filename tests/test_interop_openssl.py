"""Cross-checks of the RFC 3161 fixtures against OpenSSL, an independent
implementation. Skipped when the ``openssl`` command is not installed.

OpenSSL 3.0's ``ts -verify`` verifies through its PKCS#7 code, which has no
RSASSA-PSS, and OpenSSL 3.0 has no Ed25519 in CMS at all. For those two
fixtures the cross-check is ``openssl cms -verify`` (PSS) and an independent
pure-Python RFC 8032 Ed25519 verifier (below).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fmverify import der, pki, rfc3161
from fmverify.verdict import Outcome

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "rfc3161"
# Revocation cases are left out of the OpenSSL comparison: OpenSSL treats any
# listed serial as revoked whatever the date and reason, where RFC 3161
# section 4 (followed here) voids earlier tokens only for key compromise.
CASES = sorted(p for p in FIX.iterdir() if (p / "expected.json").is_file()
               and "crls" not in json.loads((p / "expected.json").read_text()))
OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
GEN_TIME = int(dt.datetime(2026, 10, 16, 6, 0, 0, tzinfo=dt.timezone.utc).timestamp())
NOT_SUPPORTED_BY_OPENSSL_TS = {"valid-pss", "valid-ed25519"}


def _openssl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([OPENSSL, *args], capture_output=True, text=True)


@pytest.mark.parametrize("case", [c for c in CASES if c.name not in NOT_SUPPORTED_BY_OPENSSL_TS], ids=lambda c: c.name)
def test_openssl_ts_agrees(case):
    exp = json.loads((case / "expected.json").read_text())
    args = ["ts", "-verify", "-in", str(case / "token.tsr"), "-data", str(case / exp["file"]), "-attime", str(GEN_TIME)]
    for r in exp.get("roots", []):
        args += ["-CAfile", str(case / r)]
    for c in exp.get("chain", []):
        args += ["-untrusted", str(case / c)]
    result = _openssl(*args)
    openssl_ok = "Verification: OK" in result.stdout
    assert openssl_ok == (exp["outcome"] == "valid"), result.stdout + result.stderr


def test_openssl_cms_verifies_the_pss_token(tmp_path):
    bare = der.parse((FIX / "valid-pss" / "token.tsr").read_bytes()).children()[1].raw
    (tmp_path / "ci.der").write_bytes(bare)
    result = _openssl("cms", "-verify", "-inform", "DER", "-in", str(tmp_path / "ci.der"), "-CAfile", str(FIX / "pki" / "root.pem"),
                      "-purpose", "any", "-attime", str(GEN_TIME), "-binary", "-out", str(tmp_path / "content"))
    assert "Verification successful" in result.stderr + result.stdout, result.stderr
    assert (tmp_path / "content").read_bytes() == rfc3161.parse_token((FIX / "valid-pss" / "token.tsr").read_bytes()).econtent


# RFC 8032, section 6: the reference Ed25519 verification, independent of OpenSSL and of the cryptography library.
_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_Q = 2**252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A, B = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    C, D = t1 * 2 * _D * t2 % _P, z1 * 2 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


def _point(b):
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, -1, _P) % _P
_G = (_x(_GY, 0), _GY, 1, _x(_GY, 0) * _GY % _P)


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    a, r = _point(public), _point(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    lhs, rhs = _mul(s, _G), _add(r, _mul(h, a))
    return (lhs[0] * rhs[2] - rhs[0] * lhs[2]) % _P == 0 and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % _P == 0


def test_rfc8032_reference_verifies_the_ed25519_token():
    from cryptography.hazmat.primitives import serialization

    token = rfc3161.parse_token((FIX / "valid-ed25519" / "token.tsr").read_bytes())
    signer = token.signers[0]
    cert = pki.load_certificates((FIX / "pki" / "tsa-ed25519.pem").read_bytes())[0]
    public = cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert ed25519_verify(public, signer.signed_attrs_raw, signer.signature)
    assert not ed25519_verify(public, signer.signed_attrs_raw + b"x", signer.signature)


def test_token_made_by_openssl_is_verified(tmp_path):
    from cryptography.hazmat.primitives import serialization

    sys.path.insert(0, str(ROOT / "tools"))
    import tsa_fixtures

    key = tsa_fixtures.rsa_key("fm-verify test TSA rsa")
    (tmp_path / "tsa.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    shutil.copy(FIX / "pki" / "tsa-rsa.pem", tmp_path / "tsa.pem")
    shutil.copy(FIX / "pki" / "issuing-ca.pem", tmp_path / "chain.pem")
    (tmp_path / "serial").write_text("01\n")
    (tmp_path / "tsa.cnf").write_text(f"""
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir = {tmp_path}
serial = $dir/serial
crypto_device = builtin
signer_cert = $dir/tsa.pem
certs = $dir/chain.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.32473.1.2
digests = sha256, sha512
accuracy = secs:1, millisecs:500
ordering = yes
tsa_name = yes
ess_cert_id_alg = sha256
""")
    doc = tmp_path / "doc.txt"
    doc.write_bytes(b"a document stamped by OpenSSL's own time-stamping authority code\n")
    q = _openssl("ts", "-query", "-data", str(doc), "-sha256", "-cert", "-out", str(tmp_path / "req.tsq"))
    assert q.returncode == 0, q.stderr
    r = _openssl("ts", "-reply", "-config", str(tmp_path / "tsa.cnf"), "-queryfile", str(tmp_path / "req.tsq"),
                 "-out", str(tmp_path / "resp.tsr"))
    assert r.returncode == 0, r.stderr
    roots = pki.load_certificates((FIX / "pki" / "root.pem").read_bytes())
    v = rfc3161.verify_file(tmp_path / "resp.tsr", doc, roots=roots)
    assert v.outcome is Outcome.VALID, v.to_text()
    assert "accuracy 1.5 s" in v.statement
    doc.write_bytes(b"a different document\n")
    assert rfc3161.verify_file(tmp_path / "resp.tsr", doc, roots=roots).outcome is Outcome.INVALID


def test_differential_fuzz_against_openssl():
    """tools/differential_openssl.py, briefly: changed tokens are judged as
    OpenSSL judges them, but for the two differences made by design."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("differential_openssl", ROOT / "tools" / "differential_openssl.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    result = tool.run(150, OPENSSL)
    assert result["totals"]["agree"] > 250
    assert not result["other"], result["other"]


def test_the_designed_differences_are_established_from_the_token(tmp_path):
    """The differences tools/differential_openssl.py accepts are each seen here, on the token changed one way, with
    OpenSSL's own answer: found at 20,000 rounds a token, before v0.2.0."""
    import importlib.util
    import json
    import subprocess

    from fmverify import pki, rfc3161

    spec = importlib.util.spec_from_file_location("differential_openssl", ROOT / "tools" / "differential_openssl.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    case = ROOT / "fixtures" / "rfc3161" / "valid-p256-chain-supplied"
    exp = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    roots = [c for r in exp["roots"] for c in pki.load_certificates((case / r).read_bytes())]
    chain = [c for r in exp["chain"] for c in pki.load_certificates((case / r).read_bytes())]
    data = (case / exp["file"]).read_bytes()
    token = (case / "token.tsr").read_bytes()
    # The signer identifier's issuer name (the issuing CA's, its first occurrence; the TSTInfo before it names the
    # authority itself), and the signer's digest algorithm right after its serial number.
    cn = token.index(b"\x0c\x19FM Verify Test Issuing CA")
    org, space = token.rindex(b"\x0c\x20FundingMachine verifier test PKI", 0, cn), cn + 4
    null = token.index(bytes.fromhex("020166300d0609608648016503040201") + b"\x05\x00") + 16
    assert token[org] == 0x0C and token[space] == 0x20 and token[null] == 0x05
    for at, value, ours_valid in ((org, 0x16, False), (space, 0x09, False), (null, 0x01, True)):
        changed = token[:at] + bytes([value]) + token[at + 1:]
        path = tmp_path / "token.tsr"
        path.write_bytes(changed)
        args = [OPENSSL, "ts", "-verify", "-in", str(path), "-data", str(case / exp["file"]), "-attime", tool.AT,
                "-CAfile", str(case / exp["roots"][0]), "-untrusted", str(case / exp["chain"][0])]
        theirs = "Verification: OK" in subprocess.run(args, capture_output=True, text=True).stdout
        verdict = rfc3161.verify(changed, file_bytes=data, roots=roots, extra_certs=chain)
        ours = verdict.outcome.value == "valid"
        assert ours is ours_valid and theirs is not ours_valid, (at, value)
        assert tool.by_design(token, changed, ours, theirs, verdict), (at, value)
        if not ours:
            row = next(c for c in verdict.checks if c.id == "rfc3161.signer_cert")
            assert "byte for byte" in row.reasons[0]
