"""Real tokens from DigiCert and Sectigo, the Provenance Ledger's two RFC 3161
authorities, taken from public NuGet package signatures by
tools/fetch_public_tokens.py. They are not copied into this repository: set
FM_PUBLIC_TOKENS to the directory that tool wrote.

The roots are taken by SHA-256 fingerprint from the system's trust bundle
(FM_TRUST_BUNDLE, default /etc/ssl/certs/ca-certificates.crt), as a reader
would. Recorded on 16 October 2026: every outcome below agreed with
`openssl ts -verify` against the same bundle, and with the authorities'
CRLs of 14 and 15 October every path was shown not revoked.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from fmverify import der, pki, rfc3161
from fmverify.hashes import sha256
from fmverify.verdict import Outcome, Status

BASE = os.environ.get("FM_PUBLIC_TOKENS")
BUNDLE = Path(os.environ.get("FM_TRUST_BUNDLE", "/etc/ssl/certs/ca-certificates.crt"))
pytestmark = pytest.mark.skipif(not BASE, reason="set FM_PUBLIC_TOKENS to the output of tools/fetch_public_tokens.py")

DIGICERT_G4 = "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"  # DigiCert Trusted Root G4
USERTRUST_RSA = "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2"  # USERTrust RSA, Sectigo's root

# Token: (signer, genTime, root reached, outcome).
EXPECTED = {
    "newtonsoft.json.13.0.3.signer0.tsr": ("DigiCert Timestamp 2022 - 2", "2023-03-08T07:09:56Z", DIGICERT_G4, "valid"),
    "newtonsoft.json.13.0.3.signer0-countersignature.tsr": ("DigiCert Timestamp 2022 - 2", "2023-03-08T07:43:22Z", DIGICERT_G4, "valid"),
    "serilog.4.0.0.signer0.tsr": ("DigiCert Timestamp 2023", "2024-06-01T06:21:51Z", DIGICERT_G4, "valid"),
    "castle.core.5.2.1.signer0.tsr": ("DigiCert Timestamp 2024", "2025-03-09T21:10:52Z", DIGICERT_G4, "valid"),
    "npgsql.10.0.3.signer0.tsr": ("DigiCert SHA256 RSA4096 Timestamp Responder 2025 1", "2026-05-27T11:34:48Z", DIGICERT_G4, "valid"),
    "dapper.2.1.89.signer0.tsr": ("DigiCert SHA256 RSA4096 Timestamp Responder 2026 1", "2026-09-23T04:36:22Z", DIGICERT_G4, "valid"),
    "nodatime.3.3.5.signer0.tsr": ("Sectigo Public Time Stamping Signer R37", "2026-09-30T05:39:32Z", USERTRUST_RSA, "valid"),
    "nodatime.3.3.5.signer0-countersignature.tsr": ("DigiCert SHA256 RSA4096 Timestamp Responder 2026 1", "2026-09-30T05:40:54Z",
                                                    DIGICERT_G4, "valid"),
    "bouncycastle.cryptography.2.7.0.signer0.tsr": ("Sectigo Public Time Stamping Signer R37", "2026-07-30T09:27:47Z", USERTRUST_RSA, "valid"),
    "bouncycastle.cryptography.2.7.0.signer0-countersignature.tsr": ("DigiCert SHA256 RSA4096 Timestamp Responder 2025 1",
                                                                     "2026-07-30T11:09:59Z", DIGICERT_G4, "valid"),
    "polly.8.8.0.signer0-countersignature.tsr": ("DigiCert SHA256 RSA4096 Timestamp Responder 2026 1", "2026-09-14T13:25:39Z",
                                                 DIGICERT_G4, "valid"),
    # Microsoft's authority: its root is not one of the two given, so the chain fails.
    "polly.8.8.0.signer0.tsr": ("Microsoft Public RSA Time Stamping Authority", "2026-09-14T13:22:03.419Z", None, "invalid"),
}


@pytest.fixture(scope="module")
def roots():
    if not BUNDLE.is_file():
        pytest.skip(f"no trust bundle at {BUNDLE}")
    found = {pki.fingerprint(c): c for c in pki.load_certificates(BUNDLE.read_bytes())}
    missing = [f for f in (DIGICERT_G4, USERTRUST_RSA) if f not in found]
    if missing:
        pytest.skip(f"the trust bundle lacks {missing}")
    return [found[DIGICERT_G4], found[USERTRUST_RSA]]


def _read(name):
    path = Path(BASE) / name
    if not path.is_file():
        pytest.skip(f"{name} not captured")
    return path.read_bytes(), (Path(BASE) / (name + ".stamped")).read_bytes()


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_public_token(name, roots):
    signer, when, root, outcome = EXPECTED[name]
    token, stamped = _read(name)
    v = rfc3161.verify(token, digest=sha256(stamped), roots=roots)
    assert v.outcome.value == outcome, v.to_text()
    by_id = {c.id: c for c in v.checks}
    assert signer in by_id["rfc3161.signer_cert"].summary
    assert f"time {when}" in by_id["rfc3161.parse"].summary
    if outcome == "valid":
        assert by_id["rfc3161.tsa_eku"].status is Status.PASS
        assert by_id["rfc3161.chain"].data["root_sha256"] == root
    else:
        assert [c.id for c in v.checks if c.status is Status.FAIL] == ["rfc3161.chain"]
    # Another digest is never covered.
    assert rfc3161.verify(token, digest=sha256(stamped + b"x"), roots=roots).outcome is Outcome.INVALID


def _without_certificates(token: bytes) -> bytes:
    content_type, explicit = der.parse(token).children()
    signed_data = explicit.children()[0]
    kept = [k.raw for k in signed_data.children() if not k.is_context(0)]
    return der.seq(content_type.raw, der.ctx(0, der.seq(*kept)))


@pytest.mark.parametrize("name", ["dapper.2.1.89.signer0.tsr", "nodatime.3.3.5.signer0.tsr"])
def test_token_without_certificates_needs_the_chain(name, roots):
    """A token requested without certReq carries no certificates: without the
    chain it is indeterminate, with it (as anchors/tsa/ will hold) valid."""
    token, stamped = _read(name)
    bare = _without_certificates(token)
    alone = rfc3161.verify(bare, digest=sha256(stamped), roots=roots)
    assert alone.outcome is Outcome.INDETERMINATE
    assert "neither in the token nor among those supplied" in alone.statement
    bag = rfc3161.parse_token(token).certificates
    assert rfc3161.verify(bare, digest=sha256(stamped), roots=roots, extra_certs=bag).outcome is Outcome.VALID


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_openssl_agrees(name, roots, tmp_path):
    """OpenSSL, given the same two roots, reaches the same outcome."""
    from cryptography.hazmat.primitives.serialization import Encoding

    _read(name)
    ca = tmp_path / "roots.pem"
    ca.write_bytes(b"".join(c.public_bytes(Encoding.PEM) for c in roots))
    r = subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", str(Path(BASE) / name),
                        "-data", str(Path(BASE) / (name + ".stamped")), "-CAfile", str(ca)], capture_output=True, text=True)
    assert ("Verification: OK" in r.stdout) == (EXPECTED[name][3] == "valid"), r.stdout + r.stderr
