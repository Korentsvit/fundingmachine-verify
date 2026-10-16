"""Real-world RFC 3161 tokens, read from the test fixtures that the
rfc3161-client package (Trail of Bits, Apache-2.0) publishes in its source
distribution. They are not copied into this repository: set
FM_RFC3161_CLIENT_FIXTURES to the sdist's test/fixtures directory to run this.

Recorded on 16 October 2026 with rfc3161-client 1.0.9: every outcome below
also agreed with `openssl ts -verify -attime <genTime>`.
"""

import os
from pathlib import Path

import pytest

from fmverify import pki, rfc3161

BASE = os.environ.get("FM_RFC3161_CLIENT_FIXTURES")
pytestmark = pytest.mark.skipif(not BASE, reason="set FM_RFC3161_CLIENT_FIXTURES to rfc3161-client's test/fixtures")

EXPECTED = {
    "identrust/issue-104.tsr": "valid",  # IdenTrust's public authority, RSA 4096, under IdenTrust Commercial Root CA 1
    "sigstage/response-invalid-signature.tsr": "invalid",
    "sigstage/response-no-embedded-cert.tsr": "valid",
    "sigstage/response-sha256.tsr": "valid",
    "sigstage/response-sha384.tsr": "valid",
    "sigstage/response-sha512.tsr": "valid",
    "sigstore.mock/response-expired.tsr": "valid",  # expired now, valid at its stated time
    "test_tsa/other_response.tsr": "invalid",  # its signer's chain is not the one supplied
    "test_tsa/response-injected-certs.tsr": "valid",
    "test_tsa/response.tsr": "valid",
    "test_tsa_full_chain/response.tsr": "valid",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_real_token(name):
    path = Path(BASE) / name
    certs = pki.load_certificates((path.parent / "ts_chain.pem").read_bytes())
    roots = [c for c in certs if c.issuer == c.subject]
    chain = [c for c in certs if c.issuer != c.subject]
    v = rfc3161.verify(path.read_bytes(), roots=roots, extra_certs=chain)
    assert v.outcome.value == EXPECTED[name], v.to_text()
