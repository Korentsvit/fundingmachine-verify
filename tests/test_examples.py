"""The published examples (README, Examples): the two record certificates of 17 October 2026, beside their
verdicts. Each file is the one whose SHA-256 the verdict recorded, and each certificate, JSON and PDF, verifies
valid against the header committed beside it and the system's roots, when the system holds them."""

import hashlib
from pathlib import Path

import pytest

from fmverify import record_certificate as rc
from fmverify.bitcoin import HeaderSet

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = [ROOT / "verdicts" / "certificates" / n for n in ("2026-10-17T2110Z", "2026-10-17T2305Z")]
BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


@pytest.mark.parametrize("d", EXAMPLES, ids=lambda d: d.name)
def test_the_published_files_are_the_ones_verified(d):
    sums = dict(reversed(line.split("  ", 1)) for line in (d / "certificate.sha256").read_text().splitlines())
    for name in ("certificate.json", "certificate.sig", "certificate.pdf"):
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == sums[name], name


@pytest.mark.skipif(not BUNDLE.is_file(), reason="no system root bundle")
@pytest.mark.parametrize("d", EXAMPLES, ids=lambda d: d.name)
def test_the_published_certificates_verify(d):
    from fmverify import pki

    roots = pki.load_certificates(BUNDLE.read_bytes())
    headers = [HeaderSet.parse((d / "headers.txt").read_text(), name="headers.txt")]
    for data, sig in (((d / "certificate.json").read_bytes(), (d / "certificate.sig").read_bytes()),
                      ((d / "certificate.pdf").read_bytes(), None)):
        v = rc.verify(data, sig, header_sources=headers, roots=roots)
        if any(c.id.startswith("record_certificate.rfc3161") and c.status.value == "not_checked" for c in v.checks):
            pytest.skip("the system bundle lacks an authority's root")
        assert v.outcome.value == "valid", [(c.id, c.status.value, c.summary) for c in v.checks if c.status.value != "pass"]
