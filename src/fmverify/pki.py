"""X.509 certificate chains for time-stamping authorities.

The verifier ships no trust store. The caller supplies the roots they trust
(and, optionally, intermediates); the verdict names the root a chain reached
and its SHA-256 fingerprint, so the caller can compare it with the
authority's own published fingerprint.

Checked for each certificate on the path, at the time the token states:
validity period; for the CAs above the signer, basic constraints, key usage
and path length; every signature, by the next certificate's key. Revocation
is checked only from CRLs the caller supplies (not yet implemented: reported
as not checked).
"""

from __future__ import annotations

import datetime as _dt
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from .verdict import Check, Status

MAX_PATH = 8


def load_certificates(data: bytes) -> list[x509.Certificate]:
    """PEM (one or many) or a single DER certificate."""
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificates(data)
    return [x509.load_der_x509_certificate(data)]


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def describe(cert: x509.Certificate) -> str:
    return f"{cert.subject.rfc4514_string()} (SHA-256 {fingerprint(cert)})"


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:  # name mismatch, bad signature, unsupported key: all mean "not this issuer"
        return False


def build_path(cert: x509.Certificate, pool: Sequence[x509.Certificate], roots: Sequence[x509.Certificate],
               seen: tuple[str, ...] = ()) -> list[x509.Certificate] | None:
    """A path from ``cert`` to one of ``roots``, by name and signature."""
    root_fps = {fingerprint(r) for r in roots}
    if fingerprint(cert) in root_fps:
        return [cert]
    if len(seen) >= MAX_PATH:
        return None
    here = seen + (fingerprint(cert),)
    for cand in list(pool) + list(roots):
        if fingerprint(cand) in here or cand.subject != cert.issuer:
            continue
        if _issued_by(cert, cand):
            rest = build_path(cand, pool, roots, here)
            if rest:
                return [cert] + rest
    return None


def highest_issuer(cert: x509.Certificate, pool: Sequence[x509.Certificate]) -> x509.Certificate:
    """Follow issuers through ``pool`` as far as signatures allow."""
    current, seen = cert, {fingerprint(cert)}
    for _ in range(MAX_PATH):
        nxt = next((c for c in pool if fingerprint(c) not in seen and c.subject == current.issuer and _issued_by(current, c)), None)
        if nxt is None:
            return current
        seen.add(fingerprint(nxt))
        current = nxt
    return current


def _valid_at(cert: x509.Certificate, at: _dt.datetime) -> bool:
    return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc


def _ext(cert: x509.Certificate, cls):
    try:
        return cert.extensions.get_extension_for_class(cls)
    except x509.ExtensionNotFound:
        return None


def check_timestamping_signer(cert: x509.Certificate) -> list[Check]:
    """RFC 3161 section 2.3: the extended key usage extension is present,
    critical, and holds id-kp-timeStamping only."""
    eku = _ext(cert, x509.ExtendedKeyUsage)
    if eku is None:
        return [Check("rfc3161.tsa_eku", Status.FAIL, "the signing certificate has no extended key usage extension",
                      reasons=["RFC 3161 requires a critical extended key usage of id-kp-timeStamping only"])]
    purposes = list(eku.value)
    problems = []
    if ExtendedKeyUsageOID.TIME_STAMPING not in purposes:
        problems.append("id-kp-timeStamping is absent")
    elif len(purposes) != 1:
        problems.append("it holds purposes besides id-kp-timeStamping: " + ", ".join(p.dotted_string for p in purposes))
    if not eku.critical:
        problems.append("the extension is not marked critical")
    checks = []
    if problems:
        checks.append(Check("rfc3161.tsa_eku", Status.FAIL, "the signing certificate is not a time-stamping certificate as RFC 3161 defines it",
                            reasons=problems))
    else:
        checks.append(Check("rfc3161.tsa_eku", Status.PASS, "the signing certificate is for time-stamping only (critical id-kp-timeStamping)"))
    ku = _ext(cert, x509.KeyUsage)
    if ku is not None and not (ku.value.digital_signature or ku.value.content_commitment):
        checks.append(Check("rfc3161.tsa_key_usage", Status.FAIL, "the signing certificate's key usage allows neither digital signature nor non-repudiation"))
    return checks


def check_path(path: list[x509.Certificate], at: _dt.datetime) -> list[Check]:
    """Validity at ``at`` for every certificate; CA constraints above the signer."""
    checks: list[Check] = []
    expired = [c for c in path if not _valid_at(c, at)]
    when = at.isoformat().replace("+00:00", "Z")
    if expired:
        checks.append(Check("rfc3161.validity", Status.FAIL, f"a certificate on the path was not valid at {when}",
                            reasons=[f"{describe(c)}: valid {c.not_valid_before_utc.isoformat()} to {c.not_valid_after_utc.isoformat()}" for c in expired]))
    else:
        checks.append(Check("rfc3161.validity", Status.PASS, f"every certificate on the path was within its validity period at {when}",
                            reasons=["a certificate that has expired since then does not undo a time-stamp made while it was valid"]))
    problems = []
    for i, ca in enumerate(path[1:], start=1):
        is_anchor = i == len(path) - 1
        bc = _ext(ca, x509.BasicConstraints)
        if bc is None or not bc.value.ca:
            if not is_anchor:
                problems.append(f"{describe(ca)} issues certificates but is not marked as a CA")
            continue
        ku = _ext(ca, x509.KeyUsage)
        if ku is not None and not ku.value.key_cert_sign and not is_anchor:
            problems.append(f"{describe(ca)} has a key usage that does not allow signing certificates")
        if bc.value.path_length is not None and not is_anchor and i - 1 > bc.value.path_length:
            problems.append(f"{describe(ca)} allows {bc.value.path_length} CAs below it, the path has {i - 1}")
    if problems:
        checks.append(Check("rfc3161.ca_constraints", Status.FAIL, "a certificate authority on the path breaks its constraints", reasons=problems))
    elif len(path) > 1:
        checks.append(Check("rfc3161.ca_constraints", Status.PASS, "every intermediate authority is a CA allowed to issue the certificate below it"))
    return checks
