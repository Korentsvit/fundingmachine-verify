"""X.509 certificate chains for time-stamping authorities.

The verifier ships no trust store. The caller supplies the roots they trust
(and, optionally, intermediates); the verdict names the root a chain reached
and its SHA-256 fingerprint, so the caller can compare it with the
authority's own published fingerprint.

Checked for each certificate on the path, at the time the token states:
validity period; for the CAs above the signer, basic constraints, key usage
and path length; every signature, by the next certificate's key. Revocation
is checked only from CRLs the caller supplies; without them it is reported as
not checked and listed as relied on.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Sequence

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from .verdict import Check, Status, utc

MAX_PATH = 8


def parsed(cert: x509.Certificate) -> x509.Certificate:
    """The certificate, with every field the verifier reads parsed now.

    The cryptography library parses some fields only when they are read; a
    malformed certificate must fail here, as malformed input, not later in
    the middle of a check. Raises ValueError."""
    try:
        cert.subject, cert.issuer, cert.serial_number, cert.public_key()
        cert.not_valid_before_utc, cert.not_valid_after_utc
        for ext in cert.extensions:
            ext.value
    except ValueError:
        raise
    except (UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType, TypeError) as exc:
        raise ValueError(f"the certificate cannot be read: {type(exc).__name__}: {exc}") from exc
    return cert


def load_der(raw: bytes) -> x509.Certificate:
    """One DER certificate, fully parsed; any parsing failure is a ValueError."""
    try:
        cert = x509.load_der_x509_certificate(raw)
    except ValueError:
        raise
    except Exception as exc:  # the library raises its own types (InvalidVersion and others)
        raise ValueError(f"the certificate cannot be read: {type(exc).__name__}: {exc}") from exc
    return parsed(cert)


def load_certificates(data: bytes) -> list[x509.Certificate]:
    """PEM (one or many) or a single DER certificate."""
    if b"-----BEGIN" in data:
        try:
            certs = x509.load_pem_x509_certificates(data)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"the certificates cannot be read: {type(exc).__name__}: {exc}") from exc
        return [parsed(c) for c in certs]
    return [load_der(data)]


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
    when = utc(at)
    if expired:
        checks.append(Check("rfc3161.validity", Status.FAIL, f"a certificate on the path was not valid at {when}",
                            reasons=[f"{describe(c)}: valid {utc(c.not_valid_before_utc)} to {utc(c.not_valid_after_utc)}" for c in expired]))
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


def load_crls(data: bytes) -> list[x509.CertificateRevocationList]:
    """PEM (one or many) or a single DER certificate revocation list."""
    if b"-----BEGIN" in data:
        blocks = re.findall(rb"-----BEGIN X509 CRL-----.+?-----END X509 CRL-----", data, re.S)
        if not blocks:
            raise ValueError("no PEM CRL found")
        return [x509.load_pem_x509_crl(b + b"\n") for b in blocks]
    return [x509.load_der_x509_crl(data)]


def check_revocation(path: list[x509.Certificate], crls: Sequence[x509.CertificateRevocationList], at: _dt.datetime) -> list[Check]:
    """Revocation of every certificate on the path below the trust anchor,
    from the CRLs supplied. RFC 3161 section 4: a certificate revoked for
    key compromise voids every token its key signed, whenever revoked; any
    other revocation voids tokens stated after it."""
    when = utc(at)
    covered, open_items, failures, warnings = [], [], [], []
    for cert, issuer in zip(path[:-1], path[1:]):
        usable = []
        for crl in crls:
            if crl.issuer != cert.issuer:
                continue
            if not crl.is_signature_valid(issuer.public_key()):
                warnings.append(f"a CRL naming {crl.issuer.rfc4514_string()} as issuer does not verify with that issuer's key; ignored")
                continue
            usable.append(crl)
        # A listing in any authentic CRL counts, whenever the CRL was issued.
        listed = [(crl, crl.get_revoked_certificate_by_serial_number(cert.serial_number)) for crl in usable]
        listed = [(crl, entry) for crl, entry in listed if entry is not None]
        voiding = []
        later = []
        for crl, entry in listed:
            revoked_at = entry.revocation_date_utc
            try:
                reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
            except x509.ExtensionNotFound:
                reason = None
            reason_text = reason.value if reason is not None else "no reason given"
            if reason == x509.ReasonFlags.key_compromise:
                voiding.append(f"{describe(cert)} was revoked for key compromise on {utc(revoked_at)}: "
                               "RFC 3161 section 4 says no token its key signed can be trusted")
            elif revoked_at <= at:
                voiding.append(f"{describe(cert)} was revoked ({reason_text}) on {utc(revoked_at)}, before {when}")
            else:
                later.append(f"{cert.subject.rfc4514_string()}: revoked later ({reason_text}, {utc(revoked_at)}), "
                             "which leaves earlier tokens standing")
        if voiding:
            failures += voiding
            continue
        if later:
            covered += later
            continue
        # Not listed: only a CRL issued at or after the token's time shows the status then.
        fresh = [crl for crl in usable if crl.last_update_utc >= at]
        if fresh:
            issued = utc(max(c.last_update_utc for c in fresh))
            covered.append(f"{cert.subject.rfc4514_string()}: not revoked as of {issued}")
        elif usable:
            open_items.append(f"{describe(cert)}: the CRLs supplied were all issued before {when}, so they cannot show the status at that time")
        else:
            open_items.append(f"{describe(cert)}: no CRL from its issuer was supplied")
    checks: list[Check] = []
    if warnings:
        checks.append(Check("rfc3161.crl", Status.WARN, "a CRL supplied could not be used", reasons=warnings, required=False))
    if failures:
        checks.append(Check("rfc3161.revocation", Status.FAIL, "a certificate on the path is revoked in a way that voids this token",
                            reasons=failures))
    elif open_items:
        checks.append(Check("rfc3161.revocation", Status.NOT_CHECKED, "revocation was not checked for every certificate on the path",
                            reasons=covered + open_items,
                            relies_on=["the authority's certificates not covered by a CRL were not revoked for key compromise"],
                            required=False))
    else:
        checks.append(Check("rfc3161.revocation", Status.PASS, f"no certificate on the path is revoked in a way that voids a token from {when}",
                            reasons=covered, relies_on=["the CRLs supplied are the issuers' latest"]))
    return checks
