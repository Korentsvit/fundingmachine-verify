"""RFC 3161 time-stamp tokens, checked against the authority's certificate chain.

Accepts a TimeStampResp (``.tsr``) or a bare TimeStampToken (CMS ContentInfo).
Checks, each reported with reasons:

* the message imprint against the file (or digest) the caller holds;
* the CMS structure: one signer, content type id-ct-TSTInfo;
* the signed attributes: content type, message digest of the TSTInfo, and
  the ESS signing certificate (RFC 2634, or version 2 of RFC 5035/5816)
  naming the signer's certificate;
* the signature (RSA PKCS#1 v1.5 or PSS, ECDSA, Ed25519, Ed448);
* the signer's certificate: time-stamping only, valid at the stated time;
* the chain to a root the caller supplies, valid at the stated time.

Revocation is checked from CRLs the caller supplies (RFC 3161 section 4: a
key-compromise revocation voids every token from that key); without them the
verdict says it was not checked and lists it as relied on.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from . import der, pki
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, Verdict, make_verdict

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"

HASHES = {
    "1.3.14.3.2.26": ("sha1", hashes.SHA1),
    "2.16.840.1.101.3.4.2.4": ("sha224", hashes.SHA224),
    "2.16.840.1.101.3.4.2.1": ("sha256", hashes.SHA256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashes.SHA384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashes.SHA512),
    "2.16.840.1.101.3.4.2.8": ("sha3_256", hashes.SHA3_256),
    "2.16.840.1.101.3.4.2.9": ("sha3_384", hashes.SHA3_384),
    "2.16.840.1.101.3.4.2.10": ("sha3_512", hashes.SHA3_512),
}
HASH_BY_NAME = {name: oid for oid, (name, _) in HASHES.items()}
WEAK_HASHES = {"sha1"}

RSA_PKCS1 = {
    "1.2.840.113549.1.1.1": None,  # rsaEncryption: the hash is the signer's digest algorithm
    "1.2.840.113549.1.1.5": "1.3.14.3.2.26",
    "1.2.840.113549.1.1.14": "2.16.840.1.101.3.4.2.4",
    "1.2.840.113549.1.1.11": "2.16.840.1.101.3.4.2.1",
    "1.2.840.113549.1.1.12": "2.16.840.1.101.3.4.2.2",
    "1.2.840.113549.1.1.13": "2.16.840.1.101.3.4.2.3",
}
RSA_PSS = "1.2.840.113549.1.1.10"
MGF1 = "1.2.840.113549.1.1.8"
ECDSA = {
    "1.2.840.10045.2.1": None,  # id-ecPublicKey used as a signature algorithm
    "1.2.840.10045.4.1": "1.3.14.3.2.26",
    "1.2.840.10045.4.3.1": "2.16.840.1.101.3.4.2.4",
    "1.2.840.10045.4.3.2": "2.16.840.1.101.3.4.2.1",
    "1.2.840.10045.4.3.3": "2.16.840.1.101.3.4.2.2",
    "1.2.840.10045.4.3.4": "2.16.840.1.101.3.4.2.3",
}
ED25519 = "1.3.101.112"
ED448 = "1.3.101.113"

PKI_STATUS = {0: "granted", 1: "granted with modifications", 2: "rejection", 3: "waiting",
              4: "revocation warning", 5: "revocation notification"}


class TokenError(ValueError):
    pass


@dataclass
class TstInfo:
    raw: bytes
    version: int
    policy: str
    hash_oid: str
    hashed_message: bytes
    serial: int
    gen_time: _dt.datetime
    accuracy_us: int | None
    ordering: bool
    nonce: int | None
    tsa: der.Node | None


@dataclass
class SignerInfo:
    version: int
    sid_issuer: bytes | None
    sid_serial: int | None
    sid_ski: bytes | None
    digest_oid: str
    signed_attrs_raw: bytes
    attrs: dict[str, list[der.Node]]
    sig_oid: str
    sig_params: der.Node | None
    signature: bytes


@dataclass
class Token:
    tst: TstInfo
    econtent_type: str
    econtent: bytes
    certificates: list[x509.Certificate]
    signers: list[SignerInfo]
    status: int | None = None
    status_text: list[str] = field(default_factory=list)


def _alg(node: der.Node) -> tuple[str, der.Node | None]:
    parts = der.expect(node, der.SEQUENCE, "algorithm identifier").children()
    if not parts or len(parts) > 2:
        raise TokenError("malformed algorithm identifier")
    params = parts[1] if len(parts) == 2 and not parts[1].is_universal(der.NULL) else None
    return der.oid(parts[0]), params


def _parse_tstinfo(raw: bytes) -> TstInfo:
    items = der.expect(der.parse(raw), der.SEQUENCE, "TSTInfo").children()
    if len(items) < 5:
        raise TokenError("TSTInfo has too few fields")
    version = der.integer(items[0])
    policy = der.oid(items[1])
    mi = der.expect(items[2], der.SEQUENCE, "message imprint").children()
    if len(mi) != 2:
        raise TokenError("malformed message imprint")
    hash_oid, _ = _alg(mi[0])
    hashed = der.octet_string(mi[1])
    serial = der.integer(items[3])
    gen_time = der.generalized_time(items[4])
    accuracy_us, ordering, nonce, tsa = None, False, None, None
    for item in items[5:]:
        if item.is_universal(der.SEQUENCE):
            us = 0
            for part in item.children():
                if part.is_universal(der.INTEGER):
                    us += der.integer(part) * 1_000_000
                elif part.cls == der.CONTEXT and part.tag in (0, 1) and not part.constructed:
                    v = int.from_bytes(part.content, "big")
                    us += v * (1000 if part.tag == 0 else 1)
            accuracy_us = us
        elif item.is_universal(der.BOOLEAN):
            ordering = der.boolean(item)
        elif item.is_universal(der.INTEGER):
            nonce = der.integer(item)
        elif item.is_context(0):
            tsa = item.children()[0]
        elif item.is_context(1):
            pass  # extensions: reported by presence only
        else:
            raise TokenError(f"unexpected field {item.describe()} in TSTInfo")
    return TstInfo(raw, version, policy, hash_oid, hashed, serial, gen_time, accuracy_us, ordering, nonce, tsa)


def _parse_signer(node: der.Node) -> SignerInfo:
    parts = der.expect(node, der.SEQUENCE, "SignerInfo").children()
    i = 0
    version = der.integer(parts[i]); i += 1
    sid = parts[i]; i += 1
    issuer = serial = ski = None
    if sid.is_universal(der.SEQUENCE):
        iss, ser = sid.children()
        issuer, serial = iss.raw, der.integer(ser)
    elif sid.is_context(0) and not sid.constructed:
        ski = sid.content
    else:
        raise TokenError("SignerInfo identifies its signer in neither form CMS allows")
    digest_oid, _ = _alg(parts[i]); i += 1
    if i >= len(parts) or not parts[i].is_context(0):
        raise TokenError("SignerInfo has no signed attributes; RFC 3161 tokens require them")
    sa = parts[i]; i += 1
    attrs: dict[str, list[der.Node]] = {}
    for a in sa.children():
        t, vals = der.expect(a, der.SEQUENCE, "attribute").children()
        key = der.oid(t)
        if key in attrs:
            raise TokenError(f"signed attribute {key} appears twice")
        attrs[key] = der.expect(vals, der.SET, "attribute values").children()
    sig_oid, sig_params = _alg(parts[i]); i += 1
    signature = der.octet_string(parts[i]); i += 1
    # The signature covers the attributes encoded as a SET OF: the same bytes with the tag 0x31.
    signed_raw = b"\x31" + sa.raw[1:]
    return SignerInfo(version, issuer, serial, ski, digest_oid, signed_raw, attrs, sig_oid, sig_params, signature)


def parse_token(data: bytes) -> Token:
    try:
        top = der.expect(der.parse(data), der.SEQUENCE, "token")
        kids = top.children()
        status, status_text = None, []
        if kids and kids[0].is_universal(der.SEQUENCE):  # TimeStampResp: PKIStatusInfo first
            info = kids[0].children()
            status = der.integer(info[0])
            for extra in info[1:]:
                if extra.is_universal(der.SEQUENCE):
                    status_text = [der.string(s) for s in extra.children()]
            if status not in (0, 1):
                raise TokenError(f"the authority answered '{PKI_STATUS.get(status, status)}'"
                                 + (f": {'; '.join(status_text)}" if status_text else "") + "; there is no token")
            if len(kids) < 2:
                raise TokenError("the response is granted but carries no token")
            top = kids[1]
            kids = top.children()
        if der.oid(kids[0]) != OID_SIGNED_DATA:
            raise TokenError("the token is not CMS SignedData")
        sd = kids[1].children()[0].children()
        der.integer(sd[0])  # SignedData version: read to check it is an integer; any value is accepted
        encap = der.expect(sd[2], der.SEQUENCE, "encapsulated content").children()
        econtent_type = der.oid(encap[0])
        if len(encap) != 2 or not encap[1].is_context(0):
            raise TokenError("the token encapsulates no content")
        econtent = der.octet_string(encap[1].children()[0])
        certs: list[x509.Certificate] = []
        rest = sd[3:]
        while rest and rest[0].cls == der.CONTEXT:
            if rest[0].tag == 0:
                for c in rest[0].children():
                    if c.is_universal(der.SEQUENCE):
                        certs.append(x509.load_der_x509_certificate(c.raw))
            rest = rest[1:]
        if len(rest) != 1:
            raise TokenError("SignedData does not end with its signer infos")
        signers = [_parse_signer(s) for s in der.expect(rest[0], der.SET, "signer infos").children()]
        tst = _parse_tstinfo(econtent)
        return Token(tst, econtent_type, econtent, certs, signers, status, status_text)
    except (der.DerError, IndexError, ValueError) as exc:
        if isinstance(exc, TokenError):
            raise
        raise TokenError(f"the token is malformed: {exc}") from exc


def _hash(oid: str, data: bytes) -> bytes:
    if oid not in HASHES:
        raise TokenError(f"hash algorithm {oid} is not one this verifier knows")
    return hashlib.new(HASHES[oid][0], data).digest()


def _hash_name(oid: str) -> str:
    return HASHES[oid][0] if oid in HASHES else oid


def _find_signer_cert(si: SignerInfo, pool: Sequence[x509.Certificate]) -> x509.Certificate | None:
    for c in pool:
        if si.sid_ski is not None:
            try:
                if c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == si.sid_ski:
                    return c
            except x509.ExtensionNotFound:
                continue
        elif c.serial_number == si.sid_serial and c.issuer.public_bytes() == si.sid_issuer:
            return c
    return None


def _ess_check(si: SignerInfo, cert: x509.Certificate) -> Check:
    cert_der = pki.der(cert)
    for oid, version in ((OID_SIGNING_CERT_V2, 2), (OID_SIGNING_CERT, 1)):
        if oid not in si.attrs:
            continue
        values = si.attrs[oid]
        if len(values) != 1:
            return Check("rfc3161.ess", Status.FAIL, "the signing certificate attribute has more than one value")
        first_id = values[0].children()[0].children()[0].children()
        if version == 2 and first_id[0].is_universal(der.SEQUENCE):
            h_oid, _ = _alg(first_id[0])
            first_id = first_id[1:]
        else:
            h_oid = "2.16.840.1.101.3.4.2.1" if version == 2 else "1.3.14.3.2.26"
        want = der.octet_string(first_id[0])
        if want != _hash(h_oid, cert_der):
            return Check("rfc3161.ess", Status.FAIL, "the signed attributes name a different certificate than the one that signed",
                         reasons=[f"ESS signing certificate v{version} hash ({_hash_name(h_oid)}) {want.hex()} does not match {pki.describe(cert)}"])
        if len(first_id) > 1:
            issuer_serial = first_id[1].children()
            if der.integer(issuer_serial[1]) != cert.serial_number:
                return Check("rfc3161.ess", Status.FAIL, "the ESS issuer and serial do not match the signing certificate")
        reasons = [f"ESS signing certificate v{version}, {_hash_name(h_oid)}"]
        status = Status.PASS
        if _hash_name(h_oid) in WEAK_HASHES:
            reasons.append("SHA-1 identifies the certificate here, as RFC 3161 originally specified")
        return Check("rfc3161.ess", status, "the signed attributes bind the signing certificate", reasons=reasons)
    return Check("rfc3161.ess", Status.FAIL, "the signed attributes do not name the signing certificate",
                 reasons=["RFC 3161 requires an ESS signing certificate attribute (RFC 5816 allows version 2)"])


def _pss_params(node: der.Node | None) -> tuple[str, str, int]:
    h, mgf_h, salt = "1.3.14.3.2.26", "1.3.14.3.2.26", 20
    if node is not None:
        for part in node.children():
            inner = part.children()[0]
            if part.is_context(0):
                h, _ = _alg(inner)
            elif part.is_context(1):
                m_oid, m_params = _alg(inner)
                if m_oid != MGF1 or m_params is None:
                    raise TokenError("RSASSA-PSS with a mask generation function other than MGF1")
                mgf_h, _ = _alg(m_params)
            elif part.is_context(2):
                salt = der.integer(inner)
            elif part.is_context(3) and der.integer(inner) != 1:
                raise TokenError("RSASSA-PSS with a trailer field other than 1")
    return h, mgf_h, salt


def verify_signature(cert: x509.Certificate, si: SignerInfo) -> tuple[bool, str]:
    key = cert.public_key()
    data, sig = si.signed_attrs_raw, si.signature
    try:
        if si.sig_oid in RSA_PKCS1 and isinstance(key, rsa.RSAPublicKey):
            h = RSA_PKCS1[si.sig_oid] or si.digest_oid
            key.verify(sig, data, padding.PKCS1v15(), HASHES[h][1]())
            return True, f"RSA PKCS#1 v1.5 with {_hash_name(h)}, {key.key_size}-bit key"
        if si.sig_oid == RSA_PSS and isinstance(key, rsa.RSAPublicKey):
            h, mgf_h, salt = _pss_params(si.sig_params)
            key.verify(sig, data, padding.PSS(mgf=padding.MGF1(HASHES[mgf_h][1]()), salt_length=salt), HASHES[h][1]())
            return True, f"RSASSA-PSS with {_hash_name(h)}, salt {salt}, {key.key_size}-bit key"
        if si.sig_oid in ECDSA and isinstance(key, ec.EllipticCurvePublicKey):
            h = ECDSA[si.sig_oid] or si.digest_oid
            key.verify(sig, data, ec.ECDSA(HASHES[h][1]()))
            return True, f"ECDSA with {_hash_name(h)} on {key.curve.name}"
        if si.sig_oid == ED25519 and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, data)
            return True, "Ed25519"
        if si.sig_oid == ED448 and isinstance(key, ed448.Ed448PublicKey):
            key.verify(sig, data)
            return True, "Ed448"
    except InvalidSignature:
        return False, "the signature does not verify with the signing certificate's key"
    except KeyError as exc:
        return False, f"hash algorithm {exc} is not one this verifier knows"
    return False, f"signature algorithm {si.sig_oid} does not fit a {type(key).__name__.replace('_', '')} key, or is not one this verifier knows"


def _general_name_matches(node: der.Node, cert: x509.Certificate) -> tuple[bool | None, str]:
    if node.is_context(4):
        name = node.children()[0]
        text = der.name_to_text(name)
        return name.raw == cert.subject.public_bytes(), text
    return None, f"a general name of type [{node.tag}]"


def verify(
    token_bytes: bytes,
    file_bytes: bytes | None = None,
    digest: bytes | None = None,
    digest_alg: str = "sha256",
    roots: Sequence[x509.Certificate] = (),
    extra_certs: Sequence[x509.Certificate] = (),
    subject: str | None = None,
    checked_at: str | None = None,
    crls: Sequence[x509.CertificateRevocationList] = (),
) -> Verdict:
    """Check an RFC 3161 token. ``roots`` are the certificates the caller
    trusts; without any, the verdict is at best indeterminate. ``crls`` are
    revocation lists the caller holds, checked along the trusted path."""
    checks: list[Check] = []
    fail_statement = {o: "The RFC 3161 time-stamp token does not hold: see the failing checks." for o in Outcome}
    try:
        tok = parse_token(token_bytes)
    except TokenError as exc:
        checks.append(Check("rfc3161.parse", Status.FAIL, "the token could not be read", reasons=[str(exc)]))
        return make_verdict("rfc3161", subject or "RFC 3161 token", checks, fail_statement, ANCHOR_LIMITS, checked_at)
    tst = tok.tst
    imprint_hash = _hash_name(tst.hash_oid)
    subject = subject or f"{imprint_hash} digest {tst.hashed_message.hex()}"
    when = tst.gen_time.isoformat().replace("+00:00", "Z")
    acc = f" (accuracy {tst.accuracy_us / 1e6:g} s)" if tst.accuracy_us is not None else " (no accuracy stated)"
    checks.append(Check("rfc3161.parse", Status.PASS, f"the token is well formed: {imprint_hash} imprint, time {when}{acc}",
                        data={"gen_time": when, "accuracy_seconds": None if tst.accuracy_us is None else tst.accuracy_us / 1e6,
                              "policy": tst.policy, "serial": str(tst.serial), "nonce": None if tst.nonce is None else str(tst.nonce),
                              "imprint_hash": imprint_hash, "imprint": tst.hashed_message.hex(),
                              "response_status": None if tok.status is None else PKI_STATUS.get(tok.status, tok.status)}))

    # The subject.
    if file_bytes is not None:
        try:
            actual = _hash(tst.hash_oid, file_bytes)
        except TokenError as exc:
            checks.append(Check("rfc3161.subject", Status.NOT_CHECKED, "the file could not be hashed as the token requires", reasons=[str(exc)]))
        else:
            if actual == tst.hashed_message:
                checks.append(Check("rfc3161.subject", Status.PASS, f"the file's {imprint_hash} digest equals the token's message imprint"))
            else:
                checks.append(Check("rfc3161.subject", Status.FAIL, f"the file's {imprint_hash} digest differs from the token's message imprint",
                                    reasons=[f"file {actual.hex()}", f"token {tst.hashed_message.hex()}"]))
    elif digest is not None:
        if HASH_BY_NAME.get(digest_alg) != tst.hash_oid:
            checks.append(Check("rfc3161.subject", Status.NOT_CHECKED, f"the token's imprint is {imprint_hash}, the digest given is {digest_alg}",
                                reasons=["give the file itself, or its digest under the token's hash"]))
        elif digest == tst.hashed_message:
            checks.append(Check("rfc3161.subject", Status.PASS, "the expected digest equals the token's message imprint"))
        else:
            checks.append(Check("rfc3161.subject", Status.FAIL, "the expected digest differs from the token's message imprint",
                                reasons=[f"expected {digest.hex()}", f"token {tst.hashed_message.hex()}"]))
    if imprint_hash in WEAK_HASHES:
        checks.append(Check("rfc3161.weak_hash", Status.WARN, "the message imprint uses SHA-1, which is broken for collisions",
                            reasons=["whoever chose the file could have prepared a second file with the same imprint"]))

    # Structure.
    problems = []
    if tok.econtent_type != OID_TSTINFO:
        problems.append(f"content type is {tok.econtent_type}, not id-ct-TSTInfo")
    if len(tok.signers) != 1:
        problems.append(f"{len(tok.signers)} signers; RFC 3161 allows only the authority's")
    if tst.version != 1:
        problems.append(f"TSTInfo version {tst.version}, not 1")
    if problems:
        checks.append(Check("rfc3161.structure", Status.FAIL, "the token is not shaped as RFC 3161 requires", reasons=problems))
        return make_verdict("rfc3161", subject, checks, fail_statement, ANCHOR_LIMITS, checked_at)
    checks.append(Check("rfc3161.structure", Status.PASS, "one signer over a TSTInfo, as RFC 3161 requires"))
    si = tok.signers[0]

    # Signed attributes.
    attr_problems = []
    ct = si.attrs.get(OID_CONTENT_TYPE, [])
    if len(ct) != 1 or der.oid(ct[0]) != OID_TSTINFO:
        attr_problems.append("the content-type attribute is missing or is not id-ct-TSTInfo")
    md = si.attrs.get(OID_MESSAGE_DIGEST, [])
    try:
        expected_md = _hash(si.digest_oid, tok.econtent)
    except TokenError as exc:
        attr_problems.append(str(exc))
        expected_md = None
    if len(md) != 1:
        attr_problems.append("the message-digest attribute is missing")
    elif expected_md is not None and der.octet_string(md[0]) != expected_md:
        attr_problems.append("the message-digest attribute does not match the TSTInfo: the time-stamp content was changed after signing")
    if attr_problems:
        checks.append(Check("rfc3161.signed_attrs", Status.FAIL, "the signed attributes do not cover this TSTInfo", reasons=attr_problems))
    else:
        checks.append(Check("rfc3161.signed_attrs", Status.PASS,
                            f"the signed attributes carry the TSTInfo's {_hash_name(si.digest_oid)} digest and its content type"))

    # The signer's certificate.
    pool = list(tok.certificates) + list(extra_certs) + list(roots)
    signer = _find_signer_cert(si, pool)
    if signer is None:
        checks.append(Check("rfc3161.signer_cert", Status.NOT_CHECKED, "the signing certificate is neither in the token nor among those supplied",
                            reasons=["pass the authority's certificate with --chain"]))
        return make_verdict("rfc3161", subject, checks, _statements(tst, None, None, when, acc), ANCHOR_LIMITS, checked_at)
    checks.append(Check("rfc3161.signer_cert", Status.PASS, f"signed by {pki.describe(signer)}",
                        data={"subject": signer.subject.rfc4514_string(), "sha256": pki.fingerprint(signer),
                              "in_token": any(pki.fingerprint(c) == pki.fingerprint(signer) for c in tok.certificates)}))
    checks.append(_ess_check(si, signer))
    ok, how = verify_signature(signer, si)
    checks.append(Check("rfc3161.signature", Status.PASS if ok else Status.FAIL,
                        f"the authority's signature verifies ({how})" if ok else "the authority's signature does not verify",
                        reasons=[] if ok else [how]))
    if _hash_name(si.digest_oid) in WEAK_HASHES:
        checks.append(Check("rfc3161.weak_digest", Status.WARN, "the signer's digest algorithm is SHA-1, which is broken for collisions"))
    if tst.tsa is not None:
        match, text = _general_name_matches(tst.tsa, signer)
        if match is None:
            checks.append(Check("rfc3161.tsa_name", Status.INFO, f"the token names its authority as {text}; not compared", required=False))
        elif match:
            checks.append(Check("rfc3161.tsa_name", Status.PASS, f"the token's authority name, {text}, is the signing certificate's subject"))
        else:
            checks.append(Check("rfc3161.tsa_name", Status.FAIL, f"the token names its authority as {text}, but {signer.subject.rfc4514_string()} signed it"))
    checks.extend(pki.check_timestamping_signer(signer))

    # The chain.
    path = pki.build_path(signer, list(tok.certificates) + list(extra_certs), roots) if roots else None
    anchor = None
    if not roots:
        top = pki.highest_issuer(signer, list(tok.certificates) + list(extra_certs))
        checks.append(Check("rfc3161.chain", Status.NOT_CHECKED, "no trusted root was supplied, so the authority is not identified",
                            reasons=[f"the certificates at hand lead up to {pki.describe(top)}"
                                     + ("" if top.issuer == top.subject else f", issued by {top.issuer.rfc4514_string()}"),
                                     "pass the authority's root with --roots, after comparing its fingerprint with the authority's own"]))
        checks.extend(pki.check_path([signer], tst.gen_time))
    elif path is None:
        checks.append(Check("rfc3161.chain", Status.FAIL, "the signing certificate does not chain to any root supplied as trusted",
                            reasons=[f"trusted: {pki.describe(r)}" for r in roots]
                            + [f"the certificates at hand lead up to {pki.describe(pki.highest_issuer(signer, list(tok.certificates) + list(extra_certs)))}"]))
    else:
        anchor = path[-1]
        checks.append(Check("rfc3161.chain", Status.PASS, f"the signing certificate chains to {anchor.subject.rfc4514_string()}, which you supplied as trusted",
                            reasons=[" -> ".join(c.subject.rfc4514_string() for c in path)],
                            relies_on=[f"{pki.describe(anchor)} is the time-stamping authority's root: compare the fingerprint with the authority's own publication"],
                            data={"path": [pki.fingerprint(c) for c in path], "root_sha256": pki.fingerprint(anchor)}))
        checks.extend(pki.check_path(path, tst.gen_time))
    if crls and path is not None:
        checks.extend(pki.check_revocation(path, crls, tst.gen_time))
    else:
        checks.append(Check("rfc3161.revocation", Status.NOT_CHECKED, "revocation was not checked",
                            reasons=["no certificate revocation list was supplied" if not crls else "no trusted chain to check it along",
                                     "an offline check sees a revocation only through a CRL it is given"],
                            relies_on=["the authority's certificates were not revoked for key compromise"],
                            required=False))
    return make_verdict("rfc3161", subject, checks, _statements(tst, signer, anchor, when, acc), ANCHOR_LIMITS, checked_at)


def _statements(tst: TstInfo, signer: x509.Certificate | None, anchor: x509.Certificate | None, when: str, acc: str) -> dict:
    who = signer.subject.rfc4514_string() if signer is not None else "an unidentified authority"
    root = f" (whose certificate chains to {anchor.subject.rfc4514_string()}, a root you trust)" if anchor is not None else ""
    return {
        Outcome.VALID: (f"The time-stamping authority {who}{root} signed that the {_hash_name(tst.hash_oid)} digest "
                        f"{tst.hashed_message.hex()} existed at {when}{acc}, under policy {tst.policy}."),
        Outcome.INVALID: "The RFC 3161 time-stamp token does not hold: see the failing checks.",
        Outcome.INDETERMINATE: (f"The token's signature was checked as far as possible, but the authority {who} could not be "
                                "tied to a root you trust, or a required item was missing."),
    }


def verify_file(token_path: str | Path, file_path: str | Path | None = None, roots: Sequence[x509.Certificate] = (),
                extra_certs: Sequence[x509.Certificate] = (), **kwargs) -> Verdict:
    file_bytes = Path(file_path).read_bytes() if file_path is not None else None
    subject = kwargs.pop("subject", None) or (str(file_path) if file_path is not None else None)
    return verify(Path(token_path).read_bytes(), file_bytes=file_bytes, roots=roots, extra_certs=extra_certs,
                  subject=subject, **kwargs)
