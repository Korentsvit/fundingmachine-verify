"""RFC 3161 fixtures: a test PKI and time-stamp tokens, built deterministically.

Every private key is derived from a fixed, published seed string, so the
fixtures rebuild byte for byte and no key file is committed. These keys
protect nothing: anyone can rebuild them from this file. Signatures are
deterministic: RSA PKCS#1 v1.5 and Ed25519 by nature, ECDSA per RFC 6979,
and RSA-PSS by encoding EMSA-PSS here with a fixed salt (RFC 8017, section
9.1.1) and checking the result with the cryptography library.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import random
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fmverify import der
from fmverify.der import alg, ctx, enc_gentime, enc_int, enc_octets, enc_oid, seq, set_of, tlv

OID = {
    "sha1": "1.3.14.3.2.26",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha256WithRSA": "1.2.840.113549.1.1.11",
    "pss": "1.2.840.113549.1.1.10",
    "mgf1": "1.2.840.113549.1.1.8",
    "ecdsaSHA256": "1.2.840.10045.4.3.2",
    "ed25519": "1.3.101.112",
    "signedData": "1.2.840.113549.1.7.2",
    "tstInfo": "1.2.840.113549.1.9.16.1.4",
    "contentType": "1.2.840.113549.1.9.3",
    "messageDigest": "1.2.840.113549.1.9.4",
    "signingCert": "1.2.840.113549.1.9.16.2.12",
    "signingCertV2": "1.2.840.113549.1.9.16.2.47",
}
POLICY = "1.3.6.1.4.1.32473.1.1"  # under the documentation enterprise number of RFC 5612
GEN_TIME = dt.datetime(2026, 10, 16, 6, 0, 0, 125000, tzinfo=dt.timezone.utc)
NOT_BEFORE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER_CA = dt.datetime(2046, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER_TSA = dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc)
DOCUMENT = b"FundingMachine verifier fixture: a time-stamped decision fragment\n"


def _small_primes(limit: int = 2000) -> list[int]:
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    return [i for i in range(limit) if sieve[i]]


SMALL = _small_primes()


def _is_probable_prime(n: int, rng: random.Random) -> bool:
    for p in SMALL:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(40):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_key(seed: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    rng = random.Random(hashlib.sha256(seed.encode()).digest())
    e = 65537

    def prime() -> int:
        while True:
            c = rng.getrandbits(bits // 2) | (3 << (bits // 2 - 2)) | 1
            if _is_probable_prime(c, rng):
                return c

    while True:
        p, q = prime(), prime()
        if p == q or math.gcd(e, (p - 1) * (q - 1)) != 1:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        d = pow(e, -1, (p - 1) * (q - 1))
        return rsa.RSAPrivateNumbers(
            p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(e, n)
        ).private_key()


def ec_key(seed: str) -> ec.EllipticCurvePrivateKey:
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    return ec.derive_private_key(int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big") % (order - 1) + 1, ec.SECP256R1())


def ed_key(seed: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FundingMachine verifier test PKI"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(subject_cn: str, key, issuer_cn: str, issuer_key, serial: int, *, ca: bool, pathlen: int | None = None,
         eku: list | None = (ExtendedKeyUsageOID.TIME_STAMPING,), eku_critical: bool = True,
         not_before: dt.datetime = NOT_BEFORE, not_after: dt.datetime | None = None) -> x509.Certificate:
    pub = key.public_key()
    b = (x509.CertificateBuilder()
         .subject_name(name(subject_cn)).issuer_name(name(issuer_cn)).public_key(pub)
         .serial_number(serial).not_valid_before(not_before)
         .not_valid_after(not_after or (NOT_AFTER_CA if ca else NOT_AFTER_TSA))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=eku_critical)
    algo = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return b.sign(issuer_key, algo)


def cert_der(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.DER)


def name_der(c: x509.Certificate, which: str = "subject") -> bytes:
    return getattr(c, which).public_bytes()


def token(key, signer: x509.Certificate, certs: list[x509.Certificate], message: bytes, *, serial: int,
          sig: str, digest: str = "sha256", imprint: str = "sha256", ess: int = 2, ess_cert: x509.Certificate | None = None,
          gen_time: dt.datetime = GEN_TIME, tamper_gen_time: dt.datetime | None = None, flip_signature: bool = False,
          status: int = 0, imprint_value: bytes | None = None) -> bytes:
    """A TimeStampResp over ``message`` (its digest is the imprint), or over
    ``imprint_value`` taken as the digest itself."""
    value = imprint_value if imprint_value is not None else hashlib.new(imprint, message).digest()

    def tstinfo(t: dt.datetime) -> bytes:
        return seq(enc_int(1), enc_oid(POLICY),
                   seq(alg(OID[imprint], der.NULL_DER), enc_octets(value)),
                   enc_int(serial), enc_gentime(t), seq(enc_int(1)),
                   ctx(0, ctx(4, name_der(signer))))

    tst = tstinfo(gen_time)
    ess_target = cert_der(ess_cert or signer)
    issuer_serial = seq(seq(ctx(4, name_der(ess_cert or signer, "issuer"))), enc_int((ess_cert or signer).serial_number))
    if ess == 2:
        ess_attr = seq(enc_oid(OID["signingCertV2"]), set_of(seq(seq(seq(enc_octets(hashlib.sha256(ess_target).digest()), issuer_serial)))))
    else:
        ess_attr = seq(enc_oid(OID["signingCert"]), set_of(seq(seq(seq(enc_octets(hashlib.sha1(ess_target).digest()), issuer_serial)))))
    attrs = set_of(
        seq(enc_oid(OID["contentType"]), set_of(enc_oid(OID["tstInfo"]))),
        seq(enc_oid(OID["messageDigest"]), set_of(enc_octets(hashlib.new(digest, tst).digest()))),
        ess_attr,
    )
    if sig == "rsa":
        signature = key.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
        sig_alg = alg(OID["sha256WithRSA"], der.NULL_DER)
    elif sig == "pss":
        signature = pss_sign(key, attrs, salt=hashlib.sha256(b"fm-verify fixture salt").digest())
        sha = alg(OID["sha256"], der.NULL_DER)
        sig_alg = alg(OID["pss"], seq(ctx(0, sha), ctx(1, alg(OID["mgf1"], sha)), ctx(2, enc_int(32))))
    elif sig == "ecdsa":
        signature = key.sign(attrs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        sig_alg = alg(OID["ecdsaSHA256"])
    elif sig == "ed25519":
        signature = key.sign(attrs)
        sig_alg = alg(OID["ed25519"])
    else:
        raise ValueError(sig)
    if flip_signature:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
    if tamper_gen_time is not None:
        tst = tstinfo(tamper_gen_time)
    signer_info = seq(enc_int(1), seq(name_der(signer, "issuer"), enc_int(signer.serial_number)),
                      alg(OID[digest], der.NULL_DER), b"\xa0" + attrs[1:], sig_alg, enc_octets(signature))
    parts = [enc_int(3), set_of(alg(OID[digest], der.NULL_DER)), seq(enc_oid(OID["tstInfo"]), ctx(0, enc_octets(tst)))]
    if certs:
        parts.append(tlv(0xA0, b"".join(sorted(cert_der(c) for c in certs))))
    parts.append(set_of(signer_info))
    content_info = seq(enc_oid(OID["signedData"]), ctx(0, seq(*parts)))
    return seq(seq(enc_int(status)), content_info)


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    for counter in range(-(-length // 32)):
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
    return out[:length]


def pss_sign(key: rsa.RSAPrivateKey, message: bytes, salt: bytes) -> bytes:
    """RSASSA-PSS with SHA-256, MGF1-SHA-256 and the given salt (RFC 8017, 8.1.1 and 9.1.1)."""
    nums = key.private_numbers()
    n, d = nums.public_numbers.n, nums.d
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = -(-em_bits // 8)
    m_hash = hashlib.sha256(message).digest()
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - len(salt) - 32 - 2) + b"\x01" + salt
    masked = bytes(a ^ b for a, b in zip(db, _mgf1(h, em_len - 32 - 1)))
    masked = bytes([masked[0] & (0xFF >> (8 * em_len - em_bits))]) + masked[1:]
    em = masked + h + b"\xbc"
    k = -(-mod_bits // 8)
    signature = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
    key.public_key().verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=len(salt)), hashes.SHA256())
    return signature


def rejection() -> bytes:
    return seq(seq(enc_int(2), seq(tlv(0x0C, b"request refused by the test authority"))))


def pem(c: x509.Certificate) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def test_authority() -> tuple:
    """The RSA test authority's key, its certificate and the issuing CA, as build() makes them."""
    root_k, ica_k, tsa_k = rsa_key("fm-verify test root CA"), rsa_key("fm-verify test issuing CA"), rsa_key("fm-verify test TSA rsa")
    ica = cert("FM Verify Test Issuing CA", ica_k, "FM Verify Test Root CA", root_k, 2, ca=True, pathlen=0)
    tsa = cert("FM Verify Test TSA RSA", tsa_k, "FM Verify Test Issuing CA", ica_k, 101, ca=False)
    return tsa_k, tsa, ica


def test_authority_p256() -> tuple:
    """The P-256 test authority's key, its certificate and the issuing CA, as build() makes them."""
    root_k, ica_k, tsa_k = rsa_key("fm-verify test root CA"), rsa_key("fm-verify test issuing CA"), ec_key("fm-verify test TSA p256")
    ica = cert("FM Verify Test Issuing CA", ica_k, "FM Verify Test Root CA", root_k, 2, ca=True, pathlen=0)
    tsa = cert("FM Verify Test TSA P-256", tsa_k, "FM Verify Test Issuing CA", ica_k, 102, ca=False)
    return tsa_k, tsa, ica


def build(fix: Path) -> None:
    out = fix / "rfc3161"
    pki_dir = out / "pki"
    pki_dir.mkdir(parents=True, exist_ok=True)

    root_k = rsa_key("fm-verify test root CA")
    other_k = rsa_key("fm-verify test other root CA")
    ica_k = rsa_key("fm-verify test issuing CA")
    tsa_rsa_k = rsa_key("fm-verify test TSA rsa")
    tsa_ec_k = ec_key("fm-verify test TSA p256")
    tsa_ed_k = ed_key("fm-verify test TSA ed25519")

    root = cert("FM Verify Test Root CA", root_k, "FM Verify Test Root CA", root_k, 1, ca=True)
    other = cert("FM Verify Test Other Root CA", other_k, "FM Verify Test Other Root CA", other_k, 1, ca=True)
    ica = cert("FM Verify Test Issuing CA", ica_k, "FM Verify Test Root CA", root_k, 2, ca=True, pathlen=0)
    tsa_rsa = cert("FM Verify Test TSA RSA", tsa_rsa_k, "FM Verify Test Issuing CA", ica_k, 101, ca=False)
    tsa_ec = cert("FM Verify Test TSA P-256", tsa_ec_k, "FM Verify Test Issuing CA", ica_k, 102, ca=False)
    tsa_ed = cert("FM Verify Test TSA Ed25519", tsa_ed_k, "FM Verify Test Issuing CA", ica_k, 103, ca=False)
    tsa_noeku = cert("FM Verify Test TSA without EKU", tsa_rsa_k, "FM Verify Test Issuing CA", ica_k, 104, ca=False, eku=None)
    tsa_server = cert("FM Verify Test TSA for servers", tsa_rsa_k, "FM Verify Test Issuing CA", ica_k, 105, ca=False,
                      eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.TIME_STAMPING])
    tsa_expired = cert("FM Verify Test TSA expired", tsa_rsa_k, "FM Verify Test Issuing CA", ica_k, 106, ca=False,
                       not_after=dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc))

    files = {"root.pem": root, "other-root.pem": other, "issuing-ca.pem": ica, "tsa-rsa.pem": tsa_rsa,
             "tsa-p256.pem": tsa_ec, "tsa-ed25519.pem": tsa_ed}
    for fname, c in files.items():
        (pki_dir / fname).write_bytes(pem(c))
    (pki_dir / "chain-p256.pem").write_bytes(pem(tsa_ec) + pem(ica))

    def case(name: str, tok: bytes, expected: dict, document: bytes = DOCUMENT) -> None:
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "token.tsr").write_bytes(tok)
        (d / "document.txt").write_bytes(document)
        expected = {"file": "document.txt", **expected}
        (d / "expected.json").write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")

    roots = ["../pki/root.pem"]
    rsa_tok = token(tsa_rsa_k, tsa_rsa, [tsa_rsa, ica], DOCUMENT, serial=1001, sig="rsa")
    case("valid-rsa", rsa_tok, {"description": "RSA authority under an issuing CA, ESS v2, certificates in the token",
                                "roots": roots, "outcome": "valid"})
    case("valid-pss", token(tsa_rsa_k, tsa_rsa, [tsa_rsa, ica], DOCUMENT, serial=1002, sig="pss"),
         {"description": "RSASSA-PSS signature", "roots": roots, "outcome": "valid"})
    case("valid-p256-chain-supplied", token(tsa_ec_k, tsa_ec, [], DOCUMENT, serial=1003, sig="ecdsa", ess=1),
         {"description": "P-256 authority, ESS v1, no certificates in the token: the chain is supplied separately",
          "roots": roots, "chain": ["../pki/chain-p256.pem"], "outcome": "valid"})
    case("p256-chain-missing", token(tsa_ec_k, tsa_ec, [], DOCUMENT, serial=1003, sig="ecdsa", ess=1),
         {"description": "The same token without its certificates: the signer cannot be found",
          "roots": roots, "outcome": "indeterminate"})
    case("valid-ed25519", token(tsa_ed_k, tsa_ed, [tsa_ed, ica], DOCUMENT, serial=1004, sig="ed25519", digest="sha512"),
         {"description": "Ed25519 authority (RFC 8419), SHA-512 message digest", "roots": roots, "outcome": "valid"})
    case("no-roots", rsa_tok, {"description": "No trusted root supplied", "roots": [], "outcome": "indeterminate"})
    case("wrong-root", rsa_tok, {"description": "Only an unrelated root is trusted", "roots": ["../pki/other-root.pem"],
                                 "outcome": "invalid", "failing": ["rfc3161.chain"]})
    case("tampered-file", rsa_tok, {"description": "The document changed after time-stamping", "roots": roots,
                                    "outcome": "invalid", "failing": ["rfc3161.subject"]},
         document=DOCUMENT.replace(b"decision", b"Decision"))
    case("back-dated", token(tsa_rsa_k, tsa_rsa, [tsa_rsa, ica], DOCUMENT, serial=1005, sig="rsa",
                             tamper_gen_time=dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)),
         {"description": "genTime moved a month earlier after signing", "roots": roots, "outcome": "invalid",
          "failing": ["rfc3161.signed_attrs"]})
    case("tampered-signature", token(tsa_rsa_k, tsa_rsa, [tsa_rsa, ica], DOCUMENT, serial=1006, sig="rsa", flip_signature=True),
         {"description": "One bit of the signature flipped", "roots": roots, "outcome": "invalid", "failing": ["rfc3161.signature"]})
    case("ess-mismatch", token(tsa_rsa_k, tsa_rsa, [tsa_rsa, ica], DOCUMENT, serial=1007, sig="rsa", ess_cert=ica),
         {"description": "The ESS attribute names the issuing CA instead of the signer", "roots": roots, "outcome": "invalid",
          "failing": ["rfc3161.ess"]})
    case("eku-missing", token(tsa_rsa_k, tsa_noeku, [tsa_noeku, ica], DOCUMENT, serial=1008, sig="rsa"),
         {"description": "The signer's certificate has no extended key usage", "roots": roots, "outcome": "invalid",
          "failing": ["rfc3161.tsa_eku"]})
    case("eku-not-exclusive", token(tsa_rsa_k, tsa_server, [tsa_server, ica], DOCUMENT, serial=1009, sig="rsa"),
         {"description": "The signer's certificate is also for TLS servers", "roots": roots, "outcome": "invalid",
          "failing": ["rfc3161.tsa_eku"]})
    case("expired-at-time", token(tsa_rsa_k, tsa_expired, [tsa_expired, ica], DOCUMENT, serial=1010, sig="rsa"),
         {"description": "The signer's certificate expired before the time the token states", "roots": roots,
          "outcome": "invalid", "failing": ["rfc3161.validity"]})
    # Revocation lists from the issuing CA (over the RSA authority, serial 101) and the root.
    crl_dir = out / "crl"
    crl_dir.mkdir(parents=True, exist_ok=True)

    def crl(issuer_cn: str, key, this_update: dt.datetime, revoked: list[tuple[int, dt.datetime, x509.ReasonFlags]] = ()) -> bytes:
        b = (x509.CertificateRevocationListBuilder().issuer_name(name(issuer_cn))
             .last_update(this_update).next_update(this_update + dt.timedelta(days=30)))
        for serial, when, reason in revoked:
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when)
                                          .add_extension(x509.CRLReason(reason), critical=False).build())
        return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    after = dt.datetime(2026, 10, 20, tzinfo=dt.timezone.utc)
    december = dt.datetime(2026, 12, 1, tzinfo=dt.timezone.utc)
    crls = {
        "root-clean.pem": crl("FM Verify Test Root CA", root_k, after),
        "ica-clean.pem": crl("FM Verify Test Issuing CA", ica_k, after),
        "ica-key-compromise.pem": crl("FM Verify Test Issuing CA", ica_k, december + dt.timedelta(days=1),
                                      [(101, december, x509.ReasonFlags.key_compromise)]),
        "ica-superseded-later.pem": crl("FM Verify Test Issuing CA", ica_k, december + dt.timedelta(days=1),
                                        [(101, december, x509.ReasonFlags.superseded)]),
        "ica-revoked-before.pem": crl("FM Verify Test Issuing CA", ica_k, dt.datetime(2026, 9, 2, tzinfo=dt.timezone.utc),
                                      [(101, dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc), x509.ReasonFlags.superseded)]),
        "ica-stale.pem": crl("FM Verify Test Issuing CA", ica_k, dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)),
        "ica-forged.pem": crl("FM Verify Test Issuing CA", other_k, after),
    }
    for fname, data in crls.items():
        (crl_dir / fname).write_bytes(data)

    def crl_case(name: str, files: list[str], expected: dict) -> None:
        case(name, rsa_tok, {"roots": roots, "crls": [f"../crl/{f}" for f in files], **expected})

    crl_case("crl-clean", ["root-clean.pem", "ica-clean.pem"],
             {"description": "Fresh CRLs from the root and the issuing CA list nothing", "outcome": "valid"})
    crl_case("crl-key-compromise", ["root-clean.pem", "ica-key-compromise.pem"],
             {"description": "The authority's certificate was revoked for key compromise after the token's time",
              "outcome": "invalid", "failing": ["rfc3161.revocation"]})
    crl_case("crl-superseded-later", ["root-clean.pem", "ica-superseded-later.pem"],
             {"description": "The authority's certificate was superseded after the token's time", "outcome": "valid"})
    crl_case("crl-revoked-before", ["root-clean.pem", "ica-revoked-before.pem"],
             {"description": "The authority's certificate was revoked before the token's time", "outcome": "invalid",
              "failing": ["rfc3161.revocation"]})
    crl_case("crl-stale", ["root-clean.pem", "ica-stale.pem"],
             {"description": "The issuing CA's CRL predates the token: it cannot show the status then", "outcome": "valid"})
    crl_case("crl-forged", ["root-clean.pem", "ica-forged.pem"],
             {"description": "A CRL carrying the issuing CA's name but signed by another key", "outcome": "valid",
              "warning": ["rfc3161.crl"]})

    case("rejected", rejection(), {"description": "The authority refused the request", "roots": roots,
                                   "outcome": "invalid", "failing": ["rfc3161.parse"]})
