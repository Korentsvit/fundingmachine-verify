"""Provenance Ledger certificates, contract ledger-certificate/v0.

Written from the Provenance Ledger session's published documents
(fundingmachine-ledger: docs/CERTIFICATE.md, docs/ANCHORING.md,
docs/AUTHORSHIP_MAP.md and the JSON Schemas, read 16 October 2026), not from
its code. The steps are the document's, reported one by one, and a verdict
never claims more than the steps it ran:

1. the Data Integrity proof (eddsa-jcs-2022) under the issuer's did:key;
2. the scope statement, word for word;
3. the exported file, when given: SHA-256 and size;
4. the hourly root record's signature under the issuer key;
5. the sign event's inclusion in that root (RFC 9162);
6. the anchor: the record's inclusion in the anchored root, each RFC 3161
   token, and the OpenTimestamps proof;
7. the event chain and the authorship map: not run by this version.

Two checks are added: the authorship percentages must follow from the counts
by the document's rounding rule, and fields this verifier does not
understand are reported, never ignored silently.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, merkle, ots, rfc3161
from .base58 import EncodingError, b64url_decode, did_key_ed25519, multibase_decode
from .bitcoin import MAINNET, HeaderSource, Network
from .hashes import sha256
from .verdict import Check, Outcome, Status, Verdict, make_verdict

CONTRACT = "ledger-certificate/v0"
SCOPE_STATEMENT = ("This record shows how this document was written in this environment; it does not detect AI, "
                   "certify originality, or prove what the author consulted elsewhere.")
ORIGINS = ["human_typed", "imported", "tool_generated", "tool_edited"]
FIDELITIES = ["live", "snapshot_diff", "tool_report", "reconstructed", "declared"]

KNOWN = {
    "credential": {"@context", "id", "type", "issuer", "validFrom", "credentialSubject", "proof"},
    "subject": {"type", "contract", "scope_statement", "tenant_id", "doc_id", "document", "signed", "chain",
                "authorship", "tools", "evidence", "ledger_root"},
    "proof": {"type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "@context", "proofValue"},
    "ledger_root": {"record", "leaf_index", "audit_path", "anchor"},
    "record": {"contract", "tenant_id", "window", "size", "root", "prev_root", "key_id", "sig"},
    "anchor": {"contract", "root", "size", "leaf_index", "audit_path", "opentimestamps", "rfc3161"},
}

LIMITS = [
    "that the document was written by any particular person, or that it was not written with AI assistance elsewhere",
    "that the document's content is true, original, or what its author read elsewhere",
    "anything about writing outside this environment: the record shows how the document was written in it",
]


class CertificateError(ValueError):
    pass


def _ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def percentages(counts: dict[str, int], keys: list[str], total: int) -> dict[str, str]:
    """docs/AUTHORSHIP_MAP.md, Percentages: tenths of a percent, largest remainder, ties to the key listed first."""
    if total == 0:
        return {k: "0.0" for k in keys}
    floors = {k: counts[k] * 1000 // total for k in keys}
    remainders = {k: counts[k] * 1000 - floors[k] * total for k in keys}
    left = 1000 - sum(floors.values())
    for k in sorted(keys, key=lambda k: (-remainders[k], keys.index(k)))[:left]:
        floors[k] += 1
    return {k: f"{floors[k] // 10}.{floors[k] % 10}" for k in keys}


def _unknown_fields(cred: dict) -> list[str]:
    out = []

    def extra(obj: Any, known: set, where: str) -> None:
        if isinstance(obj, dict):
            out.extend(f"{where}.{k}" for k in sorted(set(obj) - known))

    extra(cred, KNOWN["credential"], "credential")
    subj = cred.get("credentialSubject", {})
    extra(subj, KNOWN["subject"], "credentialSubject")
    extra(cred.get("proof"), KNOWN["proof"], "proof")
    lr = subj.get("ledger_root") if isinstance(subj, dict) else None
    if isinstance(lr, dict):
        extra(lr, KNOWN["ledger_root"], "ledger_root")
        extra(lr.get("record"), KNOWN["record"], "ledger_root.record")
        extra(lr.get("anchor"), KNOWN["anchor"], "ledger_root.anchor")
    return out


def _check_proof(cred: dict) -> tuple[Check, bytes | None]:
    proof = cred.get("proof")
    if not isinstance(proof, dict):
        return Check("certificate.proof", Status.FAIL, "the certificate carries no proof"), None
    problems = []
    if proof.get("type") != "DataIntegrityProof" or proof.get("cryptosuite") != "eddsa-jcs-2022":
        problems.append(f"proof type {proof.get('type')!r} / cryptosuite {proof.get('cryptosuite')!r}, not DataIntegrityProof / eddsa-jcs-2022")
    if proof.get("proofPurpose") != "assertionMethod":
        problems.append(f"proof purpose {proof.get('proofPurpose')!r}, not assertionMethod")
    issuer = cred.get("issuer", {}).get("id") if isinstance(cred.get("issuer"), dict) else None
    vm = proof.get("verificationMethod", "")
    did, _, fragment = vm.partition("#")
    if did != issuer:
        problems.append(f"the verification method's DID {did!r} is not the issuer {issuer!r}")
    if fragment != did[len("did:key:"):]:
        problems.append("the verification method's fragment is not the did:key's own key")
    ctx = proof.get("@context")
    if ctx is not None and (not isinstance(ctx, list) or cred.get("@context", [])[: len(ctx)] != ctx):
        problems.append("the proof's @context is not a prefix of the credential's")
    try:
        public = did_key_ed25519(did)
    except EncodingError as exc:
        problems.append(str(exc))
        public = None
    if problems:
        return Check("certificate.proof", Status.FAIL, "the proof is not a well-formed eddsa-jcs-2022 proof by the issuer", reasons=problems), None
    try:
        signature = multibase_decode(proof.get("proofValue", ""))
    except EncodingError as exc:
        return Check("certificate.proof", Status.FAIL, "the proof value cannot be decoded", reasons=[str(exc)]), None
    unsecured = {k: v for k, v in cred.items() if k != "proof"}
    config = {k: v for k, v in proof.items() if k != "proofValue"}
    hash_data = sha256(jcs.dumps(config)) + sha256(jcs.dumps(unsecured))
    if len(signature) != 64 or not _ed25519_verify(public, signature, hash_data):
        return Check("certificate.proof", Status.FAIL, "the issuer's signature over the certificate does not verify",
                     reasons=["the certificate or its proof was changed after signing, or was signed by another key"]), None
    return Check("certificate.proof", Status.PASS, f"signed by {issuer} (eddsa-jcs-2022), created {proof.get('created')}",
                 relies_on=[f"{issuer} is the tenant's signing key: the certificate names it, nothing outside it vouches for it"],
                 data={"issuer": issuer, "public_key": public.hex(), "created": proof.get("created")}), public


def _check_authorship(subj: dict) -> Check:
    a = subj.get("authorship") or {}
    problems = []

    def one(block: dict, keys: list[str], where: str) -> None:
        counts, total = block.get("counts", {}), block.get("total")
        if set(counts) != set(keys) or sum(counts.values()) != total:
            problems.append(f"{where}: the counts do not add up to the total {total}")
            return
        want = percentages(counts, keys, total)
        if block.get("percent") != want:
            problems.append(f"{where}: percent {block.get('percent')} where the counts give {want}")

    try:
        one(a["document"], ORIGINS, "document")
        one(a["fidelity"], FIDELITIES, "fidelity")
        for s in a.get("sections", []):
            one(s, ORIGINS, f"section {s.get('section_id')}")
        if sum(s["total"] for s in a.get("sections", [])) != a["document"]["total"]:
            problems.append("the sections' totals do not add up to the document's")
        if a["fidelity"]["total"] != a["document"]["total"]:
            problems.append("the fidelity total differs from the document total")
    except (KeyError, TypeError, AttributeError) as exc:
        problems.append(f"the authorship block is missing a field: {exc}")
    if problems:
        return Check("certificate.authorship_arithmetic", Status.FAIL, "the authorship figures contradict each other", reasons=problems)
    d = a["document"]
    return Check("certificate.authorship_arithmetic", Status.PASS,
                 "the authorship counts add up and every percentage follows from its counts (docs/AUTHORSHIP_MAP.md rounding)",
                 data={"document": d, "map_sha256": a.get("map_sha256")})


def _b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise CertificateError(f"not base64: {exc}") from exc


def _summarize(sub: Verdict, cid: str, what: str, others_valid: int) -> Check:
    if sub.outcome is Outcome.VALID:
        return Check(cid, Status.PASS, sub.statement, relies_on=sub.relies_on, data={"verdict": sub.to_dict()})
    if sub.outcome is Outcome.INVALID:
        return Check(cid, Status.FAIL, f"{what} does not hold",
                     reasons=[f"{c.id}: {c.summary}" for c in sub.checks if c.status is Status.FAIL], data={"verdict": sub.to_dict()})
    return Check(cid, Status.NOT_CHECKED, f"{what} could not be checked: {sub.statement}",
                 reasons=[f"{c.id}: {c.summary}" for c in sub.checks if c.status is Status.NOT_CHECKED and c.required],
                 required=others_valid == 0, data={"verdict": sub.to_dict()})


def verify(
    cert_bytes: bytes,
    exported_file: bytes | None = None,
    header_sources: Sequence[HeaderSource] = (),
    network: Network = MAINNET,
    roots=(),
    extra_certs=(),
    crls=(),
    subject: str | None = None,
    checked_at: str | None = None,
) -> Verdict:
    checks: list[Check] = []
    bad = {o: "The certificate does not hold: see the failing checks." for o in Outcome}
    try:
        cred = jcs.loads(cert_bytes)
        if not isinstance(cred, dict) or not isinstance(cred.get("credentialSubject"), dict):
            raise CertificateError("not a credential with a credentialSubject")
    except (jcs.JcsError, CertificateError, UnicodeDecodeError) as exc:
        checks.append(Check("certificate.parse", Status.FAIL, "the certificate could not be read", reasons=[str(exc)]))
        return make_verdict("certificate", subject or "certificate", checks, bad, LIMITS, checked_at)
    subj = cred["credentialSubject"]
    subject = subject or f"certificate {cred.get('id')} for document {subj.get('doc_id')}"

    if subj.get("contract") != CONTRACT:
        checks.append(Check("certificate.contract", Status.NOT_CHECKED, f"contract {subj.get('contract')!r} is not one this verifier knows",
                            reasons=[f"this version verifies {CONTRACT}; an unknown version is reported as not verified"]))
        return make_verdict("certificate", subject, checks,
                            {o: "The certificate is of a version this verifier does not know; it was not verified." for o in Outcome},
                            LIMITS, checked_at)
    checks.append(Check("certificate.contract", Status.PASS, f"contract {CONTRACT}"))
    unknown = _unknown_fields(cred)
    if unknown:
        checks.append(Check("certificate.unknown_fields", Status.WARN, "fields this verifier does not understand: they are signed, but not checked",
                            reasons=unknown))

    # 1. Proof.
    proof_check, public = _check_proof(cred)
    checks.append(proof_check)

    # 2. Scope statement.
    if subj.get("scope_statement") == SCOPE_STATEMENT:
        checks.append(Check("certificate.scope_statement", Status.PASS, "the scope statement is present word for word"))
    else:
        checks.append(Check("certificate.scope_statement", Status.FAIL, "the scope statement is missing or altered",
                            reasons=[f"expected: {SCOPE_STATEMENT}", f"found: {subj.get('scope_statement')!r}"]))

    # Added: the authorship figures are internally consistent.
    checks.append(_check_authorship(subj))

    # 3. The exported file.
    doc = subj.get("document") or {}
    if exported_file is not None:
        actual = sha256(exported_file).hex()
        if actual == doc.get("exported_sha256") and len(exported_file) == doc.get("byte_length"):
            checks.append(Check("certificate.file", Status.PASS, f"the file presented is the exported document: SHA-256 {actual}, {len(exported_file)} bytes"))
        else:
            checks.append(Check("certificate.file", Status.FAIL, "the file presented is not the exported document the certificate covers",
                                reasons=[f"file: SHA-256 {actual}, {len(exported_file)} bytes",
                                         f"certificate: SHA-256 {doc.get('exported_sha256')}, {doc.get('byte_length')} bytes"]))
    else:
        checks.append(Check("certificate.file", Status.NOT_CHECKED, "no exported file was presented",
                            reasons=["the verdict is about the certificate, not about any file you hold"], required=False))

    # 4 to 6. The hourly root and its anchor.
    lr = subj.get("ledger_root")
    anchored_statement = ""
    if lr is None:
        checks.append(Check("certificate.ledger_root", Status.NOT_CHECKED, "the certificate carries no hourly root yet",
                            reasons=["steps 4 to 6 (root signature, inclusion, anchor) cannot run"], required=False))
    elif public is not None:
        record = lr.get("record") or {}
        # 4. Root record signature.
        problems = []
        if record.get("contract") != "ledger-root/v0":
            problems.append(f"record contract {record.get('contract')!r}")
        if record.get("tenant_id") != subj.get("tenant_id"):
            problems.append("the record's tenant is not the certificate's")
        if record.get("key_id") != sha256(public).hex():
            problems.append("the record's key_id is not the SHA-256 of the issuer's public key")
        try:
            sig = b64url_decode(record.get("sig", ""))
        except EncodingError as exc:
            problems.append(f"record signature: {exc}")
            sig = b""
        unsigned = {k: v for k, v in record.items() if k != "sig"}
        message = ("ledger-root/v0:" + sha256(jcs.dumps(unsigned)).hex()).encode("utf-8")
        if not problems and not (len(sig) == 64 and _ed25519_verify(public, sig, message)):
            problems.append("the record's signature does not verify under the issuer key")
        if problems:
            checks.append(Check("certificate.root_record", Status.FAIL, "the hourly root record does not hold", reasons=problems))
        else:
            w = record.get("window", {})
            checks.append(Check("certificate.root_record", Status.PASS,
                                f"the issuer signed hourly root {record.get('root')} over {record.get('size')} events for {w.get('start')} to {w.get('end')}"))
        # 5. Inclusion of the sign event.
        signed = subj.get("signed") or {}
        try:
            computed = merkle.root_from_inclusion(merkle.leaf_hash(bytes.fromhex(signed["event_hash"])), int(lr["leaf_index"]),
                                                  int(record["size"]), [bytes.fromhex(h) for h in lr["audit_path"]])
            ok = computed.hex() == record.get("root")
            reason = None if ok else f"the path gives {computed.hex()}"
        except (KeyError, ValueError, TypeError) as exc:
            ok, reason = False, str(exc)
        if ok:
            checks.append(Check("certificate.inclusion", Status.PASS,
                                f"the sign event {signed.get('event_hash')} is leaf {lr['leaf_index']} of {record['size']} under that root"))
        else:
            checks.append(Check("certificate.inclusion", Status.FAIL, "the sign event is not shown to be under the hourly root", reasons=[reason]))
        # 6. The anchor.
        anchor = lr.get("anchor")
        if anchor is None:
            checks.append(Check("certificate.anchor", Status.NOT_CHECKED, "the hourly root is not anchored yet in this certificate",
                                reasons=["a later issue of the certificate carries the anchor"], required=False))
        else:
            anchored_statement = _check_anchor(anchor, record, checks, header_sources, network, roots, extra_certs, crls, checked_at)

    # 7. The chain.
    checks.append(Check("certificate.chain", Status.NOT_CHECKED, "the event chain and the authorship map were not checked",
                        reasons=["step 7 needs the events up to the sign event; this version of the verifier does not run it"],
                        required=False))

    signed = subj.get("signed") or {}
    file_part = (" The exported file presented is the one it covers." if exported_file is not None
                 else " No exported file was presented.")
    root_part = ""
    if lr is not None:
        root_part = (f" The sign event is in the issuer's signed hourly root {lr.get('record', {}).get('root')}"
                     + (f"; {anchored_statement}" if anchored_statement else "; that root is not anchored in this certificate") + ".")
    statements = {
        Outcome.VALID: (f"{cred.get('issuer', {}).get('id')} signed this record of how document {subj.get('doc_id')} "
                        f"(exported SHA-256 {doc.get('exported_sha256')}) was written in this environment, signed at event "
                        f"{signed.get('seq')} ({signed.get('event_hash')}) on {signed.get('ts')}.{root_part}{file_part} "
                        "The event chain itself was not checked."),
        Outcome.INVALID: "The certificate does not hold: see the failing checks.",
        Outcome.INDETERMINATE: "The certificate could not be fully checked: see the checks not run.",
    }
    return make_verdict("certificate", subject, checks, statements, LIMITS, checked_at)


def _check_anchor(anchor: dict, record: dict, checks: list[Check], header_sources, network, roots, extra_certs, crls,
                  checked_at) -> str:
    problems = []
    if anchor.get("contract") != "ledger-anchor/v0":
        problems.append(f"anchor contract {anchor.get('contract')!r}")
    try:
        anchor_root = bytes.fromhex(anchor["root"])
        leaf = sha256(jcs.dumps(record))
        computed = merkle.root_from_inclusion(merkle.leaf_hash(leaf), int(anchor["leaf_index"]), int(anchor["size"]),
                                              [bytes.fromhex(h) for h in anchor["audit_path"]])
        if computed != anchor_root:
            problems.append(f"the record's path gives {computed.hex()}, not the anchored root {anchor['root']}")
    except (KeyError, ValueError, TypeError) as exc:
        problems.append(f"the anchor is malformed: {exc}")
        anchor_root = None
    if problems:
        checks.append(Check("certificate.anchor_inclusion", Status.FAIL, "the hourly root record is not shown to be under the anchored root",
                            reasons=problems))
        return ""
    checks.append(Check("certificate.anchor_inclusion", Status.PASS,
                        f"the root record is leaf {anchor['leaf_index']} of {anchor['size']} under the anchored root {anchor['root']}"))
    subs: list[tuple[str, str, Verdict, list[Check]]] = []
    for i, t in enumerate(anchor.get("rfc3161", [])):
        extra: list[Check] = []
        try:
            v = rfc3161.verify(_b64(t.get("token_b64")), digest=anchor_root, roots=roots, extra_certs=extra_certs, crls=crls,
                               subject=f"anchored root {anchor['root']}", checked_at=checked_at)
        except CertificateError as exc:
            checks.append(Check(f"certificate.rfc3161.{i}", Status.FAIL, f"RFC 3161 token {i} cannot be decoded", reasons=[str(exc)]))
            continue
        stated = t.get("gen_time")
        actual = next((c.data.get("gen_time") for c in v.checks if c.id == "rfc3161.parse" and c.status is Status.PASS), None)
        if actual is not None and stated is not None and not _same_instant(stated, actual):
            extra.append(Check(f"certificate.rfc3161.{i}.gen_time", Status.FAIL,
                               f"the certificate states {stated} for {t.get('authority')}, the token says {actual}"))
        subs.append((f"certificate.rfc3161.{i}", f"the RFC 3161 token of {t.get('authority')}", v, extra))
    o = anchor.get("opentimestamps") or {}
    if o:
        extra = []
        try:
            v = ots.verify(_b64(o.get("proof_b64")), header_sources, digest=anchor_root, network=network,
                           subject=f"anchored root {anchor['root']}", checked_at=checked_at)
        except CertificateError as exc:
            checks.append(Check("certificate.opentimestamps", Status.FAIL, "the OpenTimestamps proof cannot be decoded", reasons=[str(exc)]))
            v = None
        if v is not None:
            heights = []
            try:
                heights = sorted(l.attestation.height for l in ots.leaves(ots.parse(_b64(o["proof_b64"])).timestamp)
                                 if l.attestation.kind == "bitcoin")
            except (ots.OtsError, CertificateError, KeyError):
                pass
            if o.get("status") == "bitcoin" and o.get("bitcoin_block") not in heights:
                extra.append(Check("certificate.opentimestamps.status", Status.FAIL,
                                   f"the certificate says the proof is in Bitcoin block {o.get('bitcoin_block')}, the proof holds {heights or 'no Bitcoin attestation'}"))
            subs.append(("certificate.opentimestamps", "the OpenTimestamps proof", v, extra))
    valid = sum(1 for _, _, v, extra in subs if v.outcome is Outcome.VALID and not extra)
    for cid, what, v, extra in subs:
        checks.append(_summarize(v, cid, what, valid))
        checks.extend(extra)
    if not subs:
        checks.append(Check("certificate.anchor", Status.NOT_CHECKED, "the anchor carries no proof"))
    return " ".join(v.statement for _, _, v, extra in subs if v.outcome is Outcome.VALID and not extra)


def _same_instant(a: str, b: str) -> bool:
    import datetime as dt

    def parse(s: str):
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))

    try:
        return parse(a) == parse(b)
    except ValueError:
        return a == b


def verify_file(cert_path: str | Path, exported_path: str | Path | None = None, **kwargs) -> Verdict:
    exported = Path(exported_path).read_bytes() if exported_path is not None else None
    return verify(Path(cert_path).read_bytes(), exported_file=exported, **kwargs)
