"""A tenant's hourly root records (ledger-root/v0) as a chain of their own.

docs/ANCHORING.md: each record's ``prev_root`` is SHA-256(JCS(previous
record, with its sig)), 64 zeros for the first, "so a tenant's roots form a
chain of their own and an hour cannot be dropped unnoticed"; each record is
signed with the tenant's Ed25519 key: the signature covers the UTF-8 bytes of
``"ledger-root/v0:" + SHA-256(JCS(record without sig))``, and ``key_id`` is
the SHA-256 of the raw public key. An hour with no events has no record, so
windows increase but need not be consecutive.
"""

from __future__ import annotations

import datetime as _dt

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs
from .base58 import EncodingError, b64url_decode
from .hashes import sha256
from .verdict import Check, Outcome, Status, guarded, make_verdict

ZERO = "0" * 64
FIELDS = {"contract", "tenant_id", "window", "size", "root", "prev_root", "key_id", "sig"}
LIMITS = [
    "that the records cover every event the ledger accepted: a record states its own size and root",
    "that the hours before the first record given were not dropped, unless the first record's prev_root is 64 zeros",
    "who holds the tenant key: the key is the caller's evidence",
]


def record_hash(record: dict) -> str:
    return sha256(jcs.dumps(record)).hex()


def _time(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)


@guarded("root-chain", "roots.records", "root record chain", LIMITS)
def verify(records: list, public_key: bytes | None = None, subject: str | None = None, checked_at: str | None = None):
    """``public_key`` is the tenant's raw Ed25519 key (from its did:key);
    without it the signatures cannot be checked."""
    checks: list[Check] = []
    subject = subject or f"{len(records)} hourly root records"
    problems: list[str] = []
    tenant = records[0].get("tenant_id") if records and isinstance(records[0], dict) else None
    prev = None
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or set(rec) != FIELDS or rec.get("contract") != "ledger-root/v0":
            problems.append(f"record {i} is not a ledger-root/v0 record")
            break
        if rec["tenant_id"] != tenant:
            problems.append(f"record {i} is for tenant {rec['tenant_id']!r}, the chain for {tenant!r}")
        start, end = _time(rec["window"]["start"]), _time(rec["window"]["end"])
        if end - start != _dt.timedelta(hours=1) or start.minute or start.second or start.microsecond:
            problems.append(f"record {i}'s window is not one whole UTC hour")
        want_prev = record_hash(prev) if prev is not None else None
        if prev is None:
            if rec["prev_root"] != ZERO:
                checks.append(Check("roots.start", Status.INFO,
                                    "the first record given is not the tenant's first: earlier records were not given", required=False))
        else:
            if rec["prev_root"] != want_prev:
                problems.append(f"record {i}'s prev_root is not the hash of record {i - 1}: a record between them is missing, or one was changed")
            if start <= _time(prev["window"]["start"]):
                problems.append(f"record {i}'s hour is not after record {i - 1}'s")
        prev = rec
    if problems:
        checks.append(Check("roots.links", Status.FAIL, "the records do not form an unbroken chain", reasons=problems))
    else:
        checks.append(Check("roots.links", Status.PASS,
                            f"{len(records)} records link one to the next by prev_root, each for a later hour, one tenant throughout",
                            data={"first": records[0]["window"]["start"] if records else None,
                                  "last": records[-1]["window"]["start"] if records else None}))
    if public_key is None:
        checks.append(Check("roots.signatures", Status.NOT_CHECKED, "no tenant key was given, so the signatures were not checked",
                            reasons=["pass the tenant's public key (its did:key)"]))
    elif not problems or all(isinstance(r, dict) and set(r) == FIELDS for r in records):
        key_id = sha256(public_key).hex()
        bad = []
        for i, rec in enumerate(records):
            if rec["key_id"] != key_id:
                bad.append(f"record {i} names key {rec['key_id'][:16]}..., not the key given")
                continue
            try:
                sig = b64url_decode(rec["sig"])
                unsigned = {k: v for k, v in rec.items() if k != "sig"}
                Ed25519PublicKey.from_public_bytes(public_key).verify(sig, ("ledger-root/v0:" + record_hash(unsigned)).encode())
            except (InvalidSignature, EncodingError, ValueError):
                bad.append(f"record {i}'s signature does not verify")
        if bad:
            checks.append(Check("roots.signatures", Status.FAIL, "a record is not signed by the tenant key", reasons=bad))
        else:
            checks.append(Check("roots.signatures", Status.PASS, f"all {len(records)} records are signed by the tenant key",
                                relies_on=["the key given is the tenant's"]))
    statements = {
        Outcome.VALID: (f"The {len(records)} hourly root records of tenant {tenant} form an unbroken chain signed by the tenant key"
                        + (f", from the hour of {records[0]['window']['start']} to that of {records[-1]['window']['start']}." if records else ".")),
        Outcome.INVALID: "The root records do not form an unbroken, signed chain: see the failing checks.",
        Outcome.INDETERMINATE: "The root records link, but their signatures were not checked.",
    }
    return make_verdict("root-chain", subject, checks, statements, LIMITS, checked_at)
