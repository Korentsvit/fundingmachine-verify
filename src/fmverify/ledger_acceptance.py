"""When the ledger accepted an event: an acceptance proof (ledger-acceptance/v0).

The Provenance Ledger's docs/ANCHORING.md, "Acceptance records", and its
src/acceptance.ts (its main, 20 October 2026). For one tenant and one UTC
hour, beside the hour's ledger-root/v0 record, the acceptance record binds
the time the ledger accepted each event, by its own clock:

* leaves: ``SHA-256(0x00 || event_hash || received_at)``, the event hash as
  its 32 bytes and ``received_at`` as UTF-8, UTC with microseconds and ``Z``,
  in the order the ledger accepted the events;
* ``accepted_root``: the RFC 9162 root over them, ``size`` their number;
* ``root_record``: SHA-256(JCS(the hour's root record, with its sig));
* ``sig``: the tenant's Ed25519 signature of the UTF-8 bytes of
  ``"ledger-acceptance/v0:" + SHA-256(JCS(record without sig))``;
  ``key_id`` is the SHA-256 of the raw public key.

The hour's anchored tree holds SHA-256(JCS(record)) of each tenant's root
record, each followed by that of its acceptance record. A proof is what
``GET /api/acceptance?event_hash=`` answers the tenant: the event's time,
the hour's acceptance record, the event's leaf index and audit path, and the
record's leaf index and audit path in the anchored tree with its root. The
anchored root's proofs are public: ``GET /api/anchors?hour=`` answers them.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import re
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, merkle, ots, rfc3161
from .base58 import EncodingError, b64url_decode
from .bitcoin import MAINNET, HeaderSource, Network
from .hashes import sha256
from .verdict import Check, Outcome, Status, Verdict, guarded, make_verdict, summarize, utc, whole_number

CONTRACT = "ledger-acceptance/v0"
RECORD_FIELDS = {"contract", "tenant_id", "window", "size", "root_record", "accepted_root", "key_id", "sig"}
PROOF_FIELDS = {"event_hash", "received_at", "record", "leaf_index", "audit_path", "anchor"}
ANCHOR_FIELDS = {"root", "size", "leaf_index", "audit_path"}
ROOT_FIELDS = {"contract", "tenant_id", "window", "size", "root", "prev_root", "key_id", "sig"}
RECEIVED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
HOUR = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00:00\.000Z")
TENANT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SIG = re.compile(r"[A-Za-z0-9_-]{86}")
LIMITS = [
    "that the ledger's clock was right: the acceptance time is the ledger's own, from its database",
    "which document the event belongs to: the event's own chain ties its hash to a document",
    "who holds the tenant key: the key is the caller's evidence",
    "who wrote the document, or how, or that its content is true, original, or free of AI assistance",
]


class AcceptanceError(ValueError):
    pass


def record_hash(record: dict) -> str:
    """The hash that names a signed acceptance record: its leaf in the hour's anchored tree."""
    return sha256(jcs.dumps(record)).hex()


def acceptance_leaf(event_hash: str, received_at: str) -> bytes:
    """The leaf data of one event: its hash's 32 bytes, then the acceptance time's UTF-8 bytes."""
    return bytes.fromhex(event_hash) + received_at.encode("utf-8")


def _instant(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=_dt.timezone.utc)


def _form(proof: Any) -> list[str]:
    """What is wrong with the proof's shape, the acceptance record's included; empty when it is well formed."""
    if not isinstance(proof, dict):
        return ["the proof is not a JSON object"]
    problems = []
    if set(proof) != PROOF_FIELDS:
        missing, extra = sorted(PROOF_FIELDS - set(proof)), sorted(set(proof) - PROOF_FIELDS)
        problems.append("the proof's fields are not those of GET /api/acceptance"
                        + (f": missing {', '.join(missing)}" if missing else "") + (f"; unknown {', '.join(extra)}" if extra else ""))
        return problems
    if not isinstance(proof["event_hash"], str) or not HEX64.fullmatch(proof["event_hash"]):
        problems.append("event_hash is not 64 lowercase hexadecimal characters")
    at = proof["received_at"]
    if not isinstance(at, str) or not RECEIVED_AT.fullmatch(at):
        problems.append(f"received_at {at!r} is not UTC with microseconds and Z, as the record binds it")
    else:
        try:
            _instant(at)
        except ValueError:
            problems.append(f"received_at {at!r} is no real instant")
    rec = proof["record"]
    if rec is None:
        return problems
    if not isinstance(rec, dict) or set(rec) != RECORD_FIELDS:
        return problems + [f"the record is not a {CONTRACT} record: its fields are not the contract's"]
    if rec["contract"] != CONTRACT:
        problems.append(f"the record's contract is {rec['contract']!r}, not {CONTRACT}")
    if not isinstance(rec["tenant_id"], str) or not TENANT.fullmatch(rec["tenant_id"]):
        problems.append("the record's tenant_id is not a tenant identifier")
    w = rec["window"]
    if not isinstance(w, dict) or set(w) != {"start", "end"} or not all(isinstance(w[k], str) and HOUR.fullmatch(w[k]) for k in w):
        problems.append("the record's window is not two whole UTC hours, start and end")
    else:
        try:
            if _instant(w["end"]) - _instant(w["start"]) != _dt.timedelta(hours=1):
                problems.append("the record's window is not one hour")
        except ValueError:
            problems.append("the record's window names no real hour")
    try:
        size = whole_number(rec["size"], "the record's size", 1)
    except ValueError as exc:
        problems.append(str(exc))
        size = None
    for k in ("root_record", "accepted_root", "key_id"):
        if not isinstance(rec[k], str) or not HEX64.fullmatch(rec[k]):
            problems.append(f"the record's {k} is not 64 lowercase hexadecimal characters")
    if not isinstance(rec["sig"], str) or not SIG.fullmatch(rec["sig"]):
        problems.append("the record's sig is not 64 bytes in base64url")
    try:
        index = whole_number(proof["leaf_index"], "leaf_index")
        if size is not None and index >= size:
            problems.append(f"leaf_index {index} is not below the record's size {size}")
    except ValueError as exc:
        problems.append(str(exc))
    if not isinstance(proof["audit_path"], list) or not all(isinstance(h, str) and HEX64.fullmatch(h) for h in proof["audit_path"]):
        problems.append("audit_path is not a list of 64-character hexadecimal hashes")
    a = proof["anchor"]
    if a is not None:
        if not isinstance(a, dict) or set(a) != ANCHOR_FIELDS:
            problems.append("the anchor is not root, size, leaf_index and audit_path")
        else:
            if not isinstance(a["root"], str) or not HEX64.fullmatch(a["root"]):
                problems.append("the anchor's root is not 64 lowercase hexadecimal characters")
            try:
                if whole_number(a["leaf_index"], "the anchor's leaf_index") >= whole_number(a["size"], "the anchor's size", 1):
                    problems.append("the anchor's leaf_index is not below its size")
            except ValueError as exc:
                problems.append(str(exc))
            if not isinstance(a["audit_path"], list) or not all(isinstance(h, str) and HEX64.fullmatch(h) for h in a["audit_path"]):
                problems.append("the anchor's audit_path is not a list of 64-character hexadecimal hashes")
    return problems


def _signed(rec: dict, prefix: str, public_key: bytes) -> bool:
    try:
        unsigned = {k: v for k, v in rec.items() if k != "sig"}
        Ed25519PublicKey.from_public_bytes(public_key).verify(b64url_decode(rec["sig"]), (prefix + record_hash(unsigned)).encode())
        return True
    except (InvalidSignature, EncodingError, ValueError):
        return False


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise AcceptanceError("not a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AcceptanceError(f"not base64: {exc}") from exc


def _root_record_check(rec: dict, root_record: Any, public_key: bytes | None) -> Check:
    if root_record is None:
        return Check("acceptance.root_record", Status.NOT_CHECKED, "the hour's root record was not given",
                     reasons=["pass the hour's ledger-root/v0 record (a certificate of the hour carries it) to compare it with "
                              "the record's root_record"], required=False)
    problems = []
    if not isinstance(root_record, dict) or set(root_record) != ROOT_FIELDS or root_record.get("contract") != "ledger-root/v0":
        return Check("acceptance.root_record", Status.FAIL, "the root record given is not a ledger-root/v0 record")
    got = record_hash(root_record)
    if got != rec["root_record"]:
        problems.append(f"the root record given hashes to {got}, the acceptance record names {rec['root_record']}")
    if root_record["tenant_id"] != rec["tenant_id"] or root_record["window"] != rec["window"]:
        problems.append("the root record is for another tenant or hour")
    if root_record["size"] != rec["size"]:
        problems.append(f"the root record holds {root_record['size']} events, the acceptance record {rec['size']}: "
                        "both hold the hour's events, in the same order")
    if public_key is not None and not (root_record["key_id"] == sha256(public_key).hex() and _signed(root_record, "ledger-root/v0:", public_key)):
        problems.append("the root record is not signed by the tenant key")
    if problems:
        return Check("acceptance.root_record", Status.FAIL, "the acceptance record is not the one of this root record", reasons=problems)
    return Check("acceptance.root_record", Status.PASS,
                 f"the acceptance record names the hour's root record {got} (root {root_record['root']}, {root_record['size']} events)"
                 + (", signed by the tenant key" if public_key is not None else ""),
                 data={"root": root_record["root"]})


def _hour_checks(anchor: dict, rec: dict, received_at: str, hour: dict, checks: list[Check], header_sources, network, roots,
                 extra_certs, crls, checked_at) -> tuple[str, list[str]]:
    """The anchored root's public proofs: the RFC 3161 tokens and the OpenTimestamps proof the hour's public record holds."""
    problems = []
    if not isinstance(hour, dict):
        checks.append(Check("acceptance.hour", Status.FAIL, "the hour's record is not a JSON object"))
        return "", []
    try:
        same_hour = _dt.datetime.fromisoformat(str(hour.get("window_start")).replace("Z", "+00:00")) == _instant(rec["window"]["start"])
    except ValueError:
        same_hour = False
    if not same_hour:
        problems.append(f"the hour's record is for {hour.get('window_start')!r}, the acceptance record for {rec['window']['start']}")
    if hour.get("root") != anchor["root"] or hour.get("size") != anchor["size"]:
        problems.append(f"the hour's record names root {hour.get('root')} of {hour.get('size')}, "
                        f"the proof {anchor['root']} of {anchor['size']}")
    if problems:
        checks.append(Check("acceptance.hour", Status.FAIL, "the hour's public record is not the anchor of this proof", reasons=problems))
        return "", []
    checks.append(Check("acceptance.hour", Status.PASS, f"the hour's public record names the same anchored root {anchor['root']}"))
    anchor_root = bytes.fromhex(anchor["root"])
    subs: list[tuple[str, str, Verdict, list[Check]]] = []
    times: list[str] = []
    for i, t in enumerate(hour.get("rfc3161") or []):
        extra: list[Check] = []
        try:
            v = rfc3161.verify(_b64(t.get("token_b64")), digest=anchor_root, roots=roots, extra_certs=extra_certs, crls=crls,
                               subject=f"anchored root {anchor['root']}", checked_at=checked_at)
        except AcceptanceError as exc:
            checks.append(Check(f"acceptance.rfc3161.{i}", Status.FAIL, f"RFC 3161 token {i} cannot be decoded", reasons=[str(exc)]))
            continue
        actual = next((c.data.get("gen_time") for c in v.checks if c.id == "rfc3161.parse" and c.status is Status.PASS), None)
        stated = t.get("gen_time")
        if actual is not None and stated is not None and not _same_instant(stated, actual):
            extra.append(Check(f"acceptance.rfc3161.{i}.gen_time", Status.FAIL,
                               f"the hour's record states {stated} for {t.get('authority')}, the token says {actual}"))
        if v.outcome is Outcome.VALID and actual is not None:
            times.append(actual)
        subs.append((f"acceptance.rfc3161.{i}", f"the RFC 3161 token of {t.get('authority')}", v, extra))
    if hour.get("opentimestamps_b64"):
        try:
            proof_bytes = _b64(hour["opentimestamps_b64"])
            v = ots.verify(proof_bytes, header_sources, digest=anchor_root, network=network,
                           subject=f"anchored root {anchor['root']}", checked_at=checked_at)
            subs.append(("acceptance.opentimestamps", "the OpenTimestamps proof", v, _bitcoin_summary(hour.get("bitcoin"), proof_bytes)))
        except AcceptanceError as exc:
            checks.append(Check("acceptance.opentimestamps", Status.FAIL, "the OpenTimestamps proof cannot be decoded", reasons=[str(exc)]))
    def holds(v: Verdict, extra: list[Check]) -> bool:
        return v.outcome is Outcome.VALID and not any(c.status is Status.FAIL for c in extra)

    valid = sum(1 for _, _, v, extra in subs if holds(v, extra))
    for cid, what, v, extra in subs:
        checks.append(summarize(v, cid, what, valid))
        checks.extend(extra)
    if not subs:
        checks.append(Check("acceptance.anchor", Status.NOT_CHECKED, "the hour's record carries no proof", required=False))
    early = [t for t in times if _parse(t) < _instant(received_at)]
    if early:
        checks.append(Check("acceptance.order", Status.FAIL, "an authority stamped the anchored root before the stated acceptance time",
                            reasons=[f"a token's time {t} is before {received_at}: the root cannot bind a time that came later" for t in early]))
    elif times:
        checks.append(Check("acceptance.order", Status.PASS, f"every authority stamped the anchored root after the acceptance time {received_at}"))
    return " ".join(v.statement for _, _, v, extra in subs if holds(v, extra)), times


def _bitcoin_summary(stated: Any, proof_bytes: bytes) -> list[Check]:
    """The hour's record summarises its OpenTimestamps proof (the Ledger's bitcoinStatus): a summary that says
    otherwise than the proof is a warning. The verdict rests on the proof, never on the summary."""
    if stated is None:
        return []
    try:
        found = list(ots.leaves(ots.parse(proof_bytes).timestamp))
    except (ots.OtsError, ValueError):
        return []
    held = sorted((l.attestation.height, l.commitment[::-1].hex()) for l in found if l.attestation.kind == "bitcoin")
    calendars = sorted({l.attestation.uri for l in found if l.attestation.kind == "pending"})
    want = {"status": "attested" if held else "pending", "attestations": [{"height": h, "merkle_root": m} for h, m in held],
            "pending_calendars": calendars}
    ok = isinstance(stated, dict) and set(stated) == set(want) and stated["status"] == want["status"] \
        and isinstance(stated["attestations"], list) and isinstance(stated["pending_calendars"], list) \
        and sorted(json_key(a) for a in stated["attestations"]) == sorted(json_key(a) for a in want["attestations"]) \
        and sorted(map(str, stated["pending_calendars"])) == calendars
    if ok:
        return []
    return [Check("acceptance.hour.bitcoin", Status.WARN, "the hour's record summarises its OpenTimestamps proof otherwise than the proof",
                  reasons=[f"it states {stated!r}", f"the proof holds {want!r}", "the verdict rests on the proof, not on the summary"])]


def json_key(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True)


def _parse(s: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _same_instant(a: str, b: str) -> bool:
    try:
        return _parse(a) == _parse(b)
    except ValueError:
        return a == b


@guarded("ledger-acceptance", "acceptance.form", "acceptance proof", LIMITS)
def verify(
    proof: Any,
    public_key: bytes | None = None,
    root_record: dict | None = None,
    hour: dict | None = None,
    header_sources: Sequence[HeaderSource] = (),
    network: Network = MAINNET,
    roots: Sequence = (),
    extra_certs: Sequence = (),
    crls: Sequence = (),
    subject: str | None = None,
    checked_at: str | None = None,
) -> Verdict:
    """``proof`` is what GET /api/acceptance answers; ``public_key`` the
    tenant's raw Ed25519 key; ``root_record`` the hour's ledger-root/v0
    record; ``hour`` what GET /api/anchors?hour= answers for its hour."""
    subject = subject or (f"the acceptance of event {proof.get('event_hash')}" if isinstance(proof, dict) else "an acceptance proof")
    checks: list[Check] = []
    problems = _form(proof)
    if problems:
        checks.append(Check("acceptance.form", Status.FAIL, "the acceptance proof is malformed", reasons=problems))
        return make_verdict("ledger-acceptance", subject, checks,
                            {o: "The acceptance proof is malformed: see the failing check." for o in Outcome}, LIMITS, checked_at)
    event, at, rec = proof["event_hash"], proof["received_at"], proof["record"]
    checks.append(Check("acceptance.form", Status.PASS, f"a {CONTRACT} proof for event {event}, accepted at {at} by the ledger's clock"))
    if rec is None:
        checks.append(Check("acceptance.record", Status.NOT_CHECKED, "the proof carries no acceptance record for the event's hour",
                            reasons=["hours sealed before 20 October 2026 have root records only, and an hour not yet sealed has none yet: "
                                     "the time is the ledger's statement, bound by nothing"]))
        return make_verdict("ledger-acceptance", subject, checks,
                            {o: f"Nothing binds the time {at} the ledger states for event {event}: the proof carries no acceptance record."
                             for o in Outcome}, LIMITS, checked_at)

    # The tenant's signature.
    if public_key is None:
        checks.append(Check("acceptance.signature", Status.NOT_CHECKED, "no tenant key was given, so the record's signature was not checked",
                            reasons=["pass the tenant's public key (its did:key, which its certificates name)"]))
    elif rec["key_id"] != sha256(public_key).hex():
        checks.append(Check("acceptance.signature", Status.FAIL, "the record names another key than the one given",
                            reasons=[f"key_id {rec['key_id']}, the key given has {sha256(public_key).hex()}"]))
    elif not _signed(rec, CONTRACT + ":", public_key):
        checks.append(Check("acceptance.signature", Status.FAIL, "the record's signature does not verify with the tenant key"))
    else:
        checks.append(Check("acceptance.signature", Status.PASS, f"the acceptance record is signed by the tenant key {rec['key_id'][:16]}...",
                            relies_on=["the key given is the tenant's"]))

    # The event's time, inside the hour, as a leaf of the signed accepted_root.
    start, end = _instant(rec["window"]["start"]), _instant(rec["window"]["end"])
    if start <= _instant(at) < end:
        checks.append(Check("acceptance.window", Status.PASS, f"{at} falls in the record's hour, from {rec['window']['start']}"))
    else:
        checks.append(Check("acceptance.window", Status.FAIL, f"{at} is outside the record's hour {rec['window']['start']} to {rec['window']['end']}",
                            reasons=["every event's acceptance time falls inside its root's window (docs/ANCHORING.md)"]))
    try:
        got = merkle.root_from_inclusion(merkle.leaf_hash(acceptance_leaf(event, at)), proof["leaf_index"], rec["size"],
                                         [bytes.fromhex(h) for h in proof["audit_path"]])
        reason = None if got.hex() == rec["accepted_root"] else f"the path gives {got.hex()}, not the signed accepted_root {rec['accepted_root']}"
    except merkle.ProofError as exc:
        reason = str(exc)
    if reason:
        checks.append(Check("acceptance.inclusion", Status.FAIL, "the event at this time is not a leaf of the record's accepted_root",
                            reasons=[reason, "a time changed after the hour was sealed no longer hashes to the signed root"]))
    else:
        checks.append(Check("acceptance.inclusion", Status.PASS,
                            f"event {event} at {at} is leaf {proof['leaf_index']} of the {rec['size']} under accepted_root {rec['accepted_root']}"))

    checks.append(_root_record_check(rec, root_record, public_key))

    # The record as a leaf of the hour's anchored tree, and that tree's proofs.
    anchor, anchored, times = proof["anchor"], "", []
    if anchor is None:
        checks.append(Check("acceptance.anchor_inclusion", Status.NOT_CHECKED, "the proof names no anchored root: the hour is not anchored yet",
                            reasons=["a later answer carries the anchor"], required=False))
    else:
        try:
            got = merkle.root_from_inclusion(merkle.leaf_hash(bytes.fromhex(record_hash(rec))), anchor["leaf_index"], anchor["size"],
                                             [bytes.fromhex(h) for h in anchor["audit_path"]])
            reason = None if got.hex() == anchor["root"] else f"the path gives {got.hex()}, not the anchored root {anchor['root']}"
        except merkle.ProofError as exc:
            reason = str(exc)
        if reason:
            checks.append(Check("acceptance.anchor_inclusion", Status.FAIL, "the acceptance record is not shown to be under the anchored root",
                                reasons=[reason]))
            anchor = None
        else:
            checks.append(Check("acceptance.anchor_inclusion", Status.PASS,
                                f"the acceptance record {record_hash(rec)} is leaf {anchor['leaf_index']} of the {anchor['size']} "
                                f"under the anchored root {anchor['root']}"))
            if hour is None:
                checks.append(Check("acceptance.hour", Status.NOT_CHECKED, "the anchored root's proofs were not given",
                                    reasons=[f"pass the hour's public record (GET /api/anchors?hour={rec['window']['start']})"], required=False))
            else:
                anchored, times = _hour_checks(anchor, rec, at, hour, checks, header_sources, network, roots, extra_certs, crls, checked_at)

    valid_statement = (f"The acceptance record of tenant {rec['tenant_id']} for the hour from {rec['window']['start']}, signed by the "
                       f"tenant key, binds event {event} to {at}, the time the ledger accepted it by its own clock "
                       f"(leaf {proof['leaf_index']} of {rec['size']}).")
    if anchor is None:
        valid_statement += " Nothing anchors the record in this proof."
    elif not anchored:
        valid_statement += (f" The record is under the anchored root {anchor['root']}, whose proofs were not checked here.")
    else:
        valid_statement += f" The record is under the anchored root {anchor['root']}. {anchored}"
        if times:
            valid_statement += f" So the ledger stated this time no later than {utc(min(_parse(t) for t in times))}."
    statements = {
        Outcome.VALID: valid_statement,
        Outcome.INVALID: "The acceptance proof does not hold: see the failing checks.",
        Outcome.INDETERMINATE: f"The time {at} for event {event} could not be checked against a signed record: see the checks not run.",
    }
    return make_verdict("ledger-acceptance", subject, checks, statements, LIMITS, checked_at)
