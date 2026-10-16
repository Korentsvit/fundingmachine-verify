"""OpenTimestamps proofs: parsing the detached ``.ots`` format and checking it
against Bitcoin block headers.

Written from the format as the reference client serializes it: a magic
header, major version 1, the file hash operation and digest, then a tree of
operations (append, prepend, hashes) ending in attestations. The parser keeps
the reference implementation's limits (messages and results of at most 4096
bytes, attestation payloads of at most 8192 bytes, depth at most 256) and
requires the input to end exactly where the proof ends.

The verifier never contacts a calendar server. A pending attestation is
reported as not yet anchored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence

from . import hashes
from .bitcoin import HeaderSource, Network, MAINNET, lookup_header
from .verdict import ANCHOR_LIMITS, Check, Outcome, Status, Verdict, guarded, make_verdict

HEADER_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
MAJOR_VERSION = 1
MAX_MSG = 4096
MAX_PAYLOAD = 8192
MAX_DEPTH = 256

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_LITECOIN = bytes.fromhex("06869a0d73d71b45")
URI_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")

# tag: (name, function, digest length for use as the file hash, weak)
_UNARY = {
    0x08: ("sha256", hashes.sha256, 32, False),
    0x02: ("sha1", hashes.sha1, 20, True),
    0x03: ("ripemd160", hashes.ripemd160, 20, False),
    0x67: ("keccak256", hashes.keccak256, 32, False),
    0xF2: ("reverse", lambda m: m[::-1], None, False),
    0xF3: ("hexlify", lambda m: m.hex().encode("ascii"), None, False),
}
_BINARY = {0xF0: "append", 0xF1: "prepend"}
_CRYPT = {0x08, 0x02, 0x03, 0x67}


class OtsError(ValueError):
    """A proof that is malformed or exceeds the format's limits."""


@dataclass(frozen=True)
class Op:
    tag: int
    arg: bytes | None = None

    @property
    def name(self) -> str:
        return _BINARY.get(self.tag) or _UNARY[self.tag][0]

    def apply(self, msg: bytes) -> bytes:
        if len(msg) > MAX_MSG:
            raise OtsError(f"message of {len(msg)} bytes exceeds {MAX_MSG}")
        if self.tag == 0xF0:
            out = msg + self.arg
        elif self.tag == 0xF1:
            out = self.arg + msg
        elif self.tag == 0xF2:
            if not msg:
                raise OtsError("cannot reverse an empty message")
            out = msg[::-1]
        elif self.tag == 0xF3:
            if not msg:
                raise OtsError("cannot hexlify an empty message")
            if len(msg) > MAX_MSG // 2:
                raise OtsError("message too long to hexlify")
            out = msg.hex().encode("ascii")
        else:
            out = _UNARY[self.tag][1](msg)
        if len(out) > MAX_MSG:
            raise OtsError(f"result of {len(out)} bytes exceeds {MAX_MSG}")
        return out

    def serialize(self) -> bytes:
        if self.tag in _BINARY:
            return bytes([self.tag]) + _varbytes(self.arg)
        return bytes([self.tag])

    def describe(self) -> str:
        if self.tag in _BINARY:
            return f"{self.name} {self.arg.hex()}"
        return self.name


@dataclass(frozen=True)
class Attestation:
    tag: bytes
    payload: bytes

    @property
    def kind(self) -> str:
        return {TAG_BITCOIN: "bitcoin", TAG_PENDING: "pending", TAG_LITECOIN: "litecoin"}.get(self.tag, "unknown")

    @property
    def height(self) -> int | None:
        if self.tag in (TAG_BITCOIN, TAG_LITECOIN):
            r = _Reader(self.payload)
            h = r.varuint()
            r.end()
            return h
        return None

    @property
    def uri(self) -> str | None:
        if self.tag == TAG_PENDING:
            r = _Reader(self.payload)
            u = r.varbytes(1000)
            r.end()
            return u.decode("ascii")
        return None

    def serialize(self) -> bytes:
        return self.tag + _varbytes(self.payload)

    def describe(self) -> str:
        if self.kind == "bitcoin":
            return f"Bitcoin block {self.height}"
        if self.kind == "pending":
            return f"pending at {self.uri}"
        if self.kind == "litecoin":
            return f"Litecoin block {self.height}"
        return f"unknown attestation {self.tag.hex()}"


@dataclass
class Timestamp:
    msg: bytes
    # Entries in the order the proof lists them: an Attestation, or (Op, Timestamp).
    entries: list = field(default_factory=list)

    def serialize(self) -> bytes:
        out = bytearray()
        for i, entry in enumerate(self.entries):
            if i < len(self.entries) - 1:
                out.append(0xFF)
            if isinstance(entry, Attestation):
                out.append(0x00)
                out += entry.serialize()
            else:
                op, child = entry
                out += op.serialize()
                out += child.serialize()
        return bytes(out)


@dataclass
class DetachedTimestamp:
    file_hash: Op
    timestamp: Timestamp

    @property
    def digest(self) -> bytes:
        return self.timestamp.msg

    def serialize(self) -> bytes:
        return HEADER_MAGIC + _varuint(MAJOR_VERSION) + self.file_hash.serialize() + self.timestamp.msg + self.timestamp.serialize()


def _varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _varbytes(b: bytes) -> bytes:
    return _varuint(len(b)) + b


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise OtsError(f"proof ends early: needed {n} bytes at offset {self.pos}")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.bytes(1)[0]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsError("variable-length integer longer than 64 bits")

    def varbytes(self, max_len: int, min_len: int = 0) -> bytes:
        n = self.varuint()
        if n > max_len:
            raise OtsError(f"length {n} exceeds {max_len}")
        if n < min_len:
            raise OtsError(f"length {n} below {min_len}")
        return self.bytes(n)

    def end(self) -> None:
        if self.pos != len(self.data):
            raise OtsError(f"{len(self.data) - self.pos} unexpected bytes after the proof")


def _parse_attestation(r: _Reader) -> Attestation:
    tag = r.bytes(8)
    payload = r.varbytes(MAX_PAYLOAD)
    att = Attestation(tag, payload)
    if tag in (TAG_BITCOIN, TAG_LITECOIN):
        att.height  # noqa: B018 - parses and checks the payload
    elif tag == TAG_PENDING:
        pr = _Reader(payload)
        uri = pr.varbytes(1000)
        pr.end()
        if any(c not in URI_CHARS for c in uri):
            raise OtsError("pending attestation URI holds characters the format forbids")
    return att


def _parse_entry(r: _Reader, tag: int, msg: bytes, depth: int):
    if tag == 0x00:
        return _parse_attestation(r)
    if tag in _BINARY:
        op = Op(tag, r.varbytes(MAX_MSG, min_len=1))
    elif tag in _UNARY:
        op = Op(tag)
    else:
        raise OtsError(f"unknown operation tag 0x{tag:02x}")
    return op, _parse_timestamp(r, op.apply(msg), depth - 1)


def _parse_timestamp(r: _Reader, msg: bytes, depth: int = MAX_DEPTH) -> Timestamp:
    if depth <= 0:
        raise OtsError(f"proof nests deeper than {MAX_DEPTH}")
    ts = Timestamp(msg)
    tag = r.byte()
    while tag == 0xFF:
        ts.entries.append(_parse_entry(r, r.byte(), msg, depth))
        tag = r.byte()
    ts.entries.append(_parse_entry(r, tag, msg, depth))
    return ts


def parse(data: bytes) -> DetachedTimestamp:
    r = _Reader(data)
    if r.bytes(len(HEADER_MAGIC)) != HEADER_MAGIC:
        raise OtsError("not an OpenTimestamps proof: the magic header is missing")
    version = r.varuint()
    if version != MAJOR_VERSION:
        raise OtsError(f"proof format version {version}; this verifier reads version {MAJOR_VERSION}")
    tag = r.byte()
    if tag not in _CRYPT:
        raise OtsError(f"file hash operation 0x{tag:02x} is not a hash")
    op = Op(tag)
    digest = r.bytes(_UNARY[tag][2])
    ts = _parse_timestamp(r, digest)
    r.end()
    return DetachedTimestamp(op, ts)


@dataclass
class Leaf:
    """One attestation, the message it commits to, and the path that led there."""

    attestation: Attestation
    commitment: bytes
    path: list[Op]


def leaves(ts: Timestamp, path: Sequence[Op] = ()) -> Iterator[Leaf]:
    for entry in ts.entries:
        if isinstance(entry, Attestation):
            yield Leaf(entry, ts.msg, list(path))
        else:
            op, child = entry
            yield from leaves(child, [*path, op])


@guarded("opentimestamps", "ots.parse", "OpenTimestamps proof")
def verify(
    proof_bytes: bytes,
    sources: Sequence[HeaderSource] = (),
    file_bytes: bytes | None = None,
    digest: bytes | None = None,
    network: Network = MAINNET,
    subject: str | None = None,
    checked_at: str | None = None,
) -> Verdict:
    """Check an OpenTimestamps proof.

    ``file_bytes`` or ``digest`` (the digest the caller expects the proof to
    cover) ties the proof to a subject; without either, the verdict speaks of
    the digest the proof carries. ``sources`` supply block headers.
    """
    checks: list[Check] = []
    try:
        dt = parse(proof_bytes)
    except OtsError as exc:
        checks.append(Check("ots.parse", Status.FAIL, "the proof could not be read", reasons=[str(exc)]))
        return make_verdict("opentimestamps", subject or "OpenTimestamps proof", checks,
                            {o: "The OpenTimestamps proof is malformed." for o in Outcome}, ANCHOR_LIMITS, checked_at)

    hash_name = dt.file_hash.name
    subject = subject or f"{hash_name} digest {dt.digest.hex()}"
    checks.append(Check("ots.parse", Status.PASS, f"the proof is well formed and covers the {hash_name} digest {dt.digest.hex()}",
                        data={"file_hash": hash_name, "digest": dt.digest.hex()}))

    if file_bytes is not None:
        actual = _UNARY[dt.file_hash.tag][1](file_bytes)
        if actual == dt.digest:
            checks.append(Check("ots.subject", Status.PASS, f"the file's {hash_name} digest equals the digest the proof covers"))
        else:
            checks.append(Check("ots.subject", Status.FAIL, f"the file's {hash_name} digest differs from the digest the proof covers",
                                reasons=[f"file {actual.hex()}", f"proof {dt.digest.hex()}"]))
    elif digest is not None:
        if digest == dt.digest:
            checks.append(Check("ots.subject", Status.PASS, "the expected digest equals the digest the proof covers"))
        else:
            checks.append(Check("ots.subject", Status.FAIL, "the expected digest differs from the digest the proof covers",
                                reasons=[f"expected {digest.hex()}", f"proof {dt.digest.hex()}"]))
    if _UNARY[dt.file_hash.tag][3]:
        checks.append(Check("ots.weak_hash", Status.WARN, f"the file hash is {hash_name}, which is broken for collisions",
                            reasons=["a party who chose the file could have prepared a second file with the same digest"]))

    found = list(leaves(dt.timestamp))
    weak_on_path = sorted({op.name for leaf in found for op in leaf.path if op.tag in _UNARY and _UNARY[op.tag][3]})
    if weak_on_path:
        checks.append(Check("ots.weak_hash_path", Status.WARN, f"the proof's paths use {', '.join(weak_on_path)}, broken for collisions"))

    confirmed: list[tuple[int, str, str]] = []
    pending: list[str] = []
    for leaf in found:
        att = leaf.attestation
        path_text = " ; ".join(op.describe() for op in leaf.path) or "(no operations)"
        if att.kind == "bitcoin":
            height = att.height
            cid = f"ots.bitcoin.{height}"
            if len(leaf.commitment) != 32:
                checks.append(Check(cid, Status.FAIL, f"the path to Bitcoin block {height} ends in {len(leaf.commitment)} bytes, not a 32-byte Merkle root"))
                continue
            evidence, notes = lookup_header(sources, height)
            checks.extend(notes)
            if evidence is None:
                if not notes:
                    checks.append(Check(cid, Status.NOT_CHECKED, f"no header for Bitcoin block {height} was available",
                                        reasons=["pass a headers file, or an explorer URL, that covers this height"]))
                continue
            checks.extend(evidence.checks)
            if evidence.header.merkle_root == leaf.commitment:
                checks.append(Check(
                    cid, Status.PASS,
                    f"the proof's path ends in the Merkle root of Bitcoin block {height}",
                    reasons=[f"Merkle root {leaf.commitment[::-1].hex()} (display order)", f"path: {path_text}",
                             f"header time {evidence.header.time_iso}, set by the miner and only roughly accurate (Bitcoin accepts blocks up to two hours ahead of network time)"],
                    relies_on=evidence.relies_on + ["SHA-256 (and any other hash on the path) is second-preimage resistant"],
                    data={"height": height, "block_hash": evidence.header.hash_hex, "header_time": evidence.header.time_iso,
                          "path": [op.describe() for op in leaf.path]},
                ))
                confirmed.append((height, evidence.header.hash_hex, evidence.header.time_iso))
            else:
                checks.append(Check(
                    cid, Status.FAIL, f"the proof's path does not end in the Merkle root of Bitcoin block {height}",
                    reasons=[f"proof commits to {leaf.commitment[::-1].hex()} (display order)",
                             f"block {evidence.header.hash_hex} has Merkle root {evidence.header.merkle_root[::-1].hex()}",
                             "the proof was altered, or names a block that is not on the chain the header came from"],
                    relies_on=evidence.relies_on,
                ))
        elif att.kind == "pending":
            pending.append(att.uri)
            checks.append(Check("ots.pending", Status.INFO,
                                f"a calendar ({att.uri}) promised a Bitcoin attestation for the commitment {leaf.commitment.hex()} "
                                "that this proof does not yet hold",
                                reasons=["this verifier does not contact calendars; upgrade the proof with the OpenTimestamps client to fetch it",
                                         "the path to the commitment is not checked until the attestation arrives"],
                                required=False, data={"uri": att.uri, "commitment": leaf.commitment.hex()}))
        else:
            checks.append(Check(f"ots.{att.kind}", Status.INFO, f"{att.describe()}: not checked by this verifier, and not relied on", required=False))

    if confirmed:
        # One confirmed attestation is enough; others that could not be checked are reported, not required.
        for c in checks:
            if c.status is Status.NOT_CHECKED and (c.id.startswith("ots.bitcoin.") or c.id == "bitcoin.header_source"):
                c.required = False
    if not confirmed and not any(c.status in (Status.FAIL, Status.NOT_CHECKED) for c in checks):
        checks.append(Check("ots.anchor", Status.NOT_CHECKED, "the proof holds no Bitcoin attestation yet",
                            reasons=["only pending or unsupported attestations were found"]))

    net = "" if network is MAINNET else f" on the test network {network.name}"
    if confirmed:
        first = min(confirmed)
        statement_ok = (f"The {hash_name} digest {dt.digest.hex()} existed no later than Bitcoin block {first[0]}{net} "
                        f"({first[1]}), whose header gives the time {first[2]}.")
    else:
        statement_ok = "The proof checks out."
    statements = {
        Outcome.VALID: statement_ok,
        Outcome.INVALID: "The OpenTimestamps proof does not hold: see the failing checks.",
        Outcome.INDETERMINATE: ("The proof is well formed but its Bitcoin anchor could not be checked: "
                                + ("it is still pending." if pending and not any(l.attestation.kind == "bitcoin" for l in found)
                                   else "no usable header was available.")),
    }
    return make_verdict("opentimestamps", subject, checks, statements, ANCHOR_LIMITS, checked_at)


def verify_file(proof_path: str | Path, sources: Sequence[HeaderSource] = (), file_path: str | Path | None = None,
                **kwargs) -> Verdict:
    file_bytes = Path(file_path).read_bytes() if file_path is not None else None
    subject = kwargs.pop("subject", None) or (str(file_path) if file_path is not None else None)
    return verify(Path(proof_path).read_bytes(), sources, file_bytes=file_bytes, subject=subject, **kwargs)
