"""Provenance Ledger event chains (ledger-event/v0 and v0.1) and authorship
maps (authorship-map/v0), checked from the chain alone.

Written from the Provenance Ledger session's docs/EVENT_CONTRACT.md,
docs/AUTHORSHIP_MAP.md and its JSON Schemas (read 16 October 2026), not from
its code. The schema's constraints are encoded here by hand, so this module
needs no schema file and no JSON Schema library.

v0.1 is an addition, proposed on 16 October 2026 (the Ledger's branch, not
yet its main): ``capture.resync`` for changes made while capture was off,
``import.paste`` from an ``unknown`` source, and a ``sign`` with ``meaning``
and ``signer_name_hash``; the reserved actor ``person:unattributed`` never
signs. A chain may mix versions; each event is checked against its own
version, and its signature names that version.

``validate_chain`` applies the contract's chain rules in the contract's
order and stops at the first failure, with the contract's code.
``authorship_map`` builds the map of the state after a given event.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs
from .base58 import EncodingError, b64url_decode
from .hashes import sha256

CONTRACT = "ledger-event/v0"
CONTRACT_V01 = "ledger-event/v0.1"
CONTRACTS = (CONTRACT, CONTRACT_V01)
UNATTRIBUTED = "person:unattributed"
MEANINGS = ("authorship", "review", "approval", "responsibility")
MAX_RESYNC_ENTRIES = 10000
ZERO = "0" * 64
MAXINT = 9007199254740991
TYPES = ["session.open", "session.close", "edit.insert", "edit.delete", "edit.replace", "edit.move", "import.paste",
         "tool.generate", "tool.edit", "evidence.bind", "evidence.unbind", "statement.split", "statement.merge", "sign"]
FIDELITIES = ["live", "snapshot_diff", "tool_report", "reconstructed", "declared"]
ORIGINS = ["human_typed", "imported", "tool_generated", "tool_edited"]
ORIGIN_OF = {"edit.insert": "human_typed", "edit.replace": "human_typed", "import.paste": "imported",
             "tool.generate": "tool_generated", "tool.edit": "tool_edited"}

_RE = {
    "hash": re.compile(r"^[0-9a-f]{64}$"),
    "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    "local_id": re.compile(r"^[A-Za-z0-9_-]{1,64}$"),
    "actor_id": re.compile(r"^[A-Za-z0-9._:-]{1,128}$"),
    "tenant": re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$"),
    "ts": re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"),
    "section_ref": re.compile(r"^call:[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,64}$"),
    "client_name": re.compile(r"^[A-Za-z0-9._-]{1,64}$"),
    "client_version": re.compile(r"^[A-Za-z0-9.+_-]{1,64}$"),
    "public_key": re.compile(r"^[A-Za-z0-9_-]{43}$"),
    "sig": re.compile(r"^[A-Za-z0-9_-]{86}$"),
    "date": re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
    "licence": re.compile(r"^(unknown|LicenseRef-[A-Za-z0-9.-]{1,64}|[A-Za-z0-9.+-]{1,64})$"),
    "ref": re.compile(r"^(vault:(fact|evidence|claim):[A-Za-z0-9_-]{1,64}|atlas:[A-Za-z0-9._-]{1,128}|"
                      r"call:[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,64}|kg:(doi|pmid|pmcid|nct):[^\s]{1,256}|url:https://[^\s]{1,2000})$"),
    "media_type": re.compile(r"^[a-z0-9.+-]+/[a-z0-9.+-]+$"),
}


class SchemaError(ValueError):
    pass


class UnknownContract(SchemaError):
    """An event names a contract version this verifier does not read: the
    chain cannot be checked past it, which is not a contradiction."""


def _fail(where: str, why: str):
    raise SchemaError(f"{where}: {why}")


def _obj(v: Any, where: str, required: tuple, optional: tuple = ()) -> dict:
    if not isinstance(v, dict):
        _fail(where, "must be an object")
    missing = [k for k in required if k not in v]
    if missing:
        _fail(where, f"missing {', '.join(missing)}")
    extra = sorted(set(v) - set(required) - set(optional))
    if extra:
        _fail(where, f"fields not in the contract: {', '.join(extra)}")
    return v


def _str(v: Any, kind: str, where: str) -> None:
    if not isinstance(v, str) or not _RE[kind].match(v):
        _fail(where, f"is not a valid {kind}")


def _opt(v: Any, kind: str, where: str) -> None:
    if v is not None:
        _str(v, kind, where)


def _int(v: Any, lo: int, where: str) -> None:
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= MAXINT:
        _fail(where, f"must be an integer from {lo}")


def _text(v: Any, lo: int, hi: int, where: str) -> None:
    if not isinstance(v, str) or not lo <= len(v) <= hi:
        _fail(where, f"must be a string of {lo} to {hi} characters")


def _payload(t: str, p: Any, seq: int, v01: bool = False) -> None:
    w = f"payload ({t})"
    if t == "session.open":
        _obj(p, w, ("client", "client_key"), ("genesis",))
        _obj(p["client"], f"{w}.client", ("name", "version"))
        _str(p["client"]["name"], "client_name", f"{w}.client.name")
        _str(p["client"]["version"], "client_version", f"{w}.client.version")
        _obj(p["client_key"], f"{w}.client_key", ("alg", "public_key"))
        if p["client_key"]["alg"] != "ed25519":
            _fail(f"{w}.client_key.alg", "must be ed25519")
        _str(p["client_key"]["public_key"], "public_key", f"{w}.client_key.public_key")
        if "genesis" in p:
            g = _obj(p["genesis"], f"{w}.genesis", ("statement_id", "section_id", "section_ref", "key_commitment"))
            _str(g["statement_id"], "local_id", f"{w}.genesis.statement_id")
            _str(g["section_id"], "local_id", f"{w}.genesis.section_id")
            _opt(g["section_ref"], "section_ref", f"{w}.genesis.section_ref")
            _str(g["key_commitment"], "hash", f"{w}.genesis.key_commitment")
        if seq == 1 and "genesis" not in p:
            _fail(w, "the first event must carry genesis")
    elif t == "session.close":
        _obj(p, w, ("reason",))
        if p["reason"] not in ("user", "idle", "client_exit", "error"):
            _fail(f"{w}.reason", "is not a reason the contract names")
    elif t == "edit.insert":
        _obj(p, w, ("length",))
        _int(p["length"], 1, f"{w}.length")
    elif t == "edit.delete":
        _obj(p, w, ())
    elif t == "edit.replace":
        _obj(p, w, ("length", "removed_hash"))
        _int(p["length"], 1, f"{w}.length")
        _str(p["removed_hash"], "hash", f"{w}.removed_hash")
    elif t == "edit.move":
        _obj(p, w, ("to",))
        _obj(p["to"], f"{w}.to", ("statement_id", "offset"))
        _str(p["to"]["statement_id"], "local_id", f"{w}.to.statement_id")
        _int(p["to"]["offset"], 0, f"{w}.to.offset")
    elif t == "import.paste":
        _obj(p, w, ("length", "removed_hash", "source"))
        _int(p["length"], 1, f"{w}.length")
        _opt(p["removed_hash"], "hash", f"{w}.removed_hash")
        _obj(p["source"], f"{w}.source", ("kind", "ref_hash"))
        kinds = ("clipboard", "file", "web", "other_document", "preexisting") + (("unknown",) if v01 else ())
        if p["source"]["kind"] not in kinds:
            _fail(f"{w}.source.kind", "is not a kind the contract names")
        _opt(p["source"]["ref_hash"], "hash", f"{w}.source.ref_hash")
        if p["source"]["kind"] == "unknown" and p["source"]["ref_hash"] is not None:
            _fail(f"{w}.source.ref_hash", "must be null when the source is unknown")
    elif t in ("tool.generate", "tool.edit"):
        _obj(p, w, ("length", "removed_hash", "prompt_hash", "accepted_by"))
        _int(p["length"], 1 if t == "tool.generate" else 0, f"{w}.length")
        if t == "tool.generate":
            _opt(p["removed_hash"], "hash", f"{w}.removed_hash")
        else:
            _str(p["removed_hash"], "hash", f"{w}.removed_hash")
        _opt(p["prompt_hash"], "hash", f"{w}.prompt_hash")
        _opt(p["accepted_by"], "actor_id", f"{w}.accepted_by")
    elif t == "evidence.bind":
        _obj(p, w, ("binding_id", "source", "date", "licence", "page_hash", "quoted_span"))
        _str(p["binding_id"], "uuid", f"{w}.binding_id")
        src = _obj(p["source"], f"{w}.source", ("ref", "visibility"))
        if not isinstance(src["ref"], str) or len(src["ref"]) > 2048:
            _fail(f"{w}.source.ref", "is not a reference the contract allows")
        _str(src["ref"], "ref", f"{w}.source.ref")
        if src["visibility"] not in ("public", "tenant_private"):
            _fail(f"{w}.source.visibility", "must be public or tenant_private")
        date = _obj(p["date"], f"{w}.date", ("kind", "value"))
        if date["kind"] not in ("retrieved", "edition"):
            _fail(f"{w}.date.kind", "must be retrieved or edition")
        _str(date["value"], "date", f"{w}.date.value")
        _str(p["licence"], "licence", f"{w}.licence")
        _str(p["page_hash"], "hash", f"{w}.page_hash")
        qs = _obj(p["quoted_span"], f"{w}.quoted_span", ("quote_hash", "locator"))
        _str(qs["quote_hash"], "hash", f"{w}.quoted_span.quote_hash")
        if qs["locator"] is not None:
            _text(qs["locator"], 1, 256, f"{w}.quoted_span.locator")
        if src["visibility"] == "tenant_private" and qs["locator"] is not None:
            _fail(f"{w}.quoted_span.locator", "must be null for a tenant_private source")
    elif t == "evidence.unbind":
        _obj(p, w, ("binding_id", "reason"))
        _str(p["binding_id"], "uuid", f"{w}.binding_id")
        if p["reason"] not in ("wrong_source", "superseded", "withdrawn", "other"):
            _fail(f"{w}.reason", "is not a reason the contract names")
    elif t == "statement.split":
        _obj(p, w, ("new_statement_id", "section_id", "section_ref"))
        _str(p["new_statement_id"], "local_id", f"{w}.new_statement_id")
        _opt(p["section_id"], "local_id", f"{w}.section_id")
        _opt(p["section_ref"], "section_ref", f"{w}.section_ref")
    elif t == "statement.merge":
        _obj(p, w, ("merged_statement_id",))
        _str(p["merged_statement_id"], "local_id", f"{w}.merged_statement_id")
    elif t == "capture.resync":
        _obj(p, w, ("removed", "changed", "added"))
        for part in ("removed", "changed", "added"):
            if not isinstance(p[part], list) or len(p[part]) > MAX_RESYNC_ENTRIES:
                _fail(f"{w}.{part}", f"is not a list of at most {MAX_RESYNC_ENTRIES} entries")
        if not (p["removed"] or p["changed"] or p["added"]):
            _fail(w, "a capture.resync records at least one change")
        for j, x in enumerate(p["removed"]):
            _obj(x, f"{w}.removed[{j}]", ("statement_id", "removed_hash"))
            _str(x["statement_id"], "local_id", f"{w}.removed[{j}].statement_id")
            _str(x["removed_hash"], "hash", f"{w}.removed[{j}].removed_hash")
        for j, x in enumerate(p["changed"]):
            _obj(x, f"{w}.changed[{j}]", ("statement_id", "start", "end", "removed_hash", "length", "content_hash"))
            _str(x["statement_id"], "local_id", f"{w}.changed[{j}].statement_id")
            for k in ("start", "end", "length"):
                _int(x[k], 0, f"{w}.changed[{j}].{k}")
            _opt(x["removed_hash"], "hash", f"{w}.changed[{j}].removed_hash")
            _opt(x["content_hash"], "hash", f"{w}.changed[{j}].content_hash")
        for j, x in enumerate(p["added"]):
            _obj(x, f"{w}.added[{j}]", ("statement_id", "after", "section_id", "section_ref", "length", "content_hash"))
            _str(x["statement_id"], "local_id", f"{w}.added[{j}].statement_id")
            _opt(x["after"], "local_id", f"{w}.added[{j}].after")
            _str(x["section_id"], "local_id", f"{w}.added[{j}].section_id")
            _opt(x["section_ref"], "section_ref", f"{w}.added[{j}].section_ref")
            _int(x["length"], 0, f"{w}.added[{j}].length")
            _opt(x["content_hash"], "hash", f"{w}.added[{j}].content_hash")
    elif t == "sign":
        _obj(p, w, ("exported", "declaration_hash"), ("meaning", "signer_name_hash") if v01 else ())
        if "meaning" in p and p["meaning"] not in MEANINGS:
            _fail(f"{w}.meaning", "is not a meaning the contract names")
        if "signer_name_hash" in p:
            _str(p["signer_name_hash"], "hash", f"{w}.signer_name_hash")
        ex = _obj(p["exported"], f"{w}.exported", ("sha256", "media_type", "byte_length"))
        _str(ex["sha256"], "hash", f"{w}.exported.sha256")
        if not isinstance(ex["media_type"], str) or len(ex["media_type"]) > 128:
            _fail(f"{w}.exported.media_type", "is not a media type")
        _str(ex["media_type"], "media_type", f"{w}.exported.media_type")
        _int(ex["byte_length"], 0, f"{w}.exported.byte_length")
        _opt(p["declaration_hash"], "hash", f"{w}.declaration_hash")


# Per type: actor kind required (None for either), range (True required, False null), content_hash (True, False, None for either).
_SHAPE = {
    "session.open": (None, False, False), "session.close": (None, False, False),
    "edit.insert": ("human", True, True), "edit.delete": ("human", True, True), "edit.replace": ("human", True, True),
    "edit.move": ("human", True, True), "import.paste": ("human", True, True),
    "tool.generate": ("tool", True, True), "tool.edit": ("tool", True, None),
    "evidence.bind": ("human", True, True), "evidence.unbind": ("human", False, False),
    "statement.split": (None, True, False), "statement.merge": (None, True, False), "sign": ("human", False, False),
    "capture.resync": ("human", False, False),
}
FIELDS = ("contract", "event_id", "type", "doc_id", "tenant_id", "session_id", "seq", "ts", "actor", "range",
          "content_hash", "doc_hash", "prev_hash", "capture_fidelity", "payload", "client_sig")


def check_schema(ev: Any) -> None:
    """Raise SchemaError where the event breaks the contract's schema."""
    _obj(ev, "event", FIELDS)
    if ev["contract"] not in CONTRACTS:
        raise UnknownContract("contract", f"{ev['contract']!r} is not a contract version this verifier reads ({', '.join(CONTRACTS)})")
    v01 = ev["contract"] == CONTRACT_V01
    for k in ("event_id", "doc_id", "session_id"):
        _str(ev[k], "uuid", k)
    if ev["type"] not in TYPES + (["capture.resync"] if v01 else []):
        _fail("type", f"is not an event type {ev['contract']} names")
    _str(ev["tenant_id"], "tenant", "tenant_id")
    _int(ev["seq"], 1, "seq")
    _str(ev["ts"], "ts", "ts")
    try:
        _dt.datetime.strptime(ev["ts"], "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _fail("ts", "is not a real date and time")
    actor = _obj(ev["actor"], "actor", ("kind", "id"), ("tool_name", "model_id"))
    if actor["kind"] not in ("human", "tool"):
        _fail("actor.kind", "must be human or tool")
    _str(actor["id"], "actor_id", "actor.id")
    if actor["kind"] == "human" and ("tool_name" in actor or "model_id" in actor):
        _fail("actor", "a person carries no tool_name or model_id")
    if actor["kind"] == "tool":
        if "tool_name" not in actor or "model_id" not in actor:
            _fail("actor", "a tool must carry tool_name and model_id")
        _text(actor["tool_name"], 1, 128, "actor.tool_name")
        if actor["model_id"] is not None:
            _text(actor["model_id"], 1, 128, "actor.model_id")
    if ev["range"] is not None:
        r = _obj(ev["range"], "range", ("statement_id", "start", "end"))
        _str(r["statement_id"], "local_id", "range.statement_id")
        _int(r["start"], 0, "range.start")
        _int(r["end"], 0, "range.end")
    _opt(ev["content_hash"], "hash", "content_hash")
    _str(ev["doc_hash"], "hash", "doc_hash")
    _str(ev["prev_hash"], "hash", "prev_hash")
    if ev["capture_fidelity"] not in FIDELITIES:
        _fail("capture_fidelity", "is not a fidelity the contract names")
    sig = _obj(ev["client_sig"], "client_sig", ("alg", "key_id", "sig"))
    if sig["alg"] != "ed25519":
        _fail("client_sig.alg", "must be ed25519")
    _str(sig["key_id"], "hash", "client_sig.key_id")
    _str(sig["sig"], "sig", "client_sig.sig")
    if ev["seq"] == 1:
        if ev["type"] != "session.open":
            _fail("type", "the first event must be session.open")
        if ev["prev_hash"] != ZERO:
            _fail("prev_hash", "the first event's prev_hash must be 64 zeros")
    kind, needs_range, needs_content = _SHAPE[ev["type"]]
    if kind is not None and actor["kind"] != kind:
        _fail("actor.kind", f"{ev['type']} must be made by a {kind}")
    if needs_range and ev["range"] is None:
        _fail("range", f"{ev['type']} needs a range")
    if not needs_range and ev["range"] is not None:
        _fail("range", f"{ev['type']} carries no range")
    if needs_content is True and ev["content_hash"] is None:
        _fail("content_hash", f"{ev['type']} needs a content hash")
    if needs_content is False and ev["content_hash"] is not None:
        _fail("content_hash", f"{ev['type']} carries no content hash")
    if ev["type"] == "capture.resync" and ev["capture_fidelity"] != "reconstructed":
        _fail("capture_fidelity", "a capture.resync is reconstructed")
    if v01 and ev["type"] == "sign" and actor["id"] == UNATTRIBUTED:
        _fail("actor.id", f"{UNATTRIBUTED} stands for no one and never signs")
    _payload(ev["type"], ev["payload"], ev["seq"], v01)


def event_hash(ev: dict) -> str:
    return sha256(jcs.dumps({k: v for k, v in ev.items() if k != "client_sig"})).hex()


@dataclass
class Statement:
    statement_id: str
    section_id: str
    chars: list = field(default_factory=list)  # (origin, fidelity, seq) per code point


@dataclass
class State:
    tenant_id: str = ""
    doc_id: str = ""
    statements: list[Statement] = field(default_factory=list)
    used_ids: set = field(default_factory=set)
    sections: dict = field(default_factory=dict)  # section_id -> section_ref, first given
    sessions: dict = field(default_factory=dict)  # session_id -> {public_key, key_id, client, opened_seq, closed_seq}
    bindings: dict = field(default_factory=dict)  # binding_id -> statement_id, active
    used_bindings: set = field(default_factory=set)
    inserted: dict = field(default_factory=lambda: dict.fromkeys(ORIGINS, 0))
    deleted: int = 0
    hashes: list[str] = field(default_factory=list)

    def find(self, sid: str) -> int | None:
        return next((i for i, s in enumerate(self.statements) if s.statement_id == sid), None)


class ChainError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ChainResult:
    ok: bool
    count: int
    state: State
    index: int | None = None
    seq: int | None = None
    code: str | None = None
    message: str | None = None
    unknown_contract: bool = False

    @property
    def head(self) -> str | None:
        return self.state.hashes[-1] if self.state.hashes else None


def _verify_sig(public_b64: str, ev: dict, ehash: str) -> bool:
    try:
        public = b64url_decode(public_b64)
        sig = b64url_decode(ev["client_sig"]["sig"])
        Ed25519PublicKey.from_public_bytes(public).verify(sig, f"{ev['contract']}:{ehash}".encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, EncodingError):
        return False


def _apply(st: State, ev: dict, i: int, prev: dict | None) -> None:
    t, r, p, seq = ev["type"], ev["range"], ev["payload"], ev["seq"]
    if prev is None:
        st.tenant_id, st.doc_id = ev["tenant_id"], ev["doc_id"]
    else:
        if seq != prev["seq"] + 1:
            raise ChainError("seq_gap", f"seq {seq} follows {prev['seq']}")
    if prev is None and seq != 1:
        raise ChainError("seq_gap", f"the chain starts at seq {seq}")
    ehash = event_hash(ev)
    want_prev = st.hashes[-1] if st.hashes else ZERO
    if ev["prev_hash"] != want_prev:
        raise ChainError("prev_hash_mismatch", "prev_hash is not the previous event's hash")
    if prev is not None and ev["ts"] < prev["ts"]:
        raise ChainError("ts_backwards", f"{ev['ts']} is earlier than {prev['ts']}")
    if ev["doc_id"] != st.doc_id:
        raise ChainError("doc_mismatch", "the event names another document")
    if ev["tenant_id"] != st.tenant_id:
        raise ChainError("tenant_mismatch", "the event names another tenant")
    if ev["event_id"] in getattr(st, "_event_ids", set()):
        raise ChainError("event_id_duplicate", f"event_id {ev['event_id']} repeats")
    sid = ev["session_id"]
    session = st.sessions.get(sid)
    if t == "session.open":
        public = p["client_key"]["public_key"]
        key_id = sha256(b64url_decode(public)).hex()
    else:
        public, key_id = (session["public_key"], session["key_id"]) if session else (None, None)
    if key_id is not None and ev["client_sig"]["key_id"] != key_id:
        raise ChainError("key_mismatch", "the event is not signed with its session's key")
    if public is not None and not _verify_sig(public, ev, ehash):
        raise ChainError("bad_signature", "client_sig does not verify")
    if t == "session.open":
        if sid in st.sessions:
            raise ChainError("session_reopened", "the session was opened before")
    elif session is None:
        raise ChainError("session_unknown", "the session was never opened")
    elif session["closed_seq"] is not None:
        raise ChainError("session_closed", "the session is closed")
    if t == "session.open" and "genesis" in p and seq != 1:
        raise ChainError("genesis_not_first", "only seq 1 carries genesis")
    if t == "capture.resync" and getattr(st, "_last", None) != ("session.open", sid):
        raise ChainError("resync_not_first", "a capture.resync must directly follow its session's session.open")

    # Statements and ranges.
    target = None
    if r is not None:
        target = st.find(r["statement_id"])
        if target is None:
            raise ChainError("statement_unknown", f"statement {r['statement_id']} does not exist")
    if t == "edit.move" and st.find(p["to"]["statement_id"]) is None:
        raise ChainError("statement_unknown", f"statement {p['to']['statement_id']} does not exist")
    if t == "statement.merge" and st.find(p["merged_statement_id"]) is None:
        raise ChainError("statement_unknown", f"statement {p['merged_statement_id']} does not exist")
    if t == "statement.split" and p["new_statement_id"] in st.used_ids:
        raise ChainError("statement_id_reused", f"statement id {p['new_statement_id']} was used before")
    if r is not None:
        start, end, length = r["start"], r["end"], len(st.statements[target].chars)
        empty = start == end
        if t in ("edit.insert", "statement.split", "statement.merge") and not empty:
            raise ChainError("range_not_empty", f"{t} needs an empty range")
        if t in ("edit.delete", "edit.replace", "edit.move", "tool.edit") and empty:
            raise ChainError("range_empty", f"{t} needs a non-empty range")
        if start > end or end > length:
            raise ChainError("range_out_of_bounds", f"[{start}, {end}) is outside a statement of {length}")
        if t == "edit.move":
            dest = st.find(p["to"]["statement_id"])
            room = len(st.statements[dest].chars) - ((end - start) if dest == target else 0)
            if p["to"]["offset"] > room:
                raise ChainError("range_out_of_bounds", f"move offset {p['to']['offset']} is outside a statement of {room}")
        if t in ("import.paste", "tool.generate") and (p["removed_hash"] is None) != empty:
            raise ChainError("removed_hash_mismatch", "removed_hash must be null exactly when the range is empty")
        if t == "tool.edit" and (ev["content_hash"] is None) != (p["length"] == 0):
            raise ChainError("content_hash_mismatch", "content_hash must be null exactly when the tool only removes")
        if t == "statement.merge":
            merged = st.find(p["merged_statement_id"])
            if merged != target + 1:
                raise ChainError("merge_not_adjacent", "the merged statement is not directly after the surviving one")
            if start != length:
                raise ChainError("range_mismatch", "a merge's range must be at the end of the surviving statement")
    if t == "statement.split" and p["section_id"] is not None:
        known = st.sections.get(p["section_id"], p["section_ref"])
        if p["section_id"] in st.sections and known != p["section_ref"]:
            raise ChainError("section_ref_conflict", f"section {p['section_id']} already has section_ref {known}")
    if t == "evidence.bind":
        if p["binding_id"] in st.used_bindings:
            raise ChainError("binding_duplicate", f"binding {p['binding_id']} is not new")
    if t == "evidence.unbind" and p["binding_id"] not in st.bindings:
        raise ChainError("binding_unknown", f"binding {p['binding_id']} is not active")

    # Apply.
    st._event_ids = getattr(st, "_event_ids", set()) | {ev["event_id"]}
    st._last = (t, sid)
    fid = ev["capture_fidelity"]
    if t == "session.open":
        st.sessions[sid] = {"public_key": public, "key_id": key_id, "client": p["client"], "opened_seq": seq, "closed_seq": None}
        if "genesis" in p:
            g = p["genesis"]
            st.statements.append(Statement(g["statement_id"], g["section_id"]))
            st.used_ids.add(g["statement_id"])
            st.sections.setdefault(g["section_id"], g["section_ref"])
    elif t == "session.close":
        session["closed_seq"] = seq
    elif t in ("edit.insert", "edit.delete", "edit.replace", "import.paste", "tool.generate", "tool.edit"):
        chars = st.statements[target].chars
        removed = end - start
        del chars[start:end]
        st.deleted += removed
        if t != "edit.delete":
            n = p["length"]
            chars[start:start] = [(ORIGIN_OF[t], fid, seq)] * n
            st.inserted[ORIGIN_OF[t]] += n
    elif t == "edit.move":
        src = st.statements[target].chars
        seg = src[start:end]
        del src[start:end]
        dest = st.statements[st.find(p["to"]["statement_id"])].chars
        dest[p["to"]["offset"]:p["to"]["offset"]] = seg
    elif t == "evidence.bind":
        st.bindings[p["binding_id"]] = r["statement_id"]
        st.used_bindings.add(p["binding_id"])
    elif t == "evidence.unbind":
        del st.bindings[p["binding_id"]]
    elif t == "statement.split":
        s = st.statements[target]
        section = p["section_id"] if p["section_id"] is not None else s.section_id
        if p["section_id"] is not None:
            st.sections.setdefault(section, p["section_ref"])
        new = Statement(p["new_statement_id"], section, s.chars[start:])
        s.chars = s.chars[:start]
        st.statements.insert(target + 1, new)
        st.used_ids.add(p["new_statement_id"])
    elif t == "statement.merge":
        s, m = st.statements[target], st.statements[target + 1]
        s.chars += m.chars
        del st.statements[target + 1]
        for b, owner in st.bindings.items():
            if owner == m.statement_id:
                st.bindings[b] = s.statement_id
    elif t == "capture.resync":
        _resync(st, p, seq, fid)
    st.hashes.append(ehash)


def _resync(st: State, p: dict, seq: int, fid: str) -> None:
    """docs/EVENT_CONTRACT.md, v0.1: the entries are checked and applied one
    by one, removed, then changed, then added, each in array order, so an
    offset or an ``after`` is read in the document as the entries before it
    left it; each entry against the chain rules in their order."""
    for x in p["removed"]:
        i = st.find(x["statement_id"])
        if i is None:
            raise ChainError("statement_unknown", f"statement {x['statement_id']} does not exist")
        st.deleted += len(st.statements[i].chars)
        del st.statements[i]
        for b in [b for b, owner in st.bindings.items() if owner == x["statement_id"]]:
            del st.bindings[b]  # a binding ends with its statement
    for x in p["changed"]:
        i = st.find(x["statement_id"])
        if i is None:
            raise ChainError("statement_unknown", f"statement {x['statement_id']} does not exist")
        chars, start, end = st.statements[i].chars, x["start"], x["end"]
        if start > end or end > len(chars):
            raise ChainError("range_out_of_bounds", f"[{start}, {end}) is outside a statement of {len(chars)}")
        if (x["removed_hash"] is None) != (start == end):
            raise ChainError("removed_hash_mismatch", "removed_hash must be null exactly when the span is empty")
        if (x["content_hash"] is None) != (x["length"] == 0):
            raise ChainError("content_hash_mismatch", "content_hash must be null exactly when length is 0")
        del chars[start:end]
        st.deleted += end - start
        chars[start:start] = [("imported", fid, seq)] * x["length"]
        st.inserted["imported"] += x["length"]
    for x in p["added"]:
        at = 0
        if x["after"] is not None:
            j = st.find(x["after"])
            if j is None:
                raise ChainError("statement_unknown", f"statement {x['after']} does not exist")
            at = j + 1
        if x["statement_id"] in st.used_ids:
            raise ChainError("statement_id_reused", f"statement id {x['statement_id']} was used before")
        if (x["content_hash"] is None) != (x["length"] == 0):
            raise ChainError("content_hash_mismatch", "content_hash must be null exactly when length is 0")
        if x["section_id"] in st.sections and st.sections[x["section_id"]] != x["section_ref"]:
            raise ChainError("section_ref_conflict", f"section {x['section_id']} already has section_ref {st.sections[x['section_id']]}")
        st.sections.setdefault(x["section_id"], x["section_ref"])
        st.statements.insert(at, Statement(x["statement_id"], x["section_id"], [("imported", fid, seq)] * x["length"]))
        st.used_ids.add(x["statement_id"])
        st.inserted["imported"] += x["length"]
    if not st.statements:
        raise ChainError("document_empty", "a capture.resync may not leave the document without a statement")


def validate_chain(events: list) -> ChainResult:
    """Apply the chain rules in the contract's order; stop at the first failure."""
    st = State()
    prev = None
    for i, ev in enumerate(events):
        try:
            check_schema(ev)
        except SchemaError as exc:
            return ChainResult(False, i, st, i, ev.get("seq") if isinstance(ev, dict) else None, "schema", str(exc),
                               unknown_contract=isinstance(exc, UnknownContract))
        try:
            _apply(st, ev, i, prev)
        except ChainError as exc:
            return ChainResult(False, i, st, i, ev["seq"], exc.code, exc.message)
        except (EncodingError, ValueError) as exc:
            return ChainResult(False, i, st, i, ev["seq"], "schema", str(exc))
        prev = ev
    return ChainResult(True, len(events), st)


def _percent(counts: dict, keys: list[str], total: int) -> dict:
    if total == 0:
        return {k: "0.0" for k in keys}
    floors = {k: counts[k] * 1000 // total for k in keys}
    rem = {k: counts[k] * 1000 - floors[k] * total for k in keys}
    for k in sorted(keys, key=lambda k: (-rem[k], keys.index(k)))[: 1000 - sum(floors.values())]:
        floors[k] += 1
    return {k: f"{floors[k] // 10}.{floors[k] % 10}" for k in keys}


def _block(chars: list, keys: list[str], index: int) -> dict:
    counts = dict.fromkeys(keys, 0)
    for c in chars:
        counts[c[index]] += 1
    total = len(chars)
    return {"total": total, "counts": counts, "percent": _percent(counts, keys, total)}


def authorship_map(st: State, seq: int, ehash: str) -> dict:
    """docs/AUTHORSHIP_MAP.md: the map of the state after event ``seq``."""
    statements = []
    for s in st.statements:
        runs: list[dict] = []
        for origin, fid, eseq in s.chars:
            if runs and (runs[-1]["origin"], runs[-1]["fidelity"], runs[-1]["seq"]) == (origin, fid, eseq):
                runs[-1]["length"] += 1
            else:
                runs.append({"origin": origin, "fidelity": fid, "seq": eseq, "length": 1})
        statements.append({"statement_id": s.statement_id, "section_id": s.section_id, "length": len(s.chars), "runs": runs})
    sections, order = {}, []
    for s in st.statements:
        if s.section_id not in sections:
            order.append(s.section_id)
            sections[s.section_id] = {"statements": 0, "chars": []}
        sections[s.section_id]["statements"] += 1
        sections[s.section_id]["chars"] += s.chars
    all_chars = [c for s in st.statements for c in s.chars]
    return {
        "contract": "authorship-map/v0",
        "tenant_id": st.tenant_id,
        "doc_id": st.doc_id,
        "at": {"seq": seq, "event_hash": ehash},
        "unit": "unicode_code_point",
        "statements": statements,
        "sections": [{"section_id": sid, "section_ref": st.sections.get(sid), "statements": sections[sid]["statements"],
                      **_block(sections[sid]["chars"], ORIGINS, 0)} for sid in order],
        "document": _block(all_chars, ORIGINS, 0),
        "fidelity": _block(all_chars, FIDELITIES, 1),
        "activity": {"inserted": dict(st.inserted), "deleted": st.deleted},
    }


def verify(events: list, subject: str | None = None, checked_at: str | None = None):
    """A verdict for a whole chain: valid when every rule holds."""
    from .verdict import guarded

    return guarded("event-chain", "chain.rules", "event chain")(_verify_chain)(events, subject=subject, checked_at=checked_at)


def _verify_chain(events: list, subject: str | None = None, checked_at: str | None = None):
    from .verdict import Check, Outcome, Status, make_verdict

    result = validate_chain(events)
    first = events[0] if events and isinstance(events[0], dict) else {}
    subject = subject or f"event chain of document {first.get('doc_id')} (tenant {first.get('tenant_id')})"
    versions = sorted({e.get("contract") for e in events[: result.count] if isinstance(e, dict)} & set(CONTRACTS))
    named = " and ".join(versions) or CONTRACT
    if result.ok:
        checks = [Check("chain.rules", Status.PASS, f"all {result.count} events follow the {named} chain rules",
                        reasons=[f"head {result.head}", f"{len(result.state.sessions)} sessions"],
                        data={"code": None, "index": None, "head": result.head, "events": result.count, "versions": versions})]
    elif result.unknown_contract:
        checks = [Check("chain.rules", Status.NOT_CHECKED,
                        f"event {result.index} (seq {result.seq}) names a contract version this verifier does not read; "
                        f"the {result.index} events before it follow the chain rules",
                        reasons=[result.message or result.code, "a later verifier may read it: this is not a contradiction"],
                        data={"code": result.code, "index": result.index, "unknown_contract": True})]
    else:
        checks = [Check("chain.rules", Status.FAIL, f"event {result.index} (seq {result.seq}) breaks the rule '{result.code}'",
                        reasons=[result.message or result.code], data={"code": result.code, "index": result.index})]
    limits = ["that the events' times are true: they are the client's claims, and a chain re-signed with the client keys "
              "can move them consistently; only an anchor bounds when the chain existed",
              "anything about the text: the chain holds keyed hashes, checkable only with the document key and the text",
              "that the document was not written with AI assistance outside this environment"]
    statements = {
        Outcome.VALID: f"The {result.count} events form a {named} chain that follows every chain rule, ending in {result.head}.",
        Outcome.INVALID: f"The chain breaks the rule '{result.code}' at event {result.index} (seq {result.seq}).",
        Outcome.INDETERMINATE: (f"The chain could not be checked past event {result.index}: it names a contract version "
                                "this verifier does not read." if result.unknown_contract else "The chain could not be checked."),
    }
    return make_verdict("event-chain", subject, checks, statements, limits, checked_at)
