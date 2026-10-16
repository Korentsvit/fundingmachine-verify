"""A small ledger-event/v0 writer for fixtures, written from the Provenance
Ledger session's docs/EVENT_CONTRACT.md.

It keeps the document's text (which never leaves a tenant: only its keyed
hashes go into events), signs each event with its session's Ed25519 key, and
writes the chains the conformance suite publishes: valid, tampered,
back-dated and re-ordered, among others. Keys come from published seeds: they
protect nothing.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fmverify import jcs  # noqa: E402


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def seed_key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def raw_public(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def uuid_from(seed: str) -> str:
    h = bytearray(hashlib.sha256(seed.encode()).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    x = h.hex()
    return f"{x[0:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:32]}"


def event_hash(ev: dict) -> str:
    return hashlib.sha256(jcs.dumps({k: v for k, v in ev.items() if k != "client_sig"})).hexdigest()


def sign_event(ev: dict, key: Ed25519PrivateKey) -> dict:
    ev = dict(ev)
    ev.pop("client_sig", None)
    h = event_hash(ev)
    ev["client_sig"] = {"alg": "ed25519", "key_id": hashlib.sha256(raw_public(key)).hexdigest(),
                        "sig": b64url(key.sign(f"{ev['contract']}:{h}".encode()))}
    return ev


class Writer:
    def __init__(self, name: str, tenant: str = "fixture"):
        self.name = name
        self.tenant = tenant
        self.doc_id = uuid_from(f"{name} document")
        self.doc_key = hashlib.sha256(f"{name} document key".encode()).digest()
        self.events: list[dict] = []
        self.statements: list[dict] = []  # {"statement_id", "section_id", "text"}
        self.sessions: dict[str, tuple[str, Ed25519PrivateKey]] = {}
        self.minute = 0
        self.texts: dict[int, str] = {}  # seq -> the text an event inserted (never leaves a tenant)

    def keyed(self, text: str) -> str:
        return hmac.new(self.doc_key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def doc_hash(self) -> str:
        view = [{"section_id": s["section_id"], "statement_id": s["statement_id"], "text": s["text"]} for s in self.statements]
        return hmac.new(self.doc_key, jcs.dumps(view), hashlib.sha256).hexdigest()

    def stmt(self, sid: str) -> dict:
        return next(s for s in self.statements if s["statement_id"] == sid)

    def emit(self, session: str, type_: str, actor: dict, range_: dict | None, content: str | None, payload: dict,
             fidelity: str = "live") -> dict:
        sid, key = self.sessions[session]
        self.minute += 1
        ev = {"contract": "ledger-event/v0", "event_id": uuid_from(f"{self.name} event {len(self.events) + 1}"), "type": type_,
              "doc_id": self.doc_id, "tenant_id": self.tenant, "session_id": sid, "seq": len(self.events) + 1,
              "ts": f"2026-10-16T08:{self.minute // 60:02d}:{self.minute % 60:02d}.000Z" if self.minute < 3600 else "2026-10-16T08:59:59.000Z",
              "actor": actor, "range": range_, "content_hash": self.keyed(content) if content is not None else None,
              "doc_hash": self.doc_hash(), "prev_hash": event_hash(self.events[-1]) if self.events else "0" * 64,
              "capture_fidelity": fidelity, "payload": payload}
        ev = sign_event(ev, key)
        self.events.append(ev)
        if type_ in ("edit.insert", "edit.replace", "import.paste", "tool.generate", "tool.edit"):
            self.texts[ev["seq"]] = content if content is not None else ""
        return ev

    # Actors.
    person = {"kind": "human", "id": "person:0f1x"}
    tool = {"kind": "tool", "id": "tool:assistant-1", "tool_name": "Example Assistant", "model_id": "example-model-1"}

    def open(self, session: str, genesis: tuple[str, str, str | None] | None = None) -> dict:
        key = seed_key(f"{self.name} {session} key")
        self.sessions[session] = (uuid_from(f"{self.name} {session}"), key)
        payload = {"client": {"name": "fm-verify-fixture-writer", "version": "0.1.0"},
                   "client_key": {"alg": "ed25519", "public_key": b64url(raw_public(key))}}
        if genesis:
            sid, section, ref = genesis
            self.statements.append({"statement_id": sid, "section_id": section, "text": ""})
            payload["genesis"] = {"statement_id": sid, "section_id": section, "section_ref": ref,
                                  "key_commitment": hashlib.sha256(self.doc_key).hexdigest()}
        return self.emit(session, "session.open", self.person, None, None, payload)

    def close(self, session: str) -> dict:
        return self.emit(session, "session.close", self.person, None, None, {"reason": "user"})

    def _set(self, sid: str, start: int, end: int, new: str) -> str:
        s = self.stmt(sid)
        removed = s["text"][start:end]
        s["text"] = s["text"][:start] + new + s["text"][end:]
        return removed

    def insert(self, session: str, sid: str, at: int, text: str, fidelity: str = "live") -> dict:
        self._set(sid, at, at, text)
        return self.emit(session, "edit.insert", self.person, {"statement_id": sid, "start": at, "end": at}, text,
                         {"length": len(text)}, fidelity)

    def delete(self, session: str, sid: str, start: int, end: int) -> dict:
        removed = self._set(sid, start, end, "")
        return self.emit(session, "edit.delete", self.person, {"statement_id": sid, "start": start, "end": end}, removed, {})

    def replace(self, session: str, sid: str, start: int, end: int, text: str) -> dict:
        removed = self._set(sid, start, end, text)
        return self.emit(session, "edit.replace", self.person, {"statement_id": sid, "start": start, "end": end}, text,
                         {"length": len(text), "removed_hash": self.keyed(removed)})

    def paste(self, session: str, sid: str, at: int, text: str, fidelity: str = "live") -> dict:
        self._set(sid, at, at, text)
        return self.emit(session, "import.paste", self.person, {"statement_id": sid, "start": at, "end": at}, text,
                         {"length": len(text), "removed_hash": None, "source": {"kind": "web", "ref_hash": self.keyed("https://example.org/page")}},
                         fidelity)

    def generate(self, session: str, sid: str, at: int, text: str) -> dict:
        self._set(sid, at, at, text)
        return self.emit(session, "tool.generate", self.tool, {"statement_id": sid, "start": at, "end": at}, text,
                         {"length": len(text), "removed_hash": None, "prompt_hash": self.keyed("prompt"), "accepted_by": "person:0f1x"},
                         "tool_report")

    def tool_edit(self, session: str, sid: str, start: int, end: int, text: str) -> dict:
        removed = self._set(sid, start, end, text)
        return self.emit(session, "tool.edit", self.tool, {"statement_id": sid, "start": start, "end": end}, text or None,
                         {"length": len(text), "removed_hash": self.keyed(removed), "prompt_hash": None, "accepted_by": "person:0f1x"},
                         "tool_report")

    def move(self, session: str, sid: str, start: int, end: int, to_sid: str, offset: int) -> dict:
        moved = self._set(sid, start, end, "")
        self._set(to_sid, offset, offset, moved)
        return self.emit(session, "edit.move", self.person, {"statement_id": sid, "start": start, "end": end}, moved,
                         {"to": {"statement_id": to_sid, "offset": offset}})

    def split(self, session: str, sid: str, at: int, new_sid: str, section: str | None = None, ref: str | None = None) -> dict:
        s = self.stmt(sid)
        tail = s["text"][at:]
        s["text"] = s["text"][:at]
        idx = self.statements.index(s)
        self.statements.insert(idx + 1, {"statement_id": new_sid, "section_id": section or s["section_id"], "text": tail})
        return self.emit(session, "statement.split", self.person, {"statement_id": sid, "start": at, "end": at}, None,
                         {"new_statement_id": new_sid, "section_id": section, "section_ref": ref})

    def merge(self, session: str, sid: str, merged: str) -> dict:
        s, m = self.stmt(sid), self.stmt(merged)
        at = len(s["text"])
        s["text"] += m["text"]
        self.statements.remove(m)
        return self.emit(session, "statement.merge", self.person, {"statement_id": sid, "start": at, "end": at}, None,
                         {"merged_statement_id": merged})

    def bind(self, session: str, sid: str, start: int, end: int, binding: str) -> dict:
        span = self.stmt(sid)["text"][start:end]
        return self.emit(session, "evidence.bind", self.person, {"statement_id": sid, "start": start, "end": end}, span,
                         {"binding_id": uuid_from(f"{self.name} binding {binding}"),
                          "source": {"ref": "url:https://example.org/source", "visibility": "public"},
                          "date": {"kind": "retrieved", "value": "2026-10-15"}, "licence": "CC-BY-4.0",
                          "page_hash": hashlib.sha256(b"source page").hexdigest(),
                          "quoted_span": {"quote_hash": hashlib.sha256(b"quoted passage").hexdigest(), "locator": "paragraph 2"}})

    def unbind(self, session: str, binding: str) -> dict:
        return self.emit(session, "evidence.unbind", self.person, None, None,
                         {"binding_id": uuid_from(f"{self.name} binding {binding}"), "reason": "superseded"})

    def sign(self, session: str, exported: bytes, media_type: str = "text/plain") -> dict:
        return self.emit(session, "sign", self.person, None, None,
                         {"exported": {"sha256": hashlib.sha256(exported).hexdigest(), "media_type": media_type, "byte_length": len(exported)},
                          "declaration_hash": self.keyed("I declare this is how the document was written.")})


EXPORTED = b"FundingMachine verifier fixture: an exported document, as signed.\n"


def basic_chain() -> Writer:
    """Two sessions, every event type: typing, paste, tool generation and edit,
    replace, delete, move, a split into a second section, evidence bound and
    unbound, a merge, a snapshot-diff insert, and the signature."""
    w = Writer("fm-verify chain")
    w.open("s1", ("st-1", "approach", "call:example/approach"))
    w.insert("s1", "st-1", 0, "We will measure the effect on twelve sites.")
    w.split("s1", "st-1", 43, "st-2")
    w.paste("s1", "st-2", 0, " Prior work found a small effect.")
    w.generate("s1", "st-2", 33, " The design follows a stepped wedge.")
    w.tool_edit("s1", "st-2", 34, 37, "Its")
    w.replace("s1", "st-1", 32, 38, "fifteen")
    w.delete("s1", "st-1", 0, 3)
    w.insert("s1", "st-1", 0, "Our team")
    w.move("s1", "st-1", 0, 9, "st-2", 0)
    w.bind("s1", "st-2", 9, 41, "b1")
    w.bind("s1", "st-2", 0, 9, "b2")
    w.unbind("s1", "b2")
    w.close("s1")
    w.open("s2")
    w.split("s2", "st-2", 41, "st-3", "team", "call:example/team")
    w.insert("s2", "st-3", 0, "The lead has run two such trials.", fidelity="snapshot_diff")
    w.merge("s2", "st-1", "st-2")
    w.insert("s2", "st-1", 0, "In short: ")
    w.sign("s2", EXPORTED)
    return w


def resign(ev: dict, key: Ed25519PrivateKey) -> dict:
    return sign_event(ev, key)


def rechain(events: list[dict], keys: dict[str, Ed25519PrivateKey]) -> list[dict]:
    """Renumber, relink and re-sign a list of events, as an attacker holding the client keys could."""
    out = []
    for i, ev in enumerate(events):
        ev = dict(ev)
        ev["seq"] = i + 1
        ev["prev_hash"] = event_hash(out[-1]) if out else "0" * 64
        out.append(sign_event(ev, keys[ev["session_id"]]))
    return out


def build(fix: Path) -> Writer:
    out = fix / "chain"
    if out.exists():
        import shutil

        shutil.rmtree(out)
    out.mkdir(parents=True)
    w = basic_chain()
    keys = {sid: key for sid, key in w.sessions.values()}
    events = w.events

    def case(name: str, evs: list[dict], expected: dict) -> None:
        if expected["outcome"] == "invalid":
            expected = {**expected, "failing": ["chain.rules"]}
        d = out / name
        d.mkdir()
        (d / "events.json").write_text(json.dumps({"contract": "ledger-event/v0", "events": evs}, indent=1) + "\n", encoding="utf-8")
        (d / "expected.json").write_text(json.dumps(expected, indent=1) + "\n", encoding="utf-8")

    case("valid", events, {"description": "Two sessions, every event type, ending in a sign event", "outcome": "valid",
                           "head": event_hash(events[-1]), "events": len(events)})

    t = copy.deepcopy(events)
    t[4]["content_hash"] = w.keyed(" The design follows a parallel design.")
    case("tampered-content", t, {"description": "A tool event's content hash changed after signing", "outcome": "invalid",
                                 "index": 4, "code": "bad_signature"})

    t = copy.deepcopy(events)
    t[4]["actor"] = dict(Writer.person)
    case("tool-relabelled-as-person", t, {"description": "Tool-generated text relabelled as typed by a person", "outcome": "invalid",
                                          "index": 4, "code": "schema"})

    t = copy.deepcopy(events)
    t[6] = resign(dict(t[6], ts="2026-10-16T07:59:00.000Z"), keys[t[6]["session_id"]])
    t = t[:7] + rechain_tail(t[6], t[7:], keys)
    case("back-dated-event", t, {"description": "One event re-signed with a time before its predecessor", "outcome": "invalid",
                                 "index": 6, "code": "ts_backwards"})

    shifted = rechain([dict(e, ts=e["ts"].replace("2026-10-16T08", "2026-10-15T08")) for e in events], keys)
    case("back-dated-consistently", shifted,
         {"description": "Every event moved a day earlier and re-signed with the client keys: the chain alone cannot tell; only an anchor bounds its time",
          "outcome": "valid", "head": event_hash(shifted[-1]), "events": len(shifted)})

    t = copy.deepcopy(events)
    t[2], t[3] = t[3], t[2]
    case("re-ordered", t, {"description": "Two events swapped", "outcome": "invalid", "index": 2, "code": "seq_gap"})

    swapped = events[:2] + [events[3], events[2]] + events[4:]
    case("re-ordered-and-re-signed", rechain(swapped, keys),
         {"description": "Two events swapped, renumbered, relinked and re-signed: the paste now lands in a statement not yet split off",
          "outcome": "invalid", "index": 2, "code": "statement_unknown"})

    t = copy.deepcopy(events)
    del t[9]
    case("event-dropped", t, {"description": "One event removed", "outcome": "invalid", "index": 9, "code": "seq_gap"})

    t = copy.deepcopy(events)
    t[16] = resign(dict(t[16], session_id=t[0]["session_id"]), keys[t[0]["session_id"]])
    t = t[:17] + rechain_tail(t[16], t[17:], keys)
    case("after-session-close", t, {"description": "An event in the first session after it was closed", "outcome": "invalid",
                                    "index": 16, "code": "session_closed"})

    t = copy.deepcopy(events)
    t[1] = resign(t[1], keys[events[15]["session_id"]])
    case("signed-with-another-sessions-key", t, {"description": "An event signed with the second session's key", "outcome": "invalid",
                                                  "index": 1, "code": "key_mismatch"})

    disclosure = {"doc_key_hex": w.doc_key.hex(), "steps": [{"seq": s, "content_text": t} for s, t in sorted(w.texts.items())]}

    def disclosure_case(name: str, disc: dict, expected: dict) -> None:
        case(name, events, expected)
        (out / name / "disclosure.json").write_text(json.dumps(disc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        exp = json.loads((out / name / "expected.json").read_text())
        exp["disclosure"] = "disclosure.json"
        if exp["outcome"] == "invalid":
            exp["failing"] = expected.get("failing", [])
        (out / name / "expected.json").write_text(json.dumps(exp, indent=1) + "\n", encoding="utf-8")

    disclosure_case("disclosure-valid", disclosure,
                    {"description": "The document key and the inserted texts, disclosed: every keyed hash in the chain is reproduced",
                     "outcome": "valid"})
    altered = copy.deepcopy(disclosure)
    altered["steps"][0]["content_text"] = altered["steps"][0]["content_text"].replace("twelve", "eleven")
    disclosure_case("disclosure-altered-text", altered,
                    {"description": "One disclosed text differs by a word from what the chain recorded", "outcome": "invalid",
                     "failing": ["disclosure.replay"]})
    disclosure_case("disclosure-wrong-key", dict(disclosure, doc_key_hex="11" * 32),
                    {"description": "A key other than the one committed at genesis", "outcome": "invalid", "failing": ["disclosure.key"]})

    t = copy.deepcopy(events)
    t[1] = dict(t[1], payload=dict(t[1]["payload"], text="We will measure the effect on twelve sites."))
    case("text-in-payload", t, {"description": "An event carrying the text itself: text never leaves the tenant", "outcome": "invalid",
                                "index": 1, "code": "schema"})
    return w


def rechain_tail(prev: dict, tail: list[dict], keys: dict) -> list[dict]:
    out, last = [], prev
    for ev in tail:
        ev = sign_event(dict(ev, prev_hash=event_hash(last)), keys[ev["session_id"]])
        out.append(ev)
        last = ev
    return out
