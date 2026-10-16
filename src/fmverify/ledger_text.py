"""Checking a chain's keyed hashes against disclosed text.

docs/EVENT_CONTRACT.md: tenant text is hashed with HMAC-SHA-256 under the
document key, which never goes to the ledger; "a holder of the document key
and the text can" check every content_hash, removed_hash, doc_hash and
length "by replaying the chain". This module does that replay.

The disclosure is the document key and, per event, the text it inserted, in
the shape of the Ledger session's journal fixtures:
``{"doc_key_hex": ..., "signer_name"?: ..., "steps": [{"seq", "content_text", ...}]}``.
Removed and moved text, and evidence spans, follow from the replayed
document. Where a step also gives them (``content_text`` of a delete, move or
binding, ``removed_text``, ``doc_view``), they are compared too, and a step's
``type``, where given, must be its event's. Two steps for one event are a
failure; text no hash covers (a step for no event, a quotation on a sign
event without a declaration) is a warning naming it. A ``capture.resync``
(v0.1) takes its texts from the step's ``resync_text``
(``changed_and_added``, in that order; ``removed``, compared when given). A step's ``quote_text`` is checked against an evidence binding's
``quote_hash`` (plain SHA-256 for a public source, keyed for a tenant's
private one) or a sign event's ``declaration_hash``; ``signer_name`` against
a sign event's ``signer_name_hash``.

The verdict never repeats the text: only counts and the first mismatch.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from . import jcs
from .hashes import sha256


def sha256_hex(text: str) -> str:
    return sha256(text.encode("utf-8")).hex()
from .verdict import Check, Outcome, Status, guarded, make_verdict

INSERTING = {"edit.insert", "edit.replace", "import.paste", "tool.generate", "tool.edit"}
# The step fields that carry text a hash may cover; removed_text and doc_view
# are compared with the replay wherever they are given.
TEXT_FIELDS = ("content_text", "resync_text", "quote_text")

LIMITS = [
    "who typed or generated the text: the replay shows only that this text is what the chain's hashes recorded",
    "that the text is true, original, or free of AI assistance",
    "anything about prompts or paste sources, whose keyed hashes need texts a journal does not hold",
]


class Mismatch(Exception):
    pass


def _h(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


@guarded("text-disclosure", "disclosure.replay", "disclosure", LIMITS)
def verify(events: list, disclosure: dict, subject: str | None = None, checked_at: str | None = None):
    """Replay ``events`` (already valid under the chain rules) with the
    disclosed key and texts."""
    from . import ledger_events

    chain = ledger_events.validate_chain(events)
    checks: list[Check] = []
    bad = {o: "The disclosed text does not reproduce the chain's hashes." for o in Outcome}
    subject = subject or f"text disclosed for document {events[0].get('doc_id') if events else None}"
    if not chain.ok:
        checks.append(Check("disclosure.chain", Status.FAIL, f"the chain itself breaks the rule '{chain.code}' at event {chain.index}"))
        return make_verdict("text-disclosure", subject, checks, bad, LIMITS, checked_at)
    key = bytes.fromhex(disclosure["doc_key_hex"])
    if len(key) != 32:
        raise ValueError("the document key is not 32 bytes")
    raw_steps = disclosure.get("steps", [])
    if not isinstance(raw_steps, list):
        raise ValueError("the disclosure's steps are not a list")
    steps: dict[Any, dict] = {}
    twice = []
    for step in raw_steps:
        if step["seq"] in steps:
            twice.append(step["seq"])
        steps[step["seq"]] = step
    if twice:
        checks.append(Check("disclosure.steps", Status.FAIL, "the disclosure gives more than one step for an event",
                            reasons=[f"seq {', '.join(str(x) for x in sorted(set(twice), key=str))}: a reader cannot tell which text "
                                     "is the one disclosed, and only one could be checked"]))
        return make_verdict("text-disclosure", subject, checks, bad, LIMITS, checked_at)
    genesis = events[0]["payload"]["genesis"]
    if hashlib.sha256(key).hexdigest() != genesis["key_commitment"]:
        checks.append(Check("disclosure.key", Status.FAIL, "the disclosed key is not the document's key",
                            reasons=["its SHA-256 differs from the key commitment in the first event"]))
        return make_verdict("text-disclosure", subject, checks, bad, LIMITS, checked_at)
    checks.append(Check("disclosure.key", Status.PASS, "the disclosed key matches the key commitment in the first event"))

    view: list[dict] = []  # {"section_id", "statement_id", "text"}
    counts = {"content": 0, "removed": 0, "doc": 0, "views": 0, "quotes": 0, "declarations": 0, "signer_names": 0}
    unchecked = {"quotes": 0, "declarations": 0, "signer_names": 0}

    used: set[tuple[Any, str]] = set()  # (seq, field): disclosed text a hash in the chain covers

    def find(sid: str) -> dict:
        return next(s for s in view if s["statement_id"] == sid)

    try:
        for ev in events:
            seq, t, r, p = ev["seq"], ev["type"], ev["range"], ev["payload"]
            step = steps.get(seq, {})
            if "type" in step and step["type"] != t:
                raise Mismatch(f"seq {seq}: the disclosure's step is a {step['type']}, the chain's event a {t}")
            if t == "session.open" and "genesis" in p:
                g = p["genesis"]
                view.append({"section_id": g["section_id"], "statement_id": g["statement_id"], "text": ""})
            removed = None
            if r is not None and t not in ("statement.split", "statement.merge"):
                s = find(r["statement_id"])
                removed = s["text"][r["start"]:r["end"]]
            if t in INSERTING:
                used.add((seq, "content_text"))
                new = step.get("content_text")
                if new is None:
                    if t == "tool.edit" and p["length"] == 0:
                        new = ""
                    else:
                        raise Mismatch(f"seq {seq}: the disclosure gives no text for this {t}")
                if len(new) != p["length"]:
                    raise Mismatch(f"seq {seq}: the disclosed text is {len(new)} code points, the event says {p['length']}")
                if ev["content_hash"] is not None:
                    if _h(key, new) != ev["content_hash"]:
                        raise Mismatch(f"seq {seq}: the disclosed text does not give the event's content_hash")
                    counts["content"] += 1
                if p.get("removed_hash") is not None:
                    if _h(key, removed) != p["removed_hash"]:
                        raise Mismatch(f"seq {seq}: the replaced text does not give the event's removed_hash")
                    counts["removed"] += 1
                s = find(r["statement_id"])
                s["text"] = s["text"][:r["start"]] + new + s["text"][r["end"]:]
            elif t in ("edit.delete", "edit.move", "evidence.bind"):
                used.add((seq, "content_text"))
                if step.get("content_text") is not None and step["content_text"] != removed:
                    raise Mismatch(f"seq {seq}: the disclosure's text for this {t} differs from the replayed document")
                if _h(key, removed) != ev["content_hash"]:
                    raise Mismatch(f"seq {seq}: the {'removed' if t == 'edit.delete' else 'moved' if t == 'edit.move' else 'bound'} "
                                   "text does not give the event's content_hash")
                counts["content"] += 1
                if t == "edit.delete":
                    s = find(r["statement_id"])
                    s["text"] = s["text"][:r["start"]] + s["text"][r["end"]:]
                elif t == "edit.move":
                    s = find(r["statement_id"])
                    s["text"] = s["text"][:r["start"]] + s["text"][r["end"]:]
                    d = find(p["to"]["statement_id"])
                    o = p["to"]["offset"]
                    d["text"] = d["text"][:o] + removed + d["text"][o:]
            elif t == "statement.split":
                s = find(r["statement_id"])
                idx = view.index(s)
                tail = s["text"][r["start"]:]
                s["text"] = s["text"][:r["start"]]
                view.insert(idx + 1, {"section_id": p["section_id"] or s["section_id"], "statement_id": p["new_statement_id"], "text": tail})
            elif t == "statement.merge":
                s = find(r["statement_id"])
                m = find(p["merged_statement_id"])
                s["text"] += m["text"]
                view.remove(m)
            elif t == "capture.resync":
                used.add((seq, "resync_text"))
                rt = step.get("resync_text") or {}
                texts = list(rt.get("changed_and_added") or [])
                if len(texts) != len(p["changed"]) + len(p["added"]):
                    raise Mismatch(f"seq {seq}: the disclosure gives {len(texts)} resync texts, the event has "
                                   f"{len(p['changed']) + len(p['added'])} changed and added entries")
                given = rt.get("removed")
                for k, x in enumerate(p["removed"]):
                    s = find(x["statement_id"])
                    if _h(key, s["text"]) != x["removed_hash"]:
                        raise Mismatch(f"seq {seq}: removed statement {k} does not give its removed_hash")
                    if given is not None and (k >= len(given) or given[k] != s["text"]):
                        raise Mismatch(f"seq {seq}: the disclosure's removed text {k} differs from the replayed document")
                    counts["removed"] += 1
                    view.remove(s)
                for k, x in enumerate(p["changed"]):
                    s, new = find(x["statement_id"]), texts[k]
                    old = s["text"][x["start"]:x["end"]]
                    if x["removed_hash"] is not None:
                        if _h(key, old) != x["removed_hash"]:
                            raise Mismatch(f"seq {seq}: changed entry {k}'s replaced text does not give its removed_hash")
                        counts["removed"] += 1
                    if len(new) != x["length"]:
                        raise Mismatch(f"seq {seq}: changed entry {k}'s text is {len(new)} code points, the event says {x['length']}")
                    if x["content_hash"] is not None:
                        if _h(key, new) != x["content_hash"]:
                            raise Mismatch(f"seq {seq}: changed entry {k}'s text does not give its content_hash")
                        counts["content"] += 1
                    s["text"] = s["text"][:x["start"]] + new + s["text"][x["end"]:]
                for k, x in enumerate(p["added"]):
                    new = texts[len(p["changed"]) + k]
                    if len(new) != x["length"]:
                        raise Mismatch(f"seq {seq}: added entry {k}'s text is {len(new)} code points, the event says {x['length']}")
                    if x["content_hash"] is not None:
                        if _h(key, new) != x["content_hash"]:
                            raise Mismatch(f"seq {seq}: added entry {k}'s text does not give its content_hash")
                        counts["content"] += 1
                    at = 0 if x["after"] is None else view.index(find(x["after"])) + 1
                    view.insert(at, {"section_id": x["section_id"], "statement_id": x["statement_id"], "text": new})
            if t == "evidence.bind":
                used.add((seq, "quote_text"))
                q = step.get("quote_text")
                want = p["quoted_span"]["quote_hash"]
                if q is None:
                    unchecked["quotes"] += 1
                else:
                    got = sha256_hex(q) if p["source"]["visibility"] == "public" else _h(key, q)
                    if got != want:
                        raise Mismatch(f"seq {seq}: the disclosed quotation does not give the binding's quote_hash")
                    counts["quotes"] += 1
            if t == "sign":
                q = step.get("quote_text")
                if p["declaration_hash"] is not None:
                    used.add((seq, "quote_text"))
                    if q is None:
                        unchecked["declarations"] += 1
                    elif _h(key, q) != p["declaration_hash"]:
                        raise Mismatch(f"seq {seq}: the disclosed declaration does not give the sign event's declaration_hash")
                    else:
                        counts["declarations"] += 1
                if "signer_name_hash" in p:
                    used.add((None, "signer_name"))
                    name = disclosure.get("signer_name")
                    if name is None:
                        unchecked["signer_names"] += 1
                    elif _h(key, name) != p["signer_name_hash"]:
                        raise Mismatch(f"seq {seq}: the disclosed signer's name does not give the sign event's signer_name_hash")
                    else:
                        counts["signer_names"] += 1
            if "removed_text" in step and step["removed_text"] is not None and step["removed_text"] != removed:
                raise Mismatch(f"seq {seq}: the disclosure's removed text differs from the replayed document")
            current = [{"section_id": s["section_id"], "statement_id": s["statement_id"], "text": s["text"]} for s in view]
            if hmac.new(key, jcs.dumps(current), hashlib.sha256).hexdigest() != ev["doc_hash"]:
                raise Mismatch(f"seq {seq}: the replayed document does not give the event's doc_hash")
            counts["doc"] += 1
            if "doc_view" in step:
                if [{k: x[k] for k in ("statement_id", "section_id", "text")} for x in step["doc_view"]] != \
                        [{k: x[k] for k in ("statement_id", "section_id", "text")} for x in current]:
                    raise Mismatch(f"seq {seq}: the disclosure's document view differs from the replayed document")
                counts["views"] += 1
    except Mismatch as exc:
        checks.append(Check("disclosure.replay", Status.FAIL, "the disclosed text does not reproduce the chain's hashes", reasons=[str(exc)]))
        return make_verdict("text-disclosure", subject, checks, bad, LIMITS, checked_at)
    total = sum(len(s["text"]) for s in view)
    def n(k: str, noun: str) -> str:
        return f"{counts[k]} {noun} hash{'' if counts[k] == 1 else 'es'}"

    extra = [n(k, label) for k, label in (("quotes", "quotation"), ("declarations", "declaration"), ("signer_names", "signer name"))
             if counts[k]]
    checks.append(Check("disclosure.replay", Status.PASS,
                        f"replaying {len(events)} events with the disclosed text reproduces {n('content', 'content')}, "
                        f"{n('removed', 'removed-text')} and {n('doc', 'document')}"
                        + (f", and {', '.join(extra)}" if extra else ""),
                        reasons=[f"{counts['views']} document views given by the disclosure match the replay",
                                 f"the document ends with {len(view)} statements and {total} characters"],
                        data=counts | {"statements": len(view), "characters": total}))
    left = [f"{c} {label}" for k, label in (("quotes", "quotation"), ("declarations", "declaration"), ("signer_names", "signer name"))
            for c in [unchecked[k]] if c]
    seqs = {ev["seq"] for ev in events}
    unused = []
    for step in raw_steps:
        fields = [f for f in TEXT_FIELDS if step.get(f) not in (None, "") and (step["seq"], f) not in used]
        if fields:
            unused.append(f"seq {step['seq']} ({', '.join(fields)}" + ("; no event has this seq" if step["seq"] not in seqs else "") + ")")
    if disclosure.get("signer_name") not in (None, "") and (None, "signer_name") not in used:
        unused.append("signer_name (no sign event carries a signer_name_hash)")
    if unused:
        checks.append(Check("disclosure.unused", Status.WARN,
                            "the disclosure carries text that no hash in the chain covers: it was not checked and is not part of the record",
                            reasons=unused))
    checks.append(Check("disclosure.other_hashes", Status.NOT_CHECKED,
                        "prompt and paste-source hashes were not checked: a journal does not hold their texts"
                        + (f"; nor {', '.join(left)} hashes, whose texts this disclosure does not give" if left else ""),
                        required=False))
    statements = {
        Outcome.VALID: (f"The disclosed key and text reproduce every content, removed-text and document hash in the {len(events)} events: "
                        "this text is what the chain recorded, event by event."),
        Outcome.INVALID: "The disclosed text does not reproduce the chain's hashes.",
        Outcome.INDETERMINATE: "The disclosure could not be checked.",
    }
    return make_verdict("text-disclosure", subject, checks, statements, LIMITS, checked_at)


def disclosure_from_writer(doc_key: bytes, texts: dict[int, str]) -> dict[str, Any]:
    return {"doc_key_hex": doc_key.hex(), "steps": [{"seq": s, "content_text": t} for s, t in sorted(texts.items())]}
