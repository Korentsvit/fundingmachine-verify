"""Checking a chain's keyed hashes against disclosed text.

docs/EVENT_CONTRACT.md: tenant text is hashed with HMAC-SHA-256 under the
document key, which never goes to the ledger; "a holder of the document key
and the text can" check every content_hash, removed_hash, doc_hash and
length "by replaying the chain". This module does that replay.

The disclosure is the document key and, per event, the text it inserted, in
the shape of the Ledger session's journal fixture:
``{"doc_key_hex": ..., "steps": [{"seq", "content_text", ...}]}``. Removed
and moved text, and evidence spans, follow from the replayed document. Where
a step also gives ``removed_text`` or ``doc_view``, they are compared too.

The verdict never repeats the text: only counts and the first mismatch.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from . import jcs
from .verdict import Check, Outcome, Status, guarded, make_verdict

INSERTING = {"edit.insert", "edit.replace", "import.paste", "tool.generate", "tool.edit"}

LIMITS = [
    "who typed or generated the text: the replay shows only that this text is what the chain's hashes recorded",
    "that the text is true, original, or free of AI assistance",
    "anything about prompts, paste sources or declarations, whose keyed hashes need texts not disclosed here",
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
    steps = {s["seq"]: s for s in disclosure.get("steps", [])}
    genesis = events[0]["payload"]["genesis"]
    if hashlib.sha256(key).hexdigest() != genesis["key_commitment"]:
        checks.append(Check("disclosure.key", Status.FAIL, "the disclosed key is not the document's key",
                            reasons=["its SHA-256 differs from the key commitment in the first event"]))
        return make_verdict("text-disclosure", subject, checks, bad, LIMITS, checked_at)
    checks.append(Check("disclosure.key", Status.PASS, "the disclosed key matches the key commitment in the first event"))

    view: list[dict] = []  # {"section_id", "statement_id", "text"}
    counts = {"content": 0, "removed": 0, "doc": 0, "views": 0}

    def find(sid: str) -> dict:
        return next(s for s in view if s["statement_id"] == sid)

    try:
        for ev in events:
            seq, t, r, p = ev["seq"], ev["type"], ev["range"], ev["payload"]
            step = steps.get(seq, {})
            if t == "session.open" and "genesis" in p:
                g = p["genesis"]
                view.append({"section_id": g["section_id"], "statement_id": g["statement_id"], "text": ""})
            removed = None
            if r is not None and t not in ("statement.split", "statement.merge"):
                s = find(r["statement_id"])
                removed = s["text"][r["start"]:r["end"]]
            if t in INSERTING:
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
    checks.append(Check("disclosure.replay", Status.PASS,
                        f"replaying {len(events)} events with the disclosed text reproduces {counts['content']} content hashes, "
                        f"{counts['removed']} removed-text hashes and {counts['doc']} document hashes",
                        reasons=[f"{counts['views']} document views given by the disclosure match the replay",
                                 f"the document ends with {len(view)} statements and {total} characters"],
                        data=counts | {"statements": len(view), "characters": total}))
    checks.append(Check("disclosure.other_hashes", Status.NOT_CHECKED,
                        "prompt, paste-source and declaration hashes were not checked: their texts are not part of this disclosure",
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
