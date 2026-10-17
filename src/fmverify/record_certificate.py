"""Provenance Ledger record certificates (``record-certificate/v0``).

Taken from the Ledger's ``docs/RECORD_CERTIFICATE.md`` and its JSON Schema
(``schemas/record-certificate-v0.schema.json``), published on 17 October 2026.
A record certificate is a signed statement of one document's record: its
record id, its event count and head, the sealed hour whose root holds the
head, that hour's anchor across tenants with its RFC 3161 and OpenTimestamps
proofs, and the Bitcoin block the anchor reached, every hash link written out
as SHA-256 steps (x becomes SHA-256(prepend || x || append)).

Two files: ``certificate.json``, the RFC 8785 form of the certificate, and
``certificate.sig``, the issuer's Ed25519 signature of exactly those bytes.
The PDF form carries both as attachments.

Each check is reported on its own, and only checks that ran are reported as
run: the signature and form; the scope statement; the head's inclusion in
the hour's root; the hour's signed root record; its inclusion in the
anchored root; each RFC 3161 token; the OpenTimestamps path to the Bitcoin
block; the block header; and the block at that height from a source of the
reader's own. With the document's events, the record's own statements
(record id, counts, head) are checked against the chain too. The printed
shell commands (``procedure``, ``verify.sh``) are not run here.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import re
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, ots, rfc3161
from .bitcoin import MAINNET, HeaderError, HeaderSource, Network, check_pow, lookup_header, parse_header
from .hashes import sha256
from .verdict import Check, Outcome, Status, Verdict, guarded, make_verdict

CONTRACT = "record-certificate/v0"
SCOPE_STATEMENT = ("This record shows how this document was written in this environment; it does not detect AI, "
                   "certify originality, or prove what the author consulted elsewhere.")
LIMITS = [
    "who wrote the document, or how: a record certificate states the record's shape, not its authorship",
    "that the document's content is true, original, or free of AI assistance",
    "that the issuer's key is the tenant's: compare it with a key the tenant publishes somewhere you trust",
    "that the printed commands (procedure, verify.sh) do what this verdict did: they were not run or compared here",
]

HEX64 = re.compile(r"[0-9a-f]{64}")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
STEP_HEX = re.compile(r"(?:[0-9a-f]{2})*")

# The fields of record-certificate/v0, as its schema lists them: every one required, no other allowed.
FIELDS = {
    "": {"contract", "certificate_id", "issued_at", "scope_statement", "issuer", "record", "hour", "anchor", "procedure"},
    "issuer": {"name", "public_key", "key_id"},
    "record": {"record_id", "tenant", "events", "sessions", "event_contracts", "head"},
    "record.head": {"seq", "event_hash", "ts", "received_at"},
    "hour": {"window", "root", "size", "leaf_index", "head_to_root", "root_record_b64", "root_record_sha256"},
    "hour.window": {"start", "end"},
    "anchor": {"root", "size", "leaf_index", "record_to_anchor", "rfc3161", "opentimestamps_b64", "bitcoin"},
    "anchor.bitcoin": {"height", "block_hash", "time", "header", "merkle_root", "anchor_to_merkle_root"},
}
ROOT_FIELDS = {"contract", "tenant_id", "window", "size", "root", "prev_root", "key_id", "sig"}


def _at(c: dict, path: str) -> Any:
    for k in path.split(".") if path else []:
        c = c[k]
    return c


def _int(v: Any, least: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and least <= v <= 2**53 - 1


def _events(n: object) -> str:
    return f"{n} event" if n == 1 else f"{n} events"


def shape_problems(c: Any) -> list[str]:
    """Where the certificate departs from the schema of record-certificate/v0."""
    if not isinstance(c, dict):
        return ["the certificate is not a JSON object"]
    problems = []
    for path, want in FIELDS.items():
        try:
            obj = _at(c, path)
        except (KeyError, TypeError):
            continue  # reported at its parent
        if not isinstance(obj, dict):
            problems.append(f"{path or 'the certificate'} is not an object")
            continue
        if set(obj) != want:
            missing, extra = sorted(want - set(obj)), sorted(set(obj) - want)
            problems.append(f"{path or 'the certificate'}: " + "; ".join(
                ([f"missing {', '.join(missing)}"] if missing else []) + ([f"not in the contract: {', '.join(extra)}"] if extra else [])))
    if problems:
        return problems

    def need(ok: bool, what: str) -> None:
        if not ok:
            problems.append(what)

    def steps_ok(v: Any) -> bool:
        return isinstance(v, list) and all(isinstance(s, dict) and set(s) == {"prepend", "append"} and all(
            isinstance(s[k], str) and STEP_HEX.fullmatch(s[k]) for k in s) for s in v)

    need(isinstance(c["certificate_id"], str) and re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", c["certificate_id"]) is not None,
         "certificate_id is not a urn:uuid of a random UUID")
    need(isinstance(c["issued_at"], str) and STAMP.fullmatch(c["issued_at"]) is not None, "issued_at is not RFC 3339 UTC with milliseconds")
    i, r, h, a = c["issuer"], c["record"], c["hour"], c["anchor"]
    need(i["name"] == "Provenance Ledger", "issuer.name is not \"Provenance Ledger\"")
    for k in ("public_key", "key_id"):
        need(isinstance(i[k], str) and HEX64.fullmatch(i[k]) is not None, f"issuer.{k} is not 32 bytes in hex")
    need(isinstance(r["record_id"], str) and HEX64.fullmatch(r["record_id"]) is not None, "record.record_id is not a SHA-256 in hex")
    need(isinstance(r["tenant"], str) and re.fullmatch(r"tp-[0-9a-f]{32}", r["tenant"]) is not None, "record.tenant is not a tenant pseudonym")
    need(_int(r["events"], 1) and _int(r["sessions"], 0), "record.events or record.sessions is not a whole number in range")
    ec = r["event_contracts"]
    need(isinstance(ec, list) and len(ec) >= 1 and len(set(map(str, ec))) == len(ec)
         and all(isinstance(x, str) and re.fullmatch(r"ledger-event/v\d+(\.\d+)?", x) for x in ec),
         "record.event_contracts is not a list of distinct ledger-event versions")
    hd = r["head"]
    need(_int(hd["seq"], 1) and isinstance(hd["event_hash"], str) and HEX64.fullmatch(hd["event_hash"]) is not None
         and isinstance(hd["ts"], str) and isinstance(hd["received_at"], str) and STAMP.fullmatch(hd["received_at"]) is not None,
         "record.head does not hold a seq, an event hash, ts and received_at")
    need(all(isinstance(h["window"][k], str) and STAMP.fullmatch(h["window"][k]) for k in ("start", "end")), "hour.window is not two times")
    for part, names in (("hour", ("root", "root_record_sha256")), ("anchor", ("root",))):
        for k in names:
            need(isinstance(_at(c, part)[k], str) and HEX64.fullmatch(_at(c, part)[k]) is not None, f"{part}.{k} is not a SHA-256 in hex")
    for part in ("hour", "anchor"):
        p = _at(c, part)
        need(_int(p["size"], 1) and _int(p["leaf_index"], 0), f"{part}.size or {part}.leaf_index is not a whole number in range")
    need(steps_ok(h["head_to_root"]) and steps_ok(a["record_to_anchor"]) and steps_ok(a["bitcoin"]["anchor_to_merkle_root"]),
         "a list of steps is not a list of {prepend, append} in hex")
    need(isinstance(h["root_record_b64"], str) and B64.fullmatch(h["root_record_b64"]) is not None, "hour.root_record_b64 is not base64")
    need(isinstance(a["opentimestamps_b64"], str) and B64.fullmatch(a["opentimestamps_b64"]) is not None, "anchor.opentimestamps_b64 is not base64")
    toks = a["rfc3161"]
    need(isinstance(toks, list) and len(toks) >= 2 and all(
        isinstance(t, dict) and set(t) == {"authority", "gen_time", "token_b64"} and isinstance(t["authority"], str) and t["authority"]
        and isinstance(t["gen_time"], str) and isinstance(t["token_b64"], str) and B64.fullmatch(t["token_b64"]) for t in toks),
         "anchor.rfc3161 is not two or more {authority, gen_time, token_b64}")
    b = a["bitcoin"]
    need(_int(b["height"], 0) and isinstance(b["time"], str) and STAMP.fullmatch(b["time"]) is not None
         and isinstance(b["header"], str) and re.fullmatch(r"[0-9a-f]{160}", b["header"]) is not None
         and all(isinstance(b[k], str) and HEX64.fullmatch(b[k]) for k in ("block_hash", "merkle_root")),
         "anchor.bitcoin does not hold a height, a block hash, a time, an 80-byte header and a merkle root")
    need(isinstance(c["procedure"], list) and len(c["procedure"]) >= 1 and all(isinstance(x, str) for x in c["procedure"]),
         "procedure is not a list of commands")
    return problems


def apply_steps(start: bytes, steps: Sequence[dict]) -> bytes:
    x = start
    for s in steps:
        x = sha256(bytes.fromhex(s["prepend"]) + x + bytes.fromhex(s["append"]))
    return x


def inclusion_steps(index: int, size: int, path: Sequence[str]) -> list[dict]:
    """RFC 9162, section 2.1.3.2, written as steps: the leaf, then each node, left or right."""
    if not 0 <= index < size:
        raise ValueError("the leaf index is outside the tree")
    steps = [{"prepend": "00", "append": ""}]
    fn, sn = index, size - 1
    for p in path:
        if sn == 0:
            raise ValueError("the audit path is longer than the tree")
        if fn % 2 == 1 or fn == sn:
            steps.append({"prepend": "01" + p, "append": ""})
            while fn % 2 == 0 and fn != 0:
                fn, sn = fn // 2, sn // 2
        else:
            steps.append({"prepend": "01", "append": p})
        fn, sn = fn // 2, sn // 2
    if sn != 0:
        raise ValueError("the audit path is shorter than the tree")
    return steps


def inclusion_problem(steps: Sequence[dict], index: int, size: int) -> str | None:
    """None if ``steps`` are exactly the RFC 9162 inclusion of leaf ``index`` in a tree of ``size``."""
    path = []
    for s in steps[1:]:
        node = s["prepend"][2:] if len(s["prepend"]) > 2 else s["append"]
        if len(node) != 64:
            return "a node step does not carry one 32-byte sibling"
        path.append(node)
    try:
        want = inclusion_steps(index, size, path)
    except ValueError as exc:
        return str(exc)
    if list(steps) != want:
        return f"the steps are not the inclusion of leaf {index} in a tree of {size}"
    return None


def fold(path: Sequence[ots.Op]) -> list[dict]:
    """An OpenTimestamps path as steps: each run of append and prepend folded into the SHA-256 after it."""
    steps, p, a = [], "", ""
    for op in path:
        if op.name == "append":
            a += op.arg.hex()
        elif op.name == "prepend":
            p = op.arg.hex() + p
        elif op.name == "sha256":
            steps.append({"prepend": p, "append": a})
            p = a = ""
        else:
            raise ValueError(f"the operation {op.name} cannot be written as a SHA-256 step")
    if p or a:
        raise ValueError("the path adds bytes after its last SHA-256")
    return steps


def _b64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _sub(cid: str, what: str, v: Verdict, extra: list[str]) -> Check:
    bad = [f"{x.id}: {x.summary}" for x in v.checks if x.status is Status.FAIL]
    if v.outcome is Outcome.VALID and not extra:
        return Check(cid, Status.PASS, v.statement, relies_on=v.relies_on)
    if v.outcome is Outcome.INDETERMINATE and not extra:
        return Check(cid, Status.NOT_CHECKED, f"{what} could not be checked: {v.statement}",
                     reasons=[f"{x.id}: {x.summary}" for x in v.checks if x.status is Status.NOT_CHECKED and x.required])
    return Check(cid, Status.FAIL, f"{what} does not hold", reasons=extra + bad)


def _same_instant(a: str, b: str) -> bool:
    def t(s: str) -> _dt.datetime:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    try:
        return t(a) == t(b)
    except ValueError:
        return False


def read_files(data: bytes, signature: bytes | None) -> tuple[bytes, bytes | None, str]:
    """certificate.json and certificate.sig from the bytes given: the JSON with its signature, or the PDF form with
    both attached."""
    if data.startswith(b"%PDF-"):
        from . import pdf

        return pdf.extract(data, "certificate.json"), pdf.extract(data, "certificate.sig"), "the PDF's attachments"
    return data, signature, "the files given"


INDEX_FIELDS = {"record_id", "tenant", "certificate_id", "certificate_sha256", "certificate_contract", "issued_at", "events",
                "head_seq", "hour", "anchor_root", "bitcoin"}


def read_index(data: bytes) -> list:
    """The entries of the public submission index: the JSON GET /api/submission-index answers (submission-index/v0),
    or certificates/index.jsonl, one entry per line."""
    text = data.decode("utf-8")
    try:
        doc = jcs.loads(text)
    except jcs.JcsError:
        return [jcs.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(doc, dict) and ("entries" in doc or "contract" in doc):
        if doc.get("contract") != "submission-index/v0":
            raise ValueError(f"the index's contract is {doc.get('contract')!r}, not submission-index/v0")
        if set(doc) != {"contract", "statement", "scope_statement", "entries"} or not isinstance(doc["entries"], list) \
                or not all(isinstance(doc[k], str) for k in ("statement", "scope_statement")):
            raise ValueError("the index is not a submission-index/v0 object: contract, statement and scope_statement (text) and entries")
        return doc["entries"]
    if isinstance(doc, dict):
        return [doc]
    if not isinstance(doc, list):
        raise ValueError("the index is neither a submission-index/v0 object nor a list of its entries")
    return doc


def index_check(entries: list, digest: str, c: dict) -> Check:
    """The certificate's entry in the public submission index (docs/RECORD_CERTIFICATE.md, The submission index):
    found by the certificate's SHA-256, it carries the index's fields only, and they are the certificate's."""
    mine = [e for e in entries if isinstance(e, dict) and e.get("certificate_sha256") == digest]
    if not mine:
        return Check("record_certificate.index", Status.WARN, f"the index given ({len(entries)} entries) lists no certificate with "
                     f"SHA-256 {digest}", reasons=["an index read before the certificate was issued does not list it"], required=False)
    if len(mine) > 1:
        return Check("record_certificate.index", Status.FAIL, f"the index lists the certificate {len(mine)} times")
    e, r, h, a = mine[0], c["record"], c["hour"], c["anchor"]
    reasons = []
    if set(e) != INDEX_FIELDS:
        reasons.append("the entry's fields are not those of submission-index/v0: "
                       + "; ".join(([f"missing {', '.join(sorted(INDEX_FIELDS - set(e)))}"] if INDEX_FIELDS - set(e) else [])
                                   + ([f"not in the contract: {', '.join(sorted(set(e) - INDEX_FIELDS))}"] if set(e) - INDEX_FIELDS else [])))
    want = {"record_id": r["record_id"], "tenant": r["tenant"], "certificate_id": c["certificate_id"], "certificate_contract": c["contract"],
            "issued_at": c["issued_at"], "events": r["events"], "head_seq": r["head"]["seq"], "hour": h["window"]["start"],
            "anchor_root": a["root"], "bitcoin": {"height": a["bitcoin"]["height"], "block_hash": a["bitcoin"]["block_hash"]}}
    for k, v in want.items():
        if k in e and e[k] != v:
            reasons.append(f"its {k} is {e[k]!r}, the certificate's is {v!r}")
    if reasons:
        return Check("record_certificate.index", Status.FAIL, "the index's entry for this certificate does not match it", reasons=reasons)
    times = [x.get("issued_at") if isinstance(x, dict) else None for x in entries]
    if not all(isinstance(x, str) for x in times) or times != sorted(times):
        return Check("record_certificate.index", Status.WARN,
                     "the index's entry for this certificate matches it, but the index is not in issue order",
                     reasons=["the contract lists each entry in issue order"], required=False)
    return Check("record_certificate.index", Status.PASS,
                 f"the index lists this certificate (SHA-256 {digest}) once, with the certificate's record, counts, hour, anchored root "
                 "and block, and no other field", required=False)


@guarded("record-certificate", "record_certificate.read", "record certificate", LIMITS)
def verify(
    data: bytes,
    signature: bytes | None = None,
    header_sources: Sequence[HeaderSource] = (),
    network: Network = MAINNET,
    roots=(),
    extra_certs=(),
    crls=(),
    events: list | None = None,
    index: list | bytes | None = None,
    subject: str | None = None,
    checked_at: str | None = None,
) -> Verdict:
    """``data`` is certificate.json (with ``signature``, the bytes of certificate.sig) or certificate.pdf; ``index``,
    the public submission index (its bytes, or its entries), checks the certificate's entry there."""
    checks: list[Check] = []
    raw, sig, where = read_files(data, signature)
    subject = subject or "record certificate"

    def done(statements: dict[Outcome, str] | None = None) -> Verdict:
        statements = statements or {o: f"The record certificate {('does not hold' if o is Outcome.INVALID else 'could not be checked')}: "
                                       "see the checks." for o in Outcome}
        return make_verdict("record-certificate", subject, checks, statements, LIMITS, checked_at)

    try:
        c = jcs.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, jcs.JcsError, RecursionError) as exc:
        checks.append(Check("record_certificate.form", Status.FAIL, "certificate.json is not JSON this verifier reads", reasons=[str(exc)]))
        return done()
    canonical = isinstance(c, (dict, list)) and jcs.dumps(c) == raw
    checks.append(Check("record_certificate.form", Status.PASS if canonical else Status.FAIL,
                        f"certificate.json ({len(raw)} bytes, SHA-256 {sha256(raw).hex()}) is in RFC 8785 form" if canonical else
                        "certificate.json is not the RFC 8785 form of its own content, so its bytes are not the ones the contract signs",
                        data={"sha256": sha256(raw).hex(), "from": where}))
    contract = c.get("contract") if isinstance(c, dict) else None
    if contract != CONTRACT:
        if isinstance(contract, str) and re.fullmatch(r"record-certificate/v\d+(\.\d+)?", contract):
            checks.append(Check("record_certificate.contract", Status.NOT_CHECKED, f"contract {contract}: a version this verifier does not read",
                                reasons=["contracts change by versioned addition: a later verifier may read it; it is not verified here"]))
        else:
            checks.append(Check("record_certificate.contract", Status.FAIL, f"contract {contract!r} is not {CONTRACT}"))
        return done()
    problems = shape_problems(c)
    if problems:
        checks.append(Check("record_certificate.schema", Status.FAIL, "the certificate does not follow record-certificate/v0", reasons=problems))
        return done()
    checks.append(Check("record_certificate.schema", Status.PASS, "the certificate follows record-certificate/v0"))
    i, r, h, a, b = c["issuer"], c["record"], c["hour"], c["anchor"], c["anchor"]["bitcoin"]
    pub = bytes.fromhex(i["public_key"])

    # 1. The signature, by the key the certificate names.
    if sha256(pub).hex() != i["key_id"]:
        checks.append(Check("record_certificate.signature", Status.FAIL, "issuer.key_id is not the SHA-256 of issuer.public_key"))
    elif sig is None:
        checks.append(Check("record_certificate.signature", Status.NOT_CHECKED, "no certificate.sig was given, so the signature was not checked",
                            reasons=["give certificate.sig beside certificate.json, or the PDF form, which carries both"]))
    else:
        try:
            if len(sig) != 64:
                raise InvalidSignature
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, raw)
            checks.append(Check("record_certificate.signature", Status.PASS,
                                f"certificate.sig is the Ed25519 signature of certificate.json by the issuer's key (key id {i['key_id']})",
                                relies_on=[f"the issuer's key ({i['public_key']}) is the tenant's: compare it with a key the tenant publishes"]))
        except InvalidSignature:
            checks.append(Check("record_certificate.signature", Status.FAIL,
                                "certificate.sig does not verify over certificate.json under the issuer's key"))

    # The tenant pseudonym: the contract derives it from the key id of the tenant's first signing key, so it matches
    # this key unless the tenant has since rotated (the Ledger's docs/RECORD_CERTIFICATE.md, src/certificate/record.ts).
    derived = "tp-" + sha256(("tenant-pseudonym/v0:" + i["key_id"]).encode()).hex()[:32]
    if r["tenant"] == derived:
        checks.append(Check("record_certificate.pseudonym", Status.PASS,
                            f"the tenant pseudonym {r['tenant']} is the one the contract derives from the issuer's key id: the "
                            "certificate names the tenant whose first signing key this is", required=False))
    else:
        checks.append(Check("record_certificate.pseudonym", Status.INFO,
                            f"the tenant pseudonym {r['tenant']} is not derived from the issuer's key id ({derived} would be)",
                            reasons=["the contract derives it from the tenant's first signing key: this key is a later one, or "
                                     "the pseudonym names another tenant"], required=False))

    # The scope statement, word for word.
    ok = c["scope_statement"] == SCOPE_STATEMENT
    checks.append(Check("record_certificate.scope_statement", Status.PASS if ok else Status.FAIL,
                        f"as the certificate states it: {SCOPE_STATEMENT}" if ok else
                        "the scope statement is not the sentence the contract requires, word for word",
                        reasons=[] if ok else [f"it says: {c['scope_statement']}"]))

    # 2. The head in the hour's root.
    head = bytes.fromhex(r["head"]["event_hash"])
    problem = inclusion_problem(h["head_to_root"], h["leaf_index"], h["size"])
    got = apply_steps(head, h["head_to_root"])
    if problem or got.hex() != h["root"]:
        checks.append(Check("record_certificate.head_to_root", Status.FAIL, "the head's steps do not lead to the hour's root",
                            reasons=[problem] if problem else [f"they give {got.hex()}, the certificate states {h['root']}"]))
    else:
        checks.append(Check("record_certificate.head_to_root", Status.PASS,
                            f"the head (seq {r['head']['seq']}, event {r['head']['event_hash']}) is leaf {h['leaf_index']} of "
                            f"{h['size']} under the hour's root {h['root']} (RFC 9162 inclusion)"))

    # 3. The hour's signed root record.
    reasons = []
    try:
        rec_bytes = _b64(h["root_record_b64"])
        rec = jcs.loads(rec_bytes.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        rec_bytes, rec = b"", None
        reasons.append(f"root_record_b64 does not decode to JSON: {exc}")
    if rec is not None:
        if sha256(rec_bytes).hex() != h["root_record_sha256"]:
            reasons.append("its SHA-256 is not root_record_sha256")
        if jcs.dumps(rec) != rec_bytes:
            reasons.append("it is not in RFC 8785 form")
        if not isinstance(rec, dict) or set(rec) != ROOT_FIELDS or rec.get("contract") != "ledger-root/v0":
            reasons.append("it is not a ledger-root/v0 record")
        else:
            for key, want in (("root", h["root"]), ("size", h["size"]), ("window", h["window"]), ("key_id", i["key_id"])):
                if rec[key] != want:
                    reasons.append(f"its {key} is {rec[key]!r}, the certificate states {want!r}")
            try:
                from .base58 import b64url_decode

                unsigned = {k: v for k, v in rec.items() if k != "sig"}
                Ed25519PublicKey.from_public_bytes(pub).verify(
                    b64url_decode(rec["sig"]), ("ledger-root/v0:" + sha256(jcs.dumps(unsigned)).hex()).encode())
            except (InvalidSignature, ValueError):
                reasons.append("its signature does not verify under the issuer's key")
    if reasons:
        checks.append(Check("record_certificate.root_record", Status.FAIL, "the hour's root record does not hold", reasons=reasons))
    else:
        checks.append(Check("record_certificate.root_record", Status.PASS,
                            f"the issuer's key signed the hour's root record (ledger-root/v0, hour "
                            f"{h['window']['start']}): root {h['root']}, {_events(h['size'])}, SHA-256 {h['root_record_sha256']}"))

    # 4. The root record in the anchored root.
    problem = inclusion_problem(a["record_to_anchor"], a["leaf_index"], a["size"])
    got = apply_steps(bytes.fromhex(h["root_record_sha256"]), a["record_to_anchor"])
    if problem or got.hex() != a["root"]:
        checks.append(Check("record_certificate.record_to_anchor", Status.FAIL, "the root record's steps do not lead to the anchored root",
                            reasons=[problem] if problem else [f"they give {got.hex()}, the certificate states {a['root']}"]))
    else:
        checks.append(Check("record_certificate.record_to_anchor", Status.PASS,
                            f"the root record is leaf {a['leaf_index']} of {a['size']} under the anchored root {a['root']}"))
    anchor_root = bytes.fromhex(a["root"])

    # 5. RFC 3161, each token on its own.
    for n, t in enumerate(a["rfc3161"]):
        extra = []
        try:
            token = _b64(t["token_b64"])
        except binascii.Error as exc:
            checks.append(Check(f"record_certificate.rfc3161.{n}", Status.FAIL, f"the token of {t['authority']} is not base64", reasons=[str(exc)]))
            continue
        v = rfc3161.verify(token, digest=anchor_root, roots=roots, extra_certs=extra_certs, crls=crls,
                           subject=f"anchored root {a['root']}", checked_at=checked_at)
        try:
            actual = rfc3161.parse_token(token).tst.gen_time.isoformat().replace("+00:00", "Z")
        except (rfc3161.TokenError, ValueError):  # the sub-verdict already names a token it cannot read
            actual = None
        if actual is not None and not _same_instant(t["gen_time"], actual):
            extra.append(f"the certificate states {t['gen_time']} for {t['authority']}, the token says {actual}")
        checks.append(_sub(f"record_certificate.rfc3161.{n}", f"the RFC 3161 token of {t['authority']}", v, extra))

    # 6. OpenTimestamps: the proof's path to its earliest Bitcoin attestation, written as the certificate's steps.
    reasons, height_steps = [], []
    try:
        proof = ots.parse(_b64(a["opentimestamps_b64"]))
        if proof.file_hash.name != "sha256" or proof.digest != anchor_root:
            reasons.append("the proof's digest is not the anchored root")
        found = [lf for lf in ots.leaves(proof.timestamp) if lf.attestation.kind == "bitcoin"]
        if not found:
            reasons.append("the proof holds no Bitcoin attestation")
        else:
            earliest = min(lf.attestation.height for lf in found)
            if earliest != b["height"]:
                reasons.append(f"the proof's earliest Bitcoin attestation is at height {earliest}, the certificate states {b['height']}")
            for lf in found:
                if lf.attestation.height == earliest:
                    try:
                        height_steps.append((fold(lf.path), lf.commitment))
                    except ValueError as exc:
                        reasons.append(f"a path to height {earliest}: {exc}")
            if height_steps and not any(st == b["anchor_to_merkle_root"] and cm.hex() == b["merkle_root"] for st, cm in height_steps):
                reasons.append("anchor_to_merkle_root is not the proof's path to that attestation, or does not end at merkle_root")
    except (ots.OtsError, binascii.Error) as exc:
        reasons.append(f"the proof cannot be read: {exc}")
    reached = apply_steps(anchor_root, b["anchor_to_merkle_root"]).hex()
    if reached != b["merkle_root"]:
        reasons.append(f"anchor_to_merkle_root gives {reached}, the certificate states merkle root {b['merkle_root']}")
    checks.append(Check("record_certificate.opentimestamps", Status.FAIL if reasons else Status.PASS,
                        "the OpenTimestamps proof does not lead where the certificate says" if reasons else
                        f"the OpenTimestamps proof commits the anchored root to the merkle root {b['merkle_root']} of the block at "
                        f"height {b['height']}, along the certificate's {len(b['anchor_to_merkle_root'])} steps", reasons=reasons))

    # 7. The header the certificate carries.
    reasons = []
    header = None
    try:
        header = parse_header(bytes.fromhex(b["header"]))
        if header.merkle_root.hex() != b["merkle_root"]:
            reasons.append("bytes 36 to 67 of the header are not merkle_root")
        if header.hash_hex != b["block_hash"]:
            reasons.append(f"the header hashes to block {header.hash_hex}, the certificate states {b['block_hash']}")
        pow_ok, why, _ = check_pow(header, network)
        if not pow_ok:
            reasons.append(why)
        if not _same_instant(header.time_iso, b["time"]):
            reasons.append(f"the header's time is {header.time_iso}, the certificate states {b['time']}")
    except (HeaderError, ValueError) as exc:
        reasons.append(str(exc))
    checks.append(Check("record_certificate.block_header", Status.FAIL if reasons else Status.PASS,
                        "the block header does not hold" if reasons else
                        f"the header carries the merkle root, hashes to block {b['block_hash']}, meets its own target, and gives the "
                        f"time {header.time_iso}", reasons=reasons))

    # 8. The block at that height, from a source of the reader's own.
    evidence, notes = lookup_header(header_sources, b["height"])
    checks += notes
    if evidence is None and not any(n.status is Status.FAIL for n in notes):
        checks.append(Check("record_certificate.bitcoin_block", Status.NOT_CHECKED,
                            f"no source of your own was asked for the block at height {b['height']}",
                            reasons=["give headers (--headers), an explorer (--explorer) or your own node (--bitcoind): whether block "
                                     f"{b['block_hash']} is at that height on Bitcoin's chain is for the chain to say"]))
    elif evidence is not None:
        same = header is not None and evidence.header.raw == header.raw
        checks += evidence.checks
        checks.append(Check("record_certificate.bitcoin_block", Status.PASS if same else Status.FAIL,
                            f"{evidence.source} gives block {evidence.header.hash_hex} at height {b['height']}: "
                            + ("the certificate's header" if same else f"not the certificate's block {b['block_hash']}"),
                            relies_on=evidence.relies_on))

    # With the events: the record's own statements against the chain.
    if events is not None:
        from . import ledger_events

        res = ledger_events.validate_chain(events)
        rs = []
        if not res.ok:
            rs.append(f"the chain does not verify: {res.code} at index {res.index}")
        else:
            first = ledger_events.event_hash(events[0])
            if first != r["record_id"]:
                rs.append(f"the first event's hash is {first}, the record id {r['record_id']}")
            if res.head != r["head"]["event_hash"]:
                rs.append(f"the chain's head is {res.head}, the certificate states {r['head']['event_hash']}")
            if len(events) != r["events"] or events[-1].get("seq") != r["head"]["seq"]:
                rs.append(f"the chain holds {_events(len(events))} to seq {events[-1].get('seq')}, the certificate states {r['events']} "
                          f"to seq {r['head']['seq']}")
            if events[-1].get("ts") != r["head"]["ts"]:
                rs.append("the head's ts is not the last event's")
            if len(res.state.sessions) != r["sessions"]:
                rs.append(f"the chain opens {len(res.state.sessions)} sessions, the certificate states {r['sessions']}")
            if sorted({e.get("contract") for e in events}) != sorted(r["event_contracts"]):
                rs.append(f"the chain's contracts are {sorted({e.get('contract') for e in events})}, the certificate states "
                          f"{sorted(r['event_contracts'])}")
        checks.append(Check("record_certificate.chain", Status.FAIL if rs else Status.PASS,
                            "the chain does not match what the certificate states" if rs else
                            f"the chain given verifies and is the record: {_events(len(events))}, record id {r['record_id']}, head "
                            f"{r['head']['event_hash']}", reasons=rs))
    else:
        checks.append(Check("record_certificate.chain", Status.NOT_CHECKED,
                            "the document's events were not given, so the record's own statements (record id, events, sessions, "
                            "head) are the issuer's", required=False))

    if index is not None:
        try:
            entries = read_index(index) if isinstance(index, (bytes, bytearray)) else index
            checks.append(index_check(entries, sha256(raw).hex(), c))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            checks.append(Check("record_certificate.index", Status.NOT_CHECKED, "the index given cannot be read as a submission index",
                                reasons=[str(exc)], required=False))

    toks = ", ".join(f"{t['authority']} at {t['gen_time']}" for t in a["rfc3161"])
    statements = {
        Outcome.VALID: (f"The issuer (key id {i['key_id']}) signed this record certificate for record {r['record_id']} "
                        f"({_events(r['events'])}, head at seq {r['head']['seq']}). The head is in the tenant's sealed hour "
                        f"{h['window']['start']} (root {h['root']}), whose signed root record is in the anchored root {a['root']}. "
                        f"RFC 3161 tokens put that root at: {toks}. The anchored root existed no later than Bitcoin block "
                        f"{b['height']} ({b['block_hash']}), whose header gives the time {b['time']}."),
        Outcome.INVALID: "The record certificate does not hold: see the failing checks.",
        Outcome.INDETERMINATE: "Every check that ran holds, but not every one could run: see the checks not run.",
    }
    return done(statements)

