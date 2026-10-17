"""Tamper audit: change the inputs of every valid conformance case and see
which changes the verifier still calls valid.

    python tools/tamper_audit.py [ROUNDS] [--json OUT]

For each case whose expected outcome is valid, each input file the case
names (never the reader's own evidence: roots, revocation lists, block
headers) is changed ROUNDS times (default 200), deterministically: bytes
overwritten, deleted or inserted, and for JSON also a value replaced, a key
removed or two elements swapped. The case is run again on each changed copy.

A crash is a defect. A change still judged valid must either show in the
verdict (a check, a reason or the statement differs) or be explained: the
change is to something no proof covers and no verdict reads, as
``explain`` establishes from the data itself (the PDF's embedded
certificate.json is unchanged; the proof's Bitcoin attestations are
unchanged; the JSON paths changed are the job's own statements). Anything
else is listed as unexplained, and the audit fails. A change that leaves the
parsed JSON or the bytes as they were is not counted.
"""

from __future__ import annotations

import copy
import json
import random
import re
import shutil
import sys
import tempfile
import traceback
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fmverify import conformance, ots, pdf  # noqa: E402

FIX = ROOT / "fixtures"
READER_EVIDENCE = ("roots", "crls", "headers", "headers_chain")
ODD = [None, True, False, 0, -1, 1, 2**53, 1.5, "", "x", "0" * 64, [], {}, [None], {"a": None}]


def mutate_bytes(rng: random.Random, b: bytes) -> tuple[bytes, str]:
    b = bytearray(b)
    where = []
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        if op < 0.6 and b:
            i = rng.randrange(len(b))
            b[i] = (b[i] + rng.randrange(1, 256)) % 256
            where.append(f"byte {i} changed")
        elif op < 0.8 and b:
            i = rng.randrange(len(b))
            n = rng.randint(1, 8)
            del b[i:i + n]
            where.append(f"bytes {i}..{i + n} deleted")
        else:
            i = rng.randrange(len(b) + 1)
            n = rng.randint(1, 8)
            b[i:i] = bytes(rng.randrange(256) for _ in range(n))
            where.append(f"{n} bytes inserted at {i}")
    return bytes(b), "; ".join(where)


def _paths(o, path=()):
    yield path
    if isinstance(o, dict):
        for k in o:
            yield from _paths(o[k], path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, path + (i,))


def mutate_json(rng: random.Random, value) -> tuple[object, str]:
    value = copy.deepcopy(value)
    paths = [p for p in _paths(value) if p]
    if not paths:
        return rng.choice(ODD), "whole value replaced"
    path = rng.choice(paths)
    parent = value
    for k in path[:-1]:
        parent = parent[k]
    key = path[-1]
    shown = "/".join(str(k) for k in path)
    old = parent[key]
    r = rng.random()
    if r < 0.25 and isinstance(parent, dict):
        del parent[key]
        return value, f"{shown} removed"
    if r < 0.5 and isinstance(old, str) and old:
        i = rng.randrange(len(old))
        parent[key] = old[:i] + chr((ord(old[i]) + rng.randrange(1, 26)) % 0x7F or 0x41) + old[i + 1:]
        return value, f"{shown} one character changed"
    if r < 0.6 and isinstance(old, (int, float)) and not isinstance(old, bool):
        parent[key] = old + rng.choice([-1, 1])
        return value, f"{shown} off by one"
    if r < 0.7 and isinstance(parent, list) and len(parent) > 1:
        j = rng.randrange(len(parent))
        parent[key], parent[j] = parent[j], parent[key]
        return value, f"{shown} swapped with {j}"
    parent[key] = copy.deepcopy(rng.choice(ODD))
    return value, f"{shown} replaced with {json.dumps(parent[key])[:20]}"


def changed_paths(a, b, path: str = "") -> list[str]:
    """The JSON paths where ``b`` differs from ``a``; a list whose elements
    were only reordered is one path ending in " reordered"."""
    if type(a) is not type(b):
        return [path or "(root)"]
    if isinstance(a, dict):
        out = []
        for k in sorted(a.keys() | b.keys(), key=str):
            sub = f"{path}/{k}" if path else str(k)
            if k not in a or k not in b:
                out.append(sub)
            else:
                out += changed_paths(a[k], b[k], sub)
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [path or "(root)"]
        if a != b and sorted(json.dumps(x, sort_keys=True) for x in a) == sorted(json.dumps(x, sort_keys=True) for x in b):
            return [f"{path} reordered"]
        return [p for i, (x, y) in enumerate(zip(a, b)) for p in changed_paths(x, y, f"{path}/{i}" if path else str(i))]
    return [] if a == b else [path or "(root)"]


# JSON paths no proof covers and no verdict reads, by file: why a change there
# leaves the verdict as it was.
UNREAD = [
    ("manifest.json", r"proofs/rfc3161/\d+/url", "an authority's URL: the job's statement, covered by no proof"),
    ("manifest.json", r"proofs/opentimestamps/accepted_by(/\d+| reordered)?", "the calendars that accepted the root: the job's statement"),
    ("manifest.json", r"sources(/.*| reordered)?", "the job's report of what it read: covered by no proof"),
    ("manifest.json", r"proofs/rfc3161 reordered", "token entries are matched to their files by name, not by position"),
    ("disclosure.json", r"steps reordered", "steps are matched to events by seq, not by position"),
    ("disclosure.json", r"steps/\d+/resync_text/removed", "an optional copy of text the replay derives and checks against its hashes"),
    ("events.json", r"contract", "the fixture file's label: each event names its own contract"),
    ("batch.json", r"ots|rfc3161", "a batch's proof files are found by their suffix; the lists only name them"),
    ("index.json", r"statement|scope_statement", "the index's own sentences: no proof covers them and no check reads their words"),
]


def explain(case: Path, rel: str, original: bytes, mutated: bytes) -> str | None:
    """Why a change the verdict does not show is not tampering with anything
    the verdict asserts, established from the data; None when it cannot be."""
    name = Path(rel).name
    if name.endswith(".json"):
        try:
            a, b = json.loads(original), json.loads(mutated)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None
        paths = changed_paths(a, b)
        if name == "manifest.json" and isinstance(a, dict) and "contract" not in a:
            from fmverify.ledger_anchors import _descriptors

            def found(m) -> list[str]:
                return sorted(json.dumps(x, sort_keys=True) for x in _descriptors(m))

            if isinstance(b, (dict, list)) and not (isinstance(b, dict) and "contract" in b) and found(a) and found(a) == found(b):
                return "an unversioned manifest's descriptors are found by shape and sorted: the same descriptors, the same anchor"
        if name == "manifest.json":
            held = {p.name for p in (case / rel).parent.iterdir()}
            for p in paths:
                m = re.fullmatch(r"proofs/rfc3161/(\d+)/(?:policy|serial|gen_time)", p)
                if m and a["proofs"]["rfc3161"][int(m.group(1))].get("file") not in held:
                    return "the entry of a token this directory does not hold, already warned about as missing"
        if name == "disclosure.json" and case.name == "disclosure-text-no-hash-covers":
            text = [p for p in paths if re.fullmatch(r"steps/(\d+)/(content_text|quote_text|resync_text)", p)]
            extra = {i for i, s in enumerate(a["steps"]) if s["seq"] in (3, 99)}  # the steps that case adds
            if text and len(text) == len(paths) and all(int(p.split("/")[1]) in extra for p in text):
                return "text no hash covers, already named in the disclosure.unused warning"
        if name == "index.json" and isinstance(a, dict) and isinstance(b, dict) and isinstance(a.get("entries"), list):
            import hashlib

            mine = hashlib.sha256((case / "certificate.json").read_bytes()).hexdigest() if (case / "certificate.json").is_file() else None
            own = [i for i, e in enumerate(a["entries"]) if isinstance(e, dict) and e.get("certificate_sha256") == mine]
            others = [p for p in paths if re.fullmatch(r"entries/(\d+)(/.*)?", p) and int(p.split("/")[1]) not in own]
            if paths and len(others) == len(paths) and [b["entries"][i] for i in own if i < len(b.get("entries", []))] == \
                    [a["entries"][i] for i in own]:
                return "an entry of the index for another certificate: the verdict is about this certificate's entry, unchanged"
        whys = []
        for p in paths:
            why = next((w for f, pat, w in UNREAD if f == name and re.fullmatch(pat, p)), None)
            if why is None:
                return None
            whys.append(why)
        return "; ".join(sorted(set(whys))) or None
    if name.endswith(".pdf"):
        try:
            if pdf.extract(original) == pdf.extract(mutated):
                return "the page content: the embedded certificate.json, which the verdict is about, is byte for byte the same"
        except pdf.PdfError:
            return None
        return None
    if name.endswith(".ots"):
        def attested(data: bytes) -> list:
            return sorted((leaf.attestation.height, leaf.commitment) for leaf in ots.leaves(ots.parse(data).timestamp)
                          if leaf.attestation.kind == "bitcoin")
        try:
            if attested(original) == attested(mutated):
                return "a branch the verdict does not rely on (a pending or unknown attestation): its Bitcoin attestations are the same"
        except (ots.OtsError, ValueError):
            return None
    return None


def inputs(case: Path, exp: dict) -> list[str]:
    skip = {"expected.json"}
    for key in READER_EVIDENCE:
        for item in exp.get(key, []):
            skip.add(item["path"] if isinstance(item, dict) else item)
    out = []
    for p in sorted(case.rglob("*")):
        rel = p.relative_to(case).as_posix()
        if p.is_file() and rel not in skip and "__pycache__" not in p.parts:
            out.append(rel)
    return out


def _shown(v) -> dict[str, str]:
    """What a verdict tells its reader: per check, status, summary and
    reasons; and its statement."""
    ids = [c.id for c in v.checks]
    shown = {c.id + (f"#{i}" if ids.count(c.id) > 1 else ""): " | ".join([f"{c.status.value} {c.summary}", *c.reasons])
             for i, c in enumerate(v.checks)}
    shown["(statement)"] = v.statement
    return shown


def _runner_only(exc: BaseException) -> bool:
    """True when the exception never reached a verifier module: the runner
    could not read a JSON input (the CLI reports that as a usage error)."""
    frames = [f.filename for f in traceback.extract_tb(exc.__traceback__)]
    verifier = [f for f in frames if "/fmverify/" in f and not f.endswith("conformance.py")]
    return not verifier and isinstance(exc, (ValueError, KeyError, TypeError))


def audit(rounds: int) -> dict:
    shown_changes: dict[str, list[str]] = defaultdict(list)
    explained: Counter = Counter()
    unexplained: list[str] = []
    crashes: list[str] = []
    totals: Counter = Counter()
    with tempfile.TemporaryDirectory() as tmp:
        copy_root = Path(tmp) / "fixtures"
        shutil.copytree(FIX, copy_root)  # cases name files beside them (../../bitcoin/...)
        for kind, case in conformance.cases(FIX):
            exp = json.loads((case / "expected.json").read_text(encoding="utf-8"))
            if exp["outcome"] != "valid":
                continue
            work = copy_root / kind / case.name
            baseline = _shown(conformance.run_case(kind, work)[1])
            for rel in inputs(case, exp):
                original = (case / rel).read_bytes()
                rng = random.Random(f"{kind}/{case.name}/{rel}")
                parsed = None
                if rel.endswith(".json"):
                    try:
                        parsed = json.loads(original)
                    except ValueError:
                        parsed = None
                for n in range(rounds):
                    if parsed is not None and n % 2 == 0:
                        value, where = mutate_json(rng, parsed)
                        if value == parsed:
                            continue
                        data = json.dumps(value, ensure_ascii=False, indent=1).encode("utf-8")
                    else:
                        data, where = mutate_bytes(rng, original)
                        if data == original:
                            continue
                        if parsed is not None:
                            try:
                                if json.loads(data) == parsed:
                                    continue  # whitespace only
                            except (ValueError, UnicodeDecodeError, RecursionError):
                                pass
                    (work / rel).write_bytes(data)
                    totals["runs"] += 1
                    label = f"{kind}/{case.name}/{rel}"
                    try:
                        _, v = conformance.run_case(kind, work)
                        totals[v.outcome.value] += 1
                        if v.outcome.value == "valid":
                            shown = _shown(v)
                            changed = sorted(c for c in shown.keys() | baseline.keys() if shown.get(c) != baseline.get(c))
                            if changed:
                                totals["valid, shown"] += 1
                                shown_changes[label].append(f"{where} -> {', '.join(changed)}")
                            else:
                                why = explain(work, rel, original, data)
                                if why:
                                    totals["valid, explained"] += 1
                                    explained[f"{kind} {Path(rel).name}: {why}"] += 1
                                else:
                                    unexplained.append(f"{label}: {where}")
                    except Exception as exc:  # noqa: BLE001 - every crash is reported
                        if _runner_only(exc):
                            totals["unreadable"] += 1  # the runner's own JSON read failed; the CLI exits 64 there
                        else:
                            totals["crash"] += 1
                            crashes.append(f"{label}: {where}\n{traceback.format_exc(limit=-4)}")
                    (work / rel).write_bytes(original)
    return {"totals": dict(totals), "shown": dict(sorted(shown_changes.items())), "explained": dict(explained.most_common()),
            "unexplained": unexplained, "crashes": crashes}


def main(argv: list[str]) -> int:
    rounds = int(argv[0]) if argv and argv[0].isdigit() else 200
    result = audit(rounds)
    if "--json" in argv:
        Path(argv[argv.index("--json") + 1]).write_text(json.dumps(result, indent=1), encoding="utf-8")
    t = result["totals"]
    print(f"{t.get('runs', 0)} changed inputs: {t.get('invalid', 0)} invalid, {t.get('indeterminate', 0)} indeterminate, "
          f"{t.get('valid', 0)} still valid ({t.get('valid, shown', 0)} with a verdict that shows the change, "
          f"{t.get('valid, explained', 0)} explained, {len(result['unexplained'])} unexplained), "
          f"{t.get('unreadable', 0)} not readable as JSON, {t.get('crash', 0)} crashes")
    for why, count in result["explained"].items():
        print(f"  explained ({count}): {why}")
    for u in result["unexplained"]:
        print(f"UNEXPLAINED {u}")
    for c in result["crashes"][:10]:
        print("CRASH", c)
    return 1 if result["crashes"] or result["unexplained"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
