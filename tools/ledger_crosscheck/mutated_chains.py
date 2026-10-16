"""Mutated event chains for a differential run against the Provenance
Ledger's own validator.

    python tools/ledger_crosscheck/mutated_chains.py OUT_DIR [N]
    (from a fundingmachine-ledger checkout) npx tsx <this repo>/tools/ledger_crosscheck/run.mts OUT_DIR > answers.jsonl
    python tools/ledger_crosscheck/mutated_chains.py --summarize answers.jsonl

The first step writes N (default 1500) chains under OUT_DIR/chain/, each the
fixture chains (v0, and v0.1 closed and open) with one change, every event
from the change on re-signed with the fixture's session keys and relinked,
so the change reaches the chain rules instead of stopping at a signature.
Most changes stay within the schema: a number moved by a little, an
enumerated value replaced by another valid one, an id pointed at another id
of the chain, events swapped, dropped or repeated; the rest replace a value
with one of any type. Each case's expected.json holds this verifier's
answer (outcome, index, code). ``run.mts`` then runs the Ledger's
validator on every case, and ``--summarize`` groups where the two differ,
apart from the difference by design (a version neither reads, or no
events: indeterminate here, invalid there, at the same event with the same
code).
"""

from __future__ import annotations

import copy
import json
import random
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from chain_fixtures import basic_chain, event_hash, sign_event, v01_chain  # noqa: E402
from tamper_audit import mutate_json  # noqa: E402

from fmverify import ledger_events as le  # noqa: E402

ID_FIELDS = ("statement_id", "section_id", "binding_id", "new_statement_id", "merged_statement_id", "after", "id", "session_id")
ENUMS = {"type": le.TYPES, "capture_fidelity": le.FIDELITIES, "fidelity": le.FIDELITIES, "meaning": list(le.MEANINGS),
         "visibility": ["public", "private"], "kind": ["person", "tool"], "contract": list(le.CONTRACTS)}


def _leaves(o, p=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _leaves(v, p + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _leaves(v, p + (i,))
    else:
        yield p, o


def _change(rng: random.Random, evs: list[dict]) -> tuple[str | None, int]:
    """One change, in place; returns its description and the first event it touched."""
    kind = rng.choice(["num", "num", "num", "enum", "id", "id", "swap", "drop", "dup", "ts", "any"])
    if kind in ("swap", "drop", "dup"):
        i = rng.randrange(1, len(evs) - 1)
        if kind == "swap":
            evs[i], evs[i + 1] = evs[i + 1], evs[i]
            return f"events {i} and {i + 1} swapped", i
        if kind == "drop":
            del evs[i]
            return f"event {i} dropped", i
        evs.insert(i, copy.deepcopy(evs[i]))
        return f"event {i} repeated", i
    i = rng.randrange(len(evs))
    ev = evs[i]
    if kind == "any":
        body = {k: v for k, v in ev.items() if k != "client_sig"}
        changed, where = mutate_json(rng, body)
        if not isinstance(changed, dict) or changed == body:
            return None, i
        evs[i] = changed
        return f"event {i}: {where}", i
    leaves = [(p, v) for p, v in _leaves(ev) if p and p[0] not in ("client_sig", "prev_hash", "event_id", "doc_id", "tenant_id")]
    if kind == "num":
        options = [(p, v) for p, v in leaves if isinstance(v, int) and not isinstance(v, bool)]
        if not options:
            return None, i
        p, v = rng.choice(options)
        new = v + rng.choice([-2, -1, 1, 2, 5, -v])
    elif kind == "ts":
        p, v = ("ts",), ev["ts"]
        new = rng.choice([evs[max(0, i - 1)]["ts"], evs[min(len(evs) - 1, i + 1)]["ts"], "2026-10-16T00:00:00.000Z"])
    elif kind == "enum":
        options = [(p, v) for p, v in leaves if p[-1] in ENUMS]
        if not options:
            return None, i
        p, v = rng.choice(options)
        new = rng.choice([x for x in ENUMS[p[-1]] if x != v] or [v])
    else:
        options = [(p, v) for p, v in leaves if isinstance(v, str) and p[-1] in ID_FIELDS]
        if not options:
            return None, i
        p, v = rng.choice(options)
        if p[-1] == "session_id":
            pool = sorted({e["session_id"] for e in evs if e["session_id"] != v})
        else:
            pool = sorted({x for e in evs for q, x in _leaves(e) if q and q[-1] == p[-1] and isinstance(x, str) and x != v})
        if not pool:
            return None, i
        new = rng.choice(pool)
    target = ev
    for k in p[:-1]:
        target = target[k]
    target[p[-1]] = new
    return f"event {i} {'/'.join(map(str, p))}: {json.dumps(v)} -> {json.dumps(new)}", i


def generate(out: Path, n: int) -> int:
    if out.exists():
        shutil.rmtree(out)
    (out / "chain").mkdir(parents=True)
    (out / "certificate").mkdir()  # run.mts reads it; no certificate cases here
    bases = []
    for w in (basic_chain(), v01_chain(), v01_chain(close=False)):
        bases.append((w.events, {sid: key for sid, key in w.sessions.values()}))
    rng = random.Random("ledger-differential")
    written = 0
    while written < n:
        events, keys = rng.choice(bases)
        evs = copy.deepcopy(events)
        where, i = _change(rng, evs)
        if where is None:
            continue
        out_evs, last = evs[:i], (evs[i - 1] if i else None)
        try:
            for ev in evs[i:]:
                ev = dict(ev, prev_hash=event_hash(last) if last is not None else "0" * 64)
                key = keys.get(ev.get("session_id")) if isinstance(ev.get("session_id"), str) else None
                ev = sign_event(ev, key or keys[events[min(i, len(events) - 1)]["session_id"]])
                out_evs.append(ev)
                last = ev
        except (TypeError, ValueError, KeyError):
            continue  # a change no signer can serialise: not a chain anyone could submit
        r = le.validate_chain(out_evs)
        outcome = "valid" if r.ok else "indeterminate" if (r.unknown_contract or r.code == "empty") else "invalid"
        exp = {"outcome": outcome, "description": where}
        if not r.ok:
            exp.update(index=r.index, code=r.code)
        d = out / "chain" / f"m{written:05d}"
        d.mkdir()
        (d / "events.json").write_text(json.dumps({"events": out_evs}), encoding="utf-8")
        (d / "expected.json").write_text(json.dumps(exp), encoding="utf-8")
        written += 1
    return written


def summarize(answers: Path) -> int:
    rows = [json.loads(line) for line in answers.read_text(encoding="utf-8").splitlines() if line.startswith('{"kind":"chain"')]
    designed = [r for r in rows if not r["agree"] and r["expected"][0] == "indeterminate" and r["ledger"][0] == "invalid"
                and r["expected"][1:] == r["ledger"][1:]]
    other = [r for r in rows if not r["agree"] and r not in designed]
    codes = Counter(r["expected"][2] or "valid" for r in rows)
    print(f"{len(rows)} chains: {sum(r['agree'] for r in rows)} answered alike, {len(designed)} differing by design "
          f"(indeterminate here, invalid there, same event and code), {len(other)} otherwise")
    print("this verifier's answers: " + ", ".join(f"{c} {n}" for c, n in codes.most_common()))
    for (ours, theirs), n in Counter((tuple(r["expected"]), tuple(r["ledger"])) for r in other).most_common():
        print(f"  {n}: here {ours}, the Ledger {theirs}")
    return 1 if other else 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--summarize"] and len(argv) == 2:
        return summarize(Path(argv[1]))
    if not argv or len(argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    print(f"{generate(Path(argv[0]), int(argv[1]) if len(argv) == 2 else 1500)} chains written under {argv[0]}/chain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
