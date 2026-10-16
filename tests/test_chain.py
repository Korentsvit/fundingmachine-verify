import json
import os
from pathlib import Path

import pytest

from fmverify import api, certificate, ledger_events
from fmverify.cli import main
from fmverify.verdict import Outcome

FIX = Path(__file__).resolve().parent.parent / "fixtures"
VALID = json.loads((FIX / "chain" / "valid" / "events.json").read_text())["events"]


def test_valid_chain_head_and_map():
    r = ledger_events.validate_chain(VALID)
    exp = json.loads((FIX / "chain" / "valid" / "expected.json").read_text())
    assert r.ok and r.head == exp["head"] and r.count == exp["events"]
    m = ledger_events.authorship_map(r.state, r.count, r.head)
    assert sum(s["length"] for s in m["statements"]) == m["document"]["total"]
    for s in m["statements"]:
        assert sum(run["length"] for run in s["runs"]) == s["length"]
    assert sum(m["document"]["counts"].values()) == m["document"]["total"]


def test_prefix_of_a_valid_chain_is_valid():
    for n in range(1, len(VALID) + 1):
        assert ledger_events.validate_chain(VALID[:n]).ok


def test_schema_rejects_extra_and_missing_fields():
    ev = dict(VALID[1])
    ev["extra"] = 1
    r = ledger_events.validate_chain([VALID[0], ev])
    assert (r.ok, r.code, r.index) == (False, "schema", 1)
    ev = dict(VALID[1])
    del ev["doc_hash"]
    assert ledger_events.validate_chain([VALID[0], ev]).code == "schema"


def test_chain_must_start_at_seq_one():
    r = ledger_events.validate_chain(VALID[1:])
    assert not r.ok and r.index == 0


def test_cli_and_api(capsys):
    assert main(["chain", str(FIX / "chain" / "valid" / "events.json")]) == 0
    assert main(["chain", str(FIX / "chain" / "re-ordered" / "events.json")]) == 1
    out = capsys.readouterr().out
    assert "breaks the rule 'seq_gap'" in out
    assert api.verify({"kind": "chain", "events": VALID})["outcome"] == "valid"
    assert "events must be" in api.verify({"kind": "chain", "events": "x"})["error"]


def test_certificate_step_seven_with_the_chain():
    case = FIX / "certificate" / "valid-with-chain"
    v = certificate.verify_file(case / "certificate.json", events=VALID)
    ids = {c.id: c.status.value for c in v.checks}
    assert ids["certificate.chain"] == ids["certificate.authorship_map"] == ids["certificate.chain_statements"] == "pass"


LEDGER = os.environ.get("FM_LEDGER_REPO")


@pytest.mark.skipif(not LEDGER, reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger to cross-check its fixtures")
def test_the_ledger_sessions_chain_fixtures():
    """Its 19 chains (read from its repository, not copied here) give the
    codes and positions they expect, its map is reproduced byte for byte,
    and its certificate's step 7 passes."""
    base = Path(LEDGER) / "fixtures"
    valid = json.loads((base / "ledger-event/v0/valid/basic.chain.json").read_text())
    r = ledger_events.validate_chain(valid["events"])
    assert r.ok and r.state.hashes == valid["expect"]["event_hashes"]
    for f in sorted((base / "ledger-event/v0/invalid").glob("*.json")):
        d = json.loads(f.read_text())
        r = ledger_events.validate_chain(d["events"])
        assert (r.ok, r.index, r.code) == (False, d["expect"]["index"], d["expect"]["code"]), f.name
    ref = json.loads((base / "authorship-map/v0/basic.authorship.json").read_text())
    r = ledger_events.validate_chain(valid["events"][: ref["at"]["seq"]])
    assert ledger_events.authorship_map(r.state, ref["at"]["seq"], r.head) == ref
    v = certificate.verify_file(base / "certificate/v0/basic.certificate.json", events=valid["events"])
    assert v.outcome is Outcome.VALID
    assert {c.id for c in v.checks if c.status.value == "pass"} >= {"certificate.chain", "certificate.authorship_map",
                                                                     "certificate.chain_statements"}


@pytest.mark.skipif(not LEDGER, reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger to cross-check its fixtures")
def test_the_ledger_sessions_v01_fixtures():
    """ledger-event/v0.1, where the checkout holds it (proposed on the Ledger's
    branch of 16 October 2026): its resumed chain gives its event hashes, and
    each invalid chain the position and code it expects."""
    base = Path(LEDGER) / "fixtures" / "ledger-event" / "v0.1"
    if not base.is_dir():
        pytest.skip("this checkout has no ledger-event/v0.1 fixtures")
    for f in sorted((base / "valid").glob("*.chain.json")):
        d = json.loads(f.read_text())
        r = ledger_events.validate_chain(d["events"])
        assert r.ok and r.state.hashes == d["expect"]["event_hashes"], f.name
    invalid = sorted((base / "invalid").glob("*.json"))
    assert invalid
    for f in invalid:
        d = json.loads(f.read_text())
        r = ledger_events.validate_chain(d["events"])
        assert (r.ok, r.index, r.code) == (False, d["expect"]["index"], d["expect"]["code"]), f.name


def test_unknown_contract_version_is_indeterminate():
    d = json.loads((FIX / "chain" / "v01-unknown-contract" / "events.json").read_text())
    v = ledger_events.verify(d["events"])
    assert v.outcome is Outcome.INDETERMINATE and "does not read" in v.statement
    assert [c.status.value for c in v.checks] == ["not_checked"]


def test_empty_chain_is_not_valid(tmp_path):
    """EVENT_CONTRACT.md: a verifier given no events answers empty."""
    r = ledger_events.validate_chain([])
    assert (r.ok, r.code) == (False, "empty")
    assert ledger_events.verify([]).outcome is Outcome.INDETERMINATE
    assert api.verify({"kind": "chain", "events": []})["outcome"] == "indeterminate"
    f = tmp_path / "events.json"
    f.write_text(json.dumps({"events": []}))
    assert main(["chain", str(f)]) == 2


def _writer_tools():
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import chain_fixtures

    return chain_fixtures


def test_null_section_ref_on_a_known_section_claims_nothing():
    """section_ref_conflict: a section keeps the ref it was first given; a
    null ref names no new one (as the Ledger's state.ts reads it), and a ref
    with no section id is the conflict."""
    cf = _writer_tools()
    w = cf.Writer("section refs")
    w.open("s1", ("st-1", "approach", "call:example/approach"))
    w.insert("s1", "st-1", 0, "One. Two.")
    w.split("s1", "st-1", 4, "st-2", "approach", None)
    assert ledger_events.validate_chain(w.events).ok
    w.contract = "ledger-event/v0.1"
    w.close("s1")
    w.open("s2")
    w.resync("s2", added=(("st-3", "st-2", "approach", None, "Three."),))
    assert ledger_events.validate_chain(w.events).ok
    bad = cf.Writer("section ref without id")
    bad.open("s1", ("st-1", "approach", "call:example/approach"))
    bad.insert("s1", "st-1", 0, "One. Two.")
    bad.split("s1", "st-1", 4, "st-2", None, "call:example/other")
    r = ledger_events.validate_chain(bad.events)
    assert (r.ok, r.code, r.index) == (False, "section_ref_conflict", 2)


def test_huge_lengths_cost_no_memory():
    """A signed event may claim a length up to 2^53 - 1; state is kept as runs,
    so the claim costs nothing (it once cost a list entry per code point)."""
    import resource
    import time

    cf = _writer_tools()
    w = cf.Writer("huge length")
    w.open("s1", ("st-1", "approach", None))
    w.emit("s1", "edit.insert", w.person, {"statement_id": "st-1", "start": 0, "end": 0}, "x", {"length": 2**53 - 1})
    w.emit("s1", "edit.delete", w.person, {"statement_id": "st-1", "start": 5, "end": 2**52}, "y", {})
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    t = time.perf_counter()
    r = ledger_events.validate_chain(w.events)
    assert r.ok and time.perf_counter() - t < 2
    assert resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before < 100 * 1024  # KiB on Linux
    amap = ledger_events.authorship_map(r.state, 3, r.head)
    assert amap["document"]["total"] == 2**53 - 1 - (2**52 - 5)


def test_a_range_ending_before_it_starts_is_empty():
    """Found by the differential run against the Ledger's validator: [34, 0)
    holds nothing, so a tool.edit over it fails as range_empty there; it was
    range_out_of_bounds here. The contract's half-open span reads the
    Ledger's way."""
    import copy
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    from chain_fixtures import basic_chain, event_hash, sign_event

    w = basic_chain()
    keys = {sid: key for sid, key in w.sessions.values()}
    evs = copy.deepcopy(w.events)
    i = next(k for k, e in enumerate(evs) if e["type"] == "tool.edit")
    evs[i]["range"] = dict(evs[i]["range"], end=0)
    last = evs[i - 1]
    for k in range(i, len(evs)):
        evs[k] = sign_event(dict(evs[k], prev_hash=event_hash(last)), keys[evs[k]["session_id"]])
        last = evs[k]
    r = ledger_events.validate_chain(evs)
    assert (r.ok, r.index, r.code) == (False, i, "range_empty")
