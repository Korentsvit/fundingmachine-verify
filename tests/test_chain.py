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
