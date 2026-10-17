"""The rule pairs (the Ledger conformance suite's CS-22): where one event breaks two chain rules, the code reported
is the one of the rule listed first in the contract's table. Each pair's fixture breaks both rules; each rule
broken alone gives its own code, so neither rule hides behind the other by accident."""

import json
import sys
from pathlib import Path

import pytest

from fmverify import ledger_events

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import chain_fixtures  # noqa: E402

# The rows of the chain rules table of the Provenance Ledger's docs/EVENT_CONTRACT.md (ledger-event/v0 and v0.1),
# in its order; a row may hold several codes.
ROWS = [
    ("schema",), ("seq_gap",), ("prev_hash_mismatch",), ("ts_backwards",), ("doc_mismatch", "tenant_mismatch"),
    ("event_id_duplicate",), ("key_mismatch",), ("bad_signature",), ("session_unknown", "session_closed", "session_reopened"),
    ("genesis_not_first",), ("resync_not_first",), ("statement_unknown", "statement_id_reused"),
    ("range_not_empty", "range_empty", "range_out_of_bounds"), ("removed_hash_mismatch", "content_hash_mismatch"),
    ("merge_not_adjacent", "range_mismatch"), ("section_ref_conflict",), ("binding_duplicate", "binding_unknown"),
    ("document_empty",),
]
ROW = {code: i for i, row in enumerate(ROWS) for code in row}

WRITER = chain_fixtures.basic_chain()
KEYS = {sid: key for sid, key in WRITER.sessions.values()}
PAIRS = chain_fixtures.rule_pairs(WRITER.events, KEYS)


def stop(events):
    r = ledger_events.validate_chain(events)
    return (r.ok, r.index, r.code)


def test_the_pairs_cover_ct02_and_the_ledgers_order_test():
    assert len(PAIRS) == 9
    assert sum(p["second"] == "event_id_duplicate" for p in PAIRS) == 5
    assert len({p["name"] for p in PAIRS}) == 9


@pytest.mark.parametrize("p", PAIRS, ids=[p["name"] for p in PAIRS])
def test_each_rule_alone_and_both(p):
    assert ROW[p["first"]] < ROW[p["second"]]
    assert stop(p["first_only"]) == (False, p["index"], p["first"])
    assert stop(p["second_only"]) == (False, p["index"], p["second"])
    assert stop(p["both"]) == (False, p["index"], p["first"])
    # Nothing before the changed event moved.
    assert p["both"][:p["index"]] == WRITER.events[:p["index"]]


@pytest.mark.parametrize("p", PAIRS, ids=[p["name"] for p in PAIRS])
def test_the_fixture_is_the_pair(p):
    case = ROOT / "fixtures" / "chain" / p["name"]
    assert json.loads((case / "events.json").read_text())["events"] == p["both"]
    exp = json.loads((case / "expected.json").read_text())
    assert (exp["outcome"], exp["index"], exp["code"], exp["breaks"]) == ("invalid", p["index"], p["first"], [p["first"], p["second"]])
