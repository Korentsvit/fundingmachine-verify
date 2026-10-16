import json
import os
from pathlib import Path

import pytest

from fmverify import ledger_text
from fmverify.cli import main
from fmverify.verdict import Outcome

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "chain"


def test_text_never_appears_in_the_verdict(capsys):
    case = FIX / "disclosure-valid"
    disclosure = json.loads((case / "disclosure.json").read_text())
    texts = [s["content_text"] for s in disclosure["steps"] if len(s["content_text"]) > 6]
    assert main(["chain", str(case / "events.json"), "--disclosure", str(case / "disclosure.json"), "--json"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out)["outcome"] == "valid"
    assert not any(t in out for t in texts)


def test_missing_text_is_a_mismatch():
    case = FIX / "disclosure-valid"
    events = json.loads((case / "events.json").read_text())["events"]
    disclosure = json.loads((case / "disclosure.json").read_text())
    disclosure["steps"] = disclosure["steps"][1:]
    v = ledger_text.verify(events, disclosure)
    assert v.outcome is Outcome.INVALID and "gives no text" in v.checks[-1].reasons[0]


def test_usage_errors(tmp_path):
    (tmp_path / "d.json").write_text("[]")
    assert main(["chain", str(FIX / "valid" / "events.json"), "--disclosure", str(tmp_path / "d.json")]) == 64


LEDGER = os.environ.get("FM_LEDGER_REPO")


@pytest.mark.skipif(not LEDGER, reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger")
def test_the_ledger_sessions_journal_replays():
    base = Path(LEDGER) / "fixtures" / "ledger-event" / "v0" / "valid"
    events = json.loads((base / "basic.chain.json").read_text())["events"]
    journal = json.loads((base / "basic.journal.json").read_text())
    v = ledger_text.verify(events, journal)
    assert v.outcome is Outcome.VALID, v.to_text()
    assert v.checks[1].data == {"content": 11, "removed": 2, "doc": 20, "views": 20, "statements": 2, "characters": 172,
                                "quotes": 2, "declarations": 1, "signer_names": 0}


def test_the_ledger_sessions_v01_journal():
    """Its v0.1 journal replays its resumed chain: the resync's texts, the
    declaration, the quotation and the signer's name (FM_LEDGER_REPO)."""
    import os

    base = Path(os.environ.get("FM_LEDGER_REPO") or "") / "fixtures" / "ledger-event" / "v0.1" / "valid"
    if not os.environ.get("FM_LEDGER_REPO") or not (base / "resync.journal.json").is_file():
        pytest.skip("set FM_LEDGER_REPO to a checkout holding ledger-event/v0.1 fixtures")
    chain = json.loads((base / "resync.chain.json").read_text())
    journal = json.loads((base / "resync.journal.json").read_text())
    v = ledger_text.verify(chain["events"], journal)
    assert v.outcome.value == "valid", v.to_text()
    data = next(c for c in v.checks if c.id == "disclosure.replay").data
    assert data["signer_names"] == 1 and data["declarations"] == 1 and data["quotes"] == 1
    journal["signer_name"] = journal["signer_name"] + "x"
    assert ledger_text.verify(chain["events"], journal).outcome.value == "invalid"


def _valid_case():
    case = FIX / "disclosure-valid"
    return json.loads((case / "events.json").read_text())["events"], json.loads((case / "disclosure.json").read_text())


def test_a_step_of_another_type_is_a_mismatch():
    events, disclosure = _valid_case()
    disclosure["steps"][0]["type"] = "edit.delete"  # seq 2 is an edit.insert
    v = ledger_text.verify(events, disclosure)
    assert v.outcome is Outcome.INVALID and "the chain's event a edit.insert" in v.checks[-1].reasons[0]


def test_text_given_for_a_delete_is_compared_with_the_replay():
    events, disclosure = _valid_case()
    deleted = next(e["seq"] for e in events if e["type"] == "edit.delete")
    disclosure["steps"].append({"seq": deleted, "content_text": "not what was deleted"})
    v = ledger_text.verify(events, disclosure)
    assert v.outcome is Outcome.INVALID and f"seq {deleted}: the disclosure's text for this edit.delete" in v.checks[-1].reasons[0]


def test_a_signer_name_no_hash_covers_is_named():
    events, disclosure = _valid_case()  # ledger-event/v0: no signer_name_hash
    disclosure["signer_name"] = "A. Reader"
    v = ledger_text.verify(events, disclosure)
    unused = next(c for c in v.checks if c.id == "disclosure.unused")
    assert v.outcome is Outcome.VALID and unused.status.value == "warn" and "signer_name" in unused.reasons[0]
    assert "A. Reader" not in json.dumps(v.to_dict())


def test_two_steps_for_one_event_fail_before_any_text_is_checked():
    case = FIX / "disclosure-step-twice"
    events = json.loads((case / "events.json").read_text())["events"]
    v = ledger_text.verify(events, json.loads((case / "disclosure.json").read_text()))
    assert [c.id for c in v.checks if c.status.value == "fail"] == ["disclosure.steps"]
    assert "seq 2" in v.checks[-1].reasons[0]
