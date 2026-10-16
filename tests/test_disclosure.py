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
    assert v.checks[1].data == {"content": 11, "removed": 2, "doc": 20, "views": 20, "statements": 2, "characters": 172}
