import json
import os
from pathlib import Path

import pytest

from fmverify import ledger_roots
from fmverify.base58 import did_key_ed25519
from fmverify.cli import main
from fmverify.verdict import Outcome, Status

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "roots"
GOOD = json.loads((FIX / "valid" / "roots.json").read_text())["records"]
KEY = json.loads((FIX / "valid" / "expected.json").read_text())["key"]


def test_without_a_key_the_signatures_are_not_checked():
    v = ledger_roots.verify(GOOD)
    assert v.outcome is Outcome.INDETERMINATE
    assert [c.status for c in v.checks if c.id == "roots.signatures"] == [Status.NOT_CHECKED]


def test_window_must_be_one_hour():
    bad = json.loads(json.dumps(GOOD))
    bad[0]["window"]["end"] = "2026-10-16T10:00:00.000Z"
    v = ledger_roots.verify(bad, public_key=did_key_ed25519(KEY))
    assert v.outcome is Outcome.INVALID and any("one whole UTC hour" in r for c in v.checks for r in c.reasons)


def test_cli(capsys):
    path = str(FIX / "valid" / "roots.json")
    assert main(["roots", path, "--key", KEY]) == 0
    assert main(["roots", path]) == 2
    assert main(["roots", path, "--key", "zz"]) == 64
    assert main(["roots", str(FIX / "hour-dropped" / "roots.json"), "--key", KEY]) == 1


LEDGER = os.environ.get("FM_LEDGER_REPO")


@pytest.mark.skipif(not LEDGER, reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger")
def test_the_ledger_sessions_record():
    cert = json.loads((Path(LEDGER) / "fixtures" / "certificate" / "v0" / "basic.certificate.json").read_text())
    record = cert["credentialSubject"]["ledger_root"]["record"]
    v = ledger_roots.verify([record], public_key=did_key_ed25519(cert["issuer"]["id"]))
    assert v.outcome is Outcome.VALID, v.to_text()
