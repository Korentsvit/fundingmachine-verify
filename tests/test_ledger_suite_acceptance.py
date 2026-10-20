"""The Provenance Ledger's acceptance record test vector (its fixtures/ledger-acceptance/v0, from a checkout of its
repository, not copied here), verified end to end: every event of the hour with the record, the hour's root record,
and the anchored root, whose tokens and OpenTimestamps proof are those of its record certificate vector
(fixtures/record-certificate/v0), anchored in the same root.

The vectors are synthetic: signed with keys.json "tenant" (RFC 8032 section 7.1 TEST 3), stamped by two test
authorities whose roots the record certificate vector carries, and anchored in a regtest block (its headers.txt).
"""

import json
import os
from pathlib import Path

import pytest

from fmverify import jcs, ledger_acceptance, pki
from fmverify.bitcoin import REGTEST, HeaderSet
from fmverify.verdict import Outcome, Status

LEDGER = Path(os.environ["FM_LEDGER_REPO"]) if os.environ.get("FM_LEDGER_REPO") else None
VEC = Path("fixtures/ledger-acceptance/v0")
RC = Path("fixtures/record-certificate/v0")
pytestmark = pytest.mark.skipif(
    LEDGER is None or not (LEDGER / VEC / "basic.acceptance.json").is_file(),
    reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger holding its acceptance record test vector")


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _inputs():
    record = _json(LEDGER / VEC / "basic.acceptance.json")
    exp = _json(LEDGER / VEC / "basic.expect.json")
    cert = jcs.loads((LEDGER / RC / "certificate.json").read_text(encoding="utf-8"))
    a = cert["anchor"]
    hour = {"window_start": record["window"]["start"], "root": a["root"], "size": len(exp["anchor"]["leaves"]),
            "opentimestamps_b64": a["opentimestamps_b64"],
            "rfc3161": [{"authority": t["authority"], "gen_time": t["gen_time"], "token_b64": t["token_b64"]} for t in a["rfc3161"]]}
    anchor = {"root": exp["anchor"]["root"], "size": len(exp["anchor"]["leaves"]), "leaf_index": 1,
              "audit_path": [exp["anchor"]["leaves"][0]]}
    roots = pki.load_certificates((LEDGER / RC / "test-tsa-one.pem").read_bytes() + (LEDGER / RC / "test-tsa-two.pem").read_bytes())
    sources = [HeaderSet.parse((LEDGER / RC / "headers.txt").read_text(encoding="utf-8"), REGTEST, name="headers.txt")]
    return record, exp, hour, anchor, roots, sources


def _proof(record: dict, exp: dict, anchor: dict, i: int, received_at: str | None = None) -> dict:
    e = exp["accepted"][i]
    return {"event_hash": e["event_hash"], "received_at": received_at or e["received_at"], "record": record, "leaf_index": i,
            "audit_path": e["audit_path"], "anchor": anchor}


def test_the_vectors_name_one_another():
    record, exp, hour, anchor, _, _ = _inputs()
    assert ledger_acceptance.record_hash(record) == exp["acceptance_record_hash"]
    assert record["root_record"] == exp["root_record_hash"] == ledger_acceptance.record_hash(exp["root_record"])
    assert hour["root"] == anchor["root"], "the record certificate vector is anchored in another root"
    assert len(exp["accepted"]) == record["size"]


def test_every_event_of_the_hour_end_to_end():
    record, exp, hour, anchor, roots, sources = _inputs()
    key = bytes.fromhex(exp["public_key"])
    for i in range(record["size"]):
        v = ledger_acceptance.verify(_proof(record, exp, anchor, i), public_key=key, root_record=exp["root_record"], hour=hour,
                                     header_sources=sources, network=REGTEST, roots=roots)
        rows = {c.id: c.status for c in v.checks}
        assert v.outcome is Outcome.VALID, (i, v.to_text())
        for check in ("signature", "window", "inclusion", "root_record", "anchor_inclusion", "hour", "rfc3161.0", "rfc3161.1",
                      "opentimestamps", "order"):
            assert rows[f"acceptance.{check}"] is Status.PASS, (i, check)


def test_one_acceptance_time_changed():
    """The vector's README: changing one acceptance time makes that event's audit path fail against accepted_root."""
    record, exp, _, anchor, _, _ = _inputs()
    at = exp["accepted"][3]["received_at"]
    later = at[:-2] + str((int(at[-2]) + 1) % 10) + "Z"
    v = ledger_acceptance.verify(_proof(record, exp, anchor, 3, later), public_key=bytes.fromhex(exp["public_key"]))
    assert {c.id: c.status for c in v.checks}["acceptance.inclusion"] is Status.FAIL and v.outcome is Outcome.INVALID
