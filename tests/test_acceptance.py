"""Acceptance proofs (ledger-acceptance/v0): the command, the library entry point, malformed input, and the
Provenance Ledger's own code both ways (tools/ledger_crosscheck/acceptance.mts, with FM_LEDGER_REPO)."""

import base64
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from fmverify import api, cli, ledger_acceptance
from fmverify.base58 import did_key_ed25519
from fmverify.verdict import Outcome, Status

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "fixtures" / "acceptance"
VALID = CASES / "valid"


def _exp(case: Path) -> dict:
    return json.loads((case / "expected.json").read_text(encoding="utf-8"))


def _load(case: Path, name: str):
    return json.loads((case / name).read_text(encoding="utf-8"))


def _rows(v) -> dict:
    return {c.id: c.status for c in v.checks}


def test_the_command_with_every_input(capsys):
    exp = _exp(VALID)
    args = ["acceptance", str(VALID / "acceptance.json"), "--key", exp["key"], "--root-record", str(VALID / "root-record.json"),
            "--hour", str(VALID / "hour.json"), "--network", "regtest", "--headers-chain", str(VALID / exp["headers_chain"][0]["path"]),
            "--json"] + [a for r in exp["roots"] for a in ("--roots", str(VALID / r))]
    assert cli.main(args) == 0
    v = json.loads(capsys.readouterr().out)
    assert v["outcome"] == "valid" and v["kind"] == "ledger-acceptance"
    assert {c["id"]: c["status"] for c in v["checks"]}["acceptance.order"] == "pass"


def test_the_command_takes_the_root_record_from_a_certificate_of_the_hour(tmp_path, capsys):
    cert = {"credentialSubject": {"ledger_root": {"record": _load(VALID, "root-record.json")}}}
    (tmp_path / "cert.json").write_text(json.dumps(cert), encoding="utf-8")
    assert cli.main(["acceptance", str(VALID / "acceptance.json"), "--key", _exp(VALID)["key"], "--root-record", str(tmp_path / "cert.json"),
                     "--json"]) == 0
    rows = {c["id"]: c["status"] for c in json.loads(capsys.readouterr().out)["checks"]}
    assert rows["acceptance.root_record"] == "pass" and rows["acceptance.hour"] == "not_checked"


def test_the_command_without_a_key_is_indeterminate(capsys):
    assert cli.main(["acceptance", str(VALID / "acceptance.json")]) == 2
    assert "acceptance.signature" in capsys.readouterr().out


def test_the_library_entry_point_takes_the_key_as_did_or_hex():
    exp = _exp(VALID)
    req = {"api": api.API, "kind": "ledger-acceptance", "proof": _load(VALID, "acceptance.json"), "root_record": _load(VALID, "root-record.json")}
    for key in (exp["key"], did_key_ed25519(exp["key"]).hex()):
        assert json.loads(api.verify_json(json.dumps({**req, "key": key})))["outcome"] == "valid"
    assert "error" in json.loads(api.verify_json(json.dumps({**req, "key": "did:key:zNotAKey"})))
    assert "error" in json.loads(api.verify_json(json.dumps({**req, "key": exp["key"], "hour": [1]})))


def test_the_window_is_checked_beyond_the_ledgers_own_check():
    """The Ledger's verifyAcceptance takes the leaf and the root; a signed record with a time outside its hour holds
    there and fails here, as docs/ANCHORING.md says every event's time falls inside its root's window."""
    case = CASES / "time-outside-the-hour"
    v = ledger_acceptance.verify(_load(case, "acceptance.json"), public_key=did_key_ed25519(_exp(case)["key"]))
    rows = _rows(v)
    assert rows["acceptance.signature"] is Status.PASS and rows["acceptance.inclusion"] is Status.PASS
    assert rows["acceptance.window"] is Status.FAIL and v.outcome is Outcome.INVALID


def _mutations(proof: dict):
    yield "a list", []
    yield "no fields", {}
    for field in ledger_acceptance.PROOF_FIELDS:
        yield f"without {field}", {k: v for k, v in proof.items() if k != field}
    yield "an extra field", {**proof, "note": 1}
    for k, bad in [("event_hash", "AB" * 32), ("event_hash", 7), ("received_at", "2026-02-30T08:00:00.000000Z"), ("leaf_index", True),
                   ("leaf_index", -1), ("leaf_index", 5), ("leaf_index", 2.0), ("audit_path", "x"), ("audit_path", ["zz"]),
                   ("audit_path", []), ("anchor", {}), ("anchor", 3)]:
        yield f"{k} = {bad!r}", {**proof, k: bad}
    for k, bad in [("contract", "ledger-root/v0"), ("tenant_id", "A"), ("window", {"start": "2026-10-16T08:00:00.000Z"}),
                   ("window", {"start": "2026-10-16T08:00:00.000Z", "end": "2026-10-16T10:00:00.000Z"}),
                   ("window", {"start": "2026-13-16T08:00:00.000Z", "end": "2026-13-16T09:00:00.000Z"}), ("size", 0), ("size", "5"),
                   ("size", 2**60), ("root_record", "0"), ("accepted_root", None), ("key_id", 1), ("sig", "=" * 86), ("sig", "A" * 85)]:
        yield f"record {k} = {bad!r}", {**proof, "record": {**proof["record"], k: bad}}
    yield "record with an extra field", {**proof, "record": {**proof["record"], "note": 1}}
    for k, bad in [("root", "0" * 63), ("size", 0), ("leaf_index", 3), ("audit_path", [1]), ("audit_path", ["00" * 32] * 70)]:
        yield f"anchor {k} = {bad!r}", {**proof, "anchor": {**proof["anchor"], k: bad}}


def test_malformed_proofs_give_a_verdict_never_an_exception():
    exp = _exp(VALID)
    proof, key = _load(VALID, "acceptance.json"), did_key_ed25519(exp["key"])
    hour = _load(VALID, "hour.json")
    for what, bad in _mutations(proof):
        v = ledger_acceptance.verify(copy.deepcopy(bad), public_key=key, root_record=_load(VALID, "root-record.json"), hour=hour)
        assert v.outcome is not Outcome.VALID, what
    for what, h in [("hour not an object", [1]), ("hour without a window", {**hour, "window_start": None}),
                    ("a token not base64", {**hour, "rfc3161": [{"authority": "x", "token_b64": "%%"}]}),
                    ("a proof not base64", {**hour, "opentimestamps_b64": "%%"})]:
        v = ledger_acceptance.verify(copy.deepcopy(proof), public_key=key, hour=h)
        assert v.outcome is Outcome.INVALID, what
    for what, r in [("a root record of another contract", {"contract": "x"}), ("a list", [1])]:
        assert ledger_acceptance.verify(copy.deepcopy(proof), public_key=key, root_record=r).outcome is Outcome.INVALID, what


def test_a_record_names_its_leaf_as_the_ledger_hashes_it():
    """The leaf is SHA-256(0x00 || event_hash || received_at), the record's hash SHA-256(JCS(record with sig))."""
    import hashlib

    from fmverify import jcs, merkle

    proof = _load(VALID, "acceptance.json")
    data = bytes.fromhex(proof["event_hash"]) + proof["received_at"].encode()
    assert merkle.leaf_hash(ledger_acceptance.acceptance_leaf(proof["event_hash"], proof["received_at"])) == \
        hashlib.sha256(b"\x00" + data).digest()
    assert ledger_acceptance.record_hash(proof["record"]) == hashlib.sha256(jcs.dumps(proof["record"])).hexdigest()


LEDGER = Path(os.environ["FM_LEDGER_REPO"]) if os.environ.get("FM_LEDGER_REPO") else None
TSX = LEDGER / "node_modules" / ".bin" / "tsx" if LEDGER else None

# What the Ledger's own functions answer on each fixture case: its verifyAcceptanceSig with the fixtures' tenant key,
# its verifyAcceptance (false where acceptanceLeaf refuses the time's form), and its verifyInclusion for the anchor.
LEDGER_ON_FIXTURES = {
    "record-altered": (False, False, False),
    "signed-by-another-key": (False, True, None),
    "time-changed": (True, False, True),
    "time-written-otherwise": (True, False, True),
    "time-outside-the-hour": (True, True, None),
    "valid-not-anchored": (True, True, None),
}


@pytest.mark.skipif(TSX is None or not TSX.exists() or shutil.which("node") is None or not (LEDGER / "src" / "acceptance.ts").is_file(),
                    reason="set FM_LEDGER_REPO to a checkout of fundingmachine-ledger with src/acceptance.ts and its dependencies installed")
def test_the_ledgers_own_code_both_ways():
    done = subprocess.run([str(TSX), str(ROOT / "tools" / "ledger_crosscheck" / "acceptance.mts"), str(ROOT / "fixtures"), "40"],
                          cwd=LEDGER, capture_output=True, text=True, timeout=600, check=True)
    lines = [json.loads(line) for line in done.stdout.splitlines()]
    built = [x for x in lines if x["kind"] == "built"]
    assert len(built) == 40
    for x in built:
        key = bytes.fromhex(x["key_hex"])
        v = ledger_acceptance.verify(x["proof"], public_key=key, root_record=x["root_record"])
        assert v.outcome is Outcome.VALID, (x["hour"], v.to_text())
        assert _rows(v)["acceptance.anchor_inclusion"] is Status.PASS
        later = copy.deepcopy(x["proof"])
        later["received_at"] = later["received_at"][:-2] + str((int(later["received_at"][-2]) + 1) % 10) + "Z"
        assert _rows(ledger_acceptance.verify(later, public_key=key))["acceptance.inclusion"] is Status.FAIL
    fixtures = {x["name"]: x for x in lines if x["kind"] == "fixture"}
    assert set(fixtures) == {p.name for p in CASES.iterdir()}
    assert fixtures["no-record"]["record"] is False
    for name, x in fixtures.items():
        if name == "no-record":
            continue
        assert (x["signature"], x["inclusion"], x["anchor"]) == LEDGER_ON_FIXTURES.get(name, (True, True, True)), name


def test_the_hour_record_is_read_as_the_ledger_writes_it():
    """GET /api/anchors?hour= gives window_start from toISOString(), gen_time from the database: both read as instants."""
    hour = _load(VALID, "hour.json")
    assert hour["window_start"].endswith(".000Z")
    base64.b64decode(hour["opentimestamps_b64"], validate=True)


def test_a_bitcoin_summary_that_misstates_the_proof_is_a_warning():
    """The hour's record summarises its proof (the Ledger's bitcoinStatus); the verdict rests on the proof, and a summary
    saying otherwise is shown, not trusted."""
    exp = _exp(VALID)
    from fmverify.bitcoin import REGTEST, HeaderChain

    sources = [HeaderChain((VALID / exp["headers_chain"][0]["path"]).read_bytes(), 0, REGTEST)]
    from fmverify import pki

    roots = [c for r in exp["roots"] for c in pki.load_certificates((VALID / r).read_bytes())]
    hour = _load(VALID, "hour.json")
    for stated in ({**hour["bitcoin"], "status": "pending"}, {**hour["bitcoin"], "attestations": []}, {"status": "attested"}):
        v = ledger_acceptance.verify(_load(VALID, "acceptance.json"), public_key=did_key_ed25519(exp["key"]), hour={**hour, "bitcoin": stated},
                                     header_sources=sources, network=REGTEST, roots=roots)
        assert _rows(v)["acceptance.hour.bitcoin"] is Status.WARN and v.outcome is Outcome.VALID, stated
        assert "no later than Bitcoin block 3" in v.statement
