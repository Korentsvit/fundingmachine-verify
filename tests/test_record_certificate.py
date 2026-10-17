"""record-certificate/v0 (the Provenance Ledger's docs/RECORD_CERTIFICATE.md): the steps, the folding of an
OpenTimestamps path, the command line in its three forms and the library entry point."""

import base64
import json
from pathlib import Path

import pytest

from fmverify import api, merkle, ots, record_certificate as rc
from fmverify.bitcoin import REGTEST
from fmverify.cli import main
from fmverify.hashes import sha256

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "record-certificate"
REG = ROOT / "fixtures" / "bitcoin" / "regtest" / "record-certificate-headers-0-5.bin"
ROOTS = [str(ROOT / "fixtures" / "rfc3161" / "pki" / "root.pem"), str(ROOT / "fixtures" / "ledger-anchors" / "pki" / "second-root.pem")]
ARGS = ["--network", "regtest", "--headers-chain", str(REG), "--roots", ROOTS[0], "--roots", ROOTS[1]]


def test_inclusion_steps_reach_the_root_for_every_leaf_of_every_size():
    for size in range(1, 34):
        leaves = [sha256(b"leaf %d" % i) for i in range(size)]
        root = merkle.tree_hash(leaves)
        for index in range(size):
            path = [p.hex() for p in merkle.inclusion_path(leaves, index)]
            steps = rc.inclusion_steps(index, size, path)
            assert rc.apply_steps(leaves[index], steps) == root
            assert rc.inclusion_problem(steps, index, size) is None
            if size > 1:
                # The same steps claimed for another position are refused.
                assert rc.inclusion_problem(steps, (index + 1) % size, size) is not None


def test_folding_an_opentimestamps_path():
    A, P, H = ots.Op(0xF0, b"\x01"), ots.Op(0xF1, b"\x02"), ots.Op(0x08)
    assert rc.fold([A, P, ots.Op(0xF1, b"\x03"), H, H]) == [{"prepend": "0302", "append": "01"}, {"prepend": "", "append": ""}]
    with pytest.raises(ValueError, match="after its last SHA-256"):
        rc.fold([H, A])
    with pytest.raises(ValueError, match="cannot be written"):
        rc.fold([ots.Op(0xF2), H])
    msg = sha256(b"x")
    assert rc.apply_steps(msg, rc.fold([A, P, H])) == H.apply(P.apply(A.apply(msg))) and len(rc.fold([A, P, H])) == 1


def test_the_command_line_takes_a_directory_the_json_or_the_pdf(capsys):
    assert main(["record-certificate", str(FIX / "valid"), *ARGS]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["record-certificate", str(FIX / "valid" / "certificate.json"), *ARGS, "--json"]) == 0
    v = json.loads(capsys.readouterr().out)
    assert v["kind"] == "record-certificate" and v["outcome"] == "valid"
    assert main(["record-certificate", str(FIX / "valid-pdf" / "certificate.pdf"), *ARGS]) == 0
    capsys.readouterr()
    # Without the signature, the signature is reported as not checked: never as checked.
    assert main(["record-certificate", str(FIX / "valid" / "certificate.json"), "--sig", "/dev/null", *ARGS, "--json"]) != 0
    v = json.loads(capsys.readouterr().out)
    assert next(c for c in v["checks"] if c["id"] == "record_certificate.signature")["status"] == "fail"


def test_every_check_is_reported_once_and_only_checks_that_ran():
    data = (FIX / "valid" / "certificate.json").read_bytes()
    v = rc.verify(data, None, network=REGTEST)
    ids = [c.id for c in v.checks]
    assert len(ids) == len(set(ids))
    status = {c.id: c.status.value for c in v.checks}
    assert status["record_certificate.signature"] == "not_checked"
    assert status["record_certificate.bitcoin_block"] == "not_checked"
    assert v.outcome.value == "indeterminate"


def test_the_library_entry_point():
    d = FIX / "valid"
    req = {"kind": "record-certificate", "network": "regtest",
           "certificate_file": base64.b64encode((d / "certificate.json").read_bytes()).decode(),
           "signature": base64.b64encode((d / "certificate.sig").read_bytes()).decode(),
           "headers": [{"kind": "chain", "data": base64.b64encode(REG.read_bytes()).decode()}],
           "roots": [Path(p).read_text() for p in ROOTS]}
    assert api.verify(req)["outcome"] == "valid"
    pdf = dict(req, certificate_file=base64.b64encode((FIX / "valid-pdf" / "certificate.pdf").read_bytes()).decode())
    del pdf["signature"]
    assert api.verify(pdf)["outcome"] == "valid"
    assert "error" in api.verify({"kind": "record-certificate", "certificate_file": 3})


def test_shape_problems_name_what_departs_from_the_contract():
    c = json.loads((FIX / "valid" / "certificate.json").read_bytes())
    assert rc.shape_problems(c) == []
    c["anchor"]["rfc3161"] = c["anchor"]["rfc3161"][:1]
    c["record"]["extra"] = 1
    problems = rc.shape_problems(c)
    assert any("not in the contract: extra" in p for p in problems)


def test_the_submission_index_as_served_or_as_lines(tmp_path, capsys):
    d = FIX / "index-entry-matches"
    doc = json.loads((d / "index.json").read_text())
    assert rc.read_index((d / "index.json").read_bytes()) == doc["entries"]
    lines = tmp_path / "index.jsonl"
    lines.write_text("".join(json.dumps(e) + "\n" for e in doc["entries"]))
    assert rc.read_index(lines.read_bytes()) == doc["entries"]
    with pytest.raises(ValueError, match="submission-index/v0"):
        rc.read_index(json.dumps(dict(doc, contract="other/v0")).encode())
    assert main(["record-certificate", str(d), *ARGS, "--index", str(lines), "--json"]) == 0
    v = json.loads(capsys.readouterr().out)
    assert next(c for c in v["checks"] if c["id"] == "record_certificate.index")["status"] == "pass"
    req = {"kind": "record-certificate", "network": "regtest",
           "certificate_file": base64.b64encode((d / "certificate.json").read_bytes()).decode(),
           "signature": base64.b64encode((d / "certificate.sig").read_bytes()).decode(),
           "headers": [{"kind": "chain", "data": base64.b64encode(REG.read_bytes()).decode()}],
           "roots": [Path(p).read_text() for p in ROOTS], "index": doc}
    assert api.verify(req)["outcome"] == "valid"
    assert "error" in api.verify(dict(req, index="x"))
