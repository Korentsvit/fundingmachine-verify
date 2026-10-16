import json
import shutil
from pathlib import Path

from fmverify import conformance
from fmverify.cli import main

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def test_published_fixtures_conform():
    manifest, results = conformance.run_suite(FIX)
    assert manifest == []
    assert results and all(r.ok for r in results), conformance.report(manifest, results)
    assert {r.kind for r in results} == {"ots", "rfc3161", "merkle", "anchors", "ledger-anchors", "certificate", "chain", "roots"}


def test_cli_conformance(capsys):
    assert main(["conformance", str(FIX)]) == 0
    assert "cases conform" in capsys.readouterr().out
    assert main(["conformance", str(FIX), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["conforms"] is True
    assert main(["conformance", "/nonexistent"]) == 64


def test_a_wrong_expectation_and_a_changed_fixture_are_reported(tmp_path, capsys):
    copy = tmp_path / "fixtures"
    shutil.copytree(FIX, copy)
    exp_path = copy / "ots" / "regtest-valid" / "expected.json"
    exp = json.loads(exp_path.read_text())
    exp["outcome"] = "invalid"
    exp_path.write_text(json.dumps(exp))
    manifest, results = conformance.run_suite(copy)
    assert manifest == ["changed: ots/regtest-valid/expected.json"]
    bad = [r for r in results if not r.ok]
    assert [r.name for r in bad] == ["regtest-valid"]
    assert main(["conformance", str(copy)]) == 1
    assert "not the published ones" in capsys.readouterr().out


def test_every_verdict_matches_the_published_schema():
    jsonschema = __import__("pytest").importorskip("jsonschema")
    schema = json.loads((FIX.parent / "docs" / "verdict.schema.json").read_text())
    for kind, case in conformance.cases(FIX):
        _, v = conformance.run_case(kind, case)
        jsonschema.validate(json.loads(v.to_json()), schema)
