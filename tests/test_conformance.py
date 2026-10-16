import json
import shlex
import shutil
import sys
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


def test_fixture_archive_is_reproducible_and_conforms(tmp_path):
    """tools/fixture_archive.py gives the same bytes twice, and the suite
    extracted from it conforms."""
    import importlib.util
    import io
    import tarfile

    spec = importlib.util.spec_from_file_location("fixture_archive", Path(__file__).resolve().parent.parent / "tools" / "fixture_archive.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    first, second = mod.build("0.1.0"), mod.build("0.1.0")
    assert first == second
    with tarfile.open(fileobj=io.BytesIO(first)) as tar:
        members = tar.getmembers()
        assert all(m.mtime == 0 and m.uid == 0 and m.name.startswith("fm-verify-fixtures-0.1.0") for m in members)
        if hasattr(tarfile, "data_filter"):
            tar.extractall(tmp_path, filter="data")
        else:  # Python releases before the extraction filters
            tar.extractall(tmp_path)
    manifest, results = conformance.run_suite(tmp_path / "fm-verify-fixtures-0.1.0")
    assert not manifest and results and all(r.ok for r in results)


ADAPTER = [sys.executable, "-m", "fmverify.cli", "conformance-case"]


def test_another_implementation_is_run_case_by_case():
    """The reference adapter, run as an outside program, conforms with check
    ids compared; an implementation answering valid to everything does not."""
    manifest, results = conformance.run_suite(FIX, implementation=ADAPTER, check_ids=True, kinds=["merkle", "roots"])
    assert not manifest and len(results) == 14 and all(r.ok for r in results), [r.problems for r in results if not r.ok]
    always = [sys.executable, "-c", "print('{\"outcome\": \"valid\"}')"]
    _, results = conformance.run_suite(FIX, implementation=always, kinds=["merkle"])
    wrong = [r for r in results if not r.ok]
    assert wrong and all(r.expected != "valid" and r.problems[0].startswith("outcome valid, expected") for r in wrong)
    assert all(r.ok for r in results if r.expected == "valid")


def test_an_implementation_that_does_not_answer_is_named():
    silent = [sys.executable, "-c", "import sys; sys.stderr.write('cannot read this\\n'); sys.exit(3)"]
    _, results = conformance.run_suite(FIX, implementation=silent, kinds=["roots"])
    assert all(r.got == "error" and "exit 3" in r.problems[0] and "cannot read this" in r.problems[0] for r in results)
    slow = [sys.executable, "-c", "import time; time.sleep(5)"]
    _, results = conformance.run_suite(FIX, implementation=slow, kinds=["roots"], timeout=0.2)
    assert results[0].problems == ["no answer within 0.2 s"]
    _, results = conformance.run_suite(FIX, implementation=["/nonexistent/implementation"], kinds=["roots"])
    assert results[0].problems[0].startswith("could not run /nonexistent/implementation")


def test_conformance_command_line_for_another_implementation(capsys):
    cmd = " ".join(shlex.quote(a) for a in ADAPTER)
    assert main(["conformance", str(FIX), "--implementation", cmd, "--check-ids", "--kind", "roots"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Implementation: ") and "6 of 6 cases conform" in out
    assert main(["conformance", str(FIX), "--check-ids"]) == 64
    assert main(["conformance", str(FIX), "--kind", "nothing"]) == 64
    assert main(["conformance-case", "merkle", str(FIX / "merkle" / "rfc9162-wrong-leaf")]) == 1
    assert json.loads(capsys.readouterr().out)["outcome"] == "invalid"
