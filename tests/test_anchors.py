import json
from pathlib import Path

import pytest

from fmverify import anchors, merkle, pki
from fmverify.bitcoin import NETWORKS, HeaderChain
from fmverify.cli import main
from fmverify.verdict import Outcome, Status

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "anchors"
CASES = sorted(p for p in FIX.iterdir() if (p / "expected.json").is_file())


def run_case(case: Path):
    exp = json.loads((case / "expected.json").read_text())
    net = NETWORKS[exp["network"]]
    sources = [HeaderChain.from_file(case / s["path"], s["start"], net) for s in exp.get("headers_chain", [])]
    roots = [c for r in exp.get("roots", []) for c in pki.load_certificates((case / r).read_bytes())]
    repo = case / exp["repo_root"] if "repo_root" in exp else None
    files = [repo / f for f in exp.get("files", [])]
    v = anchors.verify_batch(case, repo_root=repo, files=files, header_sources=sources, network=net, roots=roots)
    return exp, v


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_fixture_case(case):
    exp, v = run_case(case)
    assert v.outcome.value == exp["outcome"], v.to_text()
    assert [c.id for c in v.checks if c.status is Status.FAIL] == exp.get("failing", []), v.to_text()
    warned = [c.id for c in v.checks if c.status is Status.WARN]
    for w in exp.get("warning", []):
        assert w in warned, v.to_text()


def test_valid_statement_carries_both_anchors():
    _, v = run_case(FIX / "batch-valid")
    assert "Bitcoin block 4" in v.statement and "time-stamping authority" in v.statement
    assert v.statement.startswith("The 4 files listed in the batch are the leaves of Merkle root")


def test_checkout_changed_names_the_files():
    _, v = run_case(FIX / "checkout-changed")
    c = next(c for c in v.checks if c.id == "anchors.checkout")
    assert c.data["changed"] == ["docs/RULINGS-example.md"] and c.data["absent"] == ["data/example.csv"]


def test_strict_files_turns_a_change_into_a_failure():
    case = FIX / "checkout-changed"
    exp = json.loads((case / "expected.json").read_text())
    net = NETWORKS["regtest"]
    sources = [HeaderChain.from_file(case / exp["headers_chain"][0]["path"], 0, net)]
    roots = pki.load_certificates((case / exp["roots"][0]).read_bytes())
    v = anchors.verify_batch(case, repo_root=case / "../repo-changed", header_sources=sources, network=net, roots=roots,
                             strict_files=True)
    assert v.outcome is Outcome.INVALID


def test_emitted_proof_verifies_with_merkle():
    batch = anchors.load_batch(FIX / "batch-valid")
    for e in batch.entries:
        proof = anchors.inclusion_proof(batch, e.path)
        leaf = f"{e.digest.hex()} {e.path}".encode()
        assert merkle.verify_inclusion(leaf, proof, expected_root=batch.root).outcome is Outcome.VALID
    with pytest.raises(anchors.BatchError):
        anchors.inclusion_proof(batch, "not/listed.md")


def _batch(tmp_path, **changes):
    doc = json.loads((FIX / "batch-valid" / "batch.json").read_text())
    doc.update(changes)
    (tmp_path / "batch.json").write_text(json.dumps(doc))
    return tmp_path


@pytest.mark.parametrize("changes,why", [
    ({"format": "something/1"}, "format"),
    ({"tree": "sha1-pairs"}, "tree"),
    ({"leaf_encoding": "md5"}, "leaf encoding"),
    ({"leaves": []}, "no files"),
    ({"leaves": [{"path": "../etc/passwd", "sha256": "00" * 32}]}, "plain repository-relative"),
    ({"leaves": [{"path": "/abs.md", "sha256": "00" * 32}]}, "plain repository-relative"),
    ({"leaves": [{"path": "a.md", "sha256": "00" * 32}, {"path": "a.md", "sha256": "11" * 32}]}, "twice"),
    ({"root": "00"}, "32 bytes"),
    ({"ots": ["../../rfc3161/valid-rsa/token.tsr"]}, "plain file name"),
])
def test_malformed_batches(tmp_path, changes, why):
    with pytest.raises(anchors.BatchError, match=why):
        anchors.load_batch(_batch(tmp_path, **changes))
    v = anchors.verify_batch(tmp_path)
    assert v.outcome is Outcome.INVALID and v.checks[0].id == "anchors.batch"


def test_no_anchor_files_is_indeterminate(tmp_path):
    _batch(tmp_path, ots=[], rfc3161=[])
    v = anchors.verify_batch(tmp_path)
    assert v.outcome is Outcome.INDETERMINATE


def test_cli_and_emit_proof(capsys):
    case = FIX / "batch-valid"
    base = ["anchors", str(case), "--network", "regtest",
            "--headers-chain", str(FIX.parent / "bitcoin" / "regtest" / "anchors-headers-0-6.bin"),
            "--roots", str(FIX.parent / "rfc3161" / "pki" / "root.pem")]
    assert main(base + ["--repo-root", str(FIX / "repo")]) == 0
    assert main(base + ["--repo-root", str(FIX / "repo-changed"), "--file", str(FIX / "repo-changed" / "docs" / "RULINGS-example.md")]) == 1
    assert main(["anchors", str(case), "--network", "regtest"]) == 2
    capsys.readouterr()
    with pytest.raises(SystemExit) as stop:
        main(["anchors", str(case), "--emit-proof", "docs/RULINGS-example.md"])
    assert stop.value.code == 0
    proof = json.loads(capsys.readouterr().out)
    assert proof["scheme"] == "rfc9162-sha256" and proof["tree_size"] == 4
