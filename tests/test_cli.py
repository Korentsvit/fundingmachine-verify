import json
from pathlib import Path

from fmverify.cli import main

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CASE = FIX / "ots" / "mainnet-840000-sparse"
SPARSE = FIX / "bitcoin" / "mainnet" / "headers-sparse.txt"
WINDOW = FIX / "bitcoin" / "mainnet" / "headers-839990-840009.bin"


def test_ots_valid_exit_zero(capsys):
    code = main(["ots", str(CASE / "proof.ots"), "--file", str(CASE / "subject.bin"), "--headers", str(SPARSE)])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("VALID: ")
    assert "Relied on:" in out and "Does not establish:" in out


def test_ots_chain_with_start(capsys):
    code = main(["ots", str(CASE / "proof.ots"), "--file", str(CASE / "subject.bin"), "--headers-chain", f"{WINDOW}@839990"])
    assert code == 0


def test_ots_json(capsys):
    code = main(["ots", str(CASE / "proof.ots"), "--headers", str(SPARSE), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and doc["outcome"] == "valid" and doc["kind"] == "opentimestamps"
    assert doc["relies_on"] and doc["does_not_establish"]


def test_ots_invalid_exit_one(capsys):
    case = FIX / "ots" / "regtest-back-dated"
    code = main(["ots", str(case / "proof.ots"), "--file", str(case / "document.txt"), "--network", "regtest",
                 "--headers-chain", str(FIX / "bitcoin" / "regtest" / "headers-0-11.bin")])
    assert code == 1 and capsys.readouterr().out.startswith("INVALID: ")


def test_ots_indeterminate_exit_two(capsys):
    assert main(["ots", str(CASE / "proof.ots"), "--file", str(CASE / "subject.bin")]) == 2


def test_usage_errors_exit_64(capsys):
    assert main(["ots", "/nonexistent.ots"]) == 64
    assert main(["ots", str(CASE / "proof.ots"), "--digest", "zz"]) == 64
    try:
        main(["ots"])
    except SystemExit as exc:
        assert exc.code == 64


def test_merkle_cli(tmp_path, capsys):
    from fmverify import merkle

    leaves = [b"one", b"two", b"three"]
    proof = {"scheme": "rfc9162-sha256", "leaf_index": 2, "tree_size": 3,
             "path": [p.hex() for p in merkle.inclusion_path(leaves, 2)], "root": merkle.tree_hash(leaves).hex()}
    (tmp_path / "p.json").write_text(json.dumps(proof))
    (tmp_path / "leaf").write_bytes(b"three")
    assert main(["merkle", str(tmp_path / "p.json"), "--leaf-file", str(tmp_path / "leaf")]) == 0
    assert main(["merkle", str(tmp_path / "p.json"), "--leaf-hex", b"two".hex()]) == 1
    assert main(["merkle", str(tmp_path / "p.json"), "--leaf-file", str(tmp_path / "leaf"), "--root", "00" * 32]) == 1
