import base64
import json
import socket
from pathlib import Path

import pytest

from fmverify import api

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_ots_request():
    case = FIX / "ots" / "mainnet-840000-sparse"
    out = api.verify({"api": "fm-verify/0", "kind": "ots", "proof": b64(case / "proof.ots"), "file": b64(case / "subject.bin"),
                      "headers": [{"kind": "sparse", "name": "headers fetched by the page from mempool.space",
                                   "text": (FIX / "bitcoin" / "mainnet" / "headers-sparse.txt").read_text()}]})
    assert out["outcome"] == "valid"
    assert any("headers fetched by the page from mempool.space" in r for r in out["relies_on"])


def test_ots_request_with_chain():
    case = FIX / "ots" / "regtest-valid"
    out = api.verify({"kind": "ots", "network": "regtest", "proof": b64(case / "proof.ots"), "file": b64(case / "document.txt"),
                      "headers": [{"kind": "chain", "start": 0, "data": b64(FIX / "bitcoin" / "regtest" / "headers-0-11.bin")}]})
    assert out["outcome"] == "valid"


def test_rfc3161_request():
    case = FIX / "rfc3161" / "valid-p256-chain-supplied"
    pki = FIX / "rfc3161" / "pki"
    out = api.verify({"kind": "rfc3161", "token": b64(case / "token.tsr"), "file": b64(case / "document.txt"),
                      "roots": [(pki / "root.pem").read_text()], "chain": [(pki / "chain-p256.pem").read_text()]})
    assert out["outcome"] == "valid"


def test_merkle_request():
    from fmverify import merkle

    leaves = [b"a", b"b", b"c"]
    proof = {"scheme": "rfc9162-sha256", "leaf_index": 1, "tree_size": 3,
             "path": [p.hex() for p in merkle.inclusion_path(leaves, 1)], "root": merkle.tree_hash(leaves).hex()}
    assert api.verify({"kind": "merkle", "proof": proof, "leaf": base64.b64encode(b"b").decode()})["outcome"] == "valid"
    assert api.verify({"kind": "merkle", "proof": proof, "leaf": base64.b64encode(b"x").decode()})["outcome"] == "invalid"
    leaf = base64.b64encode(b"b").decode()
    assert api.verify({"kind": "merkle", "proof": proof, "leaf": leaf, "tree_size": 3})["outcome"] == "valid"
    assert api.verify({"kind": "merkle", "proof": proof, "leaf": leaf, "tree_size": 4})["outcome"] == "invalid"
    assert "error" in api.verify({"kind": "merkle", "proof": proof, "leaf": leaf, "tree_size": "3"})


def _anchor_request(case: Path, **extra):
    req = {"kind": "anchors", "network": "regtest", "label": case.name,
           "batch": json.loads((case / "batch.json").read_text()),
           "anchor_files": {p.name: b64(p) for p in case.iterdir() if p.suffix in (".ots", ".tsr")},
           "headers": [{"kind": "chain", "data": b64(FIX / "bitcoin" / "regtest" / "anchors-headers-0-6.bin")}],
           "roots": [(FIX / "rfc3161" / "pki" / "root.pem").read_text()]}
    req.update(extra)
    return req


def test_anchors_request():
    case = FIX / "anchors" / "batch-valid"
    assert api.verify(_anchor_request(case))["outcome"] == "valid"
    held = {"docs/RULINGS-example.md": b64(FIX / "anchors" / "repo-changed" / "docs" / "RULINGS-example.md")}
    out = api.verify(_anchor_request(case, files=held))
    assert out["outcome"] == "invalid"
    assert api.verify(_anchor_request(FIX / "anchors" / "batch-reordered"))["outcome"] == "invalid"


def test_anchors_request_with_bad_batch_is_a_failing_verdict():
    out = api.verify(_anchor_request(FIX / "anchors" / "batch-valid", batch={"format": "nope"}))
    assert out["outcome"] == "invalid" and out["checks"][0]["id"] == "anchors.batch"


@pytest.mark.parametrize("req,fragment", [
    ([], "JSON object"),
    ({"kind": "teleport"}, "kind must be"),
    ({"api": "fm-verify/9", "kind": "ots"}, "this verifier answers"),
    ({"kind": "ots", "proof": "!!!"}, "not base64"),
    ({"kind": "ots", "proof": "AA==", "explorer": "https://mempool.space/api"}, "no network call"),
    ({"kind": "ots", "proof": "AA==", "network": "testnet9"}, "network must be"),
    ({"kind": "ots", "proof": "AA==", "file": "AA==", "digest": "00"}, "not both"),
    ({"kind": "rfc3161", "token": "AA==", "roots": ["not pem"]}, "not a PEM"),
    ({"kind": "merkle", "proof": "x"}, "must be an object"),
])
def test_malformed_requests_answer_with_an_error(req, fragment):
    out = api.verify(req)
    assert fragment in out["error"]


def test_json_round_trip():
    out = json.loads(api.verify_json("{not json"))
    assert "not JSON" in out["error"]
    case = FIX / "ots" / "regtest-pending-only"
    out = json.loads(api.verify_json(json.dumps({"kind": "ots", "proof": b64(case / "proof.ots")})))
    assert out["outcome"] == "indeterminate"


def _ledger_anchor_request(case: Path, **extra) -> dict:
    files = {p.name: b64(p) for p in sorted(case.iterdir()) if p.name == "manifest.json" or p.name.startswith("root.preimage")}
    return {"kind": "ledger-anchor", "label": case.name, "network": "regtest", "files": files,
            "headers": [{"kind": "chain", "data": b64(FIX / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin"), "start": 0,
                         "name": "regtest fixture headers"}],
            "roots": [(FIX / "rfc3161" / "pki" / "root.pem").read_text(), (FIX / "ledger-anchors" / "pki" / "second-root.pem").read_text()],
            **extra}


def test_ledger_anchor_request():
    """The same verdicts as the command line, from files held in memory."""
    from fmverify import ledger_anchors, pki
    from fmverify.bitcoin import NETWORKS, HeaderChain

    roots = [c for p in ("rfc3161/pki/root.pem", "ledger-anchors/pki/second-root.pem") for c in pki.load_certificates((FIX / p).read_bytes())]

    for name in ("valid", "manifest-misstates-token", "leaf-hash-wrong", "one-authority", "unknown-contract"):
        case = FIX / "ledger-anchors" / name
        out = api.verify(_ledger_anchor_request(case))
        disk = ledger_anchors.verify_dir(case, roots=roots, network=NETWORKS["regtest"],
                                         header_sources=[HeaderChain.from_file(FIX / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin",
                                                                               0, NETWORKS["regtest"])])
        assert out["outcome"] == disk.outcome.value, name
        assert [c["id"] for c in out["checks"]] == [c.id for c in disk.checks], name


def test_ledger_anchor_request_refuses_other_files():
    req = _ledger_anchor_request(FIX / "ledger-anchors" / "valid")
    req["files"]["../etc/passwd"] = "AA=="
    assert "manifest.json and root.preimage files only" in api.verify(req)["error"]


def test_deeply_nested_json_is_an_error_answer_not_a_crash():
    deep = "[" * 100_000 + "]" * 100_000
    out = json.loads(api.verify_json('{"kind": "chain", "events": ' + deep + "}"))
    assert "nested too deeply" in out["error"]
