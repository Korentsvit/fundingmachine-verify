"""The public release location (tools/blob_release.py): a published release assembled for its prefix in the Blob
store, checked file by file, and the served copy compared. Offline: a local server stands in for the store."""

import functools
import hashlib
import http.server
import json
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import blob_release  # noqa: E402

COMMIT = "ff49adac1a291d8aa152ddd8c7268fcd0a8314f6"


def _release(tmp: Path) -> Path:
    rel = tmp / "release"
    rel.mkdir()
    (rel / "fundingmachine_verify-0.4.0-py3-none-any.whl").write_bytes(b"wheel bytes")
    (rel / "fundingmachine_verify-0.4.0.tar.gz").write_bytes(b"sdist bytes")
    (rel / "fm-verify-fixtures-0.4.0.tar").write_bytes(b"fixture bytes")
    (rel / "scoreboard-manifest.json").write_text("{}\n", encoding="utf-8")
    sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(rel.iterdir())]
    (rel / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return rel


def _gate(tmp: Path, **change) -> Path:
    record = {"release": "v0.4.0", "path": "package", "commit": COMMIT,
              "key1": {"holder": "verifier", "passed": True, "evidence": "https://example.org/run"},
              "key2": {"holder": "release-gate", "verdict": "no issue", "commit": COMMIT, "report": "https://example.org/r"}}
    record.update(change)
    path = tmp / "gate.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _assemble(tmp: Path, **kw) -> dict:
    args = {"release": _release(tmp), "tag": "v0.4.0", "commit": COMMIT, "gate": _gate(tmp),
            "licence": ROOT / "LICENSE", "out": tmp / "out"}
    args.update(kw)
    return blob_release.assemble(**args)


def test_the_prefix_holds_the_release_its_licence_attribution_manifest_and_sums(tmp_path):
    m = _assemble(tmp_path)
    out = tmp_path / "out"
    assert m["prefix"] == "verify-v0.4.0" and m["commit"] == COMMIT and m["gate"]["key2"]["verdict"] == "no issue"
    assert sorted(p.name for p in out.iterdir()) == sorted([
        "fundingmachine_verify-0.4.0-py3-none-any.whl", "fundingmachine_verify-0.4.0.tar.gz",
        "fm-verify-fixtures-0.4.0.tar", "scoreboard-manifest.json", "LICENSE", "ATTRIBUTION.txt",
        "manifest.json", "SHA256SUMS"])
    assert {f["path"] for f in m["files"]} == {p.name for p in out.iterdir()} - {"manifest.json", "SHA256SUMS"}
    sums = blob_release.read_sums(out / "SHA256SUMS")
    assert set(sums) == {p.name for p in out.iterdir()} - {"SHA256SUMS"}
    assert all(blob_release.sha256(out / n) == d for n, d in sums.items())
    assert (out / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    text = (out / "ATTRIBUTION.txt").read_text(encoding="utf-8")
    assert "Apache License, Version 2.0" in text and "NW PharmaTech Ltd" in text and COMMIT in text


def test_the_same_release_gives_the_same_bytes(tmp_path):
    _assemble(tmp_path)
    first = {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()}
    blob_release.assemble(tmp_path / "release", "v0.4.0", COMMIT, tmp_path / "gate.json", ROOT / "LICENSE", tmp_path / "out")
    assert {p.name: p.read_bytes() for p in (tmp_path / "out").iterdir()} == first


@pytest.mark.parametrize("change", [{"commit": "0" * 40}, {"release": "v0.3.1"}, {"key2": {"holder": "release-gate"}},
                                   {"key1": {"holder": "verifier", "passed": False}}])
def test_a_release_without_both_keys_for_its_commit_is_refused(tmp_path, change):
    rel = _release(tmp_path)
    with pytest.raises(SystemExit):
        blob_release.assemble(rel, "v0.4.0", COMMIT, _gate(tmp_path, **change), ROOT / "LICENSE", tmp_path / "out")


def test_a_changed_missing_or_extra_release_file_is_refused(tmp_path):
    rel = _release(tmp_path)
    gate = _gate(tmp_path)
    (rel / "fundingmachine_verify-0.4.0.tar.gz").write_bytes(b"other bytes")
    with pytest.raises(SystemExit):
        blob_release.assemble(rel, "v0.4.0", COMMIT, gate, ROOT / "LICENSE", tmp_path / "out")
    (rel / "fundingmachine_verify-0.4.0.tar.gz").unlink()
    with pytest.raises(SystemExit):
        blob_release.assemble(rel, "v0.4.0", COMMIT, gate, ROOT / "LICENSE", tmp_path / "out")


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def test_check_compares_every_served_file(tmp_path):
    _assemble(tmp_path)
    out = tmp_path / "out"
    served = tmp_path / "served"
    served.mkdir()
    for p in out.iterdir():
        (served / p.name).write_bytes(p.read_bytes())
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(_Quiet, directory=str(served)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert blob_release.check(base, out) == []
        (served / "LICENSE").write_text("another licence\n", encoding="utf-8")
        (served / "manifest.json").unlink()
        problems = blob_release.check(base, out)
    finally:
        server.shutdown()
    assert any(p.startswith("LICENSE: ") for p in problems) and any(p.startswith("manifest.json: not served") for p in problems)
