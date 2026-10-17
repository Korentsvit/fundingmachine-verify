"""The tools that gather a Ledger anchor verdict's inputs from the network
(tools/fetch_ledger_record.py, tools/fetch_headers.py), run against a fake
network: they keep what matches and refuse, writing nothing, what does not."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from fmverify.bitcoin import HeaderSet

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"


def _tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Response:
    def __init__(self, body, headers):
        self.body, self.headers = body, headers

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serve(monkeypatch, mod, routes):
    def urlopen(url, timeout=None):
        body, headers = routes[url]
        return _Response(body, headers)

    monkeypatch.setattr(mod.urllib.request, "urlopen", urlopen)


URL = "https://record.example/api/anchors"


def _record(files, listing_extra=None):
    entries = [{"path": p, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)} for p, b in files.items()]
    listing = {"contract": "anchor-record/v0", "anchors": [{"path": "2026/10/17/000000Z"}], "files": entries, **(listing_extra or {})}
    routes = {URL: (json.dumps(listing).encode(), {})}
    for e in entries:
        q = e["path"].replace("/", "%2F")
        routes[f"{URL}?path={q}&sha256={e['sha256']}"] = (files[e["path"]], {"x-content-sha256": e["sha256"]})
    return listing, routes


FILES = {"index.jsonl": b'{"path": "2026/10/17/000000Z"}\n', "2026/10/17/000000Z/manifest.json": b"{}"}


def test_the_record_is_copied_when_every_file_matches(monkeypatch, tmp_path):
    rec = _tool("fetch_ledger_record")
    _, routes = _record(FILES)
    _serve(monkeypatch, rec, routes)
    result = rec.copy_record(tmp_path / "out", URL)
    assert result["files"] == 2 and result["anchors"] == 1
    assert (tmp_path / "out" / "anchors" / "2026" / "10" / "17" / "000000Z" / "manifest.json").read_bytes() == b"{}"
    assert json.loads((tmp_path / "out" / "listing.json").read_text())["contract"] == "anchor-record/v0"


@pytest.mark.parametrize("damage", ["body", "header", "path"])
def test_a_record_that_does_not_match_itself_is_not_written(monkeypatch, tmp_path, damage):
    rec = _tool("fetch_ledger_record")
    listing, routes = _record(FILES)
    key = next(k for k in routes if "manifest.json" in k)
    if damage == "body":
        routes[key] = (b"{ }", routes[key][1])
    elif damage == "header":
        routes[key] = (routes[key][0], {"x-content-sha256": "0" * 64})
    else:
        listing["files"][0]["path"] = "../outside"
        routes[URL] = (json.dumps(listing).encode(), {})
    _serve(monkeypatch, rec, routes)
    with pytest.raises(rec.RecordError):
        rec.copy_record(tmp_path / "out", URL)
    assert not (tmp_path / "out").exists()


def _header_840000():
    line = next(x for x in (FIX / "bitcoin" / "mainnet" / "headers-sparse.txt").read_text().splitlines() if x.startswith("840000 "))
    return bytes.fromhex(line.split()[1])


def _explorers(hdr, second=None):
    bh = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()[::-1].hex()
    routes = {}
    for base, (h, raw) in (("https://a.example/api", (bh, hdr)), ("https://b.example/api", second or (bh, hdr))):
        routes[f"{base}/block-height/840000"] = (h.encode(), {})
        routes[f"{base}/block/{h}/header"] = (raw.hex().encode(), {})
    return routes


def test_headers_are_kept_when_two_explorers_agree(monkeypatch, tmp_path):
    hd = _tool("fetch_headers")
    assert hd.heights(FIX / "ots" / "mainnet-840000-sparse") == [840000]
    _serve(monkeypatch, hd, _explorers(_header_840000()))
    got = hd.fetch_headers([840000], ("https://a.example/api", "https://b.example/api"))
    text = hd.render(got, ("https://a.example/api", "https://b.example/api"), "2026-10-17T00:00:00Z")
    parsed = HeaderSet.parse(text)  # the form fm-verify --headers reads, comments and all
    assert parsed.headers[840000].raw == _header_840000()


def test_headers_are_refused_when_explorers_disagree_or_a_header_is_not_its_block(monkeypatch):
    hd = _tool("fetch_headers")
    hdr = _header_840000()
    other = hdr[:76] + bytes(4)  # another nonce: another block, whose hash the second explorer gives honestly
    other_hash = hashlib.sha256(hashlib.sha256(other).digest()).digest()[::-1].hex()
    _serve(monkeypatch, hd, _explorers(hdr, (other_hash, other)))
    with pytest.raises(hd.HeaderFetchError, match="disagree"):
        hd.fetch_headers([840000], ("https://a.example/api", "https://b.example/api"))
    good = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()[::-1].hex()
    _serve(monkeypatch, hd, _explorers(hdr, (good, other)))
    with pytest.raises(hd.HeaderFetchError, match="does not hash"):
        hd.fetch_headers([840000], ("https://a.example/api", "https://b.example/api"))
