"""The page's deploy tools: vercel.json from the build's _headers, and the check that a host serves the build as
built (tools/vercel_config.py, tools/check_served_page.py). Offline: a local server stands in for the host."""

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

import check_served_page  # noqa: E402
import vercel_config  # noqa: E402

CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; frame-ancestors 'none'"
HEADERS = f"/*\n  Content-Security-Policy: {CSP}\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n"


def _site(tmp: Path) -> Path:
    site = tmp / "site"
    site.mkdir()
    (site / "index.html").write_text("<!doctype html><title>page</title>\n", encoding="utf-8")
    (site / "pyodide.mjs").write_text("export const x = 1;\n", encoding="utf-8")
    (site / "pyodide.asm.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    (site / "site.json").write_text("{}\n", encoding="utf-8")
    (site / "_headers").write_text(HEADERS, encoding="utf-8")
    sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(site.iterdir())]
    (site / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return site


def test_vercel_json_carries_every_header_of_the_build():
    doc = vercel_config.config(HEADERS)
    assert doc == {"headers": [{"source": "/(.*)", "headers": [
        {"key": "Content-Security-Policy", "value": CSP},
        {"key": "Referrer-Policy", "value": "no-referrer"},
        {"key": "X-Content-Type-Options", "value": "nosniff"}]}]}


@pytest.mark.parametrize("text", ["/index.html\n  X: y\n", "/*\n  Referrer-Policy: no-referrer\n", "/*\nX: y\n"])
def test_vercel_json_refuses_headers_it_cannot_carry_whole(text):
    with pytest.raises(ValueError):
        vercel_config.config(text)


def test_vercel_config_writes_the_file(tmp_path):
    site = _site(tmp_path)
    assert vercel_config.main([str(site)]) == 0
    assert json.loads((site / "vercel.json").read_text(encoding="utf-8")) == vercel_config.config(HEADERS)


class _Host(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map, ".mjs": "text/javascript",
                      ".wasm": "application/wasm"}
    send = {}

    def end_headers(self):
        for k, v in self.send.items():
            self.send_header(k, v)
        super().end_headers()

    def log_message(self, *args):
        pass


def _serve(directory: Path, send: dict):
    handler = functools.partial(type("H", (_Host,), {"send": send}), directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


GOOD = {"Content-Security-Policy": CSP, "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"}


def test_a_host_serving_the_build_as_built(tmp_path):
    site = _site(tmp_path)
    server, url = _serve(site, GOOD)
    try:
        assert check_served_page.check(url, site) == []
    finally:
        server.shutdown()


def test_a_host_serving_other_bytes_or_without_the_policy(tmp_path):
    site = _site(tmp_path)
    served = tmp_path / "served"
    served.mkdir()
    for p in site.iterdir():
        (served / p.name).write_bytes(p.read_bytes())
    (served / "site.json").write_text('{"default_commit": "another"}\n', encoding="utf-8")
    (served / "pyodide.asm.wasm").unlink()
    server, url = _serve(served, {k: v for k, v in GOOD.items() if k != "Content-Security-Policy"})
    try:
        problems = check_served_page.check(url, site)
    finally:
        server.shutdown()
    assert any(p.startswith("/site.json: ") and "not the site.json" in p for p in problems)
    assert any(p.startswith("/pyodide.asm.wasm: not served") for p in problems)
    assert any(p.startswith("/: Content-Security-Policy is None") for p in problems)


def test_the_check_waits_for_the_address_to_serve_the_build(tmp_path):
    """Right after a deploy the address may not serve the build yet: the check looks again until it does."""
    site = _site(tmp_path)
    served = tmp_path / "served"
    served.mkdir()
    server, url = _serve(served, GOOD)  # nothing served yet
    waits = []

    def sleep(seconds):
        waits.append(seconds)
        if len(waits) == 2:  # the deploy reaches the address after the second wait
            for p in site.iterdir():
                (served / p.name).write_bytes(p.read_bytes())

    try:
        assert check_served_page.check_until(url, site, sleep=sleep) == []
    finally:
        server.shutdown()
    assert waits == [5, 10]


def test_the_check_fails_when_the_address_never_serves_the_build(tmp_path):
    site = _site(tmp_path)
    served = tmp_path / "served"
    served.mkdir()
    server, url = _serve(served, GOOD)
    waits = []
    try:
        problems = check_served_page.check_until(url, site, sleep=waits.append)
    finally:
        server.shutdown()
    assert waits == list(check_served_page.WAITS)
    assert any(p.startswith("/index.html: not served") for p in problems)
