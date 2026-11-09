"""tools/build_page.py's pinned download: a server error or a broken connection is tried again, any other answer stops
at once, and whatever arrives must still have the pinned SHA-256. Offline: a local server answers as told."""

import hashlib
import http.server
import sys
import threading
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build_page  # noqa: E402

BODY = b"the release's wheel"
PINNED = hashlib.sha256(BODY).hexdigest()


def _serve(codes: list[int]):
    """A server answering each request with the next code of `codes` (200 sends BODY), then 200."""
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code = codes[len(seen)] if len(seen) < len(codes) else 200
            seen.append(code)
            self.send_response(code)
            self.end_headers()
            if code == 200:
                self.wfile.write(BODY)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/wheel", seen


def test_a_server_error_is_tried_again():
    server, url, seen = _serve([504, 502])
    try:
        assert build_page.fetch_pinned(url, PINNED, wait=0) == BODY
    finally:
        server.shutdown()
    assert seen == [504, 502, 200]


def test_five_server_errors_stop_the_build():
    server, url, seen = _serve([504] * 5)
    try:
        with pytest.raises(urllib.error.HTTPError):
            build_page.fetch_pinned(url, PINNED, wait=0)
    finally:
        server.shutdown()
    assert seen == [504] * 5


def test_any_other_answer_stops_at_once():
    server, url, seen = _serve([404])
    try:
        with pytest.raises(urllib.error.HTTPError):
            build_page.fetch_pinned(url, PINNED, wait=0)
    finally:
        server.shutdown()
    assert seen == [404]


def test_a_retry_never_loosens_the_hash():
    server, url, _ = _serve([503])
    try:
        with pytest.raises(SystemExit):
            build_page.fetch_pinned(url, "0" * 64, wait=0)
    finally:
        server.shutdown()
