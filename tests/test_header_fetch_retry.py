"""tools/fetch_headers.py's requests to the explorers: a rate limit (429), a server error or a broken connection is
tried again, waiting as long as a Retry-After asks (at most a minute) or twice as long each time; any other answer
stops at once. Offline: a local server answers as told, and no test really waits."""

import http.server
import importlib.util
import threading
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _tool():
    spec = importlib.util.spec_from_file_location("fetch_headers", ROOT / "tools" / "fetch_headers.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hd = _tool()
BODY = "000000000000000000014a1b"


def _serve(answers: list[tuple[int, dict]]):
    """A server answering each request with the next (code, headers) of `answers` (200 sends BODY), then 200."""
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code, headers = answers[len(seen)] if len(seen) < len(answers) else (200, {})
            seen.append(code)
            self.send_response(code)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if code == 200:
                self.wfile.write(BODY.encode())

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/block-height/840000", seen


def _get(answers, **kw):
    server, url, seen = _serve(answers)
    waits = []
    try:
        return hd.get(url, sleep=waits.append, **kw), seen, waits
    finally:
        server.shutdown()


def test_a_rate_limit_waits_as_long_as_retry_after_asks():
    got, seen, waits = _get([(429, {"Retry-After": "7"}), (429, {})])
    assert got == BODY
    assert seen == [429, 429, 200]
    assert waits == [7.0, 4.0]  # the second 429 names no time: the doubling wait, second step


def test_retry_after_is_held_to_a_minute():
    got, seen, waits = _get([(503, {"Retry-After": "3600"}), (429, {"Retry-After": "soon"})])
    assert got == BODY
    assert waits == [60.0, 4.0]


def test_server_errors_wait_two_four_eight_sixteen():
    got, seen, waits = _get([(502, {}), (504, {}), (500, {}), (503, {})])
    assert got == BODY
    assert seen == [502, 504, 500, 503, 200]
    assert waits == [2.0, 4.0, 8.0, 16.0]


def test_five_rate_limits_stop_the_fetch():
    server, url, seen = _serve([(429, {})] * 5)
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            hd.get(url, sleep=lambda s: None)
    finally:
        server.shutdown()
    assert e.value.code == 429
    assert seen == [429] * 5


def test_any_other_answer_stops_at_once():
    server, url, seen = _serve([(404, {})])
    try:
        with pytest.raises(urllib.error.HTTPError):
            hd.get(url, sleep=lambda s: None)
    finally:
        server.shutdown()
    assert seen == [404]
