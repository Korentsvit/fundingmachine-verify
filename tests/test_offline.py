"""Independence: without --explorer the verifier opens no network connection."""

import socket
from pathlib import Path

import pytest

from fmverify.cli import main

FIX = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def no_network(monkeypatch):
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("the verifier tried to open a network connection")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    return attempts


def test_every_fixture_case_runs_offline(no_network, capsys):
    import json

    for case in sorted(p for p in (FIX / "ots").iterdir() if p.is_dir()):
        exp = json.loads((case / "expected.json").read_text())
        argv = ["ots", str(case / "proof.ots"), "--file", str(case / exp["file"]), "--network", exp["network"]]
        for spec in exp.get("headers_chain", []):
            argv += ["--headers-chain", f"{case / spec['path']}@{spec['start']}"]
        for path in exp.get("headers", []):
            argv += ["--headers", str(case / path)]
        main(argv)
    assert no_network == []


def test_every_rfc3161_case_runs_offline(no_network, capsys):
    import json

    for case in sorted(p for p in (FIX / "rfc3161").iterdir() if p.is_dir() and p.name != "pki"):
        exp = json.loads((case / "expected.json").read_text())
        argv = ["rfc3161", str(case / "token.tsr"), "--file", str(case / exp["file"])]
        for r in exp.get("roots", []):
            argv += ["--roots", str(case / r)]
        for c in exp.get("chain", []):
            argv += ["--chain", str(case / c)]
        main(argv)
    assert no_network == []
