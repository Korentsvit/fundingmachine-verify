"""Malformed input of every kind gets a verdict or a usage error, never an
exception: deterministic mutations of the fixtures, byte-level for binary
formats and structural for JSON. FM_FUZZ_ROUNDS raises the count."""

import copy
import json
import os
import random
from pathlib import Path

import pytest

from fmverify import api, certificate, der, ledger_events, ots, pdf, pki, rfc3161
from fmverify.verdict import Verdict

FIX = Path(__file__).resolve().parent.parent / "fixtures"
ROUNDS = int(os.environ.get("FM_FUZZ_ROUNDS", "120"))
ROOTS = pki.load_certificates((FIX / "rfc3161" / "pki" / "root.pem").read_bytes())


def mutate(rng: random.Random, b: bytes) -> bytes:
    b = bytearray(b)
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        if op < 0.5 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op < 0.75 and b:
            i = rng.randrange(len(b))
            del b[i:i + rng.randint(1, 8)]
        else:
            i = rng.randrange(len(b) + 1)
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    return bytes(b)


ODD = [None, True, 0, -1, 2**70, 1.5, "", "x" * 3, [], {}, [None], {"a": None}]


def mutate_json(rng: random.Random, value):
    value = copy.deepcopy(value)
    paths = []

    def walk(o, path):
        paths.append(path)
        if isinstance(o, dict):
            for k in o:
                walk(o[k], path + [k])
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, path + [i])

    walk(value, [])
    for _ in range(rng.randint(1, 3)):
        path = rng.choice(paths[1:] or paths)
        parent = value
        try:
            for k in path[:-1]:
                parent = parent[k]
            key = path[-1] if path else None
            if key is None:
                return copy.deepcopy(rng.choice(ODD))
            if rng.random() < 0.3 and isinstance(parent, dict):
                parent.pop(key, None)
            else:
                parent[key] = copy.deepcopy(rng.choice(ODD))
        except (KeyError, IndexError, TypeError):
            continue
    return value


BINARY = {
    "ots": (FIX / "ots" / "regtest-valid" / "proof.ots", lambda b: ots.verify(b)),
    "rfc3161-rsa": (FIX / "rfc3161" / "valid-rsa" / "token.tsr", lambda b: rfc3161.verify(b, roots=ROOTS)),
    "rfc3161-pss": (FIX / "rfc3161" / "valid-pss" / "token.tsr", lambda b: rfc3161.verify(b, roots=ROOTS)),
    "rfc3161-ed25519": (FIX / "rfc3161" / "valid-ed25519" / "token.tsr", lambda b: rfc3161.verify(b, roots=ROOTS)),
    "certificate-json": (FIX / "certificate" / "valid-anchored" / "certificate.json", lambda b: certificate.verify(b)),
    "certificate-pdf": (FIX / "certificate" / "pdf-compressed" / "certificate.pdf", lambda b: certificate.verify(b)),
}


@pytest.mark.parametrize("name", sorted(BINARY))
def test_byte_mutations_give_verdicts(name):
    path, run = BINARY[name]
    data = path.read_bytes()
    rng = random.Random(name)
    for _ in range(ROUNDS):
        assert isinstance(run(mutate(rng, data)), Verdict)


def test_der_and_pdf_raise_only_their_own_errors():
    rng = random.Random("der-pdf")
    tsr = (FIX / "rfc3161" / "valid-rsa" / "token.tsr").read_bytes()
    doc = (FIX / "certificate" / "pdf-classic" / "certificate.pdf").read_bytes()
    for _ in range(ROUNDS):
        try:
            der.parse(mutate(rng, tsr))
        except der.DerError:
            pass
        try:
            pdf.extract(mutate(rng, doc))
        except pdf.PdfError:
            pass


def test_structural_mutations_of_events_and_certificates():
    rng = random.Random("json")
    events = json.loads((FIX / "chain" / "valid" / "events.json").read_text())["events"]
    cert = json.loads((FIX / "certificate" / "valid-with-chain" / "certificate.json").read_text())
    for _ in range(ROUNDS):
        assert isinstance(ledger_events.verify(mutate_json(rng, events)), Verdict)
        assert isinstance(certificate.verify(json.dumps(mutate_json(rng, cert)).encode(), events=mutate_json(rng, events)), Verdict)


def test_api_never_raises():
    rng = random.Random("api")
    batch = json.loads((FIX / "anchors" / "batch-valid" / "batch.json").read_text())
    base = [
        {"kind": "chain", "events": json.loads((FIX / "chain" / "valid" / "events.json").read_text())["events"]},
        {"kind": "anchors", "network": "regtest", "batch": batch, "anchor_files": {}},
        {"kind": "merkle", "proof": {"scheme": "rfc9162-sha256", "leaf_index": 0, "tree_size": 1, "path": [], "root": "00" * 32}, "leaf": "AA=="},
        {"kind": "ots", "proof": "AA==", "headers": [{"kind": "sparse", "text": "1 00"}]},
    ]
    for _ in range(ROUNDS):
        answer = api.verify(mutate_json(rng, rng.choice(base)))
        assert isinstance(answer, dict) and ("outcome" in answer or "error" in answer)
        assert not answer.get("internal"), answer
