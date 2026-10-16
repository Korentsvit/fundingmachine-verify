import json
from pathlib import Path

import pytest

from fmverify import ots
from fmverify.bitcoin import MAINNET, NETWORKS, HeaderChain, HeaderSet
from fmverify.verdict import Outcome, Status

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CASES = sorted(p for p in (FIX / "ots").iterdir() if p.is_dir())


def run_case(case: Path):
    exp = json.loads((case / "expected.json").read_text())
    network = NETWORKS[exp["network"]]
    sources = []
    for spec in exp.get("headers_chain", []):
        sources.append(HeaderChain.from_file(case / spec["path"], spec["start"], network))
    for path in exp.get("headers", []):
        sources.append(HeaderSet.from_file(case / path, network))
    verdict = ots.verify_file(case / "proof.ots", sources, file_path=case / exp["file"], network=network)
    return exp, verdict


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_fixture_case(case):
    exp, verdict = run_case(case)
    assert verdict.outcome.value == exp["outcome"], verdict.to_text()
    failing = [c.id for c in verdict.checks if c.status is Status.FAIL]
    assert failing == exp.get("failing", []), verdict.to_text()
    # never a bare pass: a statement, the checks, and the limits are always there
    assert verdict.statement and verdict.checks and verdict.does_not_establish


def test_valid_statement_names_block_and_time():
    _, v = run_case(FIX / "ots" / "mainnet-840000-sparse")
    assert "no later than Bitcoin block 840000" in v.statement
    assert "2024-04-20T00:09:27Z" in v.statement
    assert v.relies_on


def test_regtest_statement_says_test_network():
    _, v = run_case(FIX / "ots" / "regtest-valid")
    assert v.outcome is Outcome.VALID and "test network" in v.statement


def test_round_trip_is_exact():
    for case in CASES:
        data = (case / "proof.ots").read_bytes()
        try:
            parsed = ots.parse(data)
        except ots.OtsError:
            continue
        assert parsed.serialize() == data


def _proof(ops, att=None, digest=b"\x11" * 32):
    att = att or ots.Attestation(ots.TAG_BITCOIN, ots._varuint(1))
    ts = ots.Timestamp(digest, [att])
    msg_chain = [digest]
    for op in ops:
        msg_chain.append(op.apply(msg_chain[-1]))
    ts = ots.Timestamp(msg_chain[-1], [att])
    for op, msg in zip(reversed(ops), reversed(msg_chain[:-1])):
        ts = ots.Timestamp(msg, [(op, ts)])
    return ots.DetachedTimestamp(ots.Op(0x08), ts).serialize()


def test_bad_magic_and_version():
    good = _proof([ots.Op(0x08)])
    with pytest.raises(ots.OtsError, match="magic"):
        ots.parse(b"\x01" + good[1:])
    bumped = good[: len(ots.HEADER_MAGIC)] + b"\x02" + good[len(ots.HEADER_MAGIC) + 1 :]
    with pytest.raises(ots.OtsError, match="version 2"):
        ots.parse(bumped)


def test_unknown_op_tag():
    good = _proof([ots.Op(0x08)])
    i = len(ots.HEADER_MAGIC) + 1 + 1 + 32
    assert good[i] == 0x08
    with pytest.raises(ots.OtsError, match="unknown operation"):
        ots.parse(good[:i] + b"\x09" + good[i + 1 :])


def test_empty_append_argument_rejected():
    raw = _proof([ots.Op(0xF0, b"x")])
    i = len(ots.HEADER_MAGIC) + 1 + 1 + 32
    tampered = raw[:i] + b"\xf0\x00" + raw[i + 3 :]
    with pytest.raises(ots.OtsError, match="below 1"):
        ots.parse(tampered)


def test_message_growth_limit():
    big = ots.Op(0xF0, b"\x00" * 4000)
    with pytest.raises(ots.OtsError, match="exceeds 4096"):
        _proof([big, big])


def test_depth_limit():
    ops = [ots.Op(0x08)] * 300
    raw = _proof(ops)
    with pytest.raises(ots.OtsError, match="deeper"):
        ots.parse(raw)


def test_varuint_overlong():
    r = ots._Reader(b"\xff" * 11)
    with pytest.raises(ots.OtsError):
        r.varuint()


def test_pending_uri_charset_enforced():
    att = ots.Attestation(ots.TAG_PENDING, ots._varbytes(b"https://calendar.example.org/?x=<script>"))
    with pytest.raises(ots.OtsError, match="forbids"):
        ots.parse(_proof([], att))


def test_bitcoin_payload_with_trailing_bytes_rejected():
    att = ots.Attestation(ots.TAG_BITCOIN, ots._varuint(5) + b"\x00")
    with pytest.raises(ots.OtsError, match="unexpected bytes"):
        ots.parse(_proof([], att))


def test_unknown_attestation_is_kept_but_not_relied_on():
    att = ots.Attestation(bytes.fromhex("0102030405060708"), b"whatever")
    v = ots.verify(_proof([ots.Op(0x08)], att))
    assert v.outcome is Outcome.INDETERMINATE
    assert any(c.id == "ots.unknown" and c.status is Status.INFO for c in v.checks)


def test_commitment_of_wrong_length_fails():
    v = ots.verify(_proof([ots.Op(0x03)]))  # ripemd160 leaves 20 bytes
    assert v.outcome is Outcome.INVALID
    assert "32-byte" in [c for c in v.checks if c.status is Status.FAIL][0].summary


def test_digest_instead_of_file():
    case = FIX / "ots" / "mainnet-840000-sparse"
    proof = (case / "proof.ots").read_bytes()
    src = [HeaderSet.from_file(FIX / "bitcoin" / "mainnet" / "headers-sparse.txt", MAINNET)]
    digest = ots.parse(proof).digest
    assert ots.verify(proof, src, digest=digest).outcome is Outcome.VALID
    assert ots.verify(proof, src, digest=b"\x00" * 32).outcome is Outcome.INVALID
    no_subject = ots.verify(proof, src)
    assert no_subject.outcome is Outcome.VALID and no_subject.subject.startswith("sha256 digest")


def test_sha1_file_hash_warns():
    ts = ots.Timestamp(b"\x22" * 20, [ots.Attestation(ots.TAG_PENDING, ots._varbytes(b"https://a.example"))])
    raw = ots.DetachedTimestamp(ots.Op(0x02), ts).serialize()
    v = ots.verify(raw)
    assert any(c.id == "ots.weak_hash" and c.status is Status.WARN for c in v.checks)
