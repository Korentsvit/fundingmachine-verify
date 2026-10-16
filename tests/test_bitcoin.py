from pathlib import Path

import pytest

from fmverify import bitcoin
from fmverify.bitcoin import MAINNET, REGTEST, EsploraSource, HeaderChain, HeaderSet, lookup_header, parse_header
from fmverify.verdict import Status

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "bitcoin"
SPARSE_TEXT = (FIX / "mainnet" / "headers-sparse.txt").read_text()
SPARSE = {int(h): bytes.fromhex(x) for h, x in (l.split() for l in SPARSE_TEXT.splitlines() if l and not l.startswith("#"))}
HASH_840000 = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"


def test_genesis():
    g = parse_header(SPARSE[0])
    assert g.hash == MAINNET.genesis_hash
    assert g.hash_hex == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    assert g.time_iso == "2009-01-03T18:15:05Z"


def test_block_840000():
    h = parse_header(SPARSE[840000])
    assert h.hash_hex == HASH_840000
    ok, _, target = bitcoin.check_pow(h, MAINNET)
    assert ok
    assert 78 < bitcoin.work_bits(bitcoin.work_for_target(target)) < 79


@pytest.mark.parametrize("bits", [0x1D00FFFF, 0x17034219, 0x207FFFFF, 0x1B0404CB])
def test_compact_round_trip(bits):
    assert bitcoin.target_to_bits(bitcoin.bits_to_target(bits)) == bits


def test_compact_rejects_negative_and_overflow():
    with pytest.raises(bitcoin.HeaderError):
        bitcoin.bits_to_target(0x04923456)
    with pytest.raises(bitcoin.HeaderError):
        bitcoin.bits_to_target(0xFF123456)


def test_retarget_rule_on_a_real_boundary():
    first, last, new = (parse_header(SPARSE[h]) for h in (836640, 838655, 838656))
    assert bitcoin.next_bits(MAINNET, last.bits, first.time, last.time) == new.bits
    assert new.bits != last.bits


def test_chain_from_genesis():
    chain = HeaderChain((FIX / "mainnet" / "headers-0-19.bin").read_bytes(), 0, MAINNET)
    assert chain.problem is None and chain.valid_count == 20
    ev = chain.lookup(5)
    assert ev.checks[0].status is Status.PASS
    assert ev.checks[0].data["confirmations"] == 15
    assert "genesis" in " ".join(ev.checks[0].reasons)


def test_chain_window_needs_its_start_stated():
    chain = HeaderChain((FIX / "mainnet" / "headers-839990-840009.bin").read_bytes(), 839990, MAINNET)
    assert chain.problem is None
    ev = chain.lookup(840000)
    assert ev.header.hash_hex == HASH_840000
    assert any("before height 839990" in r for r in ev.relies_on)
    assert [c.status for c in ev.checks] == [Status.PASS, Status.PASS]
    assert chain.lookup(839989) is None and chain.lookup(840010) is None


def test_chain_at_wrong_start_breaks_at_genesis_check():
    raw = (FIX / "mainnet" / "headers-839990-840009.bin").read_bytes()
    chain = HeaderChain(raw, 0, MAINNET)
    assert "genesis" in chain.problem
    assert isinstance(chain.lookup(5), str)


def test_chain_with_swapped_headers_is_rejected_from_the_break():
    raw = bytearray((FIX / "mainnet" / "headers-0-19.bin").read_bytes())
    raw[800:880], raw[880:960] = raw[880:960], raw[800:880]  # swap heights 10 and 11
    chain = HeaderChain(bytes(raw), 0, MAINNET)
    assert chain.valid_count == 10
    assert chain.lookup(9).checks[0].status is Status.PASS
    assert "does not link" in chain.lookup(12)


def _mine(prev: bytes, bits: int, time: int, root: bytes = b"\x00" * 32) -> bytes:
    import struct

    target = bitcoin.bits_to_target(bits)
    for nonce in range(1 << 20):
        h = struct.pack("<i", 4) + prev + root + struct.pack("<III", time, bits, nonce)
        if int.from_bytes(bitcoin.sha256d(h), "little") <= target:
            return h
    raise AssertionError("no nonce")


def _mined_chain(bits_list, times=None):
    prev, out = b"\x00" * 32, []
    for i, bits in enumerate(bits_list):
        h = _mine(prev, bits, (times or [1000 + 600 * j for j in range(len(bits_list))])[i])
        out.append(h)
        prev = bitcoin.sha256d(h)
    return b"".join(out)


RETARGETING_TESTNET = bitcoin.Network("test-retarget", (1 << 255) - 1, None, True, 0.0, True)


def test_chain_rejects_bits_change_outside_retarget():
    raw = _mined_chain([0x207FFFFF, 0x207FFFFF, 0x207FFFFE])
    chain = HeaderChain(raw, 0, RETARGETING_TESTNET)
    assert chain.valid_count == 2 and "outside a retarget height" in chain.problem
    assert HeaderChain(raw, 0, REGTEST).problem is None


def test_chain_rejects_time_not_after_median():
    raw = _mined_chain([0x207FFFFF] * 4, times=[1000, 2000, 3000, 2000])
    chain = HeaderChain(raw, 0, REGTEST)
    assert chain.valid_count == 3 and "median" in chain.problem


def test_chain_rejects_partial_header():
    regtest = (FIX / "regtest" / "headers-0-11.bin").read_bytes()
    with pytest.raises(bitcoin.HeaderError):
        HeaderChain(regtest[:-1], 0, REGTEST)


def test_sparse_set_links_neighbours_and_checks_work():
    s = HeaderSet.parse(SPARSE_TEXT, MAINNET, "sparse")
    ev = s.lookup(840000)
    assert ev.checks[0].status is Status.PASS
    assert "links to height 839999" in ev.checks[0].reasons[-1]
    assert any("place in the chain was not" in r for r in ev.relies_on)
    assert s.lookup(123) is None


def test_sparse_low_work_header_is_not_relied_on():
    s = HeaderSet({0: SPARSE[0]}, MAINNET, "genesis only")
    ev = s.lookup(0)
    assert ev.checks[0].status is Status.NOT_CHECKED
    assert "too little proof of work" in ev.checks[0].summary


def test_sparse_floor_can_be_raised():
    s = HeaderSet({840000: SPARSE[840000]}, MAINNET, "x", min_work_bits=90)
    assert s.lookup(840000).checks[0].status is Status.NOT_CHECKED


def test_sparse_broken_link_is_reported():
    s = HeaderSet({840000: SPARSE[840000], 840001: SPARSE[840002]}, MAINNET, "x")
    assert "does not link" in s.lookup(840000)


def test_sparse_json_forms():
    a = HeaderSet.parse('{"network": "bitcoin-mainnet", "headers": [{"height": 840000, "hex": "%s"}]}' % SPARSE[840000].hex())
    b = HeaderSet.parse('{"840000": "%s"}' % SPARSE[840000].hex())
    assert a.lookup(840000).header.raw == b.lookup(840000).header.raw == SPARSE[840000]
    with pytest.raises(bitcoin.HeaderError):
        HeaderSet.parse('{"network": "bitcoin-regtest", "headers": []}', MAINNET)


def _fake_fetch(answers):
    calls = []

    def fetch(url):
        calls.append(url)
        if url not in answers:
            raise OSError("no route to host")
        return answers[url]

    fetch.calls = calls
    return fetch


def test_explorer_states_its_reliance():
    base = "https://explorer.example/api"
    fetch = _fake_fetch({f"{base}/block-height/840000": HASH_840000.encode(),
                         f"{base}/block/{HASH_840000}/header": SPARSE[840000].hex().encode()})
    src = EsploraSource(base, MAINNET, fetch=fetch, clock=lambda: "2026-10-16T00:00:00Z")
    ev = src.lookup(840000)
    assert ev.header.hash_hex == HASH_840000
    assert "truthfully reported" in ev.relies_on[0] and "2026-10-16T00:00:00Z" in ev.relies_on[0]
    assert fetch.calls == [f"{base}/block-height/840000", f"{base}/block/{HASH_840000}/header"]


def test_explorer_lying_about_the_header_is_caught():
    base = "https://explorer.example/api"
    fetch = _fake_fetch({f"{base}/block-height/840000": HASH_840000.encode(),
                         f"{base}/block/{HASH_840000}/header": SPARSE[840001].hex().encode()})
    assert "hashes to" in EsploraSource(base, MAINNET, fetch=fetch).lookup(840000)


def test_explorer_unreachable_is_a_reason_not_a_crash():
    src = EsploraSource("https://explorer.example/api", MAINNET, fetch=_fake_fetch({}))
    assert "could not be read" in src.lookup(840000)


def test_sources_that_disagree_fail():
    a = HeaderSet({840000: SPARSE[840000]}, MAINNET, "a")
    b = HeaderSet({840000: SPARSE[840001]}, MAINNET, "b")
    ev, notes = lookup_header([a, b], 840000)
    assert ev is None
    assert notes[-1].status is Status.FAIL and "disagree" in notes[-1].summary


def test_one_source_failing_while_another_vouches_is_a_warning():
    good = HeaderSet({840000: SPARSE[840000]}, MAINNET, "good")
    bad = EsploraSource("https://explorer.example/api", MAINNET, fetch=_fake_fetch({}))
    ev, notes = lookup_header([good, bad], 840000)
    assert ev is not None
    assert notes[0].status is Status.WARN and not notes[0].required
