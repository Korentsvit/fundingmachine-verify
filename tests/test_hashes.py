import hashlib

import pytest

from fmverify.hashes import keccak256, ripemd160, ripemd160_pure

# RIPEMD-160 test vectors from the algorithm's authors (Bosselaers' page).
RIPEMD = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
]


@pytest.mark.parametrize("msg,want", RIPEMD)
def test_ripemd160_pure(msg, want):
    assert ripemd160_pure(msg).hex() == want
    assert ripemd160(msg).hex() == want


def test_ripemd160_million_a():
    assert ripemd160_pure(b"a" * 1_000_000).hex() == "52783243c1697bdbe16d37f97f68f08325dc1528"


# Keccak-256 with the original padding (as Ethereum uses it).
KECCAK = [
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
]


@pytest.mark.parametrize("msg,want", KECCAK)
def test_keccak256(msg, want):
    assert keccak256(msg).hex() == want


def test_keccak256_is_not_sha3():
    assert keccak256(b"") != hashlib.sha3_256(b"").digest()


# Lengths around the 136-byte rate, recorded from this implementation and
# checked against an independent Keccak implementation (pycryptodome) when recorded.
BOUNDARIES = {
    135: "03c527855334eb2e62b3b9b4d02ab76721707d3dde5fb218369640ee2edc7f3a",
    136: "ddc757d2caa82320e140f35833c18e8cc3b230b2b9a48def3d98461ffae81716",
    137: "37a14cb79c82d4b7d837a3f8ea134a324b138a5e4e3bb0814b75e52b17975b9c",
    272: "55f08c872f52ae47a17f2ed98203965fe6361a0a3036291c800eaec1fefe1a7e",
    1000: "5f518f3dd8cb3273e2c7d70c5047017216fc6a8f2ffd8da7aa7b25fcbbf115b3",
}


@pytest.mark.parametrize("n", sorted(BOUNDARIES))
def test_keccak256_block_boundaries(n):
    assert keccak256(b"\x5a" * n).hex() == BOUNDARIES[n]
