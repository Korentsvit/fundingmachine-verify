import struct

import pytest

from fmverify import base58, jcs

BS = chr(92)  # a backslash, written this way so no tool in between can reinterpret an escape

# RFC 8785, appendix B: IEEE 754 doubles and their canonical serialization.
NUMBERS = {
    "0000000000000000": "0", "8000000000000000": "0",
    "0000000000000001": "5e-324", "8000000000000001": "-5e-324",
    "7fefffffffffffff": "1.7976931348623157e+308", "ffefffffffffffff": "-1.7976931348623157e+308",
    "4340000000000000": "9007199254740992", "c340000000000000": "-9007199254740992",
    "4430000000000000": "295147905179352830000",
    "44b52d02c7e14af5": "9.999999999999997e+22", "44b52d02c7e14af6": "1e+23", "44b52d02c7e14af7": "1.0000000000000001e+23",
    "444b1ae4d6e2ef4e": "999999999999999700000", "444b1ae4d6e2ef4f": "999999999999999900000", "444b1ae4d6e2ef50": "1e+21",
    "3eb0c6f7a0b5ed8c": "9.999999999999997e-7", "3eb0c6f7a0b5ed8d": "0.000001",
    "41b3de4355555553": "333333333.3333332", "41b3de4355555554": "333333333.33333325",
    "41b3de4355555555": "333333333.3333333", "41b3de4355555556": "333333333.3333334",
    "41b3de4355555557": "333333333.33333343",
    "becbf647612f3696": "-0.0000033333333333333333", "43143ff3c1cb0959": "1424953923781206.2",
}


@pytest.mark.parametrize("bits", sorted(NUMBERS))
def test_number_serialization(bits):
    assert jcs.canonicalize(struct.unpack(">d", bytes.fromhex(bits))[0]) == NUMBERS[bits]


def test_rfc8785_section_3_2_2_example():
    euro = chr(0x20AC)
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": euro + "$" + chr(0x0F) + chr(0x0A) + "A'B" + '"' + BS + BS + '"' + "/",
        "literals": [None, True, False],
    }
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"'
                + euro + "$" + BS + "u000f" + BS + "n" + "A'B" + BS + '"' + BS + BS + BS + BS + BS + '"' + "/" + '"}')
    assert jcs.canonicalize(value) == expected


def test_rfc8785_section_3_2_3_sorting():
    names = [chr(0x20AC), chr(0x0D), chr(0xFB33), "1", chr(0x1F600), chr(0x80), chr(0xF6)]
    value = {n: i for i, n in enumerate(names)}
    text = jcs.canonicalize(value)
    positions = [text.index(jcs._string(n) + ":") for n in [chr(0x0D), "1", chr(0x80), chr(0xF6), chr(0x20AC), chr(0x1F600), chr(0xFB33)]]
    assert positions == sorted(positions)


def test_parse_refuses_duplicates_and_non_json():
    with pytest.raises(jcs.JcsError, match="duplicate"):
        jcs.loads('{"a": 1, "a": 2}')
    with pytest.raises(jcs.JcsError):
        jcs.loads('{"a": NaN}')
    with pytest.raises(jcs.JcsError):
        jcs.canonicalize(float("inf"))


def test_lone_surrogate_refused():
    with pytest.raises(jcs.JcsError, match="surrogate"):
        jcs.canonicalize(chr(0xD800))


def test_integers():
    assert jcs.canonicalize({"b": 2, "a": [1, -0, 2**53]}) == '{"a":[1,0,9007199254740992],"b":2}'
    assert jcs.canonicalize(2**60) == "1152921504606847000"  # the double 2^60, printed with ECMAScript's shortest digits


def test_base58_and_did_key():
    # RFC 8032 section 7.1 TEST 3 public key.
    pub = bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
    did = base58.ed25519_did_key(pub)
    assert did.startswith("did:key:z6Mk")
    assert base58.did_key_ed25519(did) == pub
    assert base58.b58decode(base58.b58encode(b"\x00\x00\x01\x02")) == b"\x00\x00\x01\x02"
    with pytest.raises(base58.EncodingError):
        base58.b58decode("0OIl")
    with pytest.raises(base58.EncodingError):
        base58.did_key_ed25519("did:key:z" + base58.b58encode(b"\x12\x00" + pub))


def test_string_fast_path_matches_the_escaping_loop():
    """The C-level path for strings with nothing to escape gives what the
    character loop gives, on random strings of every kind of character."""
    import random

    def slow(s: str) -> str:
        out = ['"']
        for ch in s:
            c = ord(ch)
            out.append(jcs._SHORT[c] if c in jcs._SHORT else f"\\u{c:04x}" if c < 0x20 else ch)
        return "".join(out) + '"'

    rng = random.Random(8785)
    alphabet = [chr(c) for c in list(range(0, 0x80)) + [0xE9, 0x6F22, 0x1F600, 0x2028, 0xFEFF]]
    for _ in range(3000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
        assert jcs._string(s) == slow(s), repr(s)
    assert jcs._string("\x7f") == '"\x7f"'


def test_same_bytes_as_the_rfc8785_reference_package():
    """The `rfc8785` package (Apache-2.0, a test-time tool only) on random
    values: the same bytes, once integers of 2^53 or more are taken as the
    doubles they become, as ECMAScript takes them (the package refuses them)."""
    import math
    import random
    import struct

    reference = pytest.importorskip("rfc8785")
    rng = random.Random("jcs-reference")
    pools = ["abc", "\x00\x01\x1f\x7f  ", "\"" + BS + "/", "é漢", "\U0001F600\U00010000\U0010FFFF", "﻿�￿"]

    def text():
        return "".join(rng.choice(rng.choice(pools)) for _ in range(rng.randint(0, 6)))

    def number():
        k = rng.random()
        if k < 0.5:
            while True:
                d = struct.unpack(">d", rng.getrandbits(64).to_bytes(8, "big"))[0]
                if math.isfinite(d):
                    return d
        if k < 0.8:
            return rng.randint(-2**53 + 1, 2**53 - 1)
        return rng.choice([2**53, 2**53 + 1, 10**21, -2**60])

    def value(depth=0):
        k = rng.random()
        if depth > 3 or k < 0.35:
            return rng.choice([number, text, lambda: rng.choice([True, False, None])])()
        if k < 0.7:
            return {text(): value(depth + 1) for _ in range(rng.randint(0, 4))}
        return [value(depth + 1) for _ in range(rng.randint(0, 4))]

    def as_ecmascript(v):
        if isinstance(v, bool) or not isinstance(v, (int, list, dict)):
            return v
        if isinstance(v, int):
            return float(v) if abs(v) >= 2**53 else v
        return [as_ecmascript(x) for x in v] if isinstance(v, list) else {k: as_ecmascript(x) for k, x in v.items()}

    for _ in range(3000):
        v = value()
        assert jcs.dumps(v) == reference.dumps(as_ecmascript(v)), v
