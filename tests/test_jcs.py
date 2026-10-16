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
