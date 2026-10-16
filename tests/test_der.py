import datetime as dt

import pytest

from fmverify import der


def test_round_trip_basics():
    blob = der.seq(der.enc_int(0), der.enc_int(127), der.enc_int(128), der.enc_int(-129), der.enc_oid("1.2.840.113549.1.9.16.1.4"),
                   der.enc_octets(b"x" * 300), der.enc_bool(True))
    kids = der.parse(blob).children()
    assert [der.integer(k) for k in kids[:4]] == [0, 127, 128, -129]
    assert der.oid(kids[4]) == "1.2.840.113549.1.9.16.1.4"
    assert der.octet_string(kids[5]) == b"x" * 300
    assert der.boolean(kids[6]) is True


@pytest.mark.parametrize("bad,why", [
    (b"\x30\x80\x00\x00", "indefinite"),
    (b"\x04\x81\x05abcde", "minimally"),
    (b"\x04\x82\x00\x05abcde", "minimally"),
    (b"\x04\x05abc", "claims"),
    (b"\x02\x02\x00\x7f", "minimally"),
    (b"\x02\x02\xff\x80", "minimally"),
    (b"\x01\x01\x01", "not DER"),
    (b"\x04\x01a\x00", "after the end"),
    (b"\x1f\x80\x01\x00", "minimally"),
])
def test_strictness(bad, why):
    with pytest.raises(der.DerError, match=why):
        node = der.parse(bad)
        if node.tag == der.INTEGER:
            der.integer(node)
        if node.tag == der.BOOLEAN:
            der.boolean(node)


@pytest.mark.parametrize("text,expected", [
    (b"20261016060000Z", dt.datetime(2026, 10, 16, 6, 0, tzinfo=dt.timezone.utc)),
    (b"20261016060000.125Z", dt.datetime(2026, 10, 16, 6, 0, 0, 125000, tzinfo=dt.timezone.utc)),
])
def test_generalized_time(text, expected):
    assert der.generalized_time(der.parse(der.tlv(0x18, text))) == expected


@pytest.mark.parametrize("text", [b"20261016060000", b"20261016060000.120Z", b"202610160600Z", b"20261016060000+0100"])
def test_generalized_time_rejects_non_der(text):
    with pytest.raises(der.DerError):
        der.generalized_time(der.parse(der.tlv(0x18, text)))


def test_encoder_time_matches_reader():
    t = dt.datetime(2026, 10, 16, 6, 0, 0, 120000, tzinfo=dt.timezone.utc)
    assert der.parse(der.enc_gentime(t)).content == b"20261016060000.12Z"
    assert der.generalized_time(der.parse(der.enc_gentime(t))) == t
