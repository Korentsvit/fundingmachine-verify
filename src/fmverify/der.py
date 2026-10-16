"""A small, strict DER reader, and the few encoders the fixture builder needs.

Strict: definite lengths only, minimal length and tag encodings, and every
byte of the input accounted for. Signatures in CMS cover DER bytes, so the
reader keeps each element's exact encoding (``raw``) for re-hashing.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

UNIVERSAL, APPLICATION, CONTEXT, PRIVATE = 0, 1, 2, 3

BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
PRINTABLE_STRING = 19
T61_STRING = 20
IA5_STRING = 22
UTC_TIME = 23
GENERALIZED_TIME = 24
BMP_STRING = 30


class DerError(ValueError):
    pass


@dataclass(frozen=True)
class Node:
    cls: int
    constructed: bool
    tag: int
    raw: bytes
    header_len: int

    @property
    def content(self) -> bytes:
        return self.raw[self.header_len :]

    def is_universal(self, tag: int) -> bool:
        return self.cls == UNIVERSAL and self.tag == tag

    def is_context(self, tag: int) -> bool:
        return self.cls == CONTEXT and self.tag == tag

    def children(self) -> list["Node"]:
        if not self.constructed:
            raise DerError(f"element with tag {self.describe()} is not constructed")
        out, pos, data = [], 0, self.content
        while pos < len(data):
            node, pos = read(data, pos)
            out.append(node)
        return out

    def describe(self) -> str:
        if self.cls == CONTEXT:
            return f"[{self.tag}]"
        return {UNIVERSAL: "", APPLICATION: "APPLICATION ", PRIVATE: "PRIVATE "}[self.cls] + str(self.tag)


def read(data: bytes, pos: int = 0) -> tuple[Node, int]:
    start = pos
    if pos >= len(data):
        raise DerError("input ends where an element should start")
    first = data[pos]
    pos += 1
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    if tag == 0x1F:
        tag = 0
        if pos >= len(data):
            raise DerError("input ends inside a tag")
        if data[pos] == 0x80:
            raise DerError("tag number is not minimally encoded")
        while True:
            if pos >= len(data):
                raise DerError("input ends inside a tag")
            b = data[pos]
            pos += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        if tag < 31:
            raise DerError("tag number is not minimally encoded")
    if pos >= len(data):
        raise DerError("input ends where a length should be")
    lb = data[pos]
    pos += 1
    if lb < 0x80:
        length = lb
    elif lb == 0x80:
        raise DerError("indefinite length is not DER")
    else:
        n = lb & 0x7F
        if n > 8 or pos + n > len(data):
            raise DerError("length field is too long or truncated")
        length = int.from_bytes(data[pos : pos + n], "big")
        if data[pos] == 0 or length < 0x80:
            raise DerError("length is not minimally encoded")
        pos += n
    end = pos + length
    if end > len(data):
        raise DerError(f"element claims {length} bytes, {len(data) - pos} remain")
    return Node(cls, constructed, tag, data[start:end], pos - start), end


def parse(data: bytes) -> Node:
    node, pos = read(data, 0)
    if pos != len(data):
        raise DerError(f"{len(data) - pos} bytes after the end of the DER element")
    return node


def expect(node: Node, tag: int, what: str) -> Node:
    if not node.is_universal(tag):
        raise DerError(f"{what}: expected universal tag {tag}, found {node.describe()}")
    return node


def oid(node: Node) -> str:
    expect(node, OID, "object identifier")
    c = node.content
    if not c:
        raise DerError("empty object identifier")
    arcs, value = [], 0
    for i, b in enumerate(c):
        if value == 0 and b == 0x80:
            raise DerError("object identifier arc is not minimally encoded")
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(value)
            value = 0
        elif i == len(c) - 1:
            raise DerError("object identifier ends inside an arc")
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def integer(node: Node) -> int:
    expect(node, INTEGER, "integer")
    c = node.content
    if not c:
        raise DerError("empty integer")
    if len(c) > 1 and ((c[0] == 0 and not c[1] & 0x80) or (c[0] == 0xFF and c[1] & 0x80)):
        raise DerError("integer is not minimally encoded")
    return int.from_bytes(c, "big", signed=True)


def octet_string(node: Node) -> bytes:
    return expect(node, OCTET_STRING, "octet string").content


def boolean(node: Node) -> bool:
    expect(node, BOOLEAN, "boolean")
    if node.content == b"\x00":
        return False
    if node.content == b"\xff":
        return True
    raise DerError("boolean is not DER")


def generalized_time(node: Node) -> _dt.datetime:
    """GeneralizedTime as DER restricts it: YYYYMMDDHHMMSS[.fff]Z, no
    trailing zeros in the fraction."""
    expect(node, GENERALIZED_TIME, "generalized time")
    s = node.content.decode("ascii")
    if not s.endswith("Z") or len(s) < 15:
        raise DerError(f"generalized time {s!r} is not in DER form")
    body, frac = s[:-1], ""
    if "." in body:
        body, frac = body.split(".", 1)
        if not frac or frac.endswith("0") or not frac.isdigit():
            raise DerError(f"generalized time {s!r} has a non-DER fraction")
    if len(body) != 14 or not body.isdigit():
        raise DerError(f"generalized time {s!r} is not in DER form")
    t = _dt.datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=_dt.timezone.utc)
    if frac:
        t += _dt.timedelta(microseconds=int((frac + "000000")[:6]))
    return t


def string(node: Node) -> str:
    if node.cls != UNIVERSAL:
        raise DerError(f"expected a string, found {node.describe()}")
    try:
        if node.tag == BMP_STRING:
            return node.content.decode("utf-16-be")
        if node.tag in (UTF8_STRING, PRINTABLE_STRING, IA5_STRING, T61_STRING):
            return node.content.decode("utf-8" if node.tag == UTF8_STRING else "latin-1")
    except UnicodeDecodeError as exc:
        raise DerError(f"a string is not valid text: {exc}") from exc
    raise DerError(f"tag {node.tag} is not a string type this reader knows")


_NAME_OIDS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.97": "organizationIdentifier",
}


def name_to_text(node: Node) -> str:
    """A distinguished name for people to read, most significant part first."""
    parts = []
    for rdn in expect(node, SEQUENCE, "name").children():
        for atv in expect(rdn, SET, "relative distinguished name").children():
            t, v = atv.children()
            key = _NAME_OIDS.get(oid(t), oid(t))
            try:
                parts.append(f"{key}={string(v)}")
            except DerError:
                parts.append(f"{key}=#{v.raw.hex()}")
    return ", ".join(reversed(parts))


# Encoders: used by the fixture builder and the tests.

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(first: int, content: bytes) -> bytes:
    return bytes([first]) + _len(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def enc_int(n: int) -> bytes:
    length = max(1, (n.bit_length() + 8) // 8)
    return tlv(0x02, n.to_bytes(length, "big", signed=True))


def enc_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    values = [40 * arcs[0] + arcs[1]] + arcs[2:]
    out = bytearray()
    for v in values:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def enc_octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def enc_bool(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def enc_gentime(t: _dt.datetime) -> bytes:
    s = t.strftime("%Y%m%d%H%M%S")
    if t.microsecond:
        s += "." + f"{t.microsecond:06d}".rstrip("0")
    return tlv(0x18, (s + "Z").encode("ascii"))


def ctx(n: int, content: bytes, constructed: bool = True) -> bytes:
    return tlv(0x80 | (0x20 if constructed else 0) | n, content)


NULL_DER = b"\x05\x00"


def alg(dotted: str, params: bytes | None = None) -> bytes:
    return seq(enc_oid(dotted), params) if params is not None else seq(enc_oid(dotted))
