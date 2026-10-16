"""Base58 (the Bitcoin alphabet), multibase base58btc, base64url, and did:key."""

from __future__ import annotations

import base64

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}
ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, as a varint


class EncodingError(ValueError):
    pass


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _INDEX:
            raise EncodingError(f"{ch!r} is not a base58 character")
        n = n * 58 + _INDEX[ch]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def multibase_decode(s: str) -> bytes:
    if not s.startswith("z"):
        raise EncodingError("multibase value does not start with 'z' (base58btc)")
    return b58decode(s[1:])


def b64url_decode(s: str) -> bytes:
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise EncodingError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def did_key_ed25519(did: str) -> bytes:
    """The raw 32-byte Ed25519 public key in a did:key."""
    if not did.startswith("did:key:"):
        raise EncodingError(f"{did!r} is not a did:key")
    raw = multibase_decode(did[len("did:key:"):])
    if not raw.startswith(ED25519_PUB) or len(raw) != 34:
        raise EncodingError("the did:key does not hold an Ed25519 public key")
    return raw[2:]


def ed25519_did_key(public: bytes) -> str:
    return "did:key:z" + b58encode(ED25519_PUB + public)
