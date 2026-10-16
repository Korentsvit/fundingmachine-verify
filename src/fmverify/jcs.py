"""RFC 8785, the JSON Canonicalization Scheme (JCS).

* Objects: members sorted by the UTF-16 code units of their names; duplicate
  names refused (I-JSON, RFC 7493).
* Strings: ECMAScript's JSON.stringify escaping (the short escapes for
  backspace, tab, newline, form feed and carriage return, ``\\u00xx`` in
  lowercase for other control characters, ``\\"`` and ``\\\\``), everything
  else as is; lone surrogates refused.
* Numbers: ECMAScript's Number.prototype.toString, from the shortest
  round-trip digits; NaN and infinities refused; integers beyond 2^53 are
  serialized as the double they become, as ECMAScript would.
* No whitespace.
"""

from __future__ import annotations

import json
import math
import re
from decimal import Decimal
from typing import Any


class JcsError(ValueError):
    pass


def _reject_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise JcsError(f"duplicate member name {k!r}")
        out[k] = v
    return out


def loads(text: str | bytes) -> Any:
    """Parse JSON as I-JSON: duplicate member names are refused."""
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates,
                          parse_constant=lambda c: (_ for _ in ()).throw(JcsError(f"{c} is not JSON")))
    except json.JSONDecodeError as exc:
        raise JcsError(str(exc)) from exc


_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


_PLAIN = re.compile(r'[^\x00-\x1f"\\\ud800-\udfff]*\Z')


def _string(s: str) -> str:
    if _PLAIN.match(s):  # nothing to escape: most strings, checked in C
        return '"' + s + '"'
    out = ['"']
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            raise JcsError("lone surrogate in a string")
        if c in _SHORT:
            out.append(_SHORT[c])
        elif c < 0x20:
            out.append(f"\\u{c:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise JcsError("NaN and infinities are not JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # Shortest round-trip digits and exponent, from repr.
    d = Decimal(repr(abs(x)))
    digits_t = d.as_tuple()
    digits = "".join(str(n) for n in digits_t.digits).rstrip("0") or "0"
    # value = 0.d1d2...dk * 10^n  (ECMAScript's n)
    n = len(digits_t.digits) + digits_t.exponent
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits[0] + ("." + digits[1:] if k > 1 else "")
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _key(name: str) -> bytes:
    return name.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) <= 2**53:
            return str(value)
        return _number(float(value))
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise JcsError("object member names must be strings")
        return "{" + ",".join(f"{_string(k)}:{canonicalize(value[k])}" for k in sorted(value, key=_key)) + "}"
    raise JcsError(f"{type(value).__name__} is not a JSON value")


def dumps(value: Any) -> bytes:
    """The canonical UTF-8 bytes."""
    return canonicalize(value).encode("utf-8")
