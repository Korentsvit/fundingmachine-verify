"""Extract an embedded file (the certificate's ``certificate.json``) from a PDF.

A small reader, enough for embedded files and no more: it finds every
indirect object in the file (the last definition of an object number wins,
as with incremental updates), opens object streams (PDF 1.5), finds the file
specifications whose name is the one asked for, and decodes their embedded
file streams (no filter, or FlateDecode). It renders nothing and runs
nothing. More than one embedded file under the same name is refused: a
verifier must not choose between them.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from typing import Any


class PdfError(ValueError):
    pass


@dataclass(frozen=True)
class Ref:
    num: int
    gen: int


@dataclass(frozen=True)
class Name:
    value: str


@dataclass
class Stream:
    dict: dict
    raw: bytes


_WS = b"\x00\t\n\x0c\r "
_DELIM = b"()<>[]{}/%"
_OBJ = re.compile(rb"(?<![0-9])(\d+)\s+(\d+)\s+obj\b")


class _Lexer:
    def __init__(self, data: bytes, pos: int = 0):
        self.data, self.pos = data, pos

    def skip(self) -> None:
        d = self.data
        while self.pos < len(d):
            c = d[self.pos]
            if c in _WS:
                self.pos += 1
            elif c == 0x25:  # comment
                while self.pos < len(d) and d[self.pos] not in b"\r\n":
                    self.pos += 1
            else:
                return

    def value(self, depth: int = 0) -> Any:
        if depth > 64:
            raise PdfError("objects nest too deeply")
        self.skip()
        d = self.data
        if self.pos >= len(d):
            raise PdfError("the file ends inside an object")
        c = d[self.pos]
        if d.startswith(b"<<", self.pos):
            self.pos += 2
            out = {}
            while True:
                self.skip()
                if d.startswith(b">>", self.pos):
                    self.pos += 2
                    return out
                key = self.value(depth + 1)
                if not isinstance(key, Name):
                    raise PdfError("a dictionary key is not a name")
                out[key.value] = self.value(depth + 1)
        if c == 0x5B:  # [
            self.pos += 1
            out = []
            while True:
                self.skip()
                if d.startswith(b"]", self.pos):
                    self.pos += 1
                    return out
                out.append(self.value(depth + 1))
        if c == 0x2F:  # /
            self.pos += 1
            start = self.pos
            while self.pos < len(d) and d[self.pos] not in _WS + _DELIM:
                self.pos += 1
            raw = d[start:self.pos]
            return Name(re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1"))
        if c == 0x28:  # (
            return self._literal()
        if c == 0x3C:  # <
            end = d.find(b">", self.pos)
            if end < 0:
                raise PdfError("unterminated hex string")
            hexs = re.sub(rb"\s", b"", d[self.pos + 1:end])
            self.pos = end + 1
            if len(hexs) % 2:
                hexs += b"0"
            return bytes.fromhex(hexs.decode("ascii"))
        start = self.pos
        while self.pos < len(d) and d[self.pos] not in _WS + _DELIM:
            self.pos += 1
        tok = d[start:self.pos]
        if tok in (b"true", b"false"):
            return tok == b"true"
        if tok == b"null":
            return None
        if re.fullmatch(rb"[+-]?\d+", tok):
            save = self.pos
            self.skip()
            m = re.match(rb"(\d+)\s+R\b", d[self.pos:self.pos + 32])
            if m:
                self.pos += m.end()
                return Ref(int(tok), int(m.group(1)))
            self.pos = save
            return int(tok)
        if re.fullmatch(rb"[+-]?(\d+\.\d*|\.\d+)", tok):
            return float(tok)
        raise PdfError(f"unexpected token {tok[:20]!r}")

    def _literal(self) -> bytes:
        d, out, depth = self.data, bytearray(), 0
        self.pos += 1
        escapes = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t", ord("b"): b"\b", ord("f"): b"\f",
                   ord("("): b"(", ord(")"): b")", ord("\\"): b"\\"}
        while self.pos < len(d):
            c = d[self.pos]
            self.pos += 1
            if c == 0x5C:
                e = d[self.pos]
                if e in escapes:
                    out += escapes[e]
                    self.pos += 1
                elif 0x30 <= e <= 0x37:
                    m = re.match(rb"[0-7]{1,3}", d[self.pos:self.pos + 3])
                    out.append(int(m.group(0), 8) & 0xFF)
                    self.pos += m.end()
                elif e in b"\r\n":
                    self.pos += 2 if d[self.pos:self.pos + 2] == b"\r\n" else 1
                else:
                    self.pos += 1
            elif c == 0x28:
                depth += 1
                out.append(c)
            elif c == 0x29:
                if depth == 0:
                    return bytes(out)
                depth -= 1
                out.append(c)
            else:
                out.append(c)
        raise PdfError("unterminated literal string")


def _read_object(data: bytes, pos: int) -> tuple[Any, int]:
    lex = _Lexer(data, pos)
    value = lex.value()
    lex.skip()
    if isinstance(value, dict) and data.startswith(b"stream", lex.pos):
        start = lex.pos + len(b"stream")
        if data.startswith(b"\r\n", start):
            start += 2
        elif data.startswith(b"\n", start):
            start += 1
        length = value.get("Length")
        if isinstance(length, int) and data[start + length:start + length + 20].lstrip().startswith(b"endstream"):
            raw = data[start:start + length]
        else:
            end = data.find(b"endstream", start)
            if end < 0:
                raise PdfError("unterminated stream")
            raw = data[start:end].rstrip(b"\r\n")
        return Stream(value, raw), start + len(raw)
    return value, lex.pos


def _decode(stream: Stream, resolve) -> bytes:
    filters = resolve(stream.dict.get("Filter"))
    if filters is None:
        return stream.raw
    if isinstance(filters, Name):
        filters = [filters]
    data = stream.raw
    for f in filters:
        f = resolve(f)
        if not isinstance(f, Name) or f.value != "FlateDecode":
            raise PdfError(f"stream filter {getattr(f, 'value', f)!r} is not one this reader decodes")
        try:
            data = zlib.decompress(data)
        except zlib.error as exc:
            raise PdfError(f"a FlateDecode stream does not inflate: {exc}") from exc
    params = resolve(stream.dict.get("DecodeParms"))
    if isinstance(params, dict) and resolve(params.get("Predictor", 1)) not in (1, None):
        raise PdfError("PNG and TIFF predictors are not decoded by this reader")
    return data


class Document:
    def __init__(self, data: bytes):
        if not data.startswith(b"%PDF-"):
            raise PdfError("not a PDF: the %PDF- header is missing")
        self.data = data
        self.objects: dict[int, Any] = {}
        skip_until = 0
        for m in _OBJ.finditer(data):
            if m.start() < skip_until:
                continue  # inside a stream already read: its bytes are data, not objects
            try:
                value, end = _read_object(data, m.end())
            except (PdfError, IndexError, ValueError):
                continue
            if isinstance(value, Stream):
                skip_until = end
            self.objects[int(m.group(1))] = value  # a later definition replaces an earlier one
        for num, obj in list(self.objects.items()):
            if isinstance(obj, Stream) and self.resolve(obj.dict.get("Type")) == Name("ObjStm"):
                self._open_object_stream(obj)

    def resolve(self, value: Any, depth: int = 0) -> Any:
        while isinstance(value, Ref):
            if depth > 32:
                raise PdfError("references loop")
            value = self.objects.get(value.num)
            depth += 1
        return value

    def _open_object_stream(self, obj: Stream) -> None:
        body = _decode(obj, self.resolve)
        n, first = self.resolve(obj.dict.get("N")), self.resolve(obj.dict.get("First"))
        if not isinstance(n, int) or not isinstance(first, int):
            raise PdfError("an object stream lacks N or First")
        header = _Lexer(body)
        pairs = []
        for _ in range(n):
            num, off = header.value(), header.value()
            pairs.append((num, off))
        for num, off in pairs:
            value, _ = _read_object(body, first + off)
            self.objects.setdefault(num, value)  # without the cross-reference table, a top-level definition wins

    def embedded_files(self) -> list[tuple[str, bytes]]:
        """Every file specification with an embedded file: (name, content)."""
        out = []
        for obj in self.objects.values():
            if not isinstance(obj, dict):
                continue
            ef = self.resolve(obj.get("EF"))
            if not isinstance(ef, dict):
                continue
            name = self.resolve(obj.get("UF")) or self.resolve(obj.get("F"))
            stream = self.resolve(ef.get("UF")) or self.resolve(ef.get("F"))
            if not isinstance(stream, Stream):
                continue
            if isinstance(name, bytes):
                name = name[2:].decode("utf-16-be") if name.startswith(b"\xfe\xff") else name.decode("latin-1")
            out.append((str(name), _decode(stream, self.resolve)))
        return out


def extract(data: bytes, name: str = "certificate.json") -> bytes:
    files = [content for fname, content in Document(data).embedded_files() if fname == name]
    if not files:
        raise PdfError(f"the PDF holds no embedded file named {name}")
    if len(set(files)) > 1:
        raise PdfError(f"the PDF holds {len(set(files))} different embedded files named {name}; a verifier must not choose")
    return files[0]
