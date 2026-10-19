"""Extract an embedded file (the certificate's ``certificate.json``) from a PDF.

A small reader, enough for embedded files and no more: it finds every
indirect object in the file, opens object streams (PDF 1.5), finds the file
specifications whose name is the one asked for, and decodes their embedded
file streams (no filter, or FlateDecode). It renders nothing and runs
nothing. A verifier must not choose between versions of what it verifies,
so two things are refused: more than one embedded file under the same name,
and an embedded file whose objects are defined more than once with different
content, or more than once where one definition cannot be read (an
incremental update replacing it, or a definition no cross-reference table
lists), since readers differ on which definition holds, and a viewer could
show one while this reader checks another. A definition counts as one that
cannot be read wherever a cross-reference section (a table or a stream)
places the object at an offset that does not hold it: a reader that follows
the table, as viewers do, may still take what is there.
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
    measured: bool = True  # its end was found by a direct /Length; False when found by searching for endstream


_WS = b"\x00\t\n\x0c\r "
_DELIM = b"()<>[]{}/%"
_OBJ = re.compile(rb"(?<![0-9])(\d+)\s+(\d+)\s+obj\b")
_XREF = re.compile(rb"(?<![A-Za-z])xref[ \t]*\r?\n")
_XREF_SUB = re.compile(rb"\s*(\d+)[ \t]+(\d+)[ \t]*\r?\n")
_XREF_ENTRY = re.compile(rb"\s*(\d{10})[ \t]+(\d{5})[ \t]+([nf])")


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
        measured = isinstance(length, int) and data[start + length:start + length + 20].lstrip().startswith(b"endstream")
        if measured:
            raw = data[start:start + length]
        else:
            end = data.find(b"endstream", start)
            if end < 0:
                raise PdfError("unterminated stream")
            # One end-of-line marker before endstream is not stream data (ISO 32000-1, 7.3.8.1); any other is.
            raw = data[start:end]
            raw = raw[:-2] if raw.endswith(b"\r\n") else raw[:-1] if raw.endswith((b"\n", b"\r")) else raw
        return Stream(value, raw, measured), start + len(raw)
    return value, lex.pos


MAX_STREAM = 16 * 1024 * 1024  # decoded bytes in one stream
MAX_DOCUMENT = 64 * 1024 * 1024  # decoded bytes across one document
MAX_FILTERS = 4


def _inflate(data: bytes, limit: int) -> bytes:
    """zlib inflate that stops past ``limit`` bytes of output: a small
    stream can inflate a thousandfold, and filters can be chained."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, limit + 1)
        if len(out) <= limit and not d.unconsumed_tail:
            out += d.flush()
    except zlib.error as exc:
        raise PdfError(f"a FlateDecode stream does not inflate: {exc}") from exc
    if len(out) > limit or d.unconsumed_tail:
        raise PdfError(f"a FlateDecode stream inflates to more than {limit} bytes; this reader stops there")
    if not d.eof:
        raise PdfError("a FlateDecode stream does not inflate: incomplete or truncated stream")
    return out


def _decode(stream: Stream, resolve, budget: list[int] | None = None) -> bytes:
    """Decode a stream; ``budget`` is a one-item list of decoded bytes the
    document may still produce."""
    budget = budget if budget is not None else [MAX_DOCUMENT]
    filters = resolve(stream.dict.get("Filter"))
    if filters is None:
        return stream.raw
    if isinstance(filters, Name):
        filters = [filters]
    if not isinstance(filters, list) or len(filters) > MAX_FILTERS:
        raise PdfError(f"a stream's filters are not a list of at most {MAX_FILTERS}")
    data = stream.raw
    for f in filters:
        f = resolve(f)
        if not isinstance(f, Name) or f.value != "FlateDecode":
            raise PdfError(f"stream filter {getattr(f, 'value', f)!r} is not one this reader decodes")
        data = _inflate(data, min(MAX_STREAM, budget[0]))
        budget[0] -= len(data)
    params = resolve(stream.dict.get("DecodeParms"))
    if isinstance(params, dict) and resolve(params.get("Predictor", 1)) not in (1, None):
        raise PdfError("PNG and TIFF predictors are not decoded by this reader")
    return data


class Document:
    def __init__(self, data: bytes):
        if not data.startswith(b"%PDF-"):
            raise PdfError("not a PDF: the %PDF- header is missing")
        self.data = data
        self.budget = [MAX_DOCUMENT]
        self.objects: dict[int, Any] = {}
        self.redefined: set[int] = set()  # object numbers defined more than once, differently
        self.headers: dict[int, int] = {}  # per object number, its definitions in the file, readable or not
        self.readable: dict[int, int] = {}  # and those this reader could read
        self.misplaced: set[int] = set()  # object numbers a cross-reference section places where they are not read
        spans: list[tuple[int, int]] = []  # the objects read: what is inside them is data
        skip_until = 0
        for m in _OBJ.finditer(data):
            if m.start() < skip_until:
                continue  # inside an object already read (a stream's bytes, a string's text): data, not objects
            num = int(m.group(1))
            self.headers[num] = self.headers.get(num, 0) + 1
            try:
                value, end = _read_object(data, m.end())
            except (PdfError, IndexError, ValueError):
                # A broken object is passed over to its endobj, so that a file of many
                # unterminated objects costs one pass, not one pass per object.
                close = data.find(b"endobj", m.end())
                skip_until = len(data) if close < 0 else close
                continue
            skip_until = end
            spans.append((m.start(), end))
            self.readable[num] = self.readable.get(num, 0) + 1
            if num in self.objects and self.objects[num] != value:
                self.redefined.add(num)
            self.objects[num] = value  # the later definition is the one read; embedded_files refuses either
        for num, obj in list(self.objects.items()):
            if isinstance(obj, Stream) and self.resolve(obj.dict.get("Type")) == Name("ObjStm"):
                self._open_object_stream(obj)
        for num, offset in self._xref_entries(spans):
            m = _OBJ.match(data, offset + len(data[offset:offset + 64]) - len(data[offset:offset + 64].lstrip()))
            if m is None or int(m.group(1)) != num:
                self.misplaced.add(num)

    def _xref_entries(self, spans: list[tuple[int, int]]):
        """(object number, offset) of every in-use entry in every cross-reference section: the tables outside the
        objects read, and the cross-reference streams (entries of type 1; type 2 is inside an object stream)."""
        inside = lambda pos: any(a <= pos < b for a, b in spans)  # noqa: E731
        for m in _XREF.finditer(self.data):
            if inside(m.start()):
                continue
            pos = m.end()
            while (sub := _XREF_SUB.match(self.data, pos)) is not None:
                start, count = int(sub.group(1)), int(sub.group(2))
                pos = sub.end()
                for i in range(count):
                    entry = _XREF_ENTRY.match(self.data, pos)
                    if entry is None:
                        break
                    pos = entry.end()
                    if entry.group(3) == b"n":
                        yield start + i, int(entry.group(1))
        for obj in list(self.objects.values()):
            if not (isinstance(obj, Stream) and self.resolve(obj.dict.get("Type")) == Name("XRef")):
                continue
            widths = self.resolve(obj.dict.get("W"))
            index = self.resolve(obj.dict.get("Index")) or [0, self.resolve(obj.dict.get("Size"))]
            if not (isinstance(widths, list) and len(widths) == 3 and all(isinstance(w, int) and 0 <= w <= 8 for w in widths)
                    and isinstance(index, list) and len(index) % 2 == 0 and all(isinstance(x, int) for x in index)):
                raise PdfError("a cross-reference stream lacks its W or Index")
            body, row, at = _decode(obj, self.resolve, self.budget), sum(widths), 0
            for start, count in zip(index[::2], index[1::2]):
                for i in range(count):
                    if at + row > len(body):
                        raise PdfError("a cross-reference stream is shorter than its Index says")
                    fields, k = [], at
                    for w in widths:
                        fields.append(int.from_bytes(body[k:k + w], "big"))
                        k += w
                    at += row
                    if (fields[0] if widths[0] else 1) == 1:
                        yield start + i, fields[1]

    def resolve(self, value: Any, depth: int = 0) -> Any:
        while isinstance(value, Ref):
            if depth > 32:
                raise PdfError("references loop")
            value = self.objects.get(value.num)
            depth += 1
        return value

    def _open_object_stream(self, obj: Stream) -> None:
        body = _decode(obj, self.resolve, self.budget)
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
            if num in self.objects and self.objects[num] != value:
                self.redefined.add(num)
            self.objects.setdefault(num, value)  # without the cross-reference table, a top-level definition wins

    def embedded_files(self, only: str | None = None) -> list[tuple[str, bytes]]:
        """Every file specification with an embedded file: (name, content);
        with ``only``, just those of that name are decoded."""
        out = []
        for num, obj in list(self.objects.items()):
            if not isinstance(obj, dict):
                continue
            touched = {num}
            ef = self._follow(obj.get("EF"), touched)
            if not isinstance(ef, dict):
                continue
            name = self._follow(obj.get("UF"), touched) or self._follow(obj.get("F"), touched)
            stream = self._follow(ef.get("UF"), touched) or self._follow(ef.get("F"), touched)
            if not isinstance(stream, Stream):
                continue
            if isinstance(name, bytes):
                name = name[2:].decode("utf-16-be") if name.startswith(b"\xfe\xff") else name.decode("latin-1")
            if only is not None and str(name) != only:
                continue
            if not stream.measured and self.resolve(stream.dict.get("Length")) != len(stream.raw):
                raise PdfError(f"the embedded file {name}'s stream does not end where its /Length says: the file is damaged, "
                               "and readers differ on where such a stream ends")
            if any(n in self.redefined or n in self.misplaced or self.headers.get(n, 0) > max(1, self.readable.get(n, 0))
                   for n in touched):
                raise PdfError(f"the embedded file {name} is defined more than once in the PDF, with different content (an "
                               "incremental update replacing it, a definition no cross-reference lists, or one a "
                               "cross-reference places where it cannot be read): readers differ on which holds, and a "
                               "verifier must not choose")
            out.append((str(name), _decode(stream, self.resolve, self.budget)))
        return out

    def _follow(self, value: Any, touched: set[int]) -> Any:
        """``resolve``, recording the object numbers passed through."""
        depth = 0
        while isinstance(value, Ref):
            if depth > 32:
                raise PdfError("references loop")
            touched.add(value.num)
            value = self.objects.get(value.num)
            depth += 1
        return value


def extract(data: bytes, name: str = "certificate.json") -> bytes:
    files = [content for fname, content in Document(data).embedded_files(only=name) if fname == name]
    if not files:
        raise PdfError(f"the PDF holds no embedded file named {name}")
    if len(set(files)) > 1:
        raise PdfError(f"the PDF holds {len(set(files))} different embedded files named {name}; a verifier must not choose")
    return files[0]
