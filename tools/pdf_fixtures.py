"""Minimal PDFs carrying an embedded certificate.json, for the fixtures.

Writes what docs/CERTIFICATE.md describes for the PDF form (an embedded file
named certificate.json, AFRelationship Source), in the layouts a reader has
to cope with: a classic file, a compressed one with object and
cross-reference streams (PDF 1.5), two attachments under one name, and an
incremental update that replaces the attachment.
"""

from __future__ import annotations

import struct
import zlib


def _pdf_string(s: str) -> bytes:
    return b"(" + s.encode("latin-1").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def _page_objects() -> dict[int, bytes]:
    content = b"BT /F1 12 Tf 72 720 Td (Provenance Ledger certificate: fixture) Tj ET"
    return {
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 7 0 R >> >> >>",
        4: b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        7: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }


def _filespec(name: str, ef_num: int) -> bytes:
    return (b"<< /Type /Filespec /F " + _pdf_string(name) + b" /UF " + _pdf_string(name)
            + b" /AFRelationship /Source /EF << /F %d 0 R /UF %d 0 R >> >>" % (ef_num, ef_num))


def _embedded(data: bytes, compress: bool) -> bytes:
    body = zlib.compress(data, 9) if compress else data
    filt = b" /Filter /FlateDecode" if compress else b""
    return (b"<< /Type /EmbeddedFile /Subtype /application#2Fjson" + filt + b" /Params << /Size %d >> /Length %d >>\nstream\n" % (len(data), len(body))
            + body + b"\nendstream")


def _classic(objects: dict[int, bytes], root: int = 1) -> bytes:
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    size = max(objects) + 1
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for num in range(1, size):
        out += (b"%010d 00000 n \n" % offsets[num]) if num in offsets else b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, root, xref)
    return bytes(out)


def classic(cert: bytes, attachments: list[tuple[str, bytes]] | None = None) -> bytes:
    attachments = attachments if attachments is not None else [("certificate.json", cert)]
    objects = _page_objects()
    names, af = [], []
    num = 10
    for name, data in attachments:
        objects[num] = _filespec(name, num + 1)
        objects[num + 1] = _embedded(data, compress=False)
        names.append(_pdf_string(name) + b" %d 0 R" % num)
        af.append(b"%d 0 R" % num)
        num += 2
    objects[1] = (b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [" + b" ".join(names)
                  + b"] >> >> /AF [" + b" ".join(af) + b"] >>") if attachments else b"<< /Type /Catalog /Pages 2 0 R >>"
    return _classic(objects)


def compressed(cert: bytes) -> bytes:
    """PDF 1.5: the catalog and the file specification inside an object stream,
    the embedded file deflated, and a cross-reference stream."""
    page = _page_objects()
    in_stream = {1: b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(certificate.json) 10 0 R] >> >> /AF [10 0 R] >>",
                 10: _filespec("certificate.json", 11)}
    header, body = [], b""
    for num in sorted(in_stream):
        header.append(b"%d %d" % (num, len(body)))
        body += in_stream[num] + b"\n"
    head = b" ".join(header) + b"\n"
    objstm_data = zlib.compress(head + body, 9)
    objects = {**{n: v for n, v in page.items()}, 11: _embedded(cert, compress=True),
               12: b"<< /Type /ObjStm /N %d /First %d /Filter /FlateDecode /Length %d >>\nstream\n" % (len(in_stream), len(head), len(objstm_data))
                   + objstm_data + b"\nendstream"}
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    xref_num = 13
    size = xref_num + 1
    offsets[xref_num] = len(out)
    rows = b""
    index_in_stm = {num: i for i, num in enumerate(sorted(in_stream))}
    for num in range(size):
        if num == 0:
            rows += struct.pack(">BIH", 0, 0, 65535)
        elif num in index_in_stm:
            rows += struct.pack(">BIH", 2, 12, index_in_stm[num])
        elif num in offsets:
            rows += struct.pack(">BIH", 1, offsets[num], 0)
        else:
            rows += struct.pack(">BIH", 0, 0, 0)
    xref_data = zlib.compress(rows, 9)
    out += (b"%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length %d >>\nstream\n" % (xref_num, size, len(xref_data))
            + xref_data + b"\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n" % offsets[xref_num])
    return bytes(out)


def with_update(original: bytes, replacement: bytes) -> bytes:
    """An incremental update appending a new version of the embedded file (object 11)."""
    base = len(original)
    obj = b"11 0 obj\n" + _embedded(replacement, compress=False) + b"\nendobj\n"
    prev = int(original.rsplit(b"startxref", 1)[1].split()[0])
    xref = base + len(obj)
    tail = (b"xref\n0 1\n0000000000 65535 f \n11 1\n%010d 00000 n \n" % base
            + b"trailer\n<< /Size 12 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (prev, xref))
    return original + obj + tail
