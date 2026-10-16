import zlib

import pytest

from fmverify import pdf


def _doc(objects: bytes) -> bytes:
    return b"%PDF-1.7\n" + objects + b"trailer\n<< >>\n%%EOF\n"


def test_names_strings_and_escapes():
    data = _doc(b"1 0 obj\n<< /F (cert\\(1\\)\\056json) /UF <FEFF00630065007200740069006600690063006100740065002E006A0073006F006E> "
                b"/EF << /F 2 0 R >> >>\nendobj\n2 0 obj\n<< /Length 2 >>\nstream\n{}\nendstream\nendobj\n")
    files = dict(pdf.Document(data).embedded_files())
    assert files == {"certificate.json": b"{}"}


def test_stream_content_that_looks_like_an_object_is_not_read_as_one():
    payload = b"9 0 obj\n<< /EF << /F 2 0 R >> /F (certificate.json) >>\nendobj\n"
    data = _doc(b"1 0 obj\n<< /F (certificate.json) /EF << /F 2 0 R >> >>\nendobj\n"
                b"2 0 obj\n<< /Length %d >>\nstream\n" % len(payload) + payload + b"\nendstream\nendobj\n")
    assert pdf.extract(data) == payload


def test_flate_and_unknown_filters():
    body = zlib.compress(b'{"a": 1}')
    ok = _doc(b"1 0 obj\n<< /F (certificate.json) /EF << /F 2 0 R >> >>\nendobj\n"
              b"2 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(body) + body + b"\nendstream\nendobj\n")
    assert pdf.extract(ok) == b'{"a": 1}'
    bad = ok.replace(b"/FlateDecode", b"/LZWDecode")
    with pytest.raises(pdf.PdfError, match="LZWDecode"):
        pdf.extract(bad)


def test_not_a_pdf():
    with pytest.raises(pdf.PdfError, match="header"):
        pdf.extract(b"{}")


def _attachment(stream_dict: bytes, body: bytes) -> bytes:
    return _doc(b"1 0 obj\n<< /F (certificate.json) /EF << /F 2 0 R >> >>\nendobj\n"
                b"2 0 obj\n<< /Length %d " % len(body) + stream_dict + b" >>\nstream\n" + body + b"\nendstream\nendobj\n")


def test_decompression_bomb_stops_at_the_limit():
    """A small stream that inflates past the per-stream limit, alone or
    behind a second FlateDecode, is refused quickly, never inflated whole."""
    import time

    big = zlib.compress(b"\0" * (pdf.MAX_STREAM + 1), 9)
    assert len(big) < 40_000
    t = time.perf_counter()
    with pytest.raises(pdf.PdfError, match="more than"):
        pdf.extract(_attachment(b"/Filter /FlateDecode", big))
    double = zlib.compress(big, 9)
    with pytest.raises(pdf.PdfError, match="more than"):
        pdf.extract(_attachment(b"/Filter [/FlateDecode /FlateDecode]", double))
    assert time.perf_counter() - t < 5


def test_filter_chain_and_truncation_limits():
    with pytest.raises(pdf.PdfError, match="at most"):
        pdf.extract(_attachment(b"/Filter [/FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode]", b"x"))
    whole = zlib.compress(b'{"a": 1}')
    with pytest.raises(pdf.PdfError, match="truncated"):
        pdf.extract(_attachment(b"/Filter /FlateDecode", whole[:-4]))
    assert pdf.extract(_attachment(b"/Filter /FlateDecode", whole)) == b'{"a": 1}'


def test_document_budget_spans_streams():
    """Many streams just under the per-stream limit stop at the document's."""
    one = zlib.compress(b"\0" * (pdf.MAX_STREAM - 1), 9)
    objs = b"".join(b"%d 0 obj\n<< /Length %d /Filter /FlateDecode /Type /ObjStm /N 0 /First 0 >>\nstream\n" % (n, len(one)) + one
                    + b"\nendstream\nendobj\n" for n in range(3, 3 + pdf.MAX_DOCUMENT // pdf.MAX_STREAM + 2))
    with pytest.raises(pdf.PdfError, match="more than"):
        pdf.Document(_doc(objs))


def test_many_unterminated_objects_parse_in_one_pass():
    """Each broken object is passed over to its endobj: a small hostile file
    costs one pass, not one per object (it once took 46 s for 80 KB)."""
    import time

    data = _doc(b"".join(b"%d 0 obj (" % n for n in range(1, 8001)))
    t = time.perf_counter()
    with pytest.raises(pdf.PdfError):
        pdf.extract(data)
    assert time.perf_counter() - t < 2
