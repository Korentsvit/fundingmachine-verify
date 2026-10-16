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
