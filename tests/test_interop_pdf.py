"""The PDF fixtures, read by pypdf (BSD-3-Clause, a test-time tool only):
both readers must take the same certificate.json, or see the same
attachments where this verifier refuses to choose. Where an update has
replaced the attachment, this verifier refuses, whichever version pypdf
takes; and on damaged copies (tools/differential_pdf.py) the two never
take different certificates."""

import io
import warnings
from pathlib import Path

import pytest

from fmverify import pdf

pypdf = pytest.importorskip("pypdf")
FIX = Path(__file__).resolve().parent.parent / "fixtures" / "certificate"
CASES = sorted(FIX.glob("pdf-*"))


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_same_reading_as_pypdf(case):
    data = (case / "certificate.pdf").read_bytes()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        theirs = pypdf.PdfReader(io.BytesIO(data)).attachments.get("certificate.json", [])
    if pdf.Document(data).redefined:
        with pytest.raises(pdf.PdfError, match="defined more than once"):
            pdf.extract(data)
    elif len(set(theirs)) == 1:
        assert pdf.extract(data) == theirs[0]
    else:
        with pytest.raises(pdf.PdfError):
            pdf.extract(data)


def test_differential_fuzz_against_pypdf():
    """tools/differential_pdf.py, briefly: no damaged PDF from which both
    readers take a certificate.json and take different ones."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("differential_pdf", FIX.parent.parent / "tools" / "differential_pdf.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    result = tool.run(150)
    assert result["totals"].get("read alike", 0) > 50
    assert not result["other"], result["other"]
