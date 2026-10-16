"""The PDF fixtures, read by pypdf (BSD-3-Clause, a test-time tool only):
both readers must take the same certificate.json, or see the same
attachments where this verifier refuses to choose."""

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
    if len(set(theirs)) == 1:
        assert pdf.extract(data) == theirs[0]
    else:
        with pytest.raises(pdf.PdfError):
            pdf.extract(data)
