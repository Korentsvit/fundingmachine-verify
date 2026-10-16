"""Cross-checks against the reference OpenTimestamps implementation.

Skipped unless the ``opentimestamps`` package (LGPL-3.0, a test-time tool
only: never imported by the verifier) is installed.
"""

from pathlib import Path

import pytest

from fmverify import ots

FIX = Path(__file__).resolve().parent.parent / "fixtures"
reference = pytest.importorskip("opentimestamps.core.timestamp")
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation  # noqa: E402
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext  # noqa: E402

CASES = sorted(p for p in (FIX / "ots").iterdir() if p.is_dir())


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_same_reading_as_reference(case):
    data = (case / "proof.ots").read_bytes()
    try:
        ref = reference.DetachedTimestampFile.deserialize(BytesDeserializationContext(data))
    except Exception:
        with pytest.raises(ots.OtsError):
            ots.parse(data)
        return
    ctx = BytesSerializationContext()
    ref.serialize(ctx)
    assert ctx.getbytes() == data
    mine = ots.parse(data)
    assert mine.digest == ref.file_digest
    ref_atts = sorted((a.height, msg) for msg, a in ref.timestamp.all_attestations() if isinstance(a, BitcoinBlockHeaderAttestation))
    my_atts = sorted((l.attestation.height, l.commitment) for l in ots.leaves(mine.timestamp) if l.attestation.kind == "bitcoin")
    assert ref_atts == my_atts


def test_reference_accepts_the_mainnet_header():
    bitcoin_core = pytest.importorskip("bitcoin.core")
    case = FIX / "ots" / "mainnet-840000-sparse"
    ref = reference.DetachedTimestampFile.deserialize(BytesDeserializationContext((case / "proof.ots").read_bytes()))
    line = next(l for l in (FIX / "bitcoin" / "mainnet" / "headers-sparse.txt").read_text().splitlines() if l.startswith("840000 "))
    header = bitcoin_core.CBlockHeader.deserialize(bytes.fromhex(line.split()[1]))
    (msg, att), = list(ref.timestamp.all_attestations())
    assert att.verify_against_blockheader(msg, header) == header.nTime


def test_differential_fuzz_against_reference():
    """tools/differential_ots.py, briefly: changed proofs are refused by both
    readers, or read alike (digest, Bitcoin attestations and commitments)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("differential_ots", FIX.parent / "tools" / "differential_ots.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    result = tool.run(60)
    assert result["totals"].get("read alike", 0) > 50 and result["totals"].get("refused by both", 0) > 200
    assert not result["other"], result["other"]
