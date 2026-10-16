"""Differential fuzz of OpenTimestamps parsing against the reference library.

    python tools/differential_ots.py [ROUNDS]

Changes the bytes of every OpenTimestamps proof in the fixtures ROUNDS times
each (default 500), deterministically, and reads each changed proof with
this verifier and with the reference ``opentimestamps`` library (LGPL-3.0,
a test-time tool only). Both must accept the same proofs (the reference
leaves trailing bytes unread; this verifier refuses them, as the format
ends where the proof ends), and where both accept, they must find the same
file digest and the same Bitcoin attestations, each with the same
commitment. Any other difference fails the run.
"""

from __future__ import annotations

import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from fmverify import ots  # noqa: E402
from tamper_audit import mutate_bytes  # noqa: E402


def run(rounds: int) -> dict:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile

    def reference(data: bytes):
        ctx = BytesDeserializationContext(data)
        f = DetachedTimestampFile.deserialize(ctx)
        try:
            ctx.read_bytes(1)
            return "trailing"
        except Exception:  # noqa: BLE001 - nothing left to read: the proof ends where the data ends
            pass
        return f.file_digest, sorted((a.height, m) for m, a in f.timestamp.all_attestations()
                                     if isinstance(a, BitcoinBlockHeaderAttestation))

    def mine(data: bytes):
        p = ots.parse(data)
        return p.digest, sorted((leaf.attestation.height, leaf.commitment) for leaf in ots.leaves(p.timestamp)
                                if leaf.attestation.kind == "bitcoin")

    fix = ROOT / "fixtures"
    proofs = sorted({p.read_bytes(): p for p in [*fix.glob("ots/*/proof.ots"), *fix.glob("anchors/*/root.ots"),
                                                   *fix.glob("ledger-anchors/**/root.preimage.ots")]}.items(), key=lambda x: str(x[1]))
    totals: Counter = Counter()
    other: list[str] = []
    for data, path in proofs:
        name = str(path.relative_to(fix))
        rng = random.Random(name)
        for _ in range(rounds):
            changed, where = mutate_bytes(rng, data)
            if changed == data:
                continue
            try:
                theirs = reference(changed)
            except Exception:  # noqa: BLE001 - any error is "the reference refused it"
                theirs = None
            try:
                ours = mine(changed)
            except ots.OtsError:
                ours = None
            if theirs == "trailing":
                theirs = None  # bytes after the proof: refused here by design
            if theirs is None and ours is None:
                totals["refused by both"] += 1
            elif theirs is not None and ours is not None and theirs == ours:
                totals["read alike"] += 1
            else:
                totals["differ"] += 1
                other.append(f"{name}: {where}: reference {'refused' if theirs is None else 'read'}, "
                             f"this verifier {'refused' if ours is None else 'read'}" + (" differently" if theirs and ours else ""))
    return {"totals": dict(totals), "other": other}


def main(argv: list[str]) -> int:
    result = run(int(argv[0]) if argv else 500)
    for what, n in sorted(result["totals"].items(), key=lambda x: -x[1]):
        print(f"{n:6}  {what}")
    for o in result["other"]:
        print(f"DIFFERENT {o}")
    return 1 if result["other"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
