"""Differential fuzz of OpenTimestamps parsing against the reference library.

    python tools/differential_ots.py [ROUNDS]

Changes the bytes of every OpenTimestamps proof in the fixtures ROUNDS times
each (default 500), deterministically, and reads each changed proof with
this verifier and with the reference ``opentimestamps`` library (LGPL-3.0,
a test-time tool only). Both must accept the same proofs (the reference
leaves trailing bytes unread; this verifier refuses them, as the format
ends where the proof ends), and where both accept, they must find the same
file digest and the same Bitcoin attestations, each with the same
commitment. Any other difference fails the run, except the one this verifier
makes by design:

* Keccak-256 (tag 0x67) as the file's hash. A detached proof's file hash is
  read from the tags in ``CryptOp``'s table (``DetachedTimestampFile.deserialize``
  in ``opentimestamps/core/timestamp.py``). python-opentimestamps 0.4.5 enters
  Keccak-256 there with SHA-1, RIPEMD-160 and SHA-256 (``@CryptOp._register_op``
  in ``opentimestamps/core/op.py``); 0.5.0 enters it only among the operations
  inside a timestamp (``@UnaryOp._register_op``), so it refuses a proof naming
  it for the file. Sources: https://pypi.org/project/opentimestamps/0.4.5/ and
  https://pypi.org/project/opentimestamps/0.5.0/, read 2026-11-01. This
  verifier reads it and hashes the file with it, as before.
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


KECCAK_FILE_HASH = ("Keccak-256 (tag 0x67) as the file's hash: read here, as python-opentimestamps 0.4.5 "
                    "read it; 0.5.0 refuses it there")


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
    designed: Counter = Counter()
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
            elif theirs is None and ours is not None and ots.parse(changed).file_hash.tag == 0x67:
                totals["differ"] += 1
                designed[KECCAK_FILE_HASH] += 1
            elif theirs is not None and ours is not None and theirs == ours:
                totals["read alike"] += 1
            else:
                totals["differ"] += 1
                other.append(f"{name}: {where}: reference {'refused' if theirs is None else 'read'}, "
                             f"this verifier {'refused' if ours is None else 'read'}" + (" differently" if theirs and ours else ""))
    return {"totals": dict(totals), "by_design": dict(designed), "other": other}


def main(argv: list[str]) -> int:
    result = run(int(argv[0]) if argv else 500)
    for what, n in sorted(result["totals"].items(), key=lambda x: -x[1]):
        print(f"{n:6}  {what}")
    for why, n in result["by_design"].items():
        print(f"  by design ({n}): {why}")
    for o in result["other"]:
        print(f"DIFFERENT {o}")
    return 1 if result["other"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
