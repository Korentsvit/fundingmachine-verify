"""Capture the public Bitcoin data behind the mainnet fixtures.

Run once by hand; its output is committed under fixtures/bitcoin/mainnet/ and
everything else is built from that offline. Reads an Esplora API (default
mempool.space). Every header is checked to hash to the block id the API gave,
and the coinbase transaction is reduced to two numbers: its txid and the
single SHA-256 of its non-witness serialization. No transaction content is
kept.

    python tools/fetch_mainnet.py [--api https://mempool.space/api]
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import struct
import time
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "fixtures" / "bitcoin" / "mainnet"
WINDOWS = [(0, 19), (839990, 840009)]
SINGLES = [836640, 838655, 838656]
COINBASE_HEIGHT = 840000


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(b: bytes, i: int) -> tuple[int, int]:
    n = b[i]
    if n < 0xFD:
        return n, i + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
    return int.from_bytes(b[i + 1 : i + 1 + width], "little"), i + 1 + width


def strip_witness(raw: bytes) -> bytes:
    i = 6 if raw[4:6] == b"\x00\x01" else 4
    start = i
    n, i = compact_size(raw, i)
    for _ in range(n):
        i += 36
        length, i = compact_size(raw, i)
        i += length + 4
    n, i = compact_size(raw, i)
    for _ in range(n):
        i += 8
        length, i = compact_size(raw, i)
        i += length
    return raw[:4] + raw[start:i] + raw[-4:]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="https://mempool.space/api")
    args = ap.parse_args()

    def get(path: str) -> bytes:
        with urllib.request.urlopen(args.api + path, timeout=30) as r:
            return r.read()

    fetched_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    headers: dict[int, str] = {}
    for lo, hi in WINDOWS:
        top = hi
        while top >= lo:
            for b in json.loads(get(f"/blocks/{top}")):
                prev = bytes.fromhex(b["previousblockhash"])[::-1] if b.get("previousblockhash") else bytes(32)
                h = struct.pack("<I", b["version"]) + prev + bytes.fromhex(b["merkle_root"])[::-1] + struct.pack(
                    "<III", b["timestamp"], b["bits"], b["nonce"]
                )
                assert sha256d(h)[::-1].hex() == b["id"], b["height"]
                if lo <= b["height"] <= hi:
                    headers[b["height"]] = h.hex()
            top -= 10
            time.sleep(0.5)
    for height in SINGLES:
        block_id = get(f"/block-height/{height}").decode()
        raw = get(f"/block/{block_id}/header").decode()
        assert sha256d(bytes.fromhex(raw))[::-1].hex() == block_id
        headers[height] = raw
        time.sleep(0.5)

    block_id = get(f"/block-height/{COINBASE_HEIGHT}").decode()
    txid = get(f"/block/{block_id}/txid/0").decode()
    raw_tx = bytes.fromhex(get(f"/tx/{txid}/hex").decode())
    nonwitness = strip_witness(raw_tx)
    assert sha256d(nonwitness)[::-1].hex() == txid
    branch = json.loads(get(f"/tx/{txid}/merkle-proof"))

    lines = [
        "# Bitcoin mainnet block headers, height and 80-byte header in hex.",
        f"# Fetched from {args.api} at {fetched_at}; each header hashes to the block id the API gave.",
        "# Bitcoin protocol data, identical from any Bitcoin node; regenerate with tools/fetch_mainnet.py.",
    ]
    lines += [f"{h} {headers[h]}" for h in sorted(headers)]
    (OUT / "headers-sparse.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / f"coinbase-{COINBASE_HEIGHT}.json").write_text(
        json.dumps(
            {
                "height": COINBASE_HEIGHT,
                "block_hash": block_id,
                "txid": txid,
                "tx_sha256_single": hashlib.sha256(nonwitness).hexdigest(),
                "pos": branch["pos"],
                "merkle_branch_display": branch["merkle"],
                "source": args.api,
                "fetched_at": fetched_at,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
