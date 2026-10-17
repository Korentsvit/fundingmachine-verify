"""Fetch the Bitcoin block headers a set of OpenTimestamps proofs names, from
two explorers, and keep them only if the explorers agree.

    python tools/fetch_headers.py DIR OUT [--explorer URL --explorer URL ...]

Reads every ``*.ots`` file under DIR, collects the heights of their Bitcoin
attestations, and asks each explorer (default https://mempool.space/api and
https://blockstream.info/api, both Esplora) for the block hash at each height
and that block's header. A header is kept only if every explorer gives the
same bytes and they hash to the block hash given. OUT receives the headers as
``HEIGHT HEX`` lines, the sparse form ``fm-verify --headers`` reads, under
comments naming the explorers, the time and each block's hash. Any
disagreement stops it with exit 1 and nothing is written.

The verdict still relies on the explorers: two that agree are harder to
mislead than one, and a node of your own (``--bitcoind``) is stronger still.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fmverify import ots  # noqa: E402

EXPLORERS = ("https://mempool.space/api", "https://blockstream.info/api")


class HeaderFetchError(Exception):
    pass


def get(url: str, tries: int = 3) -> str:
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return r.read().decode("ascii").strip()
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == tries - 1:
                raise
            time.sleep(2 * 2 ** attempt)
    raise AssertionError("unreachable")


def heights(directory: Path) -> list[int]:
    found = set()
    for path in sorted(directory.rglob("*.ots")):
        proof = ots.parse(path.read_bytes())
        found.update(leaf.attestation.height for leaf in ots.leaves(proof.timestamp) if leaf.attestation.kind == "bitcoin")
    return sorted(found)


def block_hash(header: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def fetch_headers(wanted: list[int], explorers: tuple[str, ...] = EXPLORERS) -> dict[int, tuple[str, bytes]]:
    out: dict[int, tuple[str, bytes]] = {}
    for h in wanted:
        answers = []
        for base in explorers:
            bh = get(f"{base.rstrip('/')}/block-height/{h}")
            raw = bytes.fromhex(get(f"{base.rstrip('/')}/block/{bh}/header"))
            if len(raw) != 80 or block_hash(raw) != bh:
                raise HeaderFetchError(f"{base} gave height {h} the block {bh}, but a header that does not hash to it")
            answers.append((bh, raw))
        if len(set(answers)) != 1:
            raise HeaderFetchError(f"the explorers disagree on height {h}: " + ", ".join(f"{e} {a[0]}" for e, a in zip(explorers, answers)))
        out[h] = answers[0]
    return out


def render(headers: dict[int, tuple[str, bytes]], explorers: tuple[str, ...], at: str) -> str:
    lines = [f"# Bitcoin block headers fetched {at} from {' and '.join(explorers)};",
             "# every explorer gave the same header, and each hashes to the block hash given.",
             "# The verdict relies on these explorers for which block is at each height."]
    for h, (bh, raw) in sorted(headers.items()):
        lines += [f"# {h}: block {bh}", f"{h} {raw.hex()}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    explorers = tuple(argv[i + 1] for i, a in enumerate(argv) if a == "--explorer" and i + 1 < len(argv))
    rest = [a for i, a in enumerate(argv) if a != "--explorer" and (i == 0 or argv[i - 1] != "--explorer")]
    explorers = explorers or EXPLORERS
    if len(rest) != 2 or len(set(explorers)) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    directory, out = Path(rest[0]), Path(rest[1])
    try:
        wanted = heights(directory)
        if not wanted:
            print(f"no Bitcoin attestation in any proof under {directory}: nothing to fetch", file=sys.stderr)
            return 1
        headers = fetch_headers(wanted, explorers)
    except (HeaderFetchError, ots.OtsError, urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as exc:
        print(f"not written: {exc}", file=sys.stderr)
        return 1
    at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.write_text(render(headers, explorers, at), encoding="utf-8")
    print(f"{len(headers)} headers ({', '.join(map(str, wanted))}) written to {out}; {len(explorers)} explorers agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
