"""Bitcoin block headers: parsing, proof of work, header chains, and where headers come from.

Three sources, each with its reliance stated in every verdict that uses it:

* a contiguous headers file (80-byte headers back to back, from a stated
  height), validated by Bitcoin's header
  rules from its first header onward: linkage, proof of work, difficulty
  retargets and median time past. From genesis, the genesis hash is checked
  against the constant below.
* a sparse headers file (height and header per line, or JSON): each header
  is checked against its own proof of work and a minimum work floor, and
  linked where neighbours are present. Not checked to be on the most-work
  chain.
* a public explorer speaking the Esplora HTTP API, used only when a caller
  passes its URL. Its answer about which block sits at a height is trusted,
  and the verdict says so.
"""

from __future__ import annotations

import datetime as _dt
import json
import math
import struct
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .hashes import sha256d
from .verdict import Check, Status

TARGET_TIMESPAN = 14 * 24 * 60 * 60
RETARGET_INTERVAL = 2016


@dataclass(frozen=True)
class Network:
    name: str
    pow_limit: int
    genesis_hash: bytes | None  # internal byte order
    retarget: bool
    default_min_work_bits: float
    test_only: bool


MAINNET = Network(
    name="bitcoin-mainnet",
    pow_limit=(1 << 224) - 1,
    # Block 0, 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, in internal order.
    genesis_hash=bytes.fromhex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")[::-1],
    retarget=True,
    default_min_work_bits=70.0,
    test_only=False,
)
REGTEST = Network(
    name="bitcoin-regtest",
    pow_limit=(1 << 255) - 1,
    genesis_hash=None,
    retarget=False,
    default_min_work_bits=0.0,
    test_only=True,
)
NETWORKS = {"mainnet": MAINNET, "bitcoin-mainnet": MAINNET, "regtest": REGTEST, "bitcoin-regtest": REGTEST}


class HeaderError(ValueError):
    pass


@dataclass(frozen=True)
class BlockHeader:
    raw: bytes
    version: int
    prev_hash: bytes  # internal byte order
    merkle_root: bytes  # internal byte order, as serialized
    time: int
    bits: int
    nonce: int

    @property
    def hash(self) -> bytes:
        return sha256d(self.raw)

    @property
    def hash_hex(self) -> str:
        """The block hash as explorers and nodes display it."""
        return self.hash[::-1].hex()

    @property
    def time_iso(self) -> str:
        return _dt.datetime.fromtimestamp(self.time, _dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_header(raw: bytes) -> BlockHeader:
    if len(raw) != 80:
        raise HeaderError(f"a block header is 80 bytes, got {len(raw)}")
    version, = struct.unpack("<i", raw[0:4])
    time, bits, nonce = struct.unpack("<III", raw[68:80])
    return BlockHeader(raw, version, raw[4:36], raw[36:68], time, bits, nonce)


def bits_to_target(bits: int) -> int:
    """Decode nBits as Bitcoin Core's arith_uint256::SetCompact does."""
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    if word != 0 and bits & 0x00800000:
        raise HeaderError(f"nBits {bits:08x} encodes a negative target")
    if word != 0 and (size > 34 or (word > 0xFF and size > 33) or (word > 0xFFFF and size > 32)):
        raise HeaderError(f"nBits {bits:08x} overflows 256 bits")
    return target


def target_to_bits(target: int) -> int:
    """Encode a target as Bitcoin Core's arith_uint256::GetCompact does."""
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = target << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


def work_for_target(target: int) -> int:
    """Expected number of hashes to find a header meeting ``target``."""
    return (1 << 256) // (target + 1)


def work_bits(work: int) -> float:
    return math.log2(work) if work > 0 else 0.0


def check_pow(header: BlockHeader, network: Network) -> tuple[bool, str, int]:
    """Return (ok, reason, target)."""
    try:
        target = bits_to_target(header.bits)
    except HeaderError as exc:
        return False, str(exc), 0
    if target == 0:
        return False, f"nBits {header.bits:08x} encodes a zero target", 0
    if target > network.pow_limit:
        return False, f"nBits {header.bits:08x} is easier than {network.name} allows", target
    h = int.from_bytes(header.hash, "little")
    if h > target:
        return False, f"block hash {header.hash_hex} does not meet its own target (nBits {header.bits:08x})", target
    return True, f"block hash meets nBits {header.bits:08x}", target


def next_bits(network: Network, last_bits: int, first_time: int, last_time: int) -> int:
    """nBits required at a retarget height, from the period's first and last
    headers, as Bitcoin Core's CalculateNextWorkRequired computes it."""
    actual = last_time - first_time
    actual = max(TARGET_TIMESPAN // 4, min(TARGET_TIMESPAN * 4, actual))
    new = bits_to_target(last_bits) * actual // TARGET_TIMESPAN
    new = min(new, network.pow_limit)
    return target_to_bits(new)


@dataclass
class HeaderEvidence:
    """A header for one height, with what checked it and what it relies on."""

    height: int
    header: BlockHeader
    source: str
    checks: list[Check]
    relies_on: list[str]


class HeaderSource:
    name: str = "headers"

    def lookup(self, height: int) -> HeaderEvidence | None | str:
        """The evidence for ``height``; None when the source has no header there;
        a string giving the reason when the source has one but cannot vouch for it."""
        raise NotImplementedError


def _work_check(header: BlockHeader, height: int, target: int, min_work_bits: float, network: Network, cid: str) -> Check:
    bits = work_bits(work_for_target(target))
    data = {"height": height, "block_hash": header.hash_hex, "nbits": f"{header.bits:08x}", "expected_work_log2": round(bits, 2)}
    if bits + 1e-9 < min_work_bits:
        return Check(
            cid,
            Status.NOT_CHECKED,
            f"header at height {height} carries too little proof of work to rely on alone",
            reasons=[
                f"its target needs an expected 2^{bits:.1f} hashes; the floor is 2^{min_work_bits:g}",
                "a header this easy can be produced on ordinary hardware, so it shows nothing about Bitcoin's chain",
            ],
            data=data,
        )
    return Check(
        cid,
        Status.PASS,
        f"header at height {height} meets its own proof of work: an expected 2^{bits:.1f} hashes to produce",
        reasons=[f"block {header.hash_hex}, nBits {header.bits:08x}, header time {header.time_iso}"]
        + ([f"{network.name} is a test network: its proof of work is trivial and shows nothing about real time"] if network.test_only else []),
        data=data,
    )


class HeaderChain(HeaderSource):
    """A contiguous run of headers, validated by Bitcoin's header rules."""

    def __init__(self, raw: bytes, start_height: int = 0, network: Network = MAINNET, name: str = "headers file",
                 min_work_bits: float | None = None):
        if len(raw) % 80:
            raise HeaderError(f"{name}: length {len(raw)} is not a multiple of 80 bytes")
        if start_height < 0:
            raise HeaderError("start height is negative")
        self.name = name
        self.network = network
        self.start = start_height
        self.min_work_bits = network.default_min_work_bits if min_work_bits is None else min_work_bits
        self.headers = [parse_header(raw[i : i + 80]) for i in range(0, len(raw), 80)]
        self.problem: str | None = None
        self.valid_count = 0
        self.total_work = 0
        self._validate()

    @classmethod
    def from_file(cls, path: str | Path, start_height: int = 0, network: Network = MAINNET,
                  min_work_bits: float | None = None) -> "HeaderChain":
        p = Path(path)
        return cls(p.read_bytes(), start_height, network, name=str(p), min_work_bits=min_work_bits)

    @property
    def tip_height(self) -> int:
        return self.start + len(self.headers) - 1

    def _validate(self) -> None:
        hs, net = self.headers, self.network
        for i, h in enumerate(hs):
            height = self.start + i
            ok, reason, target = check_pow(h, net)
            if not ok:
                self.problem = f"height {height}: {reason}"
                return
            if i == 0:
                if height == 0 and net.genesis_hash is not None and h.hash != net.genesis_hash:
                    self.problem = f"height 0 is not {net.name}'s genesis block ({h.hash_hex})"
                    return
            else:
                prev = hs[i - 1]
                if h.prev_hash != prev.hash:
                    self.problem = f"height {height} does not link to height {height - 1}"
                    return
                if net.retarget:
                    if height % RETARGET_INTERVAL == 0:
                        j = i - RETARGET_INTERVAL
                        if j >= 0:
                            want = next_bits(net, prev.bits, hs[j].time, prev.time)
                            if h.bits != want:
                                self.problem = f"height {height}: nBits {h.bits:08x}, the retarget rule requires {want:08x}"
                                return
                    elif h.bits != prev.bits:
                        self.problem = f"height {height}: nBits changed from {prev.bits:08x} outside a retarget height"
                        return
                window = [x.time for x in hs[max(0, i - 11) : i]]
                if height - 11 >= self.start or self.start == 0:
                    mtp = sorted(window)[len(window) // 2]
                    if h.time <= mtp:
                        self.problem = f"height {height}: header time {h.time} is not after the median of the previous {len(window)} ({mtp})"
                        return
            self.valid_count = i + 1
            self.total_work += work_for_target(target)

    def lookup(self, height: int) -> HeaderEvidence | None | str:
        i = height - self.start
        if i < 0 or i >= len(self.headers):
            return None
        if i >= self.valid_count:
            return f"{self.name} breaks Bitcoin's header rules before height {height} ({self.problem})"
        h = self.headers[i]
        tip = self.headers[self.valid_count - 1]
        tip_height = self.start + self.valid_count - 1
        rules = "linkage and proof of work" + (", difficulty retargets and median time past" if self.network.retarget else "")
        reasons = [
            f"block {h.hash_hex}, header time {h.time_iso}",
            f"{tip_height - height} further headers build on it in the file, up to height {tip_height} ({tip.hash_hex})",
            f"total work in the file from height {self.start}: 2^{work_bits(self.total_work):.1f} expected hashes",
        ]
        checks = [
            Check(
                "bitcoin.header_chain",
                Status.PASS,
                f"header at height {height} is in a header chain that follows Bitcoin's header rules ({rules})",
                reasons=reasons,
                data={"height": height, "block_hash": h.hash_hex, "tip_height": tip_height, "tip_hash": tip.hash_hex,
                      "confirmations": tip_height - height + 1, "source": self.name},
            )
        ]
        if self.network.test_only:
            relies = [f"{self.name} is the {self.network.name} chain the proof was made on (a test network: it proves nothing about real time)"]
        else:
            relies = [
                f"{self.name} is on Bitcoin's most-work chain: the verifier cannot know whether a heavier chain exists; "
                f"compare block {tip.hash_hex} at height {tip_height} with any independent source"
            ]
        if self.start == 0:
            if self.network.genesis_hash is not None:
                checks[0].reasons.append(f"the file starts at {self.network.name}'s genesis block, checked against the built-in constant")
        else:
            relies.append(f"headers before height {self.start} were not in {self.name} and were not checked")
            ok, _, target = check_pow(h, self.network)
            checks.append(_work_check(h, height, target, self.min_work_bits, self.network, "bitcoin.header_work"))
        if self.network.test_only:
            checks[0].reasons.append(f"{self.network.name} is a test network: its proof of work shows nothing about real time")
        return HeaderEvidence(height, h, self.name, checks, relies)


class HeaderSet(HeaderSource):
    """Headers at chosen heights, each checked alone."""

    def __init__(self, headers: dict[int, bytes], network: Network = MAINNET, name: str = "sparse headers file",
                 min_work_bits: float | None = None):
        self.name = name
        self.network = network
        self.min_work_bits = network.default_min_work_bits if min_work_bits is None else min_work_bits
        self.headers = {h: parse_header(raw) for h, raw in headers.items()}

    @classmethod
    def parse(cls, text: str, network: Network = MAINNET, name: str = "sparse headers file",
              min_work_bits: float | None = None) -> "HeaderSet":
        """Either JSON (``{"headers": [{"height": H, "hex": "..."}]}`` or
        ``{"H": "hex"}``) or text lines ``HEIGHT HEX`` with ``#`` comments."""
        stripped = text.strip()
        entries: dict[int, bytes] = {}
        if stripped.startswith("{"):
            doc = json.loads(stripped)
            if "network" in doc and NETWORKS.get(doc["network"]) not in (None, network):
                raise HeaderError(f"{name} is for {doc['network']}, not {network.name}")
            items = doc.get("headers", doc)
            if isinstance(items, dict):
                pairs = [(int(k), v) for k, v in items.items() if k != "network"]
            else:
                pairs = [(int(e["height"]), e["hex"]) for e in items]
            for height, hexs in pairs:
                entries[height] = bytes.fromhex(hexs)
        else:
            for n, line in enumerate(text.splitlines(), 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    raise HeaderError(f"{name} line {n}: expected 'HEIGHT HEX'")
                entries[int(parts[0])] = bytes.fromhex(parts[1])
        return cls(entries, network, name, min_work_bits)

    @classmethod
    def from_file(cls, path: str | Path, network: Network = MAINNET, min_work_bits: float | None = None) -> "HeaderSet":
        p = Path(path)
        return cls.parse(p.read_text(encoding="utf-8"), network, str(p), min_work_bits)

    def lookup(self, height: int) -> HeaderEvidence | None | str:
        h = self.headers.get(height)
        if h is None:
            return None
        ok, reason, target = check_pow(h, self.network)
        if not ok:
            return f"{self.name}, height {height}: {reason}"
        checks = [_work_check(h, height, target, self.min_work_bits, self.network, "bitcoin.header_work")]
        linked = []
        below, above = self.headers.get(height - 1), self.headers.get(height + 1)
        if below is not None:
            if h.prev_hash != below.hash:
                return f"{self.name}: height {height} does not link to height {height - 1} in the same file"
            linked.append(f"links to height {height - 1}")
        if above is not None:
            if above.prev_hash != h.hash:
                return f"{self.name}: height {height + 1} does not link to height {height} in the same file"
            linked.append(f"height {height + 1} links to it")
        if linked:
            checks[0].reasons.append("in the same file, " + " and ".join(linked))
        if self.network.test_only:
            relies = [f"the header at height {height} in {self.name} is the {self.network.name} block the proof was made on "
                      "(a test network: it proves nothing about real time)"]
        else:
            relies = [
                f"the header at height {height} in {self.name} is the block at that height on Bitcoin's most-work chain: "
                f"its proof of work was checked, its place in the chain was not; compare block {h.hash_hex} with any independent source"
            ]
        return HeaderEvidence(height, h, self.name, checks, relies)


Fetch = Callable[[str], bytes]


def _urlopen_fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "fm-verify"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read(1 << 16)


class EsploraSource(HeaderSource):
    """A public explorer speaking the Esplora HTTP API (mempool.space,
    blockstream.info, or a self-hosted instance). Used only when a caller
    passes its URL; nothing is sent but the height and block hash asked for."""

    def __init__(self, base_url: str, network: Network = MAINNET, fetch: Fetch | None = None,
                 clock: Callable[[], str] | None = None, min_work_bits: float | None = None):
        self.base = base_url.rstrip("/")
        self.name = f"explorer {self.base}"
        self.network = network
        self.fetch = fetch or _urlopen_fetch
        self.min_work_bits = network.default_min_work_bits if min_work_bits is None else min_work_bits
        from .verdict import now_utc

        self.clock = clock or now_utc

    def lookup(self, height: int) -> HeaderEvidence | None | str:
        try:
            block_hash = self.fetch(f"{self.base}/block-height/{height}").decode("ascii").strip()
            if len(block_hash) != 64 or any(c not in "0123456789abcdef" for c in block_hash):
                return f"{self.name} answered height {height} with something that is not a block hash"
            raw = bytes.fromhex(self.fetch(f"{self.base}/block/{block_hash}/header").decode("ascii").strip())
        except Exception as exc:  # network errors of every kind end up as a stated reason
            return f"{self.name} could not be read for height {height}: {type(exc).__name__}: {exc}"
        fetched = self.clock()
        try:
            h = parse_header(raw)
        except HeaderError as exc:
            return f"{self.name}: {exc}"
        if h.hash_hex != block_hash:
            return f"{self.name} returned a header that hashes to {h.hash_hex}, not the block {block_hash} it named"
        ok, reason, target = check_pow(h, self.network)
        if not ok:
            return f"{self.name}, height {height}: {reason}"
        checks = [_work_check(h, height, target, self.min_work_bits, self.network, "bitcoin.header_work")]
        checks[0].reasons.append(f"fetched from {self.base} at {fetched}")
        relies = [
            f"{self.base} (a public explorer, read at {fetched}) truthfully reported block {block_hash} at height {height} "
            "on Bitcoin's most-work chain"
        ]
        return HeaderEvidence(height, h, self.name, checks, relies)


class BitcoinCoreSource(HeaderSource):
    """A Bitcoin Core node the reader runs, over JSON-RPC (getblockhash, then
    getblockheader in hex). Used only when a caller passes its URL. Credentials
    come from the node's cookie file or from the caller, are sent only to that
    URL, and are never printed."""

    def __init__(self, url: str, auth: tuple[str, str] | None = None, network: Network = MAINNET,
                 post: Callable[[str, bytes, dict], bytes] | None = None, clock: Callable[[], str] | None = None):
        from .verdict import now_utc

        self.url = url
        self.name = f"Bitcoin Core node at {url}"
        self.network = network
        self.auth = auth
        self.post = post or self._post
        self.clock = clock or now_utc
        self._id = 0

    @staticmethod
    def _post(url: str, body: bytes, headers: dict) -> bytes:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read(1 << 16)

    def _call(self, method: str, params: list):
        import base64

        self._id += 1
        headers = {"Content-Type": "application/json", "User-Agent": "fm-verify"}
        if self.auth:
            headers["Authorization"] = "Basic " + base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode()
        reply = json.loads(self.post(self.url, json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method, "params": params}).encode(), headers))
        if reply.get("error"):
            raise HeaderError(f"{method}: {reply['error'].get('message', reply['error'])}")
        return reply["result"]

    def lookup(self, height: int) -> HeaderEvidence | None | str:
        try:
            block_hash = self._call("getblockhash", [height])
            raw = bytes.fromhex(self._call("getblockheader", [block_hash, False]))
        except Exception as exc:  # every failure is a stated reason; the exception text carries no credential
            return f"{self.name} could not be read for height {height}: {type(exc).__name__}"
        try:
            h = parse_header(raw)
        except HeaderError as exc:
            return f"{self.name}: {exc}"
        if h.hash_hex != block_hash:
            return f"{self.name} returned a header that hashes to {h.hash_hex}, not {block_hash}"
        ok, reason, target = check_pow(h, self.network)
        if not ok:
            return f"{self.name}, height {height}: {reason}"
        when = self.clock()
        check = Check("bitcoin.header_node", Status.PASS,
                      f"your node reports block {block_hash} at height {height}, and its header meets its proof of work",
                      reasons=[f"asked at {when}", f"header time {h.time_iso}"],
                      data={"height": height, "block_hash": block_hash})
        relies = [f"the Bitcoin Core node at {self.url}, asked at {when}, follows Bitcoin's most-work chain (a node you run validates every block)"]
        return HeaderEvidence(height, h, self.name, [check], relies)


def read_cookie(path: str | Path) -> tuple[str, str]:
    """Bitcoin Core's .cookie file: user:password on one line."""
    user, _, password = Path(path).read_text(encoding="utf-8").strip().partition(":")
    if not password:
        raise HeaderError("the cookie file does not hold user:password")
    return user, password


def lookup_header(sources: Iterable[HeaderSource], height: int) -> tuple[HeaderEvidence | None, list[Check]]:
    """Ask every source for ``height``. Sources that disagree about the header
    make a failing check; the first source's evidence is returned otherwise."""
    found: list[HeaderEvidence] = []
    notes: list[Check] = []
    for src in sources:
        ev = src.lookup(height)
        if ev is None:
            continue
        if isinstance(ev, str):
            notes.append(Check("bitcoin.header_source", Status.NOT_CHECKED, f"{src.name} cannot vouch for height {height}", reasons=[ev]))
            continue
        found.append(ev)
    if found:
        for note in notes:
            note.status, note.required = Status.WARN, False
            note.summary += "; another source did"
    if len(found) > 1:
        first = found[0]
        for other in found[1:]:
            if other.header.raw != first.header.raw:
                notes.append(
                    Check(
                        "bitcoin.header_agreement",
                        Status.FAIL,
                        f"header sources disagree about height {height}",
                        reasons=[f"{first.source}: {first.header.hash_hex}", f"{other.source}: {other.header.hash_hex}"],
                    )
                )
                return None, notes
        notes.append(
            Check(
                "bitcoin.header_agreement",
                Status.PASS,
                f"{len(found)} header sources agree on block {first.header.hash_hex} at height {height}",
                reasons=[e.source for e in found],
                required=False,
            )
        )
    return (found[0] if found else None), notes
