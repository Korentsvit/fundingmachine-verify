"""Command line: ``fm-verify <kind> ...``.

Exit status: 0 valid, 1 invalid, 2 indeterminate, 64 usage error. Output is
the verdict as text, or as JSON with ``--json``. Nothing is fetched from the
network unless ``--explorer`` is given.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__, merkle, ots
from .bitcoin import NETWORKS, EsploraSource, HeaderChain, HeaderError, HeaderSet, HeaderSource
from .verdict import EXIT_USAGE, Verdict


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse exits 2, which is "indeterminate" here
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _read(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror}") from exc


def _hex32(value: str, what: str) -> bytes:
    try:
        b = bytes.fromhex(value)
    except ValueError as exc:
        raise UsageError(f"{what} is not hex") from exc
    if len(b) != 32:
        raise UsageError(f"{what} is {len(b)} bytes, not 32")
    return b


def header_sources(args: argparse.Namespace) -> list[HeaderSource]:
    network = NETWORKS[args.network]
    sources: list[HeaderSource] = []
    try:
        for spec in args.headers_chain or []:
            path, _, start = spec.partition("@")
            sources.append(HeaderChain(_read(path), int(start or 0), network, name=path, min_work_bits=args.min_work_bits))
        for path in args.headers or []:
            sources.append(HeaderSet.parse(_read(path).decode("utf-8"), network, name=path, min_work_bits=args.min_work_bits))
    except (HeaderError, ValueError) as exc:
        raise UsageError(f"headers: {exc}") from exc
    for url in args.explorer or []:
        sources.append(EsploraSource(url, network, min_work_bits=args.min_work_bits))
    return sources


def cmd_ots(args: argparse.Namespace) -> Verdict:
    file_bytes = _read(args.file) if args.file else None
    digest = _hex32(args.digest, "--digest") if args.digest else None
    return ots.verify(
        _read(args.proof),
        header_sources(args),
        file_bytes=file_bytes,
        digest=digest,
        network=NETWORKS[args.network],
        subject=args.file,
    )


def cmd_merkle(args: argparse.Namespace) -> Verdict:
    try:
        proof = json.loads(_read(args.proof).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"{args.proof} is not JSON: {exc}") from exc
    if args.leaf_file:
        leaf = _read(args.leaf_file)
    elif args.leaf_hex is not None:
        try:
            leaf = bytes.fromhex(args.leaf_hex)
        except ValueError as exc:
            raise UsageError("--leaf-hex is not hex") from exc
    elif "leaf" in proof:
        leaf = bytes.fromhex(proof["leaf"])
    else:
        raise UsageError("give the leaf with --leaf-file or --leaf-hex, or as 'leaf' in the proof")
    root = _hex32(args.root, "--root") if args.root else None
    return merkle.verify_inclusion(leaf, proof, expected_root=root, subject=args.leaf_file)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="fm-verify", description="Check FundingMachine anchors and certificates without trusting FundingMachine.")
    p.add_argument("--version", action="version", version=f"fm-verify {__version__}")
    sub = p.add_subparsers(dest="kind", required=True, parser_class=_Parser)

    o = sub.add_parser("ots", help="an OpenTimestamps proof against Bitcoin block headers")
    o.add_argument("proof", help="the .ots file")
    who = o.add_mutually_exclusive_group()
    who.add_argument("--file", help="the file the proof should cover")
    who.add_argument("--digest", help="the digest (hex) the proof should cover, if the file is not at hand")
    o.add_argument("--headers", action="append", metavar="FILE",
                   help="sparse headers: lines 'HEIGHT HEX' or JSON; each header is checked alone (repeatable)")
    o.add_argument("--headers-chain", action="append", metavar="FILE[@START]",
                   help="contiguous 80-byte headers from height START (default 0), checked by Bitcoin's header rules (repeatable)")
    o.add_argument("--explorer", action="append", metavar="URL",
                   help="an Esplora API base URL, e.g. https://mempool.space/api; the verdict states that its answer was trusted (repeatable)")
    o.add_argument("--network", choices=sorted(NETWORKS), default="mainnet")
    o.add_argument("--min-work-bits", type=float, default=None,
                   help="least proof of work (log2 of expected hashes) a header checked alone must carry; default 70 on mainnet")
    o.add_argument("--json", action="store_true")
    o.set_defaults(func=cmd_ots)

    m = sub.add_parser("merkle", help="a Merkle inclusion proof (RFC 9162 or explicit path)")
    m.add_argument("proof", help="the proof, as JSON")
    leaf = m.add_mutually_exclusive_group()
    leaf.add_argument("--leaf-file", help="file whose bytes are the leaf data")
    leaf.add_argument("--leaf-hex", help="the leaf data in hex")
    m.add_argument("--root", help="the root (hex) held from the anchored record; the proof's root must equal it")
    m.add_argument("--json", action="store_true")
    m.set_defaults(func=cmd_merkle)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        verdict = args.func(args)
    except UsageError as exc:
        print(f"fm-verify: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(verdict.to_json() if args.json else verdict.to_text())
    return verdict.exit_code


if __name__ == "__main__":
    sys.exit(main())
