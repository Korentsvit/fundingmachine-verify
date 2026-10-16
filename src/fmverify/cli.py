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


def _certs(paths: list[str] | None, what: str) -> list:
    from . import pki

    out = []
    for path in paths or []:
        try:
            out += pki.load_certificates(_read(path))
        except ValueError as exc:
            raise UsageError(f"{what} {path}: not a PEM or DER certificate ({exc})") from exc
    return out


def cmd_rfc3161(args: argparse.Namespace) -> Verdict:
    from . import rfc3161

    if args.digest and args.digest_alg not in rfc3161.HASH_BY_NAME:
        raise UsageError(f"--digest-alg must be one of {', '.join(sorted(rfc3161.HASH_BY_NAME))}")
    digest = None
    if args.digest:
        try:
            digest = bytes.fromhex(args.digest)
        except ValueError as exc:
            raise UsageError("--digest is not hex") from exc
    return rfc3161.verify(
        _read(args.token),
        file_bytes=_read(args.file) if args.file else None,
        digest=digest,
        digest_alg=args.digest_alg,
        roots=_certs(args.roots, "--roots"),
        extra_certs=_certs(args.chain, "--chain"),
        subject=args.file,
    )


def cmd_anchors(args: argparse.Namespace) -> Verdict:
    from . import anchors

    if args.emit_proof:
        try:
            proof = anchors.inclusion_proof(anchors.load_batch(args.batch), args.emit_proof)
        except anchors.BatchError as exc:
            raise UsageError(str(exc)) from exc
        print(json.dumps(proof, indent=2))
        raise SystemExit(0)
    return anchors.verify_batch(
        args.batch,
        repo_root=args.repo_root,
        files=args.file or [],
        header_sources=header_sources(args),
        network=NETWORKS[args.network],
        roots=_certs(args.roots, "--roots"),
        extra_certs=_certs(args.chain, "--chain"),
        strict_files=args.strict_files,
    )


def _header_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--headers", action="append", metavar="FILE",
                   help="sparse headers: lines 'HEIGHT HEX' or JSON; each header is checked alone (repeatable)")
    p.add_argument("--headers-chain", action="append", metavar="FILE[@START]",
                   help="contiguous 80-byte headers from height START (default 0), checked by Bitcoin's header rules (repeatable)")
    p.add_argument("--explorer", action="append", metavar="URL",
                   help="an Esplora API base URL, e.g. https://mempool.space/api; the verdict states that its answer was trusted (repeatable)")
    p.add_argument("--network", choices=sorted(NETWORKS), default="mainnet")
    p.add_argument("--min-work-bits", type=float, default=None,
                   help="least proof of work (log2 of expected hashes) a header checked alone must carry; default 70 on mainnet")


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
    _header_options(o)
    o.add_argument("--json", action="store_true")
    o.set_defaults(func=cmd_ots)

    r = sub.add_parser("rfc3161", help="an RFC 3161 time-stamp token against the authority's certificate chain")
    r.add_argument("token", help="the .tsr response or bare token (DER)")
    who = r.add_mutually_exclusive_group()
    who.add_argument("--file", help="the file the token should cover")
    who.add_argument("--digest", help="the digest (hex) the token should cover, if the file is not at hand")
    r.add_argument("--digest-alg", default="sha256", help="the hash --digest was made with (default sha256)")
    r.add_argument("--roots", action="append", metavar="PEM",
                   help="certificates you trust as the authority's root (repeatable); none are built in")
    r.add_argument("--chain", action="append", metavar="PEM", help="intermediate or signer certificates not in the token (repeatable)")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_rfc3161)

    a = sub.add_parser("anchors", help="an anchor batch: listed files, Merkle root, and the anchors over the root")
    a.add_argument("batch", help="the batch directory (batch.json, .ots and .tsr files)")
    a.add_argument("--repo-root", help="a checkout to compare every listed file with")
    a.add_argument("--file", action="append", help="a file you hold, named by its listed path (repeatable); a mismatch is a failure")
    a.add_argument("--strict-files", action="store_true", help="with --repo-root, treat any changed file as a failure")
    a.add_argument("--emit-proof", metavar="PATH", help="print the RFC 9162 inclusion proof for one listed path, and stop")
    _header_options(a)
    a.add_argument("--roots", action="append", metavar="PEM", help="certificates you trust as time-stamping roots (repeatable)")
    a.add_argument("--chain", action="append", metavar="PEM", help="intermediate or signer certificates not in the tokens (repeatable)")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_anchors)

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
