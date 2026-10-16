"""Command line: ``fm-verify <kind> ...``.

Exit status: 0 valid, 1 invalid, 2 indeterminate, 64 usage error, 70 a fault
in the verifier itself (never a verdict). Output is
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
from .verdict import EXIT_INTERNAL, EXIT_USAGE, Verdict


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
    if getattr(args, "bitcoind", None):
        import os

        from .bitcoin import BitcoinCoreSource, read_cookie

        auth = None
        try:
            if args.bitcoind_cookie:
                auth = read_cookie(args.bitcoind_cookie)
            elif os.environ.get("FM_BITCOIND_USER") and os.environ.get("FM_BITCOIND_PASSWORD"):
                auth = (os.environ["FM_BITCOIND_USER"], os.environ["FM_BITCOIND_PASSWORD"])
        except (OSError, HeaderError) as exc:
            raise UsageError(f"--bitcoind-cookie: {exc}") from exc
        sources.append(BitcoinCoreSource(args.bitcoind, auth, network))
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


def _crls(paths: list[str] | None) -> list:
    from . import pki

    out = []
    for path in paths or []:
        try:
            out += pki.load_crls(_read(path))
        except ValueError as exc:
            raise UsageError(f"--crl {path}: not a PEM or DER CRL ({exc})") from exc
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
        crls=_crls(args.crl),
    )


def cmd_anchors(args: argparse.Namespace) -> Verdict:
    from . import anchors, ledger_anchors

    if args.all or ledger_anchors.is_layout(args.batch):
        repos = {}
        for spec in args.repo or []:
            name, sep, path = spec.partition("=")
            if not sep or not name or not path:
                raise UsageError(f"--repo {spec!r}: expected OWNER/NAME=PATH or OWNER/NAME@TAG=PATH")
            repos[name] = path
        run = ledger_anchors.verify_all if args.all else ledger_anchors.verify_dir
        return run(args.batch, repos=repos, header_sources=header_sources(args),
                   network=NETWORKS[args.network], roots=_certs(args.roots, "--roots"),
                   extra_certs=_certs(args.chain, "--chain"), crls=_crls(args.crl))

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
        crls=_crls(args.crl),
    )


def cmd_certificate(args: argparse.Namespace) -> Verdict:
    from . import certificate

    events = _events(args.events) if args.events else None
    return certificate.verify(
        _read(args.certificate),
        events=events,
        exported_file=_read(args.file) if args.file else None,
        header_sources=header_sources(args),
        network=NETWORKS[args.network],
        roots=_certs(args.roots, "--roots"),
        extra_certs=_certs(args.chain, "--chain"),
        crls=_crls(args.crl),
    )


def _events(path: str) -> list:
    try:
        doc = json.loads(_read(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"{path} is not JSON: {exc}") from exc
    events = doc.get("events") if isinstance(doc, dict) else doc
    if not isinstance(events, list):
        raise UsageError(f"{path} must hold a JSON array of events, or an object with 'events'")
    return events


def cmd_chain(args: argparse.Namespace) -> Verdict:
    from . import ledger_events, ledger_text

    events = _events(args.events)
    if args.disclosure:
        try:
            disclosure = json.loads(_read(args.disclosure).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UsageError(f"--disclosure {args.disclosure} is not JSON: {exc}") from exc
        if not isinstance(disclosure, dict) or "doc_key_hex" not in disclosure:
            raise UsageError("--disclosure must hold doc_key_hex and steps")
        return ledger_text.verify(events, disclosure)
    return ledger_events.verify(events)


def cmd_roots(args: argparse.Namespace) -> Verdict:
    from . import ledger_roots
    from .base58 import EncodingError, did_key_ed25519

    try:
        doc = json.loads(_read(args.records).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageError(f"{args.records} is not JSON: {exc}") from exc
    records = doc.get("records") if isinstance(doc, dict) else doc
    if not isinstance(records, list):
        raise UsageError(f"{args.records} must hold a JSON array of records, or an object with 'records'")
    key = None
    if args.key:
        try:
            key = did_key_ed25519(args.key) if args.key.startswith("did:key:") else bytes.fromhex(args.key)
        except (EncodingError, ValueError) as exc:
            raise UsageError(f"--key: {exc}") from exc
        if len(key) != 32:
            raise UsageError("--key is not a 32-byte Ed25519 key")
    return ledger_roots.verify(records, public_key=key)


def _header_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--headers", action="append", metavar="FILE",
                   help="sparse headers: lines 'HEIGHT HEX' or JSON; each header is checked alone (repeatable)")
    p.add_argument("--headers-chain", action="append", metavar="FILE[@START]",
                   help="contiguous 80-byte headers from height START (default 0), checked by Bitcoin's header rules (repeatable)")
    p.add_argument("--explorer", action="append", metavar="URL",
                   help="an Esplora API base URL, e.g. https://mempool.space/api; the verdict states that its answer was trusted (repeatable)")
    p.add_argument("--bitcoind", metavar="URL",
                   help="a Bitcoin Core node you run, e.g. http://127.0.0.1:8332; credentials from --bitcoind-cookie or "
                        "FM_BITCOIND_USER and FM_BITCOIND_PASSWORD, never printed")
    p.add_argument("--bitcoind-cookie", metavar="FILE", help="the node's .cookie file")
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


def cmd_conformance(args: argparse.Namespace) -> int:
    from . import conformance

    fixtures = Path(args.fixtures)
    if not fixtures.is_dir():
        raise UsageError(f"{fixtures} is not a directory")
    manifest, results = conformance.run_suite(fixtures)
    if args.json:
        print(json.dumps({"manifest_problems": manifest,
                          "cases": [r.__dict__ for r in results],
                          "conforms": not manifest and all(r.ok for r in results)}, indent=2))
    else:
        print(conformance.report(manifest, results))
    return 0 if not manifest and results and all(r.ok for r in results) else 1


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
    o.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
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
    r.add_argument("--crl", action="append", metavar="FILE", help="certificate revocation lists you hold, PEM or DER (repeatable)")
    r.add_argument("--json", action="store_true")
    r.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
    r.set_defaults(func=cmd_rfc3161)

    a = sub.add_parser("anchors", help="an anchor: listed files, their Merkle root, and the proofs over the root")
    a.add_argument("batch", help="an anchor directory in the Provenance Ledger's layout (manifest.json, root.preimage and its proofs), "
                                 "or a batch directory in this verifier's own format (batch.json)")
    a.add_argument("--all", action="store_true",
                   help="verify every anchor directory (with root.preimage) under the path given, and summarise")
    a.add_argument("--repo", action="append", metavar="OWNER/NAME[@TAG]=PATH",
                   help=("Ledger layout: a checkout of a repository the descriptors name, to compare (repeatable); "
                         "with @TAG, a checkout of that tag, for the release manifests anchored at it"))
    a.add_argument("--repo-root", help="a checkout to compare every listed file with")
    a.add_argument("--file", action="append", help="a file you hold, named by its listed path (repeatable); a mismatch is a failure")
    a.add_argument("--strict-files", action="store_true", help="with --repo-root, treat any changed file as a failure")
    a.add_argument("--emit-proof", metavar="PATH", help="print the RFC 9162 inclusion proof for one listed path, and stop")
    _header_options(a)
    a.add_argument("--roots", action="append", metavar="PEM", help="certificates you trust as time-stamping roots (repeatable)")
    a.add_argument("--chain", action="append", metavar="PEM", help="intermediate or signer certificates not in the tokens (repeatable)")
    a.add_argument("--crl", action="append", metavar="FILE", help="certificate revocation lists you hold, PEM or DER (repeatable)")
    a.add_argument("--json", action="store_true")
    a.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
    a.set_defaults(func=cmd_anchors)

    ce = sub.add_parser("certificate", help="a Provenance Ledger certificate (ledger-certificate/v0), JSON or PDF")
    ce.add_argument("certificate", help="the certificate: its JSON, or the PDF that carries it as certificate.json")
    ce.add_argument("--file", help="the exported document the certificate covers")
    ce.add_argument("--events", help="the document's event chain (ledger-event/v0 events, a JSON array or {\"events\": [...]}), for step 7")
    _header_options(ce)
    ce.add_argument("--roots", action="append", metavar="PEM", help="certificates you trust as time-stamping roots (repeatable)")
    ce.add_argument("--chain", action="append", metavar="PEM", help="intermediate or signer certificates not in the tokens (repeatable)")
    ce.add_argument("--crl", action="append", metavar="FILE", help="certificate revocation lists you hold, PEM or DER (repeatable)")
    ce.add_argument("--json", action="store_true")
    ce.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
    ce.set_defaults(func=cmd_certificate)

    ch = sub.add_parser("chain", help="a Provenance Ledger event chain (ledger-event/v0)")
    ch.add_argument("events", help="the events, a JSON array or {\"events\": [...]}")
    ch.add_argument("--disclosure", metavar="FILE",
                    help="the document key and inserted texts ({\"doc_key_hex\", \"steps\": [{\"seq\", \"content_text\"}]}): "
                         "replays the chain and checks every keyed hash; the text is never printed")
    ch.add_argument("--json", action="store_true")
    ch.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
    ch.set_defaults(func=cmd_chain)

    ro = sub.add_parser("roots", help="a tenant's hourly root records (ledger-root/v0) as a chain")
    ro.add_argument("records", help="the records, a JSON array or {\"records\": [...]}, oldest first")
    ro.add_argument("--key", help="the tenant's key: its did:key, or the raw public key in hex")
    ro.add_argument("--json", action="store_true")
    ro.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
    ro.set_defaults(func=cmd_roots)

    c = sub.add_parser("conformance", help="run every published fixture case and compare the verdicts with the expected ones")
    c.add_argument("fixtures", nargs="?", default="fixtures", help="the fixtures directory (default ./fixtures)")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_conformance)

    m = sub.add_parser("merkle", help="a Merkle inclusion proof (RFC 9162 or explicit path)")
    m.add_argument("proof", help="the proof, as JSON")
    leaf = m.add_mutually_exclusive_group()
    leaf.add_argument("--leaf-file", help="file whose bytes are the leaf data")
    leaf.add_argument("--leaf-hex", help="the leaf data in hex")
    m.add_argument("--root", help="the root (hex) held from the anchored record; the proof's root must equal it")
    m.add_argument("--json", action="store_true")
    m.add_argument("--html", metavar="PATH", help="also write the verdict as a self-contained HTML page")
    m.set_defaults(func=cmd_merkle)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    import warnings

    # Trust bundles shipped by operating systems hold a few certificates the
    # cryptography library warns about (a non-positive serial); the warning
    # says nothing about the input being verified.
    warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")
    args = build_parser().parse_args(argv)
    try:
        verdict = args.func(args)
    except UsageError as exc:
        print(f"fm-verify: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # a fault in the verifier: reported as such, never as an outcome
        import traceback

        traceback.print_exc(file=sys.stderr)
        print(f"fm-verify: internal error ({type(exc).__name__}): this is a fault in the verifier, not a verdict; "
              "please report it with the inputs", file=sys.stderr)
        return EXIT_INTERNAL
    if isinstance(verdict, int):
        return verdict
    if getattr(args, "html", None):
        from . import report

        cert = None
        if args.kind == "certificate":
            from . import pdf

            try:
                raw = _read(args.certificate)
                cert = json.loads((pdf.extract(raw) if raw.startswith(b"%PDF-") else raw).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, pdf.PdfError):
                cert = None
        title = "Provenance Ledger certificate: verification report" if args.kind == "certificate" else None
        try:
            Path(args.html).write_text(report.render(verdict, cert if isinstance(cert, dict) else None, title), encoding="utf-8")
        except OSError as exc:
            print(f"fm-verify: cannot write {args.html}: {exc.strerror}", file=sys.stderr)
            return EXIT_USAGE
    print(verdict.to_json() if args.json else verdict.to_text())
    return verdict.exit_code


if __name__ == "__main__":
    sys.exit(main())
