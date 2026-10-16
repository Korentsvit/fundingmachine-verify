"""Capture real DigiCert and Sectigo RFC 3161 tokens from public packages.

NuGet package signatures (`.signature.p7s`, CMS) carry RFC 3161 tokens as
unsigned attributes: on the author's or repository's signature, and on
nuget.org's countersignature. Each token stamps the SHA-256 of the signature
value it is attached to (RFC 3161, appendix A). These are tokens from the
same public authorities the Provenance Ledger uses (`docs/ANCHORING.md`:
DigiCert and Sectigo), issued in the ordinary course, so the verifier meets
them before FundingMachine's own.

Nothing here is committed: the packages are third-party material. Run by
hand into a directory of your choice, then point the test at it:

    python tools/fetch_public_tokens.py DIR
    FM_PUBLIC_TOKENS=DIR python -m pytest tests/test_public_tokens.py

Each package is checked against the SHA-256 pinned below before anything is
read from it. For each token, DIR gets NAME.tsr (the token) and
NAME.tsr.stamped (the bytes whose SHA-256 it stamps).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fmverify import der  # noqa: E402

FLAT = "https://api.nuget.org/v3-flatcontainer"
TST = "1.2.840.113549.1.9.16.2.14"  # id-aa-timeStampToken
COUNTER = "1.2.840.113549.1.9.6"  # counterSignature

# Package id, version, SHA-256 of the .nupkg (read 16 October 2026).
PACKAGES = [
    ("newtonsoft.json", "13.0.3", "872fc189e638ab1056555b03aaa38f68bcb54286e221aa646eb1129babf63c77"),
    ("serilog", "4.0.0", "8fc850e5374bd538df7468813bd3f21c914c30fbc04c758dd5db6bad465994dc"),
    ("castle.core", "5.2.1", "b8d7bffcf0a76062e1c714292c3c9342ea081f9bbb7460e5ca3736c2a010e03e"),
    ("npgsql", "10.0.3", "75d0970923a8c9fcbbd37e4ebe72fee0b10362a1e36723e86777df1b6728316d"),
    ("dapper", "2.1.89", "34994ad91839374f8a1f798a4c79e016cca51ea25de3672c6b91ed11766323ef"),
    ("nodatime", "3.3.5", "0af36adafec8fc7dabaf0c56d5c0ef68364571de91957bbee9aa9be4d5ff93f2"),
    ("bouncycastle.cryptography", "2.7.0", "f091ffccab4d03993e660bace277659a79dee0972f54d7f1f4bd46d680966241"),
    ("polly", "8.8.0", "655ef1a31e275138cc2e81c3585250b86b3aa5f7c386c79f9301e4986499c2be"),
]


def _tokens(signer_info: der.Node, label: str, out: list[tuple[str, bytes, bytes]]) -> None:
    kids = signer_info.children()
    signature = der.octet_string(next(k for k in kids if k.is_universal(4)))
    for unsigned in (k for k in kids if k.is_context(1)):
        for attr in unsigned.children():
            oid_node, values = attr.children()
            oid = der.oid(oid_node)
            for value in values.children():
                if oid == TST:
                    out.append((label, value.raw, signature))
                elif oid == COUNTER:
                    _tokens(value, label + "-countersignature", out)


def tokens(p7s: bytes) -> list[tuple[str, bytes, bytes]]:
    """(label, token, stamped bytes) for every token in a package signature."""
    signed_data = der.parse(p7s).children()[1].children()[0]
    out: list[tuple[str, bytes, bytes]] = []
    for i, signer_info in enumerate(signed_data.children()[-1].children()):
        _tokens(signer_info, f"signer{i}", out)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", type=Path)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    for pid, version, pin in PACKAGES:
        with urllib.request.urlopen(f"{FLAT}/{pid}/{version}/{pid}.{version}.nupkg", timeout=60) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != pin:
            print(f"{pid} {version}: not the pinned package; skipped", file=sys.stderr)
            continue
        p7s = zipfile.ZipFile(io.BytesIO(data)).read(".signature.p7s")
        for label, token, stamped in tokens(p7s):
            name = f"{pid}.{version}.{label}.tsr"
            (args.out / name).write_bytes(token)
            (args.out / (name + ".stamped")).write_bytes(stamped)
            print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
