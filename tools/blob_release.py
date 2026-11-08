"""Assemble a published release of fm-verify for the public release location, and check what the location serves.

    python tools/blob_release.py assemble --release DIR --tag vX.Y.Z --commit SHA --gate RECORD --licence LICENSE --out OUT
    python tools/blob_release.py check --base URL --dir OUT

The public release location is the Vercel Blob store `capital-graph-public`, one prefix per release (Filipp, 8 November
2026): this repository's releases go under `verify-vX.Y.Z/`. `assemble` takes the files of the GitHub release DIR
(downloaded by the release workflow) and writes OUT, the prefix's whole content:

* every file the release's own SHA256SUMS lists, each checked against it first: a missing, extra or changed file
  stops the run;
* LICENSE, the licence notice, as the tagged commit holds it;
* ATTRIBUTION.txt, the attribution lines: this package's source and licence, and the third-party material the
  release carries with its own copyright and licence, as the material's own notice states it;
* manifest.json: the release, its tag and commit, both gate keys as recorded, and each file above with its SHA-256
  and size;
* SHA256SUMS of every file in OUT but itself.

Nothing in OUT depends on the time it was written, so the same release always gives the same bytes. `check` fetches
every file of OUT from BASE (the prefix's public address) and requires the same bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import urllib.request
from pathlib import Path

FORMAT = "fm-verify-release/1"
PACKAGE = "fundingmachine-verify"
SOURCE = "https://github.com/Korentsvit/fundingmachine-verify"
TAG = re.compile(r"^v(\d+\.\d+\.\d+)$")
OWN = ("LICENSE", "ATTRIBUTION.txt", "manifest.json", "SHA256SUMS")

# Third-party material in a release, from that material's own notice in this repository
# (fixtures/ledger-conformance/README.md and its LICENSE).
THIRD_PARTY = [
    ("fm-verify-fixtures-{version}.tar, under fm-verify-fixtures-{version}/ledger-conformance/",
     "The Provenance Ledger conformance suite's pair fixtures, from the repository Korentsvit/fundingmachine-ledger, "
     "docs/validation/conformance/fixtures/. Copyright 2026 NW PharmaTech Ltd, licensed under the Apache License, "
     "Version 2.0; their LICENSE is inside the archive beside them."),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_sums(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split("  ", 1)
            out[name] = digest
    return out


def attribution(version: str, tag: str, commit: str) -> str:
    lines = [f"fm-verify {version}", "",
             f"Source: tag {tag} of {SOURCE}, commit {commit}.",
             "Licence: Apache License, Version 2.0 (LICENSE, beside this file).", "",
             "Third-party material in this release:"]
    for where, what in THIRD_PARTY:
        lines += [f"* {where.format(version=version)}:", f"  {what}"]
    return "\n".join(lines) + "\n"


def assemble(release: Path, tag: str, commit: str, gate: Path, licence: Path, out: Path) -> dict:
    m = TAG.match(tag)
    if not m:
        raise SystemExit(f"{tag} is not a release tag vX.Y.Z")
    version = m.group(1)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("the commit must be a full SHA")
    record = json.loads(gate.read_text(encoding="utf-8"))
    if record.get("release") != tag or record.get("commit") != commit:
        raise SystemExit(f"the gate record is for {record.get('release')} at {record.get('commit')}, not {tag} at {commit}")
    if not (record.get("key1", {}).get("passed") is True and record.get("key2", {}).get("verdict") == "no issue"
            and record.get("key2", {}).get("commit") == commit):
        raise SystemExit("the gate record does not hold both keys for this commit")
    sums = read_sums(release / "SHA256SUMS")
    present = sorted(p.name for p in release.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    if present != sorted(sums):
        raise SystemExit(f"the release holds {present}; its SHA256SUMS lists {sorted(sums)}")
    for name, digest in sums.items():
        if name in OWN:
            raise SystemExit(f"the release has a file named {name}, which this prefix writes itself")
        if sha256(release / name) != digest:
            raise SystemExit(f"{name} is not the file the release's SHA256SUMS names")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in sums:
        shutil.copyfile(release / name, out / name)
    shutil.copyfile(licence, out / "LICENSE")
    (out / "ATTRIBUTION.txt").write_text(attribution(version, tag, commit), encoding="utf-8")
    files = [{"path": p.name, "sha256": sha256(p), "size": p.stat().st_size}
             for p in sorted(out.iterdir()) if p.name not in ("manifest.json", "SHA256SUMS")]
    manifest = {
        "format": FORMAT,
        "prefix": f"verify-{tag}",
        "package": PACKAGE,
        "version": version,
        "tag": tag,
        "commit": commit,
        "source": f"{SOURCE}/releases/tag/{tag}",
        "gate": {"record": f"gate/records/{tag}.json", "key1": record["key1"], "key2": record["key2"]},
        "licence": {"spdx": "Apache-2.0", "file": "LICENSE"},
        "attribution": "ATTRIBUTION.txt",
        "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines = [f"{sha256(p)}  {p.name}" for p in sorted(out.iterdir()) if p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def check(base: str, out: Path) -> list[str]:
    base = base.rstrip("/")
    problems = []
    for p in sorted(out.iterdir()):
        req = urllib.request.Request(f"{base}/{p.name}", headers={"User-Agent": "fm-verify-release-check"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                body = r.read()
        except OSError as e:
            problems.append(f"{p.name}: not served ({e})")
            continue
        if hashlib.sha256(body).hexdigest() != sha256(p):
            problems.append(f"{p.name}: {len(body)} bytes served, not the file assembled")
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assemble")
    a.add_argument("--release", type=Path, required=True)
    a.add_argument("--tag", required=True)
    a.add_argument("--commit", required=True)
    a.add_argument("--gate", type=Path, required=True)
    a.add_argument("--licence", type=Path, required=True)
    a.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("check")
    c.add_argument("--base", required=True)
    c.add_argument("--dir", type=Path, required=True)
    args = ap.parse_args(argv)
    if args.cmd == "assemble":
        m = assemble(args.release, args.tag, args.commit, args.gate, args.licence, args.out)
        print(f"{args.out}: {m['prefix']}, {len(m['files'])} files and manifest.json, SHA256SUMS "
              f"{sha256(args.out / 'SHA256SUMS')}")
        return 0
    problems = check(args.base, args.dir)
    for p in problems:
        print(p)
    print(f"{args.base}: " + ("every file as assembled" if not problems else f"{len(problems)} differences"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
