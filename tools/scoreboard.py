"""The release's scoreboard: what this verifier has verified, as of the release's commit.

    python tools/scoreboard.py VERSION OUT_DIR --commit SHA [--fixtures DIR]
    python tools/scoreboard.py --line FILE

Writes OUT_DIR/fm-verify-scoreboard-VERSION.json (contract fm-verify-scoreboard/v0), read from the commit's
own files and recomputed, never typed in:

* ``anchors``: the newest dated verdict under verdicts/ledger-anchors/, counted from its README table (the
  anchors it names, confirmed in Bitcoin, pending), with the mirror commit it read;
* ``certificates``: every verdict under verdicts/certificates/, from the table in its README, each checked
  against the verdict's own first line;
* ``conformance``: every case of the fixtures given (by default ./fixtures) run by the fmverify that is
  imported, case by case, with the fixture manifest checked first. The release runs it with the wheel it
  publishes, on the archived fixtures.

The same commit and fixtures give the same bytes: the file holds no time of its own. ``--line`` prints the
scoreboard line the release notes carry.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = "fm-verify-scoreboard/v0"
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{4}(?:\d{2})?Z")  # to the minute, or to the second where two share a minute
ANCHOR_ROW = re.compile(r"^\| (\d{4}/\d{2}/\d{2}/\d{6}Z)(?: \(new\))? \| [0-9a-f]+\.\.\. \| \d+ \| (valid|pending|invalid|indeterminate)")
MIRROR_COMMIT = re.compile(r"\*\*The commit read\.\*\* `([0-9a-f]{40})`")
CERT_ROW = re.compile(r"^\| \[[^\]]+\]\((\d{4}-\d{2}-\d{2}T\d{4}(?:\d{2})?Z)\) \| `([a-z0-9./-]+)` \| `(urn:uuid:[0-9a-f-]{36})`[^|]* \| "
                      r"(valid|invalid|indeterminate) \|$")
NOT_INCLUDED = ["the Provenance Ledger's own suite (its validation-conformance/v0): it runs from a checkout of the Ledger's "
                "repository, which a release does not depend on"]


class ScoreboardError(Exception):
    pass


def anchors(repo: Path) -> dict:
    dirs = sorted(d for d in (repo / "verdicts" / "ledger-anchors").iterdir() if d.is_dir() and STAMP.fullmatch(d.name))
    if not dirs:
        raise ScoreboardError("no anchor verdict under verdicts/ledger-anchors")
    newest = dirs[-1]
    readme = (newest / "README.md").read_text(encoding="utf-8")
    states = Counter(m.group(2) for m in map(ANCHOR_ROW.match, readme.splitlines()) if m)
    first = (newest / "verdict.txt").read_text(encoding="utf-8").splitlines()[0]
    named = re.match(r"(VALID|INVALID|INDETERMINATE): All (\d+) anchors", first)
    total = sum(states.values())
    if named and int(named.group(2)) != total:
        raise ScoreboardError(f"{newest.name}: the verdict names {named.group(2)} anchors, its table {total}")
    commit = MIRROR_COMMIT.search(readme)
    return {"verdict": newest.relative_to(repo).as_posix(), "mirror_commit": commit.group(1) if commit else None,
            "committed": total, "verified": states["valid"], "pending": states["pending"],
            "failed": total - states["valid"] - states["pending"]}


def certificates(repo: Path) -> dict:
    base = repo / "verdicts" / "certificates"
    rows = [m.groups() for m in map(CERT_ROW.match, (base / "README.md").read_text(encoding="utf-8").splitlines()) if m]
    dirs = sorted(d.name for d in base.iterdir() if d.is_dir() and STAMP.fullmatch(d.name))
    if sorted(r[0] for r in rows) != dirs:
        raise ScoreboardError(f"verdicts/certificates: the table lists {sorted(r[0] for r in rows)}, the directories are {dirs}")
    out = []
    for stamp, contract, cert_id, outcome in sorted(rows):
        first = (base / stamp / "verdict.txt").read_text(encoding="utf-8").split(":", 1)[0]
        if first.lower() != outcome:
            raise ScoreboardError(f"verdicts/certificates/{stamp}: the table says {outcome}, its verdict {first}")
        out.append({"verdict": f"verdicts/certificates/{stamp}", "contract": contract, "certificate": cert_id, "outcome": outcome})
    return {"verified": len(out), "valid": sum(1 for c in out if c["outcome"] == "valid"), "verdicts": out}


def conformance(fixtures: Path) -> dict:
    from fmverify import __version__
    from fmverify.conformance import run_suite

    manifest, results = run_suite(fixtures)
    if manifest:
        raise ScoreboardError(f"{fixtures}: the fixtures are not the published ones: {manifest[:3]}")
    kinds: dict[str, list[int]] = {}
    for r in results:
        k = kinds.setdefault(r.kind, [0, 0])
        k[0] += r.ok
        k[1] += 1
    return {"fixtures": fixtures.name, "fmverify": __version__, "passing": sum(r.ok for r in results), "total": len(results),
            "by_kind": {k: {"passing": v[0], "total": v[1]} for k, v in sorted(kinds.items())},
            "failing": sorted(f"{r.kind}/{r.name}" for r in results if not r.ok)}


def build(version: str, commit: str, fixtures: Path, repo: Path = ROOT) -> dict:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ScoreboardError("give the version as X.Y.Z and the full commit")
    return {"contract": CONTRACT, "release": f"v{version}", "commit": commit, "anchors": anchors(repo),
            "certificates": certificates(repo), "conformance": conformance(fixtures), "not_included": NOT_INCLUDED}


def line(board: dict) -> str:
    a, c, s = board["anchors"], board["certificates"], board["conformance"]
    return (f"Scoreboard ({board['release']}): Ledger anchors verified {a['verified']} of {a['committed']}"
            + (f" ({a['pending']} pending)" if a["pending"] else "") + (f" ({a['failed']} failed)" if a["failed"] else "")
            + f", in {a['verdict']}; certificates verified {c['verified']} ({c['valid']} valid); "
            f"conformance cases passing {s['passing']} of {s['total']} (this verifier's suite).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("version", nargs="?")
    ap.add_argument("out", nargs="?", type=Path)
    ap.add_argument("--commit")
    ap.add_argument("--fixtures", type=Path, default=ROOT / "fixtures")
    ap.add_argument("--line", type=Path, metavar="FILE", help="print the scoreboard line of a scoreboard file, and stop")
    a = ap.parse_args(argv)
    if a.line:
        print(line(json.loads(a.line.read_text(encoding="utf-8"))))
        return 0
    if not (a.version and a.out and a.commit):
        ap.error("give VERSION, OUT_DIR and --commit")
    try:
        board = build(a.version, a.commit, a.fixtures)
    except ScoreboardError as exc:
        print(f"scoreboard: {exc}", file=sys.stderr)
        return 1
    a.out.mkdir(parents=True, exist_ok=True)
    path = a.out / f"fm-verify-scoreboard-{a.version}.json"
    path.write_text(json.dumps(board, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(line(board))
    return 0 if not board["conformance"]["failing"] else 1


if __name__ == "__main__":
    sys.exit(main())
