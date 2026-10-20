"""The release's scoreboard: what this verifier has verified, as of the release's commit.

    python tools/scoreboard.py VERSION OUT_DIR --commit SHA [--fixtures DIR] [--run ID]
    python tools/scoreboard.py --line FILE
    python tools/scoreboard.py --check-log LOG FILE

Writes OUT_DIR/fm-verify-scoreboard-VERSION.json (contract fm-verify-scoreboard/v0), read from the commit's
own files and recomputed, never typed in:

* ``anchors``: the newest dated verdict under verdicts/ledger-anchors/, counted from its README table (the
  anchors it names, confirmed in Bitcoin, pending), with the mirror commit it read;
* ``certificates``: every verdict under verdicts/certificates/, from the table in its README, each checked
  against the verdict's own first line;
* ``conformance``: every case of the fixtures given (by default ./fixtures) run by the fmverify that is
  imported, case by case, with the fixture manifest checked first. The release runs it with the wheel it
  publishes, on the archived fixtures.

``--run`` names the conformance run on main at the commit (.github/workflows/conformance.yml), whose log shows
every figure: the passing count, the newest anchor verdict with its counts, and each certificate verdict filed
(tools/verdict_summary.py). Each figure carries that run's id, so it traces to a run that existed before the
release. ``--check-log`` checks that a run's log shows every figure of a scoreboard file.

The same commit, fixtures and run give the same bytes: the file holds no time of its own. ``--line`` prints the
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


RUNS = "https://github.com/Korentsvit/fundingmachine-verify/actions/runs/"


def build(version: str, commit: str, fixtures: Path, repo: Path = ROOT, run: int | None = None) -> dict:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ScoreboardError("give the version as X.Y.Z and the full commit")
    board = {"contract": CONTRACT, "release": f"v{version}", "commit": commit, "anchors": anchors(repo),
             "certificates": certificates(repo), "conformance": conformance(fixtures), "not_included": NOT_INCLUDED,
             "trace": None}
    if run is not None:
        # The conformance run on main at the commit: its log shows each figure (checked with --check-log).
        trace = {"run_id": run, "url": f"{RUNS}{run}", "workflow": "conformance", "event": "push to main", "commit": commit}
        board["trace"] = trace
        for section in ("anchors", "certificates", "conformance"):
            board[section]["run_id"] = run
        for c in board["certificates"]["verdicts"]:
            c["run_id"] = run
    return board


def shown(board: dict) -> list[str]:
    """The lines a run's log must hold for each figure, as tools/verdict_summary.py and fm-verify conformance print them."""
    a, c, s = board["anchors"], board["certificates"], board["conformance"]
    out = [f"{s['passing']} of {s['total']} cases conform",
           f"Certificates verified: {c['verified']} ({c['valid']} valid)",
           f"{a['verdict']}",
           f"{a['verified']} of {a['committed']} anchors confirmed in Bitcoin, {a['pending']} pending, {a['failed']} failed"]
    out += [f"| `{v['certificate']}` | `{v['contract']}` | {v['outcome']} (" for v in c["verdicts"]]
    return out


def check_log(log: str, board: dict) -> list[str]:
    """The figures of a scoreboard the log does not show; empty when it shows them all."""
    return [want for want in shown(board) if want not in log]


def line(board: dict) -> str:
    a, c, s = board["anchors"], board["certificates"], board["conformance"]
    return (f"Scoreboard ({board['release']}): Ledger anchors verified {a['verified']} of {a['committed']}"
            + (f" ({a['pending']} pending)" if a["pending"] else "") + (f" ({a['failed']} failed)" if a["failed"] else "")
            + f", in {a['verdict']}; certificates verified {c['verified']} ({c['valid']} valid); "
            f"conformance cases passing {s['passing']} of {s['total']} (this verifier's suite)"
            + (f"; each figure shown by run {board['trace']['run_id']} ({board['trace']['url']})." if board.get("trace") else "."))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("version", nargs="?")
    ap.add_argument("out", nargs="?", type=Path)
    ap.add_argument("--commit")
    ap.add_argument("--fixtures", type=Path, default=ROOT / "fixtures")
    ap.add_argument("--run", type=int, metavar="ID", help="the conformance run on main at the commit, whose log shows every figure")
    ap.add_argument("--line", type=Path, metavar="FILE", help="print the scoreboard line of a scoreboard file, and stop")
    ap.add_argument("--check-log", nargs=2, type=Path, metavar=("LOG", "FILE"),
                    help="check that a run's log shows every figure of a scoreboard file, and stop")
    a = ap.parse_args(argv)
    if a.line:
        print(line(json.loads(a.line.read_text(encoding="utf-8"))))
        return 0
    if a.check_log:
        missing = check_log(a.check_log[0].read_text(encoding="utf-8", errors="replace"), json.loads(a.check_log[1].read_text(encoding="utf-8")))
        for m in missing:
            print(f"scoreboard: the run's log does not show: {m}", file=sys.stderr)
        print("every figure is shown by the run's log" if not missing else f"{len(missing)} figures not shown")
        return 1 if missing else 0
    if not (a.version and a.out and a.commit):
        ap.error("give VERSION, OUT_DIR and --commit")
    try:
        board = build(a.version, a.commit, a.fixtures, run=a.run)
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
