"""The filed verdicts, for a CI run's summary: every certificate verdict committed under verdicts/certificates/ and
the newest anchor verdict, each as filed, and each certificate committed with its verdict verified again.

    python tools/verdict_summary.py [--roots PEM]...   (markdown on standard output)

A certificate whose holder has not agreed to publish it is not in the repository: its row gives the filed verdict
and says it was not run again. Exit status 1 when a certificate verified again does not reach its filed verdict,
or when a verdict and its table disagree (tools/scoreboard.py).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import scoreboard  # noqa: E402

SOURCE = "https://github.com/Korentsvit/fundingmachine-verify/tree"
COMMANDS = {"record-certificate/v0": "record-certificate", "ledger-certificate/v0": "certificate", "ledger-certificate/v0.1": "certificate"}


def again(row: dict, roots: list[str]) -> str | None:
    """The outcome of this run's own verification of a committed certificate, or None when none is committed."""
    d = ROOT / row["verdict"]
    target = next((d / n for n in ("certificate.json", "certificate.pdf") if (d / n).is_file()), None)
    if target is None:
        return None
    cmd = [sys.executable, "-m", "fmverify.cli", COMMANDS[row["contract"]], str(d if row["contract"] == "record-certificate/v0" else target)]
    if (d / "headers.txt").is_file():
        cmd += ["--headers", str(d / "headers.txt")]
    for r in roots:
        cmd += ["--roots", r]
    done = subprocess.run([*cmd, "--json"], capture_output=True, text=True, check=False)
    try:
        return json.loads(done.stdout)["outcome"]
    except (json.JSONDecodeError, KeyError):
        return f"error ({done.stderr.strip().splitlines()[-1] if done.stderr.strip() else done.returncode})"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--roots", action="append", help="time-stamping roots for the certificates verified again "
                                                       "(default: /etc/ssl/certs/ca-certificates.crt)")
    a = ap.parse_args(argv)
    roots = a.roots or ["/etc/ssl/certs/ca-certificates.crt"]
    try:
        certs, anchors = scoreboard.certificates(ROOT), scoreboard.anchors(ROOT)
    except scoreboard.ScoreboardError as exc:
        print(f"### Filed verdicts\n\nThe verdicts do not agree with their tables: {exc}")
        return 1
    bad = 0
    at = f"{SOURCE}/{os.environ.get('GITHUB_SHA') or 'main'}"
    lines = [f"### Filed verdicts at `{os.environ.get('GITHUB_SHA') or 'main'}`", "",
             f"Certificates verified: {certs['verified']} ({certs['valid']} valid). Newest anchor verdict, as filed: "
             f"[`{anchors['verdict']}`]({at}/{anchors['verdict']}), mirror commit `{(anchors['mirror_commit'] or '?')[:7]}`: "
             f"{anchors['verified']} of {anchors['committed']} anchors confirmed in Bitcoin, {anchors['pending']} pending, "
             f"{anchors['failed']} failed.", "",
             "| Certificate | Contract | Filed verdict | In this run |", "| --- | --- | --- | --- |"]
    for row in certs["verdicts"]:
        got = again(row, roots)
        if got is None:
            note = "not run again: the certificate is not in the repository (its holder has not agreed to publish it); its SHA-256 is in `certificate.sha256`"
        elif got == row["outcome"]:
            note = f"verified again: {got}"
        else:
            note = f"verified again: {got}, NOT the filed verdict"
            bad += 1
        lines.append(f"| `{row['certificate']}` | `{row['contract']}` | {row['outcome']} ([`{row['verdict']}`]({at}/{row['verdict']})) | {note} |")
    print("\n".join(lines))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
