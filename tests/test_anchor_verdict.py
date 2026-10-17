"""tools/anchor_verdict.py: a dated verdict directory written from a checkout of the anchors mirror, here a git
repository made from the set-valid fixture in three commits (the first anchor with its proof pending; the second
anchor; the first anchor's proof upgraded to its Bitcoin attestation)."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from fmverify import ots

ROOT = Path(__file__).resolve().parent.parent
SET = ROOT / "fixtures" / "ledger-anchors" / "set-valid"
REG = ROOT / "fixtures" / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin"
ROOTS = [ROOT / "fixtures" / "rfc3161" / "pki" / "root.pem", ROOT / "fixtures" / "ledger-anchors" / "pki" / "second-root.pem"]
FIRST, SECOND = "2026/10/17/080411Z", "2026/10/17/090411Z"

sys.path.insert(0, str(ROOT / "tools"))
import anchor_verdict  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def pending(proof: bytes) -> bytes:
    """The same proof with each Bitcoin attestation replaced by a calendar's promise: as it was before upgrading."""
    p = ots.parse(proof)

    def strip(ts):
        for i, entry in enumerate(ts.entries):
            if isinstance(entry, ots.Attestation):
                if entry.kind == "bitcoin":
                    ts.entries[i] = ots.Attestation(ots.TAG_PENDING, ots._varbytes(b"https://calendar.example"))
            else:
                strip(entry[1])

    strip(p.timestamp)
    return p.serialize()


def commit(repo: Path, message: str) -> None:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.invalid")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", message], check=True, env=env)


@pytest.fixture
def mirror(tmp_path):
    repo = tmp_path / "fundingmachine-anchors"
    anchors = repo / "anchors"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    lines = (SET / "index.jsonl").read_text().splitlines(keepends=True)
    shutil.copytree(SET / FIRST, anchors / FIRST)
    ots_file = anchors / FIRST / "root.preimage.ots"
    ots_file.write_bytes(pending(ots_file.read_bytes()))
    (anchors / "index.jsonl").write_text(lines[0])
    commit(repo, "first anchor, pending")
    shutil.copytree(SET / SECOND, anchors / SECOND)
    (anchors / "index.jsonl").write_text("".join(lines))
    commit(repo, "second anchor")
    shutil.copyfile(SET / FIRST / "root.preimage.ots", ots_file)
    commit(repo, "first anchor's proof upgraded")
    return repo


def run(repo: Path, out: Path, at: str) -> int:
    return anchor_verdict.main([str(repo), str(out), "--network", "regtest", "--headers-chain", f"{REG}@0",
                                "--roots", str(ROOTS[0]), "--roots", str(ROOTS[1]), "--checked-at", at])


def test_the_verdict_directory(mirror, tmp_path):
    out = tmp_path / "verdicts"
    assert run(mirror, out, "2026-10-17T10:00:00Z") == 0
    d = out / "2026-10-17T1000Z"
    readme = (d / "README.md").read_text()
    assert "# Ledger anchors, 17 October 2026, 10:00 UTC" in readme
    assert "**Verdict: 1 anchor valid, confirmed in Bitcoin.** One more anchor holds on its RFC 3161 tokens." in readme
    assert f"| {FIRST} | 3b9ba50bdd61... | 5 | valid | 2 (" in readme
    assert f"| {SECOND} | 7a050f0a3cbe... | 6 | pending: no verdict yet" in readme
    assert "It has\n  3 commits" in readme
    assert "`index.jsonl` changes 1 time, and each version begins with the whole of the one before it." in readme
    assert "`root.preimage.ots` changes once, in one anchor, when the pending proof is replaced" in readme
    assert "`anchor_set.index`, pass:" in readme
    assert "Since the" not in readme
    assert (d / "verdict.txt").read_text().startswith("VALID: All 2 anchors under fundingmachine-anchors/anchors hold")
    for rel in (FIRST, SECOND):
        assert (d / "anchors" / f"{rel}.txt").read_text().splitlines()[1] == f"Subject: Provenance Ledger anchor {rel}"
    text = "".join(p.read_text() for p in d.rglob("*") if p.is_file())
    assert "\u2013" not in text and "\u2014" not in text
    assert str(tmp_path) not in text and str(REG.parent) not in text  # no path on the machine that wrote it

    # A later run reads the earlier verdict's table and compares.
    assert run(mirror, out, "2026-10-17T11:00:00Z") == 0
    later = (out / "2026-10-17T1100Z" / "README.md").read_text()
    assert "Since the [10:00 UTC verdict](../2026-10-17T1000Z), 0 anchors have a verdict for the first time" in later
    assert "The 1 anchor valid at 10:00 UTC is valid here too, with the same earliest blocks and times." in later


@pytest.mark.parametrize("change, headline", [
    ("created", "**Verdict: the set does not hold.** index.jsonl under fundingmachine-anchors/anchors does not agree"),
    ("leaf", f"**Verdict: 1 anchor does not hold:** {FIRST} (ledger_anchor.leaves"),
])
def test_a_changed_manifest_shows_in_the_verdict_and_in_the_history(mirror, tmp_path, change, headline):
    manifest = mirror / "anchors" / FIRST / "manifest.json"
    m = json.loads(manifest.read_text())
    if change == "created":
        m["created"] = "2026-10-17T08:04:12.000Z"
    else:
        leaf = m["leaves"][0]
        target = leaf["descriptor"] if "descriptor" in leaf and "sha256" in leaf["descriptor"] else leaf
        target["sha256"] = ("0" if target["sha256"][0] != "0" else "1") + target["sha256"][1:]
    manifest.write_text(json.dumps(m, indent=2) + "\n")
    commit(mirror, "manifest changed")
    out = tmp_path / "verdicts"
    assert run(mirror, out, "2026-10-17T10:00:00Z") == 1
    readme = (out / "2026-10-17T1000Z" / "README.md").read_text()
    assert headline in readme
    assert f"1 change the anchoring does not explain: anchors/{FIRST}/manifest.json at " in readme
