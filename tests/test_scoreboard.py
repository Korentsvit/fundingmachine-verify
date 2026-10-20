"""The release's scoreboard (tools/scoreboard.py): recomputed from the commit's verdicts and the fixtures, the same
bytes each time, and refused where a verdict and its table disagree."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import scoreboard  # noqa: E402

COMMIT = "a" * 40


def test_it_counts_what_the_commit_holds():
    board = scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures")
    a = board["anchors"]
    assert a["committed"] == a["verified"] + a["pending"] + a["failed"] and a["committed"] > 0
    assert a["verdict"] == "verdicts/ledger-anchors/" + sorted(p.name for p in (ROOT / "verdicts/ledger-anchors").iterdir() if p.is_dir())[-1]
    c = board["certificates"]
    assert c["verified"] == len([p for p in (ROOT / "verdicts/certificates").iterdir() if p.is_dir()]) >= 4
    s = board["conformance"]
    assert s["passing"] == s["total"] == sum(k["total"] for k in s["by_kind"].values()) and not s["failing"]
    assert board["not_included"] and "Ledger" in scoreboard.line(board)


def test_the_same_commit_gives_the_same_bytes(tmp_path):
    for out in ("one", "two"):
        assert subprocess.run([sys.executable, str(ROOT / "tools/scoreboard.py"), "9.9.9", str(tmp_path / out), "--commit", COMMIT],
                              cwd=ROOT, capture_output=True, check=False).returncode == 0
    assert (tmp_path / "one/fm-verify-scoreboard-9.9.9.json").read_bytes() == (tmp_path / "two/fm-verify-scoreboard-9.9.9.json").read_bytes()
    printed = subprocess.run([sys.executable, str(ROOT / "tools/scoreboard.py"), "--line", str(tmp_path / "one/fm-verify-scoreboard-9.9.9.json")],
                             capture_output=True, text=True, check=True).stdout
    assert printed.startswith("Scoreboard (v9.9.9): Ledger anchors verified ")


def _copy(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "verdicts", repo / "verdicts")
    return repo


def test_a_table_and_a_verdict_that_disagree_are_refused(tmp_path):
    repo = _copy(tmp_path)
    readme = repo / "verdicts/certificates/README.md"
    text = readme.read_text(encoding="utf-8")
    readme.write_text(text.replace("block 971901 | valid |", "block 971901 | invalid |"), encoding="utf-8")
    with pytest.raises(scoreboard.ScoreboardError, match="the table says invalid"):
        scoreboard.certificates(repo)


def test_a_verdict_directory_the_table_does_not_list_is_refused(tmp_path):
    repo = _copy(tmp_path)
    (repo / "verdicts/certificates/2099-01-01T0000Z").mkdir()
    with pytest.raises(scoreboard.ScoreboardError, match="the table lists"):
        scoreboard.certificates(repo)


def test_bad_arguments_are_refused():
    with pytest.raises(scoreboard.ScoreboardError):
        scoreboard.build("v1.0", COMMIT, ROOT / "fixtures")
    with pytest.raises(scoreboard.ScoreboardError):
        scoreboard.build("1.0.0", "abc", ROOT / "fixtures")


def _run_log(board: dict) -> str:
    """What the conformance run prints, as its steps print it: the suite's last line and the filed verdicts."""
    done = subprocess.run([sys.executable, str(ROOT / "tools/verdict_summary.py")], cwd=ROOT, capture_output=True, text=True, check=False)
    s = board["conformance"]
    return f"... {s['passing']} of {s['total']} cases conform\n" + done.stdout


def test_each_figure_carries_the_run_that_shows_it():
    board = scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures", run=123456)
    assert board["trace"] == {"run_id": 123456, "url": scoreboard.RUNS + "123456", "workflow": "conformance",
                              "event": "push to main", "commit": COMMIT}
    assert board["anchors"]["run_id"] == board["certificates"]["run_id"] == board["conformance"]["run_id"] == 123456
    assert all(c["run_id"] == 123456 for c in board["certificates"]["verdicts"])
    assert "each figure shown by run 123456" in scoreboard.line(board)
    assert scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures")["trace"] is None


@pytest.mark.skipif(not Path("/etc/ssl/certs/ca-certificates.crt").is_file(), reason="the summary verifies the published certificates again")
def test_a_runs_log_shows_every_figure_or_the_check_says_which_not():
    board = scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures", run=1)
    log = _run_log(board)
    assert scoreboard.check_log(log, board) == []
    first = board["certificates"]["verdicts"][0]["certificate"]
    without = "\n".join(line for line in log.splitlines() if first not in line)
    assert scoreboard.check_log(without, board) == [l for l in scoreboard.shown(board) if first in l]
    fewer = log.replace(f"{board['conformance']['passing']} of", f"{board['conformance']['passing'] - 1} of")
    assert any("cases conform" in m for m in scoreboard.check_log(fewer, board))
