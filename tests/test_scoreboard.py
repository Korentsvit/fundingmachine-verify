"""The release's scoreboard (tools/scoreboard.py): recomputed from the commit's verdicts and the fixtures, the same
bytes each time, and refused where a verdict and its table disagree; and the fleet's scoreboard manifest, each figure
read from the file the conformance run kept and refused unless the release recomputed the same."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import scoreboard  # noqa: E402
from fmverify import jcs  # noqa: E402

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


# The fleet's scoreboard manifest (contract scoreboard-manifest 1.0, fundingmachine-core docs/scoreboard-contract/1.0/).

TAG, RUN, MADE_AT = "v9.9.9", 4242, "2026-10-22T06:30:00Z"
SPEC = json.loads((ROOT / "tools/scoreboard-spec.json").read_text(encoding="utf-8"))
CORE = Path(os.environ["FM_CORE_REPO"]) if os.environ.get("FM_CORE_REPO") else None
CONTRACT = CORE / "docs/scoreboard-contract/1.0" if CORE else None


def _outputs(tmp_path: Path, written: dict | None = None) -> Path:
    out = tmp_path / "outputs"
    (out / str(RUN)).mkdir(parents=True)
    written = written if written is not None else scoreboard.figures(COMMIT, ROOT / "fixtures")
    (out / str(RUN) / scoreboard.FIGURES).write_text(json.dumps(written), encoding="utf-8")
    return out


def _manifest(tmp_path: Path, written: dict | None = None, board: dict | None = None) -> dict:
    board = board or scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures", run=RUN)
    return scoreboard.manifest(TAG, COMMIT, RUN, _outputs(tmp_path, written), board, MADE_AT, SPEC)


def test_the_manifest_reads_each_figure_from_the_runs_file(tmp_path):
    board = scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures", run=RUN)
    doc = _manifest(tmp_path, board=board)
    assert [doc[k] for k in ("format", "engine", "repository", "tag", "commit", "made_at", "run_ids")] == \
        ["scoreboard-manifest/1.0", "Verifier", "fundingmachine-verify", TAG, COMMIT, MADE_AT, [RUN]]
    assert {f["name"]: (f["value"], f["target"]) for f in doc["figures"]} == {
        "Ledger anchors verified": (board["anchors"]["verified"], None),
        "Ledger certificates verified": (board["certificates"]["verified"], 10),
        "conformance cases passing": (board["conformance"]["passing"], None)}
    assert all(f["run_id"] == RUN and f["source"] == {"file": scoreboard.FIGURES, "path": s["path"]} for f, s in zip(doc["figures"], SPEC))
    body = {k: v for k, v in doc.items() if k != "sha256"}
    assert doc["sha256"] == hashlib.sha256(jcs.dumps(body)).hexdigest()


def test_a_figure_the_run_did_not_write_or_the_release_did_not_recompute_is_refused(tmp_path):
    written = scoreboard.figures(COMMIT, ROOT / "fixtures")
    fewer = json.loads(json.dumps(written))
    fewer["certificates"]["verified"] -= 1
    with pytest.raises(scoreboard.ScoreboardError, match="the release recomputed"):
        _manifest(tmp_path / "a", fewer)
    other = dict(written, commit="b" * 40)
    with pytest.raises(scoreboard.ScoreboardError, match="not " + COMMIT):
        _manifest(tmp_path / "b", other)
    missing = {k: v for k, v in written.items() if k != "conformance"}
    with pytest.raises(scoreboard.ScoreboardError, match="conformance.passing: no conformance"):
        _manifest(tmp_path / "c", missing)
    with pytest.raises(scoreboard.ScoreboardError, match="wrote no"):
        scoreboard.manifest(TAG, COMMIT, RUN, tmp_path / "nothing", scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures", run=RUN), MADE_AT, SPEC)
    for board in (scoreboard.build("9.9.9", COMMIT, ROOT / "fixtures", run=RUN + 1), scoreboard.build("9.9.8", COMMIT, ROOT / "fixtures", run=RUN)):
        with pytest.raises(scoreboard.ScoreboardError, match="the release's scoreboard is not"):
            _manifest(tmp_path / f"d{board['release']}{board['trace']['run_id']}", board=board)
    with pytest.raises(scoreboard.ScoreboardError, match="UTC to the second"):
        scoreboard.manifest(TAG, COMMIT, RUN, tmp_path, {}, "2026-10-22T06:30Z", SPEC)


def test_the_cli_writes_the_run_file_then_the_manifest_the_same_bytes_with_the_same_time(tmp_path):
    tool = [sys.executable, str(ROOT / "tools/scoreboard.py")]
    subprocess.run(tool + ["--figures", str(tmp_path / "outputs" / str(RUN)), "--commit", COMMIT], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(tool + ["9.9.9", str(tmp_path / "dist"), "--commit", COMMIT, "--run", str(RUN)], cwd=ROOT, check=True, capture_output=True)
    made = []
    for _ in range(2):
        subprocess.run(tool + ["--manifest", str(tmp_path / "dist"), "--tag", TAG, "--commit", COMMIT, "--run", str(RUN),
                               "--outputs", str(tmp_path / "outputs"), "--made-at", MADE_AT], cwd=ROOT, check=True, capture_output=True)
        made.append((tmp_path / "dist" / scoreboard.MANIFEST).read_bytes())
    assert made[0] == made[1] and json.loads(made[0])["made_at"] == MADE_AT
    refused = subprocess.run(tool + ["--manifest", str(tmp_path / "dist"), "--tag", "v9.9.8", "--commit", COMMIT, "--run", str(RUN),
                                     "--outputs", str(tmp_path / "outputs")], cwd=ROOT, capture_output=True, text=True, check=False)
    assert refused.returncode == 1 and "scoreboard:" in refused.stderr


@pytest.mark.skipif(CONTRACT is None or not (CONTRACT / "schema.json").is_file(),
                    reason="set FM_CORE_REPO to a checkout of fundingmachine-core holding docs/scoreboard-contract/1.0")
def test_the_contracts_own_schema_hash_and_example_agree(tmp_path):
    """Read from the contract's checkout, not copied: its schema ($defs/asset), its sha256.mjs and its example."""
    doc = _manifest(tmp_path)
    root = json.loads((CONTRACT / "schema.json").read_text(encoding="utf-8"))
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(doc, {"$schema": root["$schema"], "$defs": root["$defs"], "$ref": "#/$defs/asset"})
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    if shutil.which("node"):
        assert subprocess.run(["node", str(CONTRACT / "sha256.mjs"), str(path)], capture_output=True, text=True, check=True).stdout.strip() == doc["sha256"]
    example = json.loads((CORE / "docs/examples/scoreboard-manifest/scoreboard-manifest.json").read_text(encoding="utf-8"))
    assert scoreboard.digest(example) == example["sha256"]
