import json
from pathlib import Path

import pytest

from fmverify import jcs, ledger_anchors, merkle
from fmverify.cli import main
from fmverify.hashes import sha256

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CASE = FIX / "ledger-anchors" / "valid"


def test_leaves_sorted_by_utf16_code_units():
    a = {"kind": "decisions_fragment", "path": "docs/decisions.d/" + chr(0xFB33) + ".md", "ref": "main", "repo": "r/x", "sha256": "0" * 64}
    b = {"kind": "decisions_fragment", "path": "docs/decisions.d/" + chr(0x1F600) + ".md", "ref": "main", "repo": "r/x", "sha256": "0" * 64}
    leaves = ledger_anchors.sorted_leaves([a, b])
    # U+1F600 is the surrogate pair D83D DE00, which sorts before U+FB33 in UTF-16 (and after it by code point).
    assert leaves == [jcs.dumps(b), jcs.dumps(a)]


@pytest.mark.parametrize("n", [1, 2, 3, 6, 9])
def test_preimage_hashes_to_the_root(n):
    leaves = [b"leaf %d" % i for i in range(n)]
    pre = ledger_anchors.preimage_for(leaves)
    assert sha256(pre) == merkle.tree_hash(leaves)
    assert pre[0] == (0 if n == 1 else 1)


def test_manifest_descriptors_found_by_shape():
    man = json.loads((CASE / "manifest.json").read_text())
    found = ledger_anchors._descriptors(man)
    assert len(found) == 5 and all(set(d) == ledger_anchors.DESCRIPTOR_KEYS for d in found)


def test_cli(capsys):
    base = ["anchors", str(CASE), "--network", "regtest",
            "--headers-chain", str(FIX / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin"),
            "--roots", str(FIX / "rfc3161" / "pki" / "root.pem")]
    assert main(base + ["--repo", f"example/repository={FIX / 'ledger-anchors' / 'repo'}"]) == 0
    out = capsys.readouterr().out
    assert "The 5 files and entries the manifest lists are the leaves of root" in out
    assert main(base + ["--repo", "no-equals-sign"]) == 64
    assert main(["anchors", str(CASE), "--network", "regtest"]) == 2


def test_missing_preimage_is_not_this_layout(tmp_path):
    assert not ledger_anchors.is_layout(tmp_path)


def test_all_anchors_under_a_directory(capsys):
    base = ["anchors", str(FIX / "ledger-anchors"), "--all", "--network", "regtest",
            "--headers-chain", str(FIX / "bitcoin" / "regtest" / "ledger-anchor-headers-0-4.bin"),
            "--roots", str(FIX / "rfc3161" / "pki" / "root.pem"), "--json"]
    assert main(base) == 1  # the set includes the deliberately broken cases
    import json as _json

    doc = _json.loads(capsys.readouterr().out)
    assert doc["kind"] == "anchor-set"
    by_case = {c["id"].split(".", 1)[1]: c["status"] for c in doc["checks"]}
    assert by_case["valid"] == "pass" and by_case["descriptor-altered"] == "fail"
    n = len(ledger_anchors.find_anchor_dirs(FIX / "ledger-anchors"))
    assert n >= 14 and f"of {n} anchors" in doc["statement"]
    assert ledger_anchors.find_anchor_dirs(FIX / "anchors") == []


def test_entry_of_several_lines_is_found():
    """docs/ANCHORING.md: an entry's hash covers its line or lines (a dated list
    item in Knowledge-goblin), without the trailing newline."""
    lines = ["# Log", "", "- 2026-10-16: a ruling", "  that runs onto a second line", "- 2026-10-17: another"]
    runs = ledger_anchors.entry_runs(lines)
    assert runs[sha256("\n".join(lines[2:4]).encode()).hex()] == (3, 4)
    assert runs[sha256(lines[4].encode()).hex()] == (5, 5)
    assert sha256(("\n".join(lines[2:4]) + "\n").encode()).hex() not in runs


def test_fragment_of_several_rows_found_assembled():
    rows = ["| 2026-10-16 | layer | First | Why | this pull request |", "| 2026-10-16 | layer | Second | Why | this pull request |"]
    fragment = ("\n".join(rows) + "\n").encode()
    log = ["# Log", "", "| Date | Layer | Ruling | Why | Pull request |", "| --- | --- | --- | --- | --- |",
           "| 2026-10-15 | other | Earlier | Why | #7 |"] + [r.replace("this pull request", "#12") for r in rows]
    (at, number) = ledger_anchors.assembled_runs(log)[sha256(fragment).hex()]
    assert at == (6, 7) and number == "#12"
    # A fragment whose rows already named their pull request is found as written.
    plain = ("\n".join(log[4:5]) + "\n").encode()
    assert ledger_anchors.assembled_runs(log)[sha256(plain).hex()] == ((5, 5), None)
    # Only an exact match counts: other spacing is not the same fragment.
    spaced = fragment.replace(b"| First |", b"|  First |")
    assert sha256(spaced).hex() not in ledger_anchors.assembled_runs(log)


def test_assembled_fragment_named_in_the_verdict():
    from fmverify.verdict import Status

    v = ledger_anchors.verify_dir(FIX / "ledger-anchors" / "checkout-assembled",
                                  repos={"example/repository": FIX / "ledger-anchors" / "repo-assembled"})
    c = next(c for c in v.checks if c.id == "ledger_anchor.checkout.example/repository")
    assert c.status is Status.WARN
    assert c.data["changed"] == ["docs/DECISIONS_LOG.md"]
    assert c.data["assembled"] == ["docs/decisions.d/2026-10-16-example.md (assembled: line 7 of docs/DECISIONS_LOG.md, "
                                   "pull request #3 written for 'this pull request')"]
    assert c.data["absent"] == []


def test_long_log_is_quick():
    import time

    log = [f"| 2026-10-{1 + i % 28:02d} | layer | Ruling number {i} with some words | Why it was taken, at some length | #{i} |"
           for i in range(5000)]
    t = time.perf_counter()
    ledger_anchors.entry_runs(log)
    ledger_anchors.assembled_runs(log)
    assert time.perf_counter() - t < 20


def test_entry_with_trailing_white_space():
    """The Ledger's collector trims each entry line's end before hashing."""
    lines = ["| 2026-10-16 | layer | A ruling | Why | #4 |   "]
    assert ledger_anchors.entry_runs(lines)[sha256(lines[0].rstrip().encode()).hex()] == (1, 1)


def _valid_manifest():
    return json.loads((CASE / "manifest.json").read_text())


def _mutations():
    """Each yields a manifest one step away from the valid fixture's."""
    m = _valid_manifest()
    for key in list(m):
        yield f"drop {key}", {k: v for k, v in m.items() if k != key}
    yield "extra field", {**m, "note": "x"}
    yield "contract v1", {**m, "contract": "anchor-manifest/v1"}
    yield "created without ms", {**m, "created": "2026-10-17T08:04:11Z"}
    yield "root upper case", {**m, "root": m["root"].upper()}
    yield "size zero", {**m, "size": 0}
    yield "size true", {**m, "size": True}
    yield "size string", {**m, "size": "5"}
    yield "no leaves", {**m, "leaves": []}
    leaf = m["leaves"][0]
    yield "leaf extra", {**m, "leaves": [{**leaf, "x": 1}] + m["leaves"][1:]}
    yield "leaf hash short", {**m, "leaves": [{**leaf, "leaf_hash": "ab"}] + m["leaves"][1:]}
    for k, bad in (("kind", "other"), ("repo", "no-slash"), ("path", ""), ("ref", ""), ("sha256", "z" * 64)):
        yield f"descriptor {k}", {**m, "leaves": [{**leaf, "descriptor": {**leaf["descriptor"], k: bad}}] + m["leaves"][1:]}
    yield "descriptor missing ref", {**m, "leaves": [{**leaf, "descriptor": {k: v for k, v in leaf["descriptor"].items() if k != "ref"}}]}
    src = m["sources"][0]
    for k, bad in (("read", "yes"), ("reason", 1), ("head", "abc"), ("tags", [{"name": "v1", "commit": "x"}]), ("absent", [1]),
                   ("release_assets", {"read": True, "reason": None, "count": -1}), ("release_assets", {"read": True, "reason": None})):
        yield f"source {k}", {**m, "sources": [{**src, k: bad}]}
    yield "source head null", {**m, "sources": [{**src, "head": None}]}
    yield "source with a tag", {**m, "sources": [{**src, "tags": [{"name": "v1", "commit": "a" * 40}]}]}
    yield "previous set", {**m, "previous": {"path": "2026/10/17/070000Z", "root": "a" * 64}}
    yield "previous bad root", {**m, "previous": {"path": "p", "root": "x"}}
    pr = m["proofs"]
    yield "preimage name", {**m, "proofs": {**pr, "preimage": "other"}}
    yield "one calendar", {**m, "proofs": {**pr, "opentimestamps": {**pr["opentimestamps"], "accepted_by": ["a"]}}}
    yield "failed calendar", {**m, "proofs": {**pr, "opentimestamps": {**pr["opentimestamps"], "failed": [{"calendar": "c", "error": "e"}]}}}
    yield "one token", {**m, "proofs": {**pr, "rfc3161": pr["rfc3161"][:1]}}
    tok = pr["rfc3161"][0]
    for k, bad in (("serial", "0FA1"), ("gen_time", "2026-10-17T08:04:12Z"), ("policy", 1)):
        yield f"token {k}", {**m, "proofs": {**pr, "rfc3161": [{**tok, k: bad}] + pr["rfc3161"][1:]}}


def test_manifest_schema_check_agrees_with_published_schema():
    """v0_problems against the Ledger's schemas/anchor-manifest-v0.schema.json
    (when FM_LEDGER_REPO holds it): the same verdict on every mutation."""
    import os

    jsonschema = pytest.importorskip("jsonschema")
    base = os.environ.get("FM_LEDGER_REPO")
    schema_path = Path(base or "") / "schemas" / "anchor-manifest-v0.schema.json"
    if not base or not schema_path.is_file():
        pytest.skip("set FM_LEDGER_REPO to a checkout holding schemas/anchor-manifest-v0.schema.json")
    validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text()))
    assert validator.is_valid(_valid_manifest()) and not ledger_anchors.v0_problems(_valid_manifest())
    for what, m in _mutations():
        assert validator.is_valid(m) == (not ledger_anchors.v0_problems(m)), what


def test_manifest_schema_check_on_mutations():
    """Without the published schema: every mutation that breaks a stated
    constraint is caught, and the allowed ones pass."""
    allowed = {"source head null", "source with a tag", "previous set", "failed calendar"}
    for what, m in _mutations():
        assert (not ledger_anchors.v0_problems(m)) == (what in allowed), what


def test_index_path_outside_is_refused(tmp_path):
    import shutil

    shutil.copytree(FIX / "ledger-anchors" / "set-valid", tmp_path / "set")
    idx = tmp_path / "set" / "index.jsonl"
    lines = idx.read_text().splitlines()
    first = json.loads(lines[0])
    lines[0] = json.dumps({**first, "path": "../../" + first["path"]})
    idx.write_text("\n".join(lines) + "\n")
    c = ledger_anchors.check_index(tmp_path / "set", ledger_anchors.find_anchor_dirs(tmp_path / "set"))
    assert c.status.value == "fail" and any("not a relative path inside" in r for r in c.reasons)


def test_ledger_probe_proofs():
    """The Ledger's recorded responses (fixtures/anchor/ in its repository,
    when FM_LEDGER_REPO holds them): DigiCert's and Sectigo's tokens over
    probe.bin verify against the roots it ships in anchors/tsa/, and its
    OpenTimestamps proof is well formed and pending."""
    import os

    from fmverify import ots, pki, rfc3161
    from fmverify.verdict import Outcome

    base = Path(os.environ.get("FM_LEDGER_REPO") or "")
    probe = base / "fixtures" / "anchor" / "probe.bin"
    if not os.environ.get("FM_LEDGER_REPO") or not probe.is_file():
        pytest.skip("set FM_LEDGER_REPO to a checkout holding fixtures/anchor/")
    data = probe.read_bytes()
    roots = {name: pki.load_certificates((base / "anchors" / "tsa" / f"{name}.pem").read_bytes()) for name in ("digicert", "sectigo")}
    assert pki.fingerprint(roots["digicert"][0]) == "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"
    assert pki.fingerprint(roots["sectigo"][0]) == "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2"
    for name in ("digicert", "sectigo"):
        v = rfc3161.verify((probe.parent / f"probe.bin.{name}.tsr").read_bytes(), file_bytes=data, roots=roots[name])
        assert v.outcome is Outcome.VALID, v.to_text()
        other = "sectigo" if name == "digicert" else "digicert"
        assert rfc3161.verify((probe.parent / f"probe.bin.{name}.tsr").read_bytes(), file_bytes=data,
                              roots=roots[other]).outcome is Outcome.INVALID
    v = ots.verify((probe.parent / "probe.bin.ots").read_bytes(), file_bytes=data)
    assert v.outcome is Outcome.INDETERMINATE and any(c.id == "ots.pending" for c in v.checks)


def test_checkout_of_a_tag(tmp_path):
    """--repo OWNER/NAME@TAG=PATH compares the descriptors read at that tag;
    a release asset is looked for by name; a path climbing out is not read."""
    tag_tree = tmp_path / "core-R1"
    (tag_tree / "dataset" / "releases" / "R1").mkdir(parents=True)
    manifest_bytes = b'{"release": "R1"}\n'
    (tag_tree / "dataset" / "releases" / "R1" / "manifest.json").write_bytes(manifest_bytes)
    (tag_tree / "assets-manifest.json").write_bytes(b"asset\n")
    (tmp_path / "secret").write_bytes(b"not for reading\n")

    def desc(kind, path, ref, data):
        return {"kind": kind, "path": path, "ref": ref, "repo": "o/core", "sha256": sha256(data).hex()}

    descs = [desc("release_manifest", "dataset/releases/R1/manifest.json", "R1", manifest_bytes),
             desc("release_asset_manifest", "release-asset:assets-manifest.json", "R1", b"asset\n"),
             desc("release_manifest", "../secret", "R1", b"not for reading\n"),
             desc("standing_rulings", "docs/STANDING_RULINGS.md", "main", b"rulings\n")]
    leaves = ledger_anchors.sorted_leaves(descs)
    d = tmp_path / "anchor"
    d.mkdir()
    (d / "root.preimage").write_bytes(ledger_anchors.preimage_for(leaves))
    (d / "manifest.json").write_text(json.dumps({"leaves": [{"descriptor": json.loads(x)} for x in leaves]}))
    v = ledger_anchors.verify_dir(d, repos={"o/core@R1": tag_tree, "o/core": tag_tree})
    tagged = next(c for c in v.checks if c.id == "ledger_anchor.checkout.o/core@R1")
    assert sorted(tagged.data["matching"]) == ["dataset/releases/R1/manifest.json", "release-asset:assets-manifest.json"]
    assert tagged.data["absent"] == ["'../secret' (not a path inside the checkout; not read)"]
    default = next(c for c in v.checks if c.id == "ledger_anchor.checkout.o/core")
    assert default.data["absent"] == ["docs/STANDING_RULINGS.md"] and default.data["matching"] == []
