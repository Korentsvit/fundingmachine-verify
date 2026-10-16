"""House style shared with the other FundingMachine repositories: no em or en
dashes in any text file."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT = {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".txt", ".cfg"}


def test_no_em_or_en_dashes():
    bad = []
    for p in ROOT.rglob("*"):
        if any(part in {".git", ".venv", "build", "dist"} or part.endswith(".egg-info") for part in p.parts):
            continue
        if p.is_file() and p.suffix in TEXT:
            text = p.read_text(encoding="utf-8", errors="replace")
            if chr(0x2014) in text or chr(0x2013) in text:
                bad.append(str(p.relative_to(ROOT)))
    assert bad == []


def test_fixture_manifest_matches():
    import hashlib

    fix = ROOT / "fixtures"
    listed = {}
    for line in (fix / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    present = {p.relative_to(fix).as_posix() for p in fix.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    assert set(listed) == present
    for name, digest in listed.items():
        assert hashlib.sha256((fix / name).read_bytes()).hexdigest() == digest, name
