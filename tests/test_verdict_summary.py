"""The filed verdicts for a CI run's summary (tools/verdict_summary.py): every certificate verdict listed, and the
certificates committed with their verdicts verified again."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


@pytest.mark.skipif(not BUNDLE.is_file(), reason="the published record certificates' tokens chain to roots in the system bundle")
def test_every_filed_verdict_is_listed_and_the_published_ones_hold_again():
    done = subprocess.run([sys.executable, str(ROOT / "tools/verdict_summary.py")], cwd=ROOT, capture_output=True, text=True, check=False,
                          env={"PATH": "/usr/bin:/bin", "GITHUB_SHA": "f" * 40})
    assert done.returncode == 0, done.stdout + done.stderr
    rows = [line for line in done.stdout.splitlines() if line.startswith("| `urn:uuid:")]
    dirs = [p for p in (ROOT / "verdicts/certificates").iterdir() if p.is_dir()]
    assert len(rows) == len(dirs)
    published = [p for p in dirs if (p / "certificate.json").is_file() or (p / "certificate.pdf").is_file()]
    assert sum("verified again: valid" in r for r in rows) == len(published) >= 2
    assert all(f"/tree/{'f' * 40}/verdicts/" in r for r in rows)
