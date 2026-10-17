"""Assemble the anchors verifier page (page/index.html, docs/HOSTED_PAGE.md section 11) into a static site.

    python tools/build_page.py SITE --pyodide DIR

DIR is the `pyodide` npm package of the pinned version (`npm install pyodide@0.27.7`, then
node_modules/pyodide). SITE receives:

* index.html, as committed;
* Pyodide's five runtime files from DIR, and cryptography with what it depends on from Pyodide's distribution,
  each kept only if its SHA-256 is the one pyodide-lock.json names (tools/pyodide/policy/fetch_packages.py);
* the fm-verify wheel, built by tools/build_release.py from this checkout;
* roots.pem: the two time-stamping authorities' roots, fetched from each authority's own publication and kept only
  if its SHA-256 is the fingerprint pinned below. They are third-party files and are not committed;
* site.json, which the page reads: the wheel and its SHA-256, the versions, the roots with their provenance, and
  the commit of the newest verdict under verdicts/ledger-anchors/ as the page's default;
* csp.txt and _headers: the Content Security Policy, with the hashes of the page's one inline script and one inline
  style and of the verifier's report style, and the other headers the page must be served with;
* SHA256SUMS of every file above.

Nothing in SITE is served by this tool; any static host that sends _headers' headers will do.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools" / "pyodide" / "policy"))

PYODIDE_FILES = ("pyodide.mjs", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json")

# Each authority's root, from its own publication, pinned by the SHA-256 of the certificate (DER). The same two
# roots the Ledger's anchors chain to (verdicts/ledger-anchors/*/README.md).
ROOTS = [
    {"name": "DigiCert Trusted Root G4", "authority": "DigiCert",
     "url": "https://cacerts.digicert.com/DigiCertTrustedRootG4.crt",
     "sha256": "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"},
    {"name": "USERTrust RSA Certification Authority", "authority": "Sectigo",
     "url": "http://crt.usertrust.com/USERTrustRSACertificationAuthority.crt",
     "sha256": "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2"},
]

# docs/HOSTED_PAGE.md, section 11; tests/test_page.py checks the two agree.
POLICY = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval' SCRIPT_HASH; "
          "connect-src 'self' https://raw.githubusercontent.com https://fundingmachine-ledger.vercel.app "
          "https://mempool.space https://blockstream.info; style-src PAGE_STYLE_HASH REPORT_STYLE_HASH; img-src 'self'; "
          "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
OTHER_HEADERS = {
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


def csp_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


def inline(html: str, tag: str) -> str:
    """The text of the page's one inline element of this tag."""
    found = re.findall(rf"<{tag}(?:\s[^>]*)?>(.*?)</{tag}>", html, flags=re.S)
    if len(found) != 1:
        raise SystemExit(f"page/index.html must hold exactly one inline <{tag}>, it holds {len(found)}")
    return found[0]


def policy(html: str) -> str:
    from fmverify.report import CSP_STYLE_HASH

    return (POLICY.replace("SCRIPT_HASH", csp_hash(inline(html, "script")))
            .replace("PAGE_STYLE_HASH", csp_hash(inline(html, "style")))
            .replace("REPORT_STYLE_HASH", CSP_STYLE_HASH))


def newest_verdict_commit() -> str | None:
    dirs = sorted((ROOT / "verdicts" / "ledger-anchors").glob("*/README.md"))
    for readme in reversed(dirs):
        m = re.search(r"\*\*The commit read\.\*\* `([0-9a-f]{40})`", readme.read_text(encoding="utf-8"))
        if m:
            return m.group(1)
    return None


def fetch_roots(site: Path) -> list[dict]:
    pems, out = [], []
    for r in ROOTS:
        with urllib.request.urlopen(r["url"], timeout=60) as resp:
            der = resp.read()
        if hashlib.sha256(der).hexdigest() != r["sha256"]:
            raise SystemExit(f"{r['url']}: SHA-256 is not the pinned {r['sha256']}")
        b64 = base64.b64encode(der).decode("ascii")
        pems.append("-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
                    + "\n-----END CERTIFICATE-----\n")
        out.append({**r, "retrieved": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")})
    (site / "roots.pem").write_text("".join(pems), encoding="ascii")
    return out


def git(*args: str) -> str | None:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("site", type=Path)
    ap.add_argument("--pyodide", type=Path, required=True, help="the pyodide npm package directory")
    a = ap.parse_args(argv)
    site: Path = a.site
    site.mkdir(parents=True, exist_ok=True)
    html = (ROOT / "page" / "index.html").read_text(encoding="utf-8")
    (site / "index.html").write_text(html, encoding="utf-8")
    for name in PYODIDE_FILES:
        shutil.copyfile(a.pyodide / name, site / name)
    lock = json.loads((site / "pyodide-lock.json").read_text(encoding="utf-8"))

    import fetch_packages

    if fetch_packages.main([str(site), "cryptography"]) != 0:
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(ROOT / "tools" / "build_release.py"), tmp], check=True, cwd=ROOT,
                       stdout=subprocess.DEVNULL)
        wheel = next(Path(tmp).glob("*.whl"))
        shutil.copyfile(wheel, site / wheel.name)
    from fmverify import __version__

    commit = git("rev-parse", "HEAD")
    info = {
        "fmverify": {"version": __version__, "commit": commit, "tag": git("describe", "--tags", "--exact-match", "HEAD"),
                     "changed": bool(git("status", "--porcelain", "--", "src", "pyproject.toml", "page"))},
        "wheel": {"file": wheel.name, "sha256": hashlib.sha256((site / wheel.name).read_bytes()).hexdigest()},
        "pyodide": {"version": lock["info"]["version"], "cryptography": lock["packages"]["cryptography"]["version"]},
        "roots": fetch_roots(site),
        "roots_file": "roots.pem",
        "default_commit": newest_verdict_commit(),
    }
    (site / "site.json").write_text(json.dumps(info, indent=1) + "\n", encoding="utf-8")
    csp = policy(html)
    (site / "csp.txt").write_text(csp + "\n", encoding="utf-8")
    lines = ["/*", f"  Content-Security-Policy: {csp}", *[f"  {k}: {v}" for k, v in OTHER_HEADERS.items()]]
    (site / "_headers").write_text("\n".join(lines) + "\n", encoding="utf-8")
    sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(site.iterdir())
            if p.is_file() and p.name != "SHA256SUMS"]
    (site / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(f"{site}: {len(sums)} files; wheel {info['wheel']['sha256']}; policy {csp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
