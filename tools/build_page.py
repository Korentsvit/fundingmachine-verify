"""Assemble the anchors verifier page (page/index.html, docs/HOSTED_PAGE.md section 11) into a static site.

    python tools/build_page.py SITE --pyodide DIR [--release page/release.json [--wheel FILE]]

DIR is the `pyodide` npm package of the pinned version (`npm install pyodide@0.27.7`, then
node_modules/pyodide). SITE receives:

* index.html, as committed;
* Pyodide's five runtime files from DIR, and cryptography with what it depends on from Pyodide's distribution,
  each kept only if its SHA-256 is the one pyodide-lock.json names (tools/pyodide/policy/fetch_packages.py);
* the fm-verify wheel: with --release, the wheel of the tagged release the pin file names, downloaded from the
  release (or given with --wheel) and kept only if its SHA-256 is the pinned one; without it, a wheel built by
  tools/build_release.py from this checkout, which the page shows as not a tagged release;
* roots.pem: the two time-stamping authorities' roots, fetched from each authority's own publication and kept only
  if its SHA-256 is the fingerprint pinned below. They are third-party files and are not committed;
* NOTICE, with the licence texts it names: every third-party file served, its version, the licence its own
  package states, and where its source is. Licence texts a package does not carry are fetched from the project's
  own repository at the version served and kept only if their SHA-256 is pinned below;
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

# The Pyodide distribution the licence texts below are pinned for (pyodide-lock.json's own statements).
PYODIDE = {"version": "0.27.7", "python": "3.12.7", "openssl": "1.1.1w"}

# Licence texts the served packages do not carry themselves, each from its project's own repository at the version
# served, pinned by SHA-256. The wheels carry their licence files inside them, and NOTICE names those.
LICENCE_TEXTS = [
    {"file": "LICENSE-pyodide.txt", "of": "Pyodide 0.27.7", "licence": "Mozilla Public License 2.0",
     "url": "https://raw.githubusercontent.com/pyodide/pyodide/0.27.7/LICENSE",
     "sha256": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"},
    {"file": "LICENSE-python.txt", "of": "CPython 3.12.7, the Python Pyodide 0.27.7 runs (python_stdlib.zip)",
     "licence": "the Python Software Foundation License and the other terms in CPython's LICENSE",
     "url": "https://raw.githubusercontent.com/python/cpython/v3.12.7/LICENSE",
     "sha256": "3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf"},
    {"file": "LICENSE-openssl.txt", "of": "OpenSSL 1.1.1w (openssl-1.1.1w.zip, which holds no licence file)",
     "licence": "the OpenSSL License and the original SSLeay License, in OpenSSL's LICENSE",
     "url": "https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1w/LICENSE",
     "sha256": "c32913b33252e71190af2066f08115c69bc9fddadf3bf29296e20c835389841c"},
]
SOURCE = "https://github.com/Korentsvit/fundingmachine-verify"

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


def fetch_pinned(url: str, sha256: str) -> bytes:
    """The bytes at url, refused unless their SHA-256 is the pinned one."""
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise SystemExit(f"{url}: SHA-256 is not the pinned {sha256}")
    return data


def release_wheel(pin: dict, local: Path | None = None) -> bytes:
    """The wheel of the release a pin file names (page/release.json): from the release's own address, or the local
    copy given, kept only if its name and SHA-256 are the pinned ones."""
    if not re.fullmatch(r"v\d+\.\d+\.\d+", pin.get("tag", "")) or not re.fullmatch(r"[0-9a-f]{40}", pin.get("commit", "")):
        raise SystemExit("the pin file must name a tag vX.Y.Z and the full commit it is on")
    version = pin["tag"][1:]
    if pin.get("wheel") != f"fundingmachine_verify-{version}-py3-none-any.whl":
        raise SystemExit(f"the pin file names the wheel {pin.get('wheel')!r}, not the one of {pin['tag']}")
    if local is not None:
        if local.name != pin["wheel"]:
            raise SystemExit(f"{local} is not {pin['wheel']}")
        data = local.read_bytes()
        if hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise SystemExit(f"{local}: SHA-256 is not the pinned {pin['sha256']}")
        return data
    return fetch_pinned(f"{SOURCE}/releases/download/{pin['tag']}/{pin['wheel']}", pin["sha256"])


# What the page imports from the wheel (page/index.html); a release without them cannot run the page.
PAGE_NEEDS = ("verify_json", "bitcoin_heights")


def page_can_run(wheel: bytes) -> list[str]:
    """What the page needs that the wheel's fmverify/api.py does not define, read without running it."""
    import ast
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(wheel)) as z:
        if "fmverify/api.py" not in z.namelist():
            return list(PAGE_NEEDS)
        tree = ast.parse(z.read("fmverify/api.py"))
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    return [n for n in PAGE_NEEDS if n not in defined]


def wheel_licence(path: Path) -> dict:
    """What a wheel states about itself: its name, version, licence and the licence files it carries."""
    import zipfile

    with zipfile.ZipFile(path) as z:
        meta_name = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        fields: dict[str, str] = {}
        for line in z.read(meta_name).decode("utf-8").split("\n\n", 1)[0].splitlines():
            key, sep, value = line.partition(": ")
            if sep and key in ("Name", "Version", "License", "License-Expression") and key not in fields:
                fields[key] = value.strip()
        files = sorted(n for n in z.namelist() if ".dist-info/" in n and re.search(r"LICEN[CS]E|COPYING|NOTICE", n, re.I))
    return {"name": fields.get("Name", path.name), "version": fields.get("Version", "?"),
            "licence": fields.get("License-Expression") or fields.get("License") or "not stated in its metadata",
            "files": files}


def notice(site: Path, info: dict, licence_texts: list[dict]) -> str:
    """NOTICE for the site: every file it serves that is not this repository's own page, with its licence."""
    fm = info["fmverify"]
    lines = ["NOTICE", "", "This site serves the fm-verify page and, beside it, files of other projects, each unchanged but for the roots' "
             "encoding (below).", ""]
    wheel = wheel_licence(site / info["wheel"]["file"])
    origin = f"the release tagged {fm['tag']}" if fm.get("release") else "a build of this repository"
    lines += [f"{info['wheel']['file']}", f"  fm-verify {wheel['version']}, {origin} (commit {fm['commit']}).",
              f"  Licence: {wheel['licence']}; its licence file is inside the wheel ({', '.join(wheel['files'])}).",
              f"  Source: {SOURCE}", ""]
    lines += ["index.html, site.json, csp.txt, _headers, NOTICE, SHA256SUMS",
              f"  This repository's own files, Apache-2.0. Source: {SOURCE}", ""]
    t = {x["file"]: x for x in licence_texts}
    lines += [", ".join(PYODIDE_FILES), f"  Pyodide {PYODIDE['version']}. Licence: {t['LICENSE-pyodide.txt']['licence']}, "
              f"as its npm package states; the text is LICENSE-pyodide.txt.",
              f"  It runs CPython {PYODIDE['python']}, whose licence is LICENSE-python.txt.",
              f"  Source: https://github.com/pyodide/pyodide/tree/{PYODIDE['version']}", ""]
    for whl in sorted(site.glob("*.whl")):
        if whl.name == info["wheel"]["file"]:
            continue
        w = wheel_licence(whl)
        carried = f"its licence files are inside the wheel ({', '.join(w['files'])})" if w["files"] else "the wheel carries no licence file"
        lines += [whl.name, f"  {w['name']} {w['version']}, from Pyodide {PYODIDE['version']}'s distribution.",
                  f"  Licence, as its metadata states: {w['licence']}; {carried}.", ""]
    for z in sorted(site.glob("openssl-*.zip")):
        lines += [z.name, f"  {t['LICENSE-openssl.txt']['of']}, from Pyodide {PYODIDE['version']}'s distribution.",
                  f"  Licence: {t['LICENSE-openssl.txt']['licence']}; the text is LICENSE-openssl.txt.", ""]
    lines += ["roots.pem"]
    for r in info["roots"]:
        lines += [f"  {r['name']}, the root {r['authority']}'s time-stamping certificates chain to, from {r['url']}",
                  f"  (retrieved {r['retrieved']}, SHA-256 of the certificate as published {r['sha256']}), converted from DER to PEM."]
    lines += ["  No licence text accompanies either certificate at its publisher's address. They are served as the",
              "  trust anchors for the authorities' tokens, by the owner's decision of 19 October 2026.", ""]
    lines += ["Licence texts, each from its project's own repository at the version served:"]
    lines += [f"  {x['file']}: {x['of']}, from {x['url']} (SHA-256 {x['sha256']})" for x in licence_texts]
    return "\n".join(lines) + "\n"


def fetch_roots(site: Path) -> list[dict]:
    pems, out = [], []
    for r in ROOTS:
        der = fetch_pinned(r["url"], r["sha256"])
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
    ap.add_argument("--release", type=Path, help="a pin file (page/release.json): serve that release's own wheel")
    ap.add_argument("--wheel", type=Path, help="with --release: the release's wheel as a local file, not downloaded")
    a = ap.parse_args(argv)
    if a.wheel and not a.release:
        ap.error("--wheel needs --release")
    site: Path = a.site
    site.mkdir(parents=True, exist_ok=True)
    html = (ROOT / "page" / "index.html").read_text(encoding="utf-8")
    (site / "index.html").write_text(html, encoding="utf-8")
    for name in PYODIDE_FILES:
        shutil.copyfile(a.pyodide / name, site / name)
    lock = json.loads((site / "pyodide-lock.json").read_text(encoding="utf-8"))
    stated = {"version": lock["info"]["version"], "python": lock["info"]["python"],
              "openssl": lock["packages"]["openssl"]["version"]}
    if stated != PYODIDE:
        raise SystemExit(f"the licence texts are pinned for {PYODIDE}; this Pyodide states {stated}")

    import fetch_packages

    if fetch_packages.main([str(site), "cryptography"]) != 0:
        return 1
    from fmverify import __version__

    if a.release:
        pin = json.loads(a.release.read_text(encoding="utf-8"))
        data = release_wheel(pin, a.wheel)
        if missing := page_can_run(data):
            raise SystemExit(f"{pin['tag']}'s wheel does not define what the page imports: {', '.join(missing)}")
        (site / pin["wheel"]).write_bytes(data)
        wheel_name = pin["wheel"]
        fm = {"version": pin["tag"][1:], "commit": pin["commit"], "tag": pin["tag"], "changed": False,
              "release": f"{SOURCE}/releases/tag/{pin['tag']}"}
    else:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run([sys.executable, str(ROOT / "tools" / "build_release.py"), tmp], check=True, cwd=ROOT,
                           stdout=subprocess.DEVNULL)
            wheel = next(Path(tmp).glob("*.whl"))
            shutil.copyfile(wheel, site / wheel.name)
            wheel_name = wheel.name
        fm = {"version": __version__, "commit": git("rev-parse", "HEAD"),
              "tag": git("describe", "--tags", "--exact-match", "HEAD"),
              "changed": bool(git("status", "--porcelain", "--", "src", "pyproject.toml", "page")), "release": None}
    info = {
        "fmverify": fm,
        "wheel": {"file": wheel_name, "sha256": hashlib.sha256((site / wheel_name).read_bytes()).hexdigest(),
                  "url": f"{SOURCE}/releases/download/{fm['tag']}/{wheel_name}" if fm["release"] else None},
        "pyodide": {"version": lock["info"]["version"], "cryptography": lock["packages"]["cryptography"]["version"]},
        "roots": fetch_roots(site),
        "roots_file": "roots.pem",
        "default_commit": newest_verdict_commit(),
    }
    for x in LICENCE_TEXTS:
        (site / x["file"]).write_bytes(fetch_pinned(x["url"], x["sha256"]))
    (site / "NOTICE").write_text(notice(site, info, LICENCE_TEXTS), encoding="utf-8")
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
