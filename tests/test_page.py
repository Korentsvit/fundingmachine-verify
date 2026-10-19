"""The anchors page (page/index.html, docs/HOSTED_PAGE.md section 11): one file whose only script and style are
inline and pinned by hash, loading nothing from elsewhere, and asking only the hosts its policy names."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build_page  # noqa: E402

HTML = (ROOT / "page" / "index.html").read_text(encoding="utf-8")


def _doc_policy() -> str:
    doc = (ROOT / "docs" / "HOSTED_PAGE.md").read_text(encoding="utf-8")
    return re.findall(r"```\n(default-src [^\n]*)\n```", doc)[1]


def test_the_policy_the_build_writes_is_the_one_the_specification_requires():
    assert build_page.POLICY == _doc_policy()
    filled = build_page.policy(HTML)
    assert "'unsafe-eval'" not in filled and "'unsafe-inline'" not in filled
    assert "HASH" not in filled
    assert filled.count("'sha256-") == 3


def test_one_inline_script_and_style_and_nothing_loaded_from_elsewhere():
    assert len(re.findall(r"<script\b", HTML)) == 1 and 'type="module"' in HTML
    assert len(re.findall(r"<style\b", HTML)) == 1
    assert not re.search(r"<script[^>]*\bsrc=", HTML)
    assert not re.search(r"<link\b|<img\b|<iframe\b|@import|url\(", HTML)
    assert not re.search(r"\bon[a-z]+=", HTML)  # no inline event handlers
    assert "innerHTML" not in HTML and "eval(" not in HTML and "new Function" not in HTML


def test_the_page_asks_only_the_hosts_its_policy_allows():
    connect = re.search(r"connect-src ([^;]*);", build_page.POLICY).group(1).split()
    allowed = {c for c in connect if c.startswith("https://")}
    script = HTML.split("<script", 1)[1]
    consts = dict(re.findall(r'^const (MIRROR|RECORD) = "(https://[^"/]+)', script, re.M))
    explorers = re.search(r"^const EXPLORERS = \[(.*?)\];", script, re.M).group(1)
    hosts = set(consts.values()) | set(re.findall(r'"(https://[^"/]+)"', explorers))
    assert hosts == allowed
    # Every request goes through get() or is the page's own site.json; get() is only called with those constants,
    # the explorers, or a file named in site.json.
    assert len(re.findall(r"\bfetch\(", script)) == 2 and 'fetch("site.json"' in script
    for arg in re.findall(r"(?<![.\w])get\(([^,)]+)", script)[1:]:
        assert re.match(r"`\$\{(base|RECORD|origin|MIRROR)\}|site\.(wheel\.file|roots_file)|url$", arg.strip()), arg


def test_the_report_frame_is_sandboxed_with_nothing_allowed():
    assert 'el("iframe", { sandbox: "", title:' in HTML


def test_the_roots_are_pinned_not_committed():
    assert {r["sha256"] for r in build_page.ROOTS} == {
        "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
        "e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2",
    }
    assert not list((ROOT / "page").glob("*.pem")) and not list((ROOT / "page").glob("*.crt"))


def test_the_default_commit_is_the_newest_verdicts():
    assert re.fullmatch(r"[0-9a-f]{40}", build_page.newest_verdict_commit() or "")


def _wheel(path: Path, name: str, version: str, licence: str, files: dict[str, str]) -> Path:
    import zipfile

    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                   f"{licence}\n\nLicense: not a header, the description\n")
        for n, text in files.items():
            z.writestr(f"{name}-{version}.dist-info/{n}", text)
    return path


def _pin(tmp_path: Path, data: bytes) -> tuple[dict, Path]:
    import hashlib

    whl = tmp_path / "fundingmachine_verify-0.2.0-py3-none-any.whl"
    whl.write_bytes(data)
    return {"tag": "v0.2.0", "commit": "a" * 40, "wheel": whl.name, "sha256": hashlib.sha256(data).hexdigest()}, whl


def test_the_release_wheel_is_kept_only_if_it_is_the_pinned_one(tmp_path):
    import pytest

    pin, whl = _pin(tmp_path, b"the release's wheel")
    assert build_page.release_wheel(pin, whl) == b"the release's wheel"
    for change in ({"sha256": "0" * 64}, {"tag": "v0.2"}, {"tag": "0.2.0"}, {"commit": "a" * 39},
                   {"wheel": "fundingmachine_verify-0.1.0-py3-none-any.whl"}):
        with pytest.raises(SystemExit):
            build_page.release_wheel({**pin, **change}, whl)
    other = tmp_path / "other.whl"
    other.write_bytes(b"the release's wheel")
    with pytest.raises(SystemExit):
        build_page.release_wheel(pin, other)


def test_the_licence_texts_are_pinned_from_each_project_at_the_version_served():
    assert [x["file"] for x in build_page.LICENCE_TEXTS] == ["LICENSE-pyodide.txt", "LICENSE-python.txt", "LICENSE-openssl.txt"]
    tags = {"LICENSE-pyodide.txt": "pyodide/pyodide/0.27.7/", "LICENSE-python.txt": "python/cpython/v3.12.7/",
            "LICENSE-openssl.txt": "openssl/openssl/OpenSSL_1_1_1w/"}
    for x in build_page.LICENCE_TEXTS:
        assert x["url"] == f"https://raw.githubusercontent.com/{tags[x['file']]}LICENSE"
        assert re.fullmatch(r"[0-9a-f]{64}", x["sha256"])
    assert build_page.PYODIDE == {"version": "0.27.7", "python": "3.12.7", "openssl": "1.1.1w"}


def test_notice_names_every_third_party_file_with_its_licence(tmp_path):
    fm = _wheel(tmp_path / "fundingmachine_verify-0.2.0-py3-none-any.whl", "fundingmachine_verify", "0.2.0",
                "License-Expression: Apache-2.0", {"licenses/LICENSE": "Apache"})
    _wheel(tmp_path / "cffi-1.17.1-cp312-cp312-pyodide_2024_0_wasm32.whl", "cffi", "1.17.1", "License: MIT",
           {"LICENSE": "MIT"})
    _wheel(tmp_path / "six-1.16.0-py2.py3-none-any.whl", "six", "1.16.0", "License: MIT", {})
    (tmp_path / "openssl-1.1.1w.zip").write_bytes(b"")
    info = {"fmverify": {"version": "0.2.0", "commit": "a" * 40, "tag": "v0.2.0", "changed": False,
                         "release": "https://github.com/Korentsvit/fundingmachine-verify/releases/tag/v0.2.0"},
            "wheel": {"file": fm.name},
            "roots": [{"name": r["name"], "authority": r["authority"], "url": r["url"], "sha256": r["sha256"],
                       "retrieved": "2026-10-19"} for r in build_page.ROOTS]}
    text = build_page.notice(tmp_path, info, build_page.LICENCE_TEXTS)
    assert "the release tagged v0.2.0 (commit " + "a" * 40 in text
    assert "Licence: Apache-2.0; its licence file is inside the wheel (fundingmachine_verify-0.2.0.dist-info/licenses/LICENSE)" in text
    assert "cffi 1.17.1" in text and "Licence, as its metadata states: MIT; its licence files are inside the wheel" in text
    assert "six 1.16.0" in text and "the wheel carries no licence file" in text
    assert "not a header" not in text
    assert "openssl-1.1.1w.zip" in text and "LICENSE-openssl.txt" in text
    for name in build_page.PYODIDE_FILES:
        assert name in text
    for r in build_page.ROOTS:
        assert r["url"] in text and r["sha256"] in text
    assert "No licence text accompanies either certificate" in text
    for x in build_page.LICENCE_TEXTS:
        assert f"{x['file']}: {x['of']}, from {x['url']} (SHA-256 {x['sha256']})" in text
    assert str(tmp_path) not in text
    assert chr(0x2013) not in text and chr(0x2014) not in text


def test_a_release_whose_wheel_lacks_what_the_page_imports_is_refused():
    import io
    import zipfile

    script = HTML.split("<script", 1)[1]
    imported = re.search(r"from fmverify\.api import ([\w, ]+)", script).group(1)
    assert tuple(n.strip() for n in imported.split(",")) == build_page.PAGE_NEEDS

    def wheel(api: str | None) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            if api is not None:
                z.writestr("fmverify/api.py", api)
        return buf.getvalue()

    assert build_page.page_can_run(wheel((ROOT / "src" / "fmverify" / "api.py").read_text(encoding="utf-8"))) == []
    assert build_page.page_can_run(wheel("def verify_json(s):\n    pass\n")) == ["bitcoin_heights"]
    assert build_page.page_can_run(wheel(None)) == ["verify_json", "bitcoin_heights"]
