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
