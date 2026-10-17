import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _doc_policy() -> str:
    doc = (ROOT / "docs" / "HOSTED_PAGE.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```\n(default-src [^\n]*)\n```", doc)
    assert len(blocks) == 2  # hosted-page/0, section 3, and the anchors page of hosted-page/1, section 11
    return blocks[0]


def _check_policy() -> str:
    js = (ROOT / "tools" / "pyodide" / "policy" / "check.mjs").read_text(encoding="utf-8")
    expr = re.search(r"const POLICY = (.*?);\n", js, re.S).group(1)
    return "".join(re.findall(r'"([^"]*)"', expr))


def test_the_policy_ci_checks_is_the_one_the_specification_requires():
    assert _check_policy() == _doc_policy()
    policy = _doc_policy()
    assert "'unsafe-eval'" not in policy and "'unsafe-inline'" not in policy
    assert "STYLE_HASH" in policy  # filled with fmverify.report.CSP_STYLE_HASH
