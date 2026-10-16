"""The conformance suite: run every published fixture case and compare the
verdict with what the case expects.

    fm-verify conformance [FIXTURES_DIR]

Each case is a directory holding ``expected.json``: the kind (from the
directory it sits under: ``ots``, ``rfc3161``, ``anchors``, ``certificate``, ``chain``), the inputs, the
outcome the verifier must reach, the checks that must fail (``failing``,
exactly) and those that must warn (``warning``, at least). The fixture
manifest ``SHA256SUMS`` is checked first, so a run says whether the fixtures
are the published ones. The format is written down in docs/CONFORMANCE.md
for other implementations to use.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import anchors, certificate, ledger_anchors, ledger_events, ots, pki, rfc3161
from .bitcoin import NETWORKS, HeaderChain, HeaderSet
from .verdict import Status, Verdict

KINDS = ("ots", "rfc3161", "anchors", "ledger-anchors", "certificate", "chain")


@dataclass
class CaseResult:
    kind: str
    name: str
    expected: str
    got: str
    ok: bool
    problems: list[str] = field(default_factory=list)
    description: str = ""


def check_manifest(fixtures: Path) -> list[str]:
    """Differences between the fixtures on disk and SHA256SUMS; empty when they match."""
    sums = fixtures / "SHA256SUMS"
    if not sums.is_file():
        return ["SHA256SUMS is missing"]
    listed = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    present = {p.relative_to(fixtures).as_posix() for p in fixtures.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    problems = [f"not listed: {n}" for n in sorted(present - set(listed))]
    problems += [f"missing: {n}" for n in sorted(set(listed) - present)]
    for name in sorted(set(listed) & present):
        if hashlib.sha256((fixtures / name).read_bytes()).hexdigest() != listed[name]:
            problems.append(f"changed: {name}")
    return problems


def _certs(case: Path, paths) -> list:
    return [c for p in paths for c in pki.load_certificates((case / p).read_bytes())]


def _sources(case: Path, exp: dict) -> list:
    net = NETWORKS[exp.get("network", "mainnet")]
    out = [HeaderChain.from_file(case / s["path"], s.get("start", 0), net) for s in exp.get("headers_chain", [])]
    out += [HeaderSet.from_file(case / p, net) for p in exp.get("headers", [])]
    return out


def run_case(kind: str, case: Path) -> tuple[dict, Verdict]:
    exp = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    net = NETWORKS[exp.get("network", "mainnet")]
    roots, chain = _certs(case, exp.get("roots", [])), _certs(case, exp.get("chain", []))
    crls = [c for p in exp.get("crls", []) for c in pki.load_crls((case / p).read_bytes())]
    if kind == "ots":
        v = ots.verify_file(case / "proof.ots", _sources(case, exp), file_path=case / exp["file"], network=net)
    elif kind == "rfc3161":
        v = rfc3161.verify_file(case / "token.tsr", case / exp["file"], roots=roots, extra_certs=chain, crls=crls)
    elif kind == "anchors":
        repo = case / exp["repo_root"] if "repo_root" in exp else None
        files = [repo / f for f in exp.get("files", [])] if repo is not None else []
        v = anchors.verify_batch(case, repo_root=repo, files=files, header_sources=_sources(case, exp), network=net,
                                 roots=roots, extra_certs=chain, crls=crls)
    elif kind == "ledger-anchors":
        v = ledger_anchors.verify_dir(case, repos={k: case / p for k, p in exp.get("repos", {}).items()},
                                      header_sources=_sources(case, exp), network=net, roots=roots, extra_certs=chain, crls=crls)
    elif kind == "certificate":
        events = json.loads((case / exp["events"]).read_text(encoding="utf-8"))["events"] if "events" in exp else None
        v = certificate.verify_file(case / "certificate.json", case / exp["file"] if "file" in exp else None,
                                    header_sources=_sources(case, exp), network=net, roots=roots, extra_certs=chain, crls=crls,
                                    events=events)
    elif kind == "chain":
        v = ledger_events.verify(json.loads((case / "events.json").read_text(encoding="utf-8"))["events"])
    else:
        raise ValueError(f"unknown kind {kind}")
    return exp, v


def compare(exp: dict, v: Verdict) -> list[str]:
    problems = []
    if "code" in exp:
        got = next((c.data.get("code") for c in v.checks if c.id == "chain.rules"), None)
        index = next((c.data.get("index") for c in v.checks if c.id == "chain.rules"), None)
        if (got, index) != (exp["code"], exp.get("index")):
            problems.append(f"chain stops at index {index} with {got}, expected index {exp.get('index')} with {exp['code']}")
    if v.outcome.value != exp["outcome"]:
        problems.append(f"outcome {v.outcome.value}, expected {exp['outcome']}")
    failing = [c.id for c in v.checks if c.status is Status.FAIL]
    if failing != exp.get("failing", []):
        problems.append(f"failing checks {failing}, expected {exp.get('failing', [])}")
    warned = {c.id for c in v.checks if c.status is Status.WARN}
    missing = [w for w in exp.get("warning", []) if w not in warned]
    if missing:
        problems.append(f"expected warnings not given: {missing}")
    if not v.statement or not v.checks or not v.does_not_establish:
        problems.append("the verdict lacks a statement, its checks, or its limits")
    return problems


def cases(fixtures: Path) -> list[tuple[str, Path]]:
    out = []
    for kind in KINDS:
        d = fixtures / kind
        if d.is_dir():
            out += [(kind, p) for p in sorted(d.iterdir()) if (p / "expected.json").is_file()]
    return out


def run_suite(fixtures: str | Path) -> tuple[list[str], list[CaseResult]]:
    fixtures = Path(fixtures)
    results = []
    for kind, case in cases(fixtures):
        try:
            exp, v = run_case(kind, case)
            problems = compare(exp, v)
            results.append(CaseResult(kind, case.name, exp["outcome"], v.outcome.value, not problems, problems,
                                      exp.get("description", "")))
        except Exception as exc:  # a crash is a conformance failure, reported, never hidden
            results.append(CaseResult(kind, case.name, "?", "error", False, [f"{type(exc).__name__}: {exc}"]))
    return check_manifest(fixtures), results


def report(manifest_problems: list[str], results: list[CaseResult]) -> str:
    lines = []
    if manifest_problems:
        lines.append(f"Fixtures differ from SHA256SUMS ({len(manifest_problems)}):")
        lines += [f"  {p}" for p in manifest_problems[:20]]
    else:
        lines.append("Fixtures match SHA256SUMS.")
    width = max((len(f"{r.kind}/{r.name}") for r in results), default=10)
    lines.append("")
    for r in results:
        mark = "ok  " if r.ok else "FAIL"
        lines.append(f"{mark} {f'{r.kind}/{r.name}':<{width}}  expected {r.expected:<13} got {r.got}")
        for p in r.problems:
            lines.append(f"       {p}")
    passed = sum(r.ok for r in results)
    lines += ["", f"{passed} of {len(results)} cases conform" + ("" if not manifest_problems else "; the fixtures are not the published ones")]
    return "\n".join(lines)
