"""Write a dated verdict on the Provenance Ledger's anchors from a checkout of its public mirror.

    git clone https://github.com/Korentsvit/fundingmachine-anchors
    python tools/fetch_headers.py fundingmachine-anchors/anchors headers.txt   # two explorers, compared
    python tools/fetch_ledger_record.py record                                 # optional: the HTTP record
    python tools/anchor_verdict.py fundingmachine-anchors verdicts/ledger-anchors --headers headers.txt \\
        --roots /etc/ssl/certs/ca-certificates.crt [--record record]

Creates OUT/<the UTC minute it was checked, YYYY-MM-DDTHHMMZ>/ holding:

* verdict.txt: the verdict on the whole set, as `fm-verify anchors --all` prints it, with the index and the links;
* anchors/<path>.txt: each anchor's own verdict, as `fm-verify anchors <path>` prints it;
* headers.txt: the Bitcoin block headers relied on, as given;
* listing.json: the HTTP record's listing, when --record names a copy made by tools/fetch_ledger_record.py;
* README.md: the source, the cross-checks, what the verdict relied on, a row per anchor, how the newest verdict
  already under OUT judged the same anchors, what the mirror's history adds, and how to reproduce it.

An anchor whose OpenTimestamps proof is still pending at the calendars, with every other check holding, is listed as
pending, with no verdict yet. Nothing is fetched here: the checkout, the headers and the roots are the inputs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fmverify import ledger_anchors, ots  # noqa: E402
from fmverify.bitcoin import NETWORKS, HeaderSet  # noqa: E402
from fmverify.cli import _certs, header_sources  # noqa: E402
from fmverify.verdict import now_utc  # noqa: E402
from mirror_conformance import anchor_state  # noqa: E402

MIRROR = "https://github.com/Korentsvit/fundingmachine-anchors"
RECORD = "https://fundingmachine-ledger.vercel.app/api/anchors"
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{4}Z")
ROW = re.compile(r"^\| (\d{4}/\d{2}/\d{2}/\d{6}Z)(?: \(new\))? \| [0-9a-f]+\.\.\. \| \d+ \| (valid|pending)[^|]*\| "
                 r"(?:(\d+) \(([^)]+)\) |[^|]*)\|")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def anchor_row(rel: str, v) -> dict:
    """What the README's table and text need from one anchor's verdict."""
    d = v.to_dict()
    checks = {c["id"]: c for c in d["checks"]}

    def data(cid: str) -> dict:
        return checks.get(cid, {}).get("data") or {}

    row = {"path": rel, "state": anchor_state(v), "root": data("ledger_anchor.preimage").get("root"),
           "leaves": data("ledger_anchor.leaves").get("leaves"), "block": None, "tokens": [],
           "failing": [c["id"] for c in d["checks"] if c["status"] == "fail"]}
    proof = data("ledger_anchor.ots").get("verdict")
    if proof:
        blocks = [x["data"] for x in proof["checks"] if x["id"].startswith("ots.bitcoin.") and x["status"] == "pass"]
        row["block"] = min(blocks, key=lambda b: b["height"]) if blocks else None
    for cid in sorted(checks):
        sub = data(cid).get("verdict") if cid.startswith("ledger_anchor.rfc3161.") else None
        if not sub:
            continue
        parts = {x["id"]: x.get("data") or {} for x in sub["checks"]}
        named = re.search(r"chains to (.+?), a root you trust", sub.get("statement", ""))
        row["tokens"].append({"outcome": sub["outcome"], "time": parts.get("rfc3161.parse", {}).get("gen_time"),
                              "authority": parts.get("rfc3161.signer_cert", {}).get("organization"),
                              "root_name": named.group(1) if named else None,
                              "root_sha256": (parts.get("rfc3161.chain", {}).get("path") or [None])[-1]})
    return row


def previous_rows(readme: Path) -> dict[str, dict]:
    """The rows of an earlier verdict's README: each anchor's state and earliest block."""
    rows = {}
    for line in readme.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            rows[m.group(1)] = {"state": "confirmed" if m.group(2) == "valid" else "pending",
                                "height": int(m.group(3)) if m.group(3) else None, "time": m.group(4)}
    return rows


def history(mirror: Path) -> dict:
    """Every change to anchors/ across the mirror's history, oldest first: what was removed, what changed, and
    whether each change is one the anchoring explains (index.jsonl growing; a pending proof gaining Bitcoin)."""
    log = git(mirror, "log", "--reverse", "--format=commit %H", "--name-status", "--no-renames", "--", "anchors")
    removed, changes, commit = [], [], None
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1]
        elif line.strip():
            status, _, path = line.partition("\t")
            if status.startswith("D"):
                removed.append(path)
            elif status.startswith("M"):
                changes.append((commit, path))
    index_changes = [c for c, p in changes if p == "anchors/index.jsonl"]
    grows, before = True, b""
    for c in git(mirror, "log", "--reverse", "--format=%H", "--", "anchors/index.jsonl").split():
        now = git_bytes(mirror, "show", f"{c}:anchors/index.jsonl")
        grows = grows and now.startswith(before)
        before = now
    upgrades: dict[str, int] = {}
    other = []
    for c, p in changes:
        if p == "anchors/index.jsonl":
            continue
        if p.endswith("/root.preimage.ots") and ots_upgrade(git_bytes(mirror, "show", f"{c}^:{p}"), git_bytes(mirror, "show", f"{c}:{p}")):
            upgrades[p] = upgrades.get(p, 0) + 1
        else:
            other.append(f"{p} at {c[:12]}")
    return {"removed": removed, "index_changes": len(index_changes), "index_grows": grows, "upgrades": upgrades,
            "other": other}


def ots_upgrade(old: bytes, new: bytes) -> bool:
    """The same proof's digest, with no Bitcoin attestation before and one after."""
    try:
        a, b = ots.parse(old), ots.parse(new)
    except ots.OtsError:
        return False

    def bitcoin(p) -> bool:
        return any(leaf.attestation.kind == "bitcoin" for leaf in ots.leaves(p.timestamp))

    return a.digest == b.digest and not bitcoin(a) and bitcoin(b)


def files_under(base: Path) -> dict[str, bytes]:
    return {p.relative_to(base).as_posix(): p.read_bytes() for p in sorted(base.rglob("*")) if p.is_file()}


def root_fingerprints(tsa: Path) -> dict[str, str]:
    """SHA-256 of each PEM certificate's DER under the mirror's anchors/tsa/."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    out = {}
    for pem in sorted(tsa.glob("*.pem")):
        for cert in x509.load_pem_x509_certificates(pem.read_bytes()):
            out[hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()] = pem.name
    return out


def shown(path: str) -> str:
    """A path as a verdict may print it: a system bundle by its path, anything else by its file name only."""
    return path if path.startswith(("/etc/", "/usr/")) else Path(path).name


def when(stamp: str) -> str:
    t = dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")
    return f"{t.day} {t:%B %Y}, {t:%H:%M} UTC"


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def readme(info: dict) -> str:
    rows, prev, h = info["rows"], info["previous"], info["history"]
    confirmed = [r for r in rows if r["state"] == "confirmed"]
    pending = [r for r in rows if r["state"] == "pending"]
    failed = [r for r in rows if r["state"] == "failed"]
    new = [r["path"] for r in rows if r["state"] == "confirmed" and (prev is None or prev["rows"].get(r["path"], {}).get("state") != "confirmed")]
    out = [f"# Ledger anchors, {when(info['checked_at'])}", "",
           "The Provenance Ledger's anchors, verified by fm-verify from the Ledger's", "public mirror repository.", ""]
    head = f"**Verdict: {plural(len(confirmed), 'anchor')} valid, confirmed in Bitcoin.**"
    if failed or info["outcome"] != "valid":
        head = (f"**Verdict: the set does not hold.** {info['statement']} Of the anchors, "
                f"{len(confirmed)} {'is' if len(confirmed) == 1 else 'are'} confirmed in Bitcoin.")
    if failed:
        head = (f"**Verdict: {plural(len(failed), 'anchor')} do{'es' if len(failed) == 1 else ''} not hold:** "
                + ", ".join(f"{r['path']} ({', '.join(r['failing']) or 'not checked'})" for r in failed)
                + f". {len(confirmed)} valid, confirmed in Bitcoin.")
    if len(pending) == 1:
        head += " One more anchor holds on its RFC 3161 tokens. Its Bitcoin proof is still pending, so it has no verdict yet."
    elif pending:
        head += (f" {len(pending)} more anchors hold on their RFC 3161 tokens. Their Bitcoin proofs are still pending,"
                 " so they have no verdict yet.")
    out.append(head)
    if prev is not None:
        out += ["", f"Since the [{prev['label']} verdict](../{prev['name']}), {plural(len(new), 'anchor has', 'anchors have')}"
                    " a verdict for the first time, marked \"new\" below."]
    s = info["source"]
    out += ["", "## Source", "",
            f"* **The mirror.** {MIRROR}, a public repository needing no login. It holds",
            "  the Ledger's `anchors` branch with its whole history.",
            f"* **The commit read.** `{s['commit']}`, from a checkout. It has",
            f"  {s['commits']} commits, the first being `{s['first']}`. Under `anchors/`",
            f"  it names {plural(len(rows), 'anchor')}."]
    rec = info.get("record")
    if rec:
        out += ["* **Cross-check: the Ledger's HTTP record.**",
                f"  * {RECORD}, copied by `tools/fetch_ledger_record.py`, which keeps a file only",
                "    if it matches the listing and the server's hash.",
                f"  * Its listing is [`listing.json`](listing.json), SHA-256",
                f"    `{rec['listing_sha256']}`. It names {plural(rec['anchors'], 'anchor')} and"
                f" {plural(rec['files'], 'file')}.",
                f"  * {rec['same']} of those files are identical, byte for byte, to the mirror's at that commit."]
        if rec["record_only"]:
            out.append(f"  * The record holds {plural(len(rec['record_only']), 'file')} the mirror does not: "
                       + ", ".join(f"`{p}`" for p in rec["record_only"]) + ".")
        if rec["differ"]:
            out.append(f"  * {plural(len(rec['differ']), 'file differs', 'files differ')}: "
                       + ", ".join(f"`{p}`" for p in rec["differ"]) + ".")
        if rec["mirror_only"]:
            out.append(f"  * The mirror holds {plural(len(rec['mirror_only']), 'more file')}: "
                       + ", ".join(f"`{p}`" for p in rec["mirror_only"]) + ". This verdict did not use "
                       + ("it." if len(rec["mirror_only"]) == 1 else "them."))
    else:
        out.append("* **Cross-checks.** The Ledger's HTTP record was not read for this verdict.")
    hd = info["headers"]
    out += ["", "## What the verdict relied on", ""]
    if hd["heights"]:
        out.append(f"* **Bitcoin block headers:** [`headers.txt`](headers.txt), {plural(len(hd['heights']), 'header')}"
                   + (f" at heights {min(hd['heights'])} to {max(hd['heights'])}." if len(hd["heights"]) > 1 else
                      f" at height {hd['heights'][0]}."))
    else:
        out.append("* **Bitcoin block headers:** the header chain " + ", ".join(f"`{Path(c).name}`" for c in hd["chains"]) + ".")
    if hd["note"]:
        out.append(f"  * {hd['note']}")
    out += ["  * fm-verify checked each header's proof of work and that it hashes to the block it is given for.",
            *([] if hd["note"] else ["  * Which block is at each height is the headers' source's word."]),
            "  * A reader with a Bitcoin node can check the headers themselves.",
            f"* **Roots of trust for the RFC 3161 tokens:** {', '.join(f'`{shown(r)}`' for r in info['roots_given'])}."]
    for name, digest in sorted(info["roots_used"].items()):
        mirror_copy = info["tsa"].get(digest)
        out.append(f"  * Tokens chain to {name} (SHA-256 `{digest[:8]}...`)"
                   + (f"; the mirror's `anchors/tsa/{mirror_copy}` has the same fingerprint." if mirror_copy else "."))
    out += ["* **Revocation:** not checked; no revocation lists were given.", "",
            "## Results", "",
            "| Anchor | Root | Files | Verdict | Earliest Bitcoin block (its header's time) | Earliest RFC 3161 time |",
            "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        mark = " (new)" if r["path"] in new and prev is not None else ""
        verdict = {"confirmed": "valid", "pending": "pending: no verdict yet (its RFC 3161 tokens hold)",
                   "failed": "invalid: " + ", ".join(r["failing"]) if r["failing"] else "not checked"}[r["state"]]
        block = f"{r['block']['height']} ({r['block']['header_time']})" if r["block"] else (
            "pending at the calendars" if r["state"] == "pending" else "none")
        tokens = sorted((t for t in r["tokens"] if t["outcome"] == "valid" and t["time"]), key=lambda t: t["time"])
        token = f"{tokens[0]['time']} ({tokens[0]['authority']})" if tokens else "none"
        out.append(f"| {r['path']}{mark} | {(r['root'] or '?')[:12]}... | {r['leaves'] if r['leaves'] is not None else '?'} "
                   f"| {verdict} | {block} | {token} |")
    if prev is not None:
        both = [r for r in rows if r["state"] == "confirmed" and prev["rows"].get(r["path"], {}).get("state") == "confirmed"]
        moved = [r["path"] for r in both if (r["block"]["height"], r["block"]["header_time"]) !=
                 (prev["rows"][r["path"]]["height"], prev["rows"][r["path"]]["time"])]
        lost = [p for p, x in prev["rows"].items() if x["state"] == "confirmed" and p not in {r["path"] for r in both}]
        line = (f"**Agreement with the earlier verdict.** The {plural(len(both), 'anchor')} valid at {prev['label']}"
                f" {'is' if len(both) == 1 else 'are'} valid here too")
        line += (", with the same earliest blocks and times." if not moved else
                 f"; {plural(len(moved), 'anchor')} now name{'s' if len(moved) == 1 else ''} another earliest block: "
                 + ", ".join(moved) + ".")
        if lost:
            line += f" {plural(len(lost), 'anchor')} valid then {'is' if len(lost) == 1 else 'are'} not valid here: {', '.join(lost)}."
        out += ["", line]
    out += ["", "**Reading the times.** An anchor's time proofs bound when its files existed",
            "from above: the files existed no later than that time. A Bitcoin block's",
            "header time is set by its miner. Consensus keeps it later than the median of",
            "the 11 blocks before it, and no more than two hours ahead of the network's", "clock.", ""]
    out += ["**Index and links.** [`verdict.txt`](verdict.txt) holds the verdict on the",
            "whole set, including `index.jsonl` and the link from each anchor to the one", "before it.",
            f"* `anchor_set.index`, {info['index']}.",
            "* These links are the manifests' own statements. No proof covers them.",
            f"* The mirror's history adds a record the links lack. Across its {s['commits']} commits,"]
    if not h["removed"] and not h["other"]:
        out += ["  no file is removed, and only two kinds of file change:",
                f"  * `index.jsonl` changes {plural(h['index_changes'], 'time')}"
                + (", and each version begins with the whole of the one before it." if h["index_grows"] else
                   ", and some version does not begin with the whole of the one before it."),
                "  * `root.preimage.ots` " + ots_changes(h["upgrades"])]
    else:
        out.append(f"  {plural(len(h['removed']), 'file is', 'files are')} removed"
                   + (f" ({', '.join(h['removed'])})" if h["removed"] else "")
                   + f", and {plural(len(h['other']), 'change')} the anchoring does not explain"
                   + (f": {', '.join(h['other'])}." if h["other"] else "."))
    out += ["* That history is only as good as its host. Clone it fresh later and compare",
            "  it with the commit named above; a rewrite would show.", "",
            "**Per-anchor verdicts.** Each anchor's full verdict is under",
            "[`anchors/`](anchors), with every check, its reasons, what it relied on and", "what it does not establish.", "",
            "## What these verdicts do not establish", "",
            "* who wrote the content, or how it was written;",
            "* that the content is true, original, or free of AI assistance;",
            "* that the content did not exist earlier than the anchor.", "",
            "## Reproduce", "", "```sh",
            f"git clone {MIRROR}",
            f"git -C fundingmachine-anchors checkout {s['commit']}",
            "python tools/fetch_headers.py fundingmachine-anchors/anchors headers.txt   # two explorers, compared",
            "fm-verify anchors fundingmachine-anchors/anchors --all --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt",
            "```", "",
            "`tools/anchor_verdict.py` writes this directory from the same inputs. `--json`",
            "gives the machine-readable verdict; it is not committed, since it repeats every leaf.", ""]
    return "\n".join(out)


def ots_changes(upgrades: dict[str, int]) -> str:
    n, total = len(upgrades), sum(upgrades.values())
    if not n:
        return "never changes."
    how = ("changes once, in one anchor" if total == 1 else f"changes once in each of {n} anchors" if total == n else
           f"changes {total} times across {n} anchors")
    return how + (", each time when" if total > n else ", when") + \
        " the pending proof is replaced by one over the same digest holding a Bitcoin attestation."


def header_note(text: str) -> tuple[list[int], str]:
    """The heights given, and what the headers file says of where they came from (its comment lines)."""
    heights = [int(m.group(1)) for m in re.finditer(r"^(\d+) [0-9a-f]{160}$", text, flags=re.M)]
    said = " ".join(line[2:].strip() for line in text.splitlines() if line.startswith("# ") and not re.match(r"# \d+:", line))
    return heights, said


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("mirror", type=Path, help="a git checkout of the mirror, at the commit to verify")
    ap.add_argument("out", type=Path, help="the verdicts directory; the dated verdict is created inside it")
    ap.add_argument("--headers", action="append", help="Bitcoin headers, HEIGHT HEX lines (repeatable)")
    ap.add_argument("--headers-chain", action="append", help="a raw header chain, PATH[@START] (repeatable)")
    ap.add_argument("--network", default="bitcoin-mainnet", choices=sorted(NETWORKS))
    ap.add_argument("--roots", action="append", required=True, help="PEM roots for the RFC 3161 authorities (repeatable)")
    ap.add_argument("--record", type=Path, help="a copy of the HTTP record made by tools/fetch_ledger_record.py")
    ap.add_argument("--checked-at", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    mirror = a.mirror.resolve()
    anchors = mirror / "anchors"
    if not anchors.is_dir():
        ap.error(f"{anchors} is not a directory")
    checked_at = a.checked_at or now_utc()
    stamp = dt.datetime.strptime(checked_at, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H%MZ")
    dest = a.out / stamp
    if dest.exists():
        ap.error(f"{dest} exists")
    earlier = sorted(p for p in a.out.glob("*") if STAMP.fullmatch(p.name) and (p / "README.md").is_file() and p.name < stamp) \
        if a.out.is_dir() else []
    ns = argparse.Namespace(headers=a.headers, headers_chain=a.headers_chain, explorer=None, bitcoind=None,
                            bitcoind_cookie=None, min_work_bits=None, network=a.network)
    sources = header_sources(ns)
    for src in sources:
        # The verdict names the headers file committed beside it, never a path on the machine that wrote it.
        src.name = "headers.txt" if isinstance(src, HeaderSet) else Path(src.name).name
    common = dict(header_sources=sources, network=NETWORKS[a.network], roots=_certs(a.roots, "--roots"),
                  extra_certs=[], crls=[], checked_at=checked_at)
    here = os.getcwd()
    os.chdir(mirror.parent)
    try:
        name = Path(mirror.name) / "anchors"
        whole = ledger_anchors.verify_all(name, **common)
        verdicts = [(d.relative_to(name).as_posix(), ledger_anchors.verify_dir(d, **common))
                    for d in ledger_anchors.find_anchor_dirs(name)]
    finally:
        os.chdir(here)
    rows = [anchor_row(rel, v) for rel, v in verdicts]
    index = next((c for c in whole.checks if c.id == "anchor_set.index"), None)
    info = {
        "checked_at": checked_at, "rows": rows, "outcome": whole.outcome.value, "statement": whole.statement,
        "source": {"commit": git(mirror, "rev-parse", "HEAD"), "commits": int(git(mirror, "rev-list", "--count", "HEAD")),
                   "first": git(mirror, "rev-list", "--max-parents=0", "HEAD").split()[-1]},
        "history": history(mirror),
        "index": f"{index.status.value}: {index.summary}" if index else "not run: the mirror holds no index.jsonl",
        "roots_given": a.roots, "tsa": root_fingerprints(anchors / "tsa") if (anchors / "tsa").is_dir() else {},
        "roots_used": {t["root_name"]: t["root_sha256"] for r in rows for t in r["tokens"] if t["root_name"] and t["root_sha256"]},
        "previous": None, "record": None,
    }
    text = "".join(Path(p).read_text(encoding="utf-8") for p in a.headers or [])
    heights, note = header_note(text)
    info["headers"] = {"heights": sorted(set(heights)), "note": note, "chains": a.headers_chain or []}
    if earlier:
        last = earlier[-1]
        t = dt.datetime.strptime(last.name, "%Y-%m-%dT%H%MZ")
        info["previous"] = {"name": last.name, "label": f"{t:%H:%M} UTC" if last.name[:10] == stamp[:10] else f"{t.day} {t:%B}, {t:%H:%M} UTC",
                            "rows": previous_rows(last / "README.md")}
    if a.record:
        import json

        listing_raw = (a.record / "listing.json").read_bytes()
        listing = json.loads(listing_raw)
        rec_files = {f"anchors/{p}": b for p, b in files_under(a.record / "anchors").items()}
        mine = {f"anchors/{p}": b for p, b in files_under(anchors).items()}
        info["record"] = {"listing_sha256": hashlib.sha256(listing_raw).hexdigest(), "anchors": len(listing.get("anchors", [])),
                          "files": len(listing.get("files", [])),
                          "same": sum(1 for p, b in rec_files.items() if mine.get(p) == b),
                          "differ": sorted(p for p, b in rec_files.items() if p in mine and mine[p] != b),
                          "record_only": sorted(p for p in rec_files if p not in mine),
                          "mirror_only": sorted(p for p in mine if p not in rec_files)}
    (dest / "anchors").mkdir(parents=True)
    (dest / "verdict.txt").write_text(whole.to_text(), encoding="utf-8")
    for rel, v in verdicts:
        f = dest / "anchors" / f"{rel}.txt"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(v.to_text(), encoding="utf-8")
    if text:
        (dest / "headers.txt").write_text(text, encoding="utf-8")
    if a.record:
        shutil.copyfile(a.record / "listing.json", dest / "listing.json")
    (dest / "README.md").write_text(readme(info), encoding="utf-8")
    states = [r["state"] for r in rows]
    print(f"{dest}: {whole.outcome.value}; {states.count('confirmed')} confirmed in Bitcoin, {states.count('pending')} pending, "
          f"{states.count('failed')} failed, of {len(rows)} anchors at {info['source']['commit'][:12]}")
    return 0 if whole.outcome.value == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
