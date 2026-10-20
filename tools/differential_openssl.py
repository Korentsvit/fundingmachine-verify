"""Differential fuzz of RFC 3161 verification against OpenSSL.

    python tools/differential_openssl.py [ROUNDS]

Changes the bytes of each valid token that OpenSSL's ``ts -verify`` can
read (RSA PKCS#1 v1.5; ECDSA P-256 with its chain) ROUNDS times each
(default 2000), deterministically, and asks both this verifier and OpenSSL
whether the changed token holds. Where they differ, the difference must be
one of the two this verifier makes by design, established from the token:

* SignedData's ``digestAlgorithms`` no longer lists the signer's hash. No
  signature covers that list and RFC 5652 (section 5.1) allows it, so this
  verifier holds the token valid with a warning; OpenSSL refuses it.
* SignerInfo's signature algorithm names an algorithm other than the one
  signed with. OpenSSL ignores it and verifies by the key's own algorithm;
  this verifier refuses an algorithm the token does not name, so a
  signature is never checked under an algorithm other than the stated one.
* Hash parameters other than NULL, in SignedData's digestAlgorithms or the
  signer's. No signature covers them and SHA-2 takes none, so this verifier
  holds the token valid with a warning (docs/SECURITY_NOTE.md); OpenSSL
  refuses parameters it cannot parse.
* Bytes after the token. A token is one DER element, so this verifier
  refuses them; OpenSSL reads the token and ignores what follows.
* A constructed element written in primitive form (its tag's constructed
  bit cleared). That is not DER, so this verifier refuses it; OpenSSL reads
  it.
* The signer identifier spells its issuer name otherwise than the
  certificate does (another string type, other spacing or case). This
  verifier compares the two byte for byte and does not find the signer, so
  the token is indeterminate; OpenSSL compares names as RFC 5280 (section
  7.1) does and finds it.

Any other difference is printed and the run fails.
"""

from __future__ import annotations

import datetime as _dt
import json
import random
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from fmverify import pki, rfc3161  # noqa: E402
from tamper_audit import mutate_bytes  # noqa: E402

FIX = ROOT / "fixtures" / "rfc3161"
CASES = ("valid-rsa", "valid-p256-chain-supplied")
AT = str(int(_dt.datetime(2026, 10, 16, 6, 0, 0, tzinfo=_dt.timezone.utc).timestamp()))


def by_design(original: bytes, changed: bytes, ours: bool, openssl: bool, verdict) -> str | None:
    """Which of the designed differences this is, from the tokens; None if neither."""
    failing = [c.id for c in verdict.checks if c.status.value == "fail"]
    said = " ".join(r for c in verdict.checks if c.id == "rfc3161.parse" for r in [c.summary, *c.reasons])
    if not ours and openssl and failing == ["rfc3161.parse"]:
        if len(changed) > len(original) and changed.startswith(original) and "after the end of the DER element" in said:
            return "bytes after the token: refused here, where a token is one DER element; OpenSSL ignores them"
        moved = [i for i in range(len(original)) if len(changed) == len(original) and original[i] != changed[i]]
        if (len(moved) == 1 and original[moved[0]] & 0x20 and changed[moved[0]] == original[moved[0]] & ~0x20
                and "is not constructed" in said):
            return "a constructed element written in primitive form: refused here, as it is not DER; read by OpenSSL"
    try:
        a, b = rfc3161.parse_token(original), rfc3161.parse_token(changed)
    except rfc3161.TokenError:
        return None
    sa, sb = a.signers[0], b.signers[0]
    if ours and not openssl and sb.digest_oid not in b.digest_algs and any(c.id == "rfc3161.digest_algorithms" for c in verdict.checks):
        return "digestAlgorithms omits the signer's hash: a warning here, refused by OpenSSL"
    if not ours and openssl and sb.sig_oid != sa.sig_oid and failing == ["rfc3161.signature"]:
        return "the signature algorithm is not the one signed with: refused here, ignored by OpenSSL"
    warned = {c.id for c in verdict.checks if c.status.value == "warn"}
    if (ours and not openssl and "rfc3161.hash_parameters" in warned
            and ((sa.digest_params_ok and not sb.digest_params_ok) or (not a.digest_alg_params and b.digest_alg_params))):
        return "hash parameters other than NULL: a warning here, refused by OpenSSL where it cannot parse them"
    unchecked = [c.id for c in verdict.checks if c.status.value == "not_checked"]
    if (not ours and openssl and verdict.outcome.value == "indeterminate" and unchecked == ["rfc3161.signer_cert"]
            and sb.sid_serial == sa.sid_serial and sb.sid_issuer != sa.sid_issuer
            and _loose_name(sb.sid_issuer) == _loose_name(sa.sid_issuer)):
        return ("the signer identifier spells its issuer name otherwise: indeterminate here, compared byte for byte; "
                "OpenSSL compares names as RFC 5280 does")
    return None


def _loose_name(raw: bytes | None) -> list | None:
    """A Name's attributes with string types, case and runs of spaces ignored, as RFC 5280 (section 7.1)
    compares them; None if it is not a Name of strings."""
    from fmverify import der

    try:
        return [(der.oid(atv.children()[0]), " ".join(atv.children()[1].content.decode("utf-8").split()).casefold())
                for rdn in der.parse(raw).children() for atv in rdn.children()]
    except (der.DerError, IndexError, UnicodeDecodeError, TypeError):
        return None


def run(rounds: int, openssl: str = "openssl") -> dict:
    totals: Counter = Counter()
    designed: Counter = Counter()
    other: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "token.tsr"
        for name in CASES:
            case = FIX / name
            exp = json.loads((case / "expected.json").read_text(encoding="utf-8"))
            roots = [c for r in exp.get("roots", []) for c in pki.load_certificates((case / r).read_bytes())]
            chain = [c for r in exp.get("chain", []) for c in pki.load_certificates((case / r).read_bytes())]
            data = (case / exp["file"]).read_bytes()
            token = (case / "token.tsr").read_bytes()
            args = [openssl, "ts", "-verify", "-in", str(path), "-data", str(case / exp["file"]), "-attime", AT]
            args += [x for r in exp.get("roots", []) for x in ("-CAfile", str(case / r))]
            args += [x for c in exp.get("chain", []) for x in ("-untrusted", str(case / c))]
            rng = random.Random(name)
            for _ in range(rounds):
                changed, where = mutate_bytes(rng, token)
                if changed == token:
                    continue
                path.write_bytes(changed)
                verdict = rfc3161.verify(changed, file_bytes=data, roots=roots, extra_certs=chain)
                ours = verdict.outcome.value == "valid"
                theirs = "Verification: OK" in subprocess.run(args, capture_output=True, text=True).stdout
                totals["agree" if ours == theirs else "differ"] += 1
                if ours != theirs:
                    why = by_design(token, changed, ours, theirs, verdict)
                    if why:
                        designed[why] += 1
                    else:
                        other.append(f"{name}: {where}: here {verdict.outcome.value}, OpenSSL {'holds' if theirs else 'refuses'}")
    return {"totals": dict(totals), "by_design": dict(designed), "other": other}


def main(argv: list[str]) -> int:
    openssl = shutil.which("openssl")
    if openssl is None:
        print("openssl is not installed", file=sys.stderr)
        return 2
    result = run(int(argv[0]) if argv else 2000, openssl)
    t = result["totals"]
    print(f"{t.get('agree', 0) + t.get('differ', 0)} changed tokens: {t.get('agree', 0)} judged alike by OpenSSL, "
          f"{t.get('differ', 0)} differently")
    for why, n in result["by_design"].items():
        print(f"  by design ({n}): {why}")
    for o in result["other"]:
        print(f"OTHER {o}")
    return 1 if result["other"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
