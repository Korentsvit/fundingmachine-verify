import json
from html.parser import HTMLParser
from pathlib import Path

from fmverify import api, certificate, report
from fmverify.bitcoin import REGTEST, HeaderChain
from fmverify.cli import main
from fmverify import pki

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CASE = FIX / "certificate" / "valid-with-chain"


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += attrs


def _verdict(case=CASE, cred=None):
    events = json.loads((case / "events.json").read_text())["events"] if (case / "events.json").exists() else None
    src = [HeaderChain.from_file(FIX / "bitcoin" / "regtest" / "certificate-headers-0-5.bin", 0, REGTEST)]
    roots = pki.load_certificates((FIX / "rfc3161" / "pki" / "root.pem").read_bytes())
    data = json.dumps(cred).encode() if cred is not None else (case / "certificate.json").read_bytes()
    return certificate.verify(data, exported_file=(case / "exported.txt").read_bytes(), header_sources=src, network=REGTEST,
                              roots=roots, events=events)


def test_certificate_report_content():
    cred = json.loads((CASE / "certificate.json").read_text())
    html = report.render(_verdict(), cred)
    assert cred["credentialSubject"]["scope_statement"] in html
    assert "Recomputed by this verifier from the event chain" in html
    assert "Evidence coverage" in html and "1 of 2 statements" in html
    assert "What this does not establish" in html
    p = _Tags()
    p.feed(html)
    assert "script" not in p.tags and "link" not in p.tags and "img" not in p.tags
    assert not any(k == "src" or (k == "href" and v and v.startswith("http")) for k, v in p.attrs)


def test_invalid_certificate_is_labelled_as_claims():
    case = FIX / "certificate" / "authorship-overstated"
    html = report.render(_verdict(case), json.loads((case / "certificate.json").read_text()))
    assert "must not be relied on" in html and ">INVALID<" in html


def test_hostile_strings_are_escaped():
    cred = json.loads((FIX / "certificate" / "valid-not-anchored" / "certificate.json").read_text())
    cred["credentialSubject"]["authorship"]["sections"][0]["section_id"] = "<script>alert(1)</script>"
    cred["credentialSubject"]["tools"][0]["tool_name"] = '"><img src=x onerror=alert(1)>'
    v = certificate.verify(json.dumps(cred).encode())
    html = report.render(v, cred)
    assert "<script>alert" not in html and "<img" not in html
    assert "&lt;script&gt;" in html


def test_generic_verdict_report_and_cli(tmp_path, capsys):
    out = tmp_path / "r.html"
    case = FIX / "ots" / "regtest-valid"
    assert main(["ots", str(case / "proof.ots"), "--file", str(case / "document.txt"), "--network", "regtest",
                 "--headers-chain", str(FIX / "bitcoin" / "regtest" / "headers-0-11.bin"), "--html", str(out)]) == 0
    assert ">VALID<" in out.read_text()
    out2 = tmp_path / "c.html"
    assert main(["certificate", str(CASE / "certificate.json"), "--file", str(CASE / "exported.txt"), "--events", str(CASE / "events.json"),
                 "--network", "regtest", "--headers-chain", str(FIX / "bitcoin" / "regtest" / "certificate-headers-0-5.bin"),
                 "--roots", str(FIX / "rfc3161" / "pki" / "root.pem"), "--html", str(out2)]) == 0
    assert "Authorship map" in out2.read_text()
    assert main(["ots", str(case / "proof.ots"), "--html", str(tmp_path / "missing" / "x.html")]) == 64


def test_api_render():
    cred = json.loads((FIX / "certificate" / "valid-not-anchored" / "certificate.json").read_text())
    answer = api.verify({"kind": "certificate", "certificate": cred, "render": "html"})
    assert answer["outcome"] == "valid" and "<!doctype html>" in answer["html"]
