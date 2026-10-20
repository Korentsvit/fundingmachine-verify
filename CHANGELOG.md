# Change log

## 0.2.0

Adds the Provenance Ledger's record certificates, the anchors page and the
Ledger's own conformance cases. Every case of 0.1.0 keeps its expected
verdict; the suite only grows.

* **Record certificates** (`record-certificate/v0`, the Ledger's
  `docs/RECORD_CERTIFICATE.md`).
  * `fm-verify record-certificate`: the JSON with its signature, or the PDF
    carrying both. Each hash link from the record's head to the Bitcoin
    block is reported on its own: the signature, the head to the hour's
    root, the signed root record, the anchored root, the RFC 3161 tokens,
    the OpenTimestamps path and the block header.
  * `--index` checks the certificate's entry in the Ledger's public
    submission index (`submission-index/v0`). `--events` checks the record's
    own statements against the document's chain.
  * The tenant pseudonym is checked against the issuer's key id
    (`record_certificate.pseudonym`).
  * The library entry point's `record-certificate` kind, run under Pyodide
    in CI.
* **The anchors page** (`hosted-page/1`,
  [`docs/HOSTED_PAGE.md`](docs/HOSTED_PAGE.md) section 11).
  * [`page/index.html`](page/index.html) checks every anchor in the Ledger's
    public mirror, at a commit the reader names, in the browser. It compares
    each file with the Ledger's own record and takes headers from two
    explorers.
  * The library entry point's `ledger-anchor-set` kind and
    `fmverify.api.bitcoin_heights`, which the page needs. This is the first
    release the page can pin.
  * `tools/build_page.py` assembles the page under its Content Security
    Policy, serves a tagged release's wheel pinned by its SHA-256, and
    writes a `NOTICE` for every third-party file it serves. CI checks the
    page in Chrome.
* **Conformance.**
  * 242 cases (127 in 0.1.0), every one an addition: record certificates,
    and the Provenance Ledger suite's 86 rule-pair fixtures (its CS-22),
    copied unchanged under `fixtures/ledger-conformance/` and licensed
    Apache-2.0 by NW PharmaTech Ltd.
  * The full suite runs on every pull request and nightly.
  * The fixtures are published as `fm-verify-fixtures-0.2.0.tar`, which
    rebuilds byte for byte.
* **Tools for dated verdicts.**
  * `tools/anchor_verdict.py` writes an anchor verdict's directory from a
    checkout of the public mirror, with the headers and roots it relied on.
  * `tools/fetch_headers.py` also reads the heights a certificate's proof
    names, from its JSON or its PDF.
* **RFC 3161.** A token whose SignedData sits under any tag but SEQUENCE is
  refused, as OpenSSL refuses it. The differential against OpenSSL found it
  at the release's scale (4,000 changed bytes per token); 0.1.0 read such a
  token as if the tag were right. No signature covers that tag, so no time
  or digest could be changed this way, but the token was not valid DER.
  The same run, deepened to 20,000 changed bytes per token, found two more
  differences, both by design and now named by the run: hash parameters it
  cannot parse are refused by OpenSSL and a warning here, as any non-NULL
  hash parameters are; and the signer is found by its issuer name compared
  byte for byte, so a name spelled otherwise is indeterminate here, with
  that reason, where OpenSSL compares names as RFC 5280 does. At 60,000
  changed bytes per token, three more, all by design: non-NULL hash
  parameters in SignedData's digestAlgorithms (a warning here), bytes after
  the token and a SET written in primitive form (both refused here, as not
  DER, and read by OpenSSL).
* **PDF.** A certificate PDF whose attachment a cross-reference table or
  stream places at an offset where it cannot be read is refused, as one
  replaced by an incremental update is. In 0.1.0, one changed byte in an
  update's `obj` keyword hid the update from this reader, which took the
  first `certificate.json`, while pypdf, following the update's table, took
  the second. Found by the PDF differential at 20,000 changed copies per
  file.
* **Ledger anchors, from the tamper audit at 800 changes per input.**
  * A manifest's stated time (`created`, a token's `gen_time`) that is no
    real instant is refused; before, a month 80 passed the form check and
    the comparison with the token, unable to read it, said nothing.
  * A token entry that names no authority is a warning.
  * An anchor `index.jsonl` does not list is still linked: its `previous`
    must name an anchor here, with that anchor's root.
  * An RSA PKCS#1 v1.5 signature algorithm given with parameters other than
    NULL is a warning, as non-NULL hash parameters are.
* **CI.** Runners are pinned to ubuntu-24.04, and actions to their Node 24
  releases by commit.
* **Reproducible release.** As in 0.1.0: the wheel, the source archive and
  the fixture archive rebuild byte for byte from this tag
  (`tools/build_release.py`, `tools/fixture_archive.py 0.2.0`).

## 0.1.0

The first release of fm-verify, the independent verifier for FundingMachine's
certificates and anchors. Everything it checks, it checks offline from what it
is given; every verdict states what it relied on and what it does not
establish.

* **Time proofs.**
  * OpenTimestamps proofs against Bitcoin block headers, from a headers
    file, a node of your own, or an explorer named as relied on.
  * RFC 3161 tokens, checked against the roots you trust, with revocation
    lists if you give them.
  * RFC 9162 Merkle inclusion proofs.
* **Provenance Ledger records.**
  * Certificates (`ledger-certificate/v0`, JSON or the PDF carrying it),
    each of the seven steps reported on its own.
  * Event chains (`ledger-event/v0` and `v0.1`) and the authorship map
    recomputed from them.
  * Disclosure replay.
  * Hourly root records.
  * Anchors (`anchor-manifest/v0`), one by one or a whole set with its
    index, and when a file existed.
* **Outputs.**
  * A static HTML report with no script.
  * A library entry point for the hosted page, tested under Pyodide and in
    Chrome under the page's Content Security Policy.
* **Conformance.**
  * 127 cases, with a harness that runs any other implementation over them.
  * The fixtures are published as `fm-verify-fixtures-0.1.0.tar`, which
    rebuilds byte for byte.
* **Reproducible release.**
  * The wheel and source archive rebuild byte for byte from this tag
    (`tools/build_release.py`).
  * The fixture archive rebuilds byte for byte too
    (`tools/fixture_archive.py 0.1.0`).
* **What it cannot detect:** [`docs/SECURITY_NOTE.md`](docs/SECURITY_NOTE.md).
