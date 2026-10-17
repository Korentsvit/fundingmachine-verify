# Change log

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
