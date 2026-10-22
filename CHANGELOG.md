# Change log

## 0.3.1

Adds the fleet's scoreboard manifest to every release. No case, verdict or
check changes; the wheel differs from 0.3.0's only in its version.

* **`scoreboard-manifest.json`** (contract `scoreboard-manifest` 1.0,
  fundingmachine-core `docs/scoreboard-contract/1.0/`), the asset the
  fleet's scoreboard reads: engine `Verifier`, with three figures (Ledger
  anchors verified; Ledger certificates verified, its target the owner's
  end state of 10; conformance cases passing), each read from
  `fm-verify-figures.json`, the file the conformance run on main at the
  tagged commit writes and keeps (artifact `scoreboard-figures`), naming
  that run and the path read, and the file's own SHA-256 by the contract's
  JCS rule. The release refuses to write it unless each figure is the one
  it recomputed in `fm-verify-scoreboard-VERSION.json`.
  `tools/scoreboard.py --figures` writes the run's file and `--manifest`
  the asset; `made_at` is the one value a rebuild takes as given
  (`--made-at`).
* Checked against the contract's own schema (`$defs/asset`), its
  `sha256.mjs` and its example, read from a checkout of fundingmachine-core
  (`FM_CORE_REPO`), not copied.

## 0.3.0

Adds the Provenance Ledger's acceptance proofs and its certificate contract
v0.1, runs the Ledger's own record certificate cases, pins the anchors page
to a release, and gives every release a scoreboard. Every case of 0.2.0
keeps its expected verdict; the suite only grows.

* **Acceptance proofs** (`ledger-acceptance/v0`, the Ledger's
  `docs/ANCHORING.md`, "Acceptance records").
  * `fm-verify acceptance`: when the ledger accepted an event, by its own
    clock, from what `GET /api/acceptance` answers the tenant. The hour's
    acceptance record signed by the tenant key; the event's time as a leaf
    of its signed `accepted_root` and inside its hour; with
    `--root-record`, the hour's root record it names (or a ledger
    certificate of the hour that carries it); the record under the hour's
    anchored root; with `--hour`, that root's RFC 3161 tokens and
    OpenTimestamps proof from the hour's public record, each token's stated
    time, and no token stamped before the event's time.
  * The library entry point's `ledger-acceptance` kind, run under Pyodide
    in CI.
  * Checked both ways against the Ledger's own code
    (`tools/ledger_crosscheck/acceptance.mts`, from a checkout of its
    repository): hours its code built verify here and fail on a
    microsecond's change, and its functions agree with every fixture on
    what they check. The hour's window is checked here beyond its
    `verifyAcceptance`.
  * The Ledger's own acceptance test vector (its
    `fixtures/ledger-acceptance/v0`) verifies end to end, every event of
    its hour, with the hour's root record and the anchored root's tokens
    and OpenTimestamps proof from its record certificate vector, anchored
    in the same root (`tests/test_ledger_suite_acceptance.py`, reading its
    checkout).
* **Certificates `ledger-certificate/v0.1`** (the Ledger's
  `docs/CERTIFICATE.md`, Version 0.1). `certificate.meaning` checks the
  signature's meaning (required, one of authorship, review, approval,
  responsibility) and the printed name's keyed hash (64 hexadecimal
  characters or null); step 7 compares both with the sign event. A v0
  certificate over a sign event that records a meaning gets an information
  row: it claims none.
* **The Provenance Ledger's suite.**
  * Its record certificate cases on its test vector: CS-71, and CS-61 to
    CS-69 derived from it as each recipe says, re-signed with its published
    test key (`tests/test_ledger_suite_record.py`, reading its checkout,
    copying nothing).
  * Its rule-pair fixtures: 88, the two of its finding F-14 added
    (`session_unknown` with `key_mismatch`, and with `bad_signature`),
    copied unchanged from its main e64f356 under Apache-2.0.
  * A regtest header in a header file is relied on as the test network's
    block, never as Bitcoin's most-work chain.
* **The anchors page** is pinned to v0.2.0 (`page/release.json`), the
  first release it can run. CI builds the pinned page too, with the wheel
  from the release's own address, and requires it to name its release, to
  find the pinned hash in the wheel it loaded, and to give the install
  line with that hash.
* **The scoreboard.** From this release a release carries
  `fm-verify-scoreboard-VERSION.json` (`fm-verify-scoreboard/v0`,
  `tools/scoreboard.py`): the newest anchor verdict committed at the tag,
  every certificate verdict committed there, and this suite's cases
  passing, run by the release's own wheel on its fixture archive. It holds
  no time of its own and rebuilds byte for byte; its line opens the
  release notes.
* **Filed verdicts in every conformance run.** Each run's summary lists
  every certificate verdict filed here and the newest anchor verdict, and
  verifies again each certificate committed with its verdict
  (`tools/verdict_summary.py`).
* **Conformance.** 262 cases (242 in 0.2.0), every one an addition: 14
  acceptance proofs, 4 `ledger-certificate/v0.1` certificates and the 2
  new rule pairs. The verdict schema's `kind` gains `ledger-acceptance`.
* **Reproducible release.** As before: the wheel, the source archive and
  the fixture archive rebuild byte for byte from the tag
  (`tools/build_release.py`, `tools/fixture_archive.py 0.3.0`), and now the
  scoreboard (`tools/scoreboard.py`).

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
