# fundingmachine-verify

`fm-verify` checks FundingMachine's anchors and Provenance Ledger
certificates without trusting FundingMachine. It is a command-line tool and
a Python library, Apache-2.0, and it is the proof: a page that shows a
verification result is a convenience on top of it.

## What it checks

| What | Command |
| --- | --- |
| A Provenance Ledger certificate (`ledger-certificate/v0`), JSON or PDF form: all seven steps of the Ledger's `docs/CERTIFICATE.md` (the eddsa-jcs-2022 proof, the scope statement, the exported file, the signed hourly root, the sign event's inclusion, the anchor, and with the events the chain and the authorship map) | `fm-verify certificate` |
| A document's event chain (`ledger-event/v0`): every chain rule in the contract's order, with its failure codes; with a disclosed document key and text, every keyed hash replayed | `fm-verify chain` |
| A tenant's hourly root records (`ledger-root/v0`) as a chain of their own: a dropped, swapped or altered hour shows | `fm-verify roots` |
| A Provenance Ledger anchor (`docs/ANCHORING.md`): descriptor leaves, `root.preimage`, its OpenTimestamps proof and RFC 3161 tokens, and a checkout compared; or a batch in this verifier's own format | `fm-verify anchors` |
| An OpenTimestamps proof against Bitcoin block headers | `fm-verify ots` |
| An RFC 3161 time-stamp token against the authority's certificate chain, with revocation lists if you have them | `fm-verify rfc3161` |
| A Merkle inclusion proof (RFC 9162, or an explicit path) | `fm-verify merkle` |
| Every published fixture, against its expected verdict | `fm-verify conformance` |

A step-by-step guide for a reader holding a certificate:
[docs/HOW_TO_VERIFY.md](docs/HOW_TO_VERIFY.md).

Programs and pages call one function, `fmverify.api.verify`: JSON in,
verdict out, no disk or network access; it runs in a browser under Pyodide
([docs/API.md](docs/API.md)). The input formats are in
[docs/INPUTS.md](docs/INPUTS.md); the plan, with dates, in
[docs/PLAN.md](docs/PLAN.md).

## Independence

* **No private dependency.** The Python standard library and one public
  library, [`cryptography`](https://cryptography.io/) (Apache-2.0 or BSD),
  for signatures and certificates. DER, OpenTimestamps, RFC 8785 JSON, PDF
  attachments and the Ledger's contracts are read by this repository's own
  code, written from the published specifications.
* **No trust chosen for you.** No certificate authority, Bitcoin chain or
  tenant key is built in. You pass the evidence you trust; the verdict names
  what it reached (a root and its fingerprint, a block and its hash, a key)
  for you to compare with an independent source.
* **No phoning home.** No network connection unless you pass `--explorer`
  (a public explorer) or `--bitcoind` (your own node). A test replaces the
  socket layer with one that refuses, then runs every fixture through the
  command line.
* **Reliance stated.** Every verdict lists what it took on trust.

## Verdicts

A verdict is never a bare pass. It gives the outcome and the statement it
supports, every check with its status (`pass`, `fail`, `warn`,
`not_checked`, `info`) and reasons, what was relied on, and what the verdict
does not establish: who wrote the content or how, that it is true, original
or free of AI assistance, or that it did not exist earlier than its anchor.

| Outcome | Meaning | Exit status |
| --- | --- | --- |
| `valid` | every required check passed; the statement holds, given the reliance listed | 0 |
| `invalid` | something supplied contradicts something else: the file and the proof, the proof and the block, two header sources, a signature and its key, a chain and the roots you trust, a certificate and its chain | 1 |
| `indeterminate` | nothing contradicts, but something needed could not be checked: no header for the block, a proof still pending, no trusted root or key given, an unknown contract version | 2 |
| usage error | a file could not be read, an argument is malformed | 64 |
| internal error | a fault in the verifier itself: never an outcome, always reported | 70 |

`--json` prints the verdict as JSON. `--html PATH` also writes it as one
self-contained page (no script, no external resource); for a certificate the
page adds the authorship map and the evidence coverage, each figure labelled
as recomputed from the chain or read from the certificate, with the
certificate's scope statement near the top.

## Use

```sh
python -m pip install .

# A certificate (JSON, or the PDF carrying it), with the exported document,
# the document's events for step 7, Bitcoin headers and the authorities' roots
fm-verify certificate certificate.pdf --file proposal.pdf --events events.json \
    --headers-chain blockchain_headers --roots digicert-root.pem --roots sectigo-root.pem --html report.html

# An event chain, and with a disclosed key and text, every keyed hash
fm-verify chain events.json [--disclosure journal.json]

# A tenant's hourly root records, with the tenant's key
fm-verify roots records.json --key did:key:z6Mk...

# A Ledger anchor directory, compared with checkouts of the repositories it names
fm-verify anchors anchors/2026/10/17/080412Z --repo Korentsvit/fundingmachine-core=../fundingmachine-core \
    --headers-chain blockchain_headers --roots digicert-root.pem --roots sectigo-root.pem

# An OpenTimestamps proof, an RFC 3161 token, a Merkle proof
fm-verify ots document.pdf.ots --file document.pdf --headers headers.txt
fm-verify rfc3161 document.pdf.tsr --file document.pdf --roots authority-root.pem [--chain intermediates.pem] [--crl issuer.crl]
fm-verify merkle proof.json --leaf-file document.pdf --root 6f1c...
```

### Where block headers come from

| Source | Checked | Relied on |
| --- | --- | --- |
| `--headers-chain FILE[@START]`: 80-byte headers back to back, from height `START` (`bitcoin-cli getblockheader HASH false` gives one in hex) | linkage, proof of work, difficulty retargets and median time past, from `START`; from 0, the genesis hash | that the file is on Bitcoin's most-work chain; headers before `START` |
| `--headers FILE`: lines `HEIGHT HEX`, or JSON | each header's proof of work alone, against a floor of 2^70 expected hashes (`--min-work-bits`); links between neighbours in the file | that each header is the block at its height on the most-work chain |
| `--explorer URL`: an Esplora API | the header hashes to the block id the explorer gave, and meets its proof of work | that the explorer told the truth |
| `--bitcoind URL`: a Bitcoin Core node you run (credentials from `--bitcoind-cookie` or `FM_BITCOIND_USER` and `FM_BITCOIND_PASSWORD`, never printed) | the header hashes to the block id the node gave, and meets its proof of work | that your node follows the most-work chain, which it does by validating every block |

If sources disagree about a height, the verdict is `invalid`. A block's time
is set by its miner and is only roughly accurate (within about two hours);
the verdict quotes it as the header's time.

## Fixtures and the conformance suite

`fixtures/` holds every case the tests run, each with the verdict the
verifier must reach, and `fixtures/SHA256SUMS`. `python tools/make_fixtures.py`
rebuilds them offline, byte for byte. `fm-verify conformance fixtures`
checks the manifest and runs every case; the format is in
[docs/CONFORMANCE.md](docs/CONFORMANCE.md), so other implementations can use
the cases too. No key in them protects anything: every key comes from a seed
published in `tools/`, and no key file is committed. No content from
FundingMachine's private repositories is in them.

* `certificate/*`: certificates issued by the fixture builder from the
  Ledger's published documents over the fixture chain: valid (anchored, not
  yet anchored, with the chain for step 7, and in PDF form, classic and
  PDF 1.5); a total crediting a tool's text to a person and a certificate
  omitting the tool (both caught only by step 7); another document's events;
  the wrong file; changed after signing; another key; an issuer signing
  falsehoods (scope statement, percentages, root record, inclusion, anchor
  time, a token over another root, a Bitcoin block the proof does not hold);
  two attachments under one name; an attachment replaced by an incremental
  update; an unknown contract version.
* `chain/*`: chains from `tools/chain_fixtures.py` (two sessions, every event
  type, keyed hashes, no text): valid; tampered; a tool's text relabelled as
  a person's; one event back-dated; the whole chain back-dated and re-signed
  with the client keys (valid: only an anchor can bound a chain's time);
  re-ordered, plainly and re-signed; an event dropped; after close; the wrong
  key; text in a payload; and a disclosed key and text (valid, one word
  changed, the wrong key).
* `roots/*`: hourly root records: valid, an hour dropped, two swapped, one
  altered, another key, a later stretch alone.
* `ledger-anchors/*`: anchors in the Ledger's layout over a synthetic
  repository: valid; a later checkout (a warning); a descriptor altered or
  dropped; one authority only (a warning); proofs over another root.
* `anchors/*`: batches in this verifier's own format over a synthetic
  repository: valid, changed checkout, changed file, re-ordered, dropped,
  pending proof, back-dated token, proof over another root.
* `ots/*`: a real mainnet proof built from public Bitcoin data only (block
  840000's coinbase transaction id and Merkle branch; no transaction
  content), against sparse headers, a header window, no headers, the wrong
  file and a forged header; and regtest proofs: valid, tampered file,
  tampered proof, back-dated, pending, truncated, trailing bytes.
* `rfc3161/*`: tokens from a test PKI: valid with PKCS#1 v1.5, PSS, ECDSA
  and Ed25519; no root, wrong root, chain missing; tampered file, time,
  signature or ESS certificate; EKU missing or shared; expired at the stated
  time; refused; and revocation from CRLs (clean, key compromise, superseded
  later, revoked before, too old to tell, forged).

### Independent implementations

The same inputs are checked by other implementations, so a third party need
not take this code's word:

* the reference OpenTimestamps library reaches the same commitments and
  rejects the same malformed proofs (CI);
* OpenSSL agrees on every RFC 3161 case it can check (CI); RSASSA-PSS goes
  through `openssl cms` and Ed25519 through RFC 8032's reference algorithm,
  since OpenSSL 3.0 cannot check those through `ts`; a token made by
  OpenSSL's own authority code verifies here;
* eleven real-world tokens (IdenTrust's public authority, Sigstore's staging
  authority, test authorities) published in the rfc3161-client package give
  the verdicts OpenSSL gives (`tests/test_realworld_tokens.py`, when
  `FM_RFC3161_CLIENT_FIXTURES` points at them);
* pypdf (CI) and poppler's `pdfdetach` take the same `certificate.json` from
  every PDF fixture;
* the Provenance Ledger session's own fixtures, made by its TypeScript code,
  verify here: its 19 chains with their codes and positions, its authorship
  map byte for byte, its journal replayed, its certificate through all seven
  steps (`FM_LEDGER_REPO`; its repository is private and its fixtures are
  not copied here); and the reverse, `tools/ledger_crosscheck/run.mts` runs
  its validator over these fixtures: on 16 October 2026 it agreed on all 11
  chains, all 17 certificate proofs and the authorship map hash;
* the library runs under Pyodide in CI, as a browser would run it.

Those tools are test-time only; the verifier never imports them.

## What the verifier cannot detect

[docs/SECURITY_NOTE.md](docs/SECURITY_NOTE.md) (a first version of the note
due 14 November). In short: an anchor shows that a digest existed no later
than a time, not who made the content, that it is true, or that it did not
exist earlier. An event chain records what the capture client observed and
signed: whoever holds the client keys can record any history, and only an
anchor bounds its time. Headers, authority roots, revocation lists and
tenant keys are the reader's evidence, and every verdict says which it
relied on.

## Licence

Apache-2.0, see [LICENSE](LICENSE).
