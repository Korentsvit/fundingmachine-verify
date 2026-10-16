# fundingmachine-verify

`fm-verify` checks FundingMachine's anchors and Provenance Ledger
certificates without trusting FundingMachine. It is a command-line tool and
a Python library, Apache-2.0, and it is the proof: a page that shows a
verification result is a convenience on top of it.

## What it checks

| What | Command |
| --- | --- |
| A Provenance Ledger certificate (`ledger-certificate/v0`), JSON or PDF form: all seven steps of the Ledger's `docs/CERTIFICATE.md` (the eddsa-jcs-2022 proof, the scope statement, the exported file, the signed hourly root, the sign event's inclusion, the anchor, and with the events the chain and the authorship map) | `fm-verify certificate` |
| A document's event chain (`ledger-event/v0`, and its proposed addition v0.1): every chain rule in the contract's order, with its failure codes; with a disclosed document key and text, every keyed hash replayed | `fm-verify chain` |
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
* **The verifier is checkable too.** `python tools/build_release.py` builds
  the wheel and source archive so that the same commit gives the same bytes
  (CI builds twice, with different file times and umask, and compares; a
  build on GitHub's runner and one elsewhere matched byte for byte). To
  check a published release, rebuild from its tag and compare SHA-256
  values; on a machine whose zlib compresses differently,
  `python tools/build_release.py --compare A B` compares what two archives
  hold. Then install that file itself
  (`pip install ./fundingmachine_verify-VERSION-py3-none-any.whl`); with
  `--require-hashes`, pip asks for the hash of every dependency too
  (`cryptography` and what it needs), not only the verifier's.

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

`--json` prints the verdict as JSON, described by
[docs/verdict.schema.json](docs/verdict.schema.json). `--html PATH` also writes it as one
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

# Every anchor on the Ledger's anchors branch, summarised
fm-verify anchors anchors/ --all --headers-chain blockchain_headers --roots /etc/ssl/certs/ca-certificates.crt

# When did this file exist? Every anchor naming its content, earliest first, each verified
fm-verify anchors anchors/ --prove docs/STANDING_RULINGS.md --headers-chain blockchain_headers --roots /etc/ssl/certs/ca-certificates.crt

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
[docs/CONFORMANCE.md](docs/CONFORMANCE.md).
`fm-verify conformance fixtures --implementation "your-verifier"` runs
another implementation over the same cases instead (it is given each case's
kind and directory, and prints its verdict as JSON), so the suite tests any
verifier, not only this one. `python tools/tamper_audit.py` changes every input of every
valid case 200 ways and fails if any change is accepted without showing in
the verdict or being explained (the security note lists what it accepts). No key in them protects anything: every key comes from a seed
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
  update; an unknown contract version. Over the v0.1 chain: valid, anchored
  and with the chain, and a total crediting text changed while capture was
  off to the person.
* `chain/*`: chains from `tools/chain_fixtures.py` (two sessions, every event
  type, keyed hashes, no text): valid; tampered; a tool's text relabelled as
  a person's; one event back-dated; the whole chain back-dated and re-signed
  with the client keys (valid: only an anchor can bound a chain's time);
  re-ordered, plainly and re-signed; an event dropped; after close; the wrong
  key; text in a payload; and a disclosed key and text (valid, one word
  changed, the wrong key, one event given twice, text no hash covers). Under the proposed v0.1: a chain resumed with a
  `capture.resync`, valid; the resync not first in its session; a resync
  emptying the document; an event naming a version this verifier does not
  read (indeterminate); and the chain's journal, valid and with the signer's
  name changed.
* `roots/*`: hourly root records: valid, an hour dropped, two swapped, one
  altered, another key, a later stretch alone.
* `ledger-anchors/*`: anchors in the Ledger's layout (`anchor-manifest/v0`)
  over a synthetic repository: valid; a later checkout and one after the
  daily assembly (warnings); a descriptor altered or dropped; a leaf hash
  wrong; leaves out of order; a token misstated; a schema violation; a source
  not read and one token missing (warnings); an unknown contract; and anchor
  sets with `index.jsonl`: valid, a broken link, an anchor not listed.
* `merkle/*`: inclusion proofs: valid, the wrong leaf, the wrong index, another
  root, a path too long, the tree size held (valid) and a size of the same
  shape claimed (invalid), and the explicit scheme (a warning).
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
* `tools/differential_openssl.py` changes the bytes of the RSA and ECDSA
  tokens 2,000 ways each and asks both: on 16 October 2026, 3,987 of 4,000
  were judged alike, and the 13 others differ by design (a hash list no
  signature covers, warned about here and refused by OpenSSL; a signature
  algorithm other than the one signed with, refused here and ignored by
  OpenSSL); a short run is in CI;
* eleven real-world tokens (IdenTrust's public authority, Sigstore's staging
  authority, test authorities) published in the rfc3161-client package give
  the verdicts OpenSSL gives (`tests/test_realworld_tokens.py`, when
  `FM_RFC3161_CLIENT_FIXTURES` points at them);
* twelve real tokens from the Provenance Ledger's two authorities and one
  other, taken from public NuGet package signatures: DigiCert's responders of
  2022 to 2026 and Sectigo's R37 signer (chained through Sectigo's
  time-stamping root to USERTrust RSA) are valid against those roots taken
  from the system bundle, Microsoft's authority is invalid against them, and
  OpenSSL agrees on every one; with the authorities' CRLs of 14 and 15
  October 2026, every path was shown not revoked
  (`tests/test_public_tokens.py`, when `FM_PUBLIC_TOKENS` holds the output of
  `tools/fetch_public_tokens.py`, which pins each package by SHA-256);
* pypdf (CI) and poppler's `pdfdetach` take the same `certificate.json` from
  every PDF fixture; `tools/differential_pdf.py` damages the PDF fixtures
  4,000 ways each, and of the 20,000 copies none yields a `certificate.json`
  that pypdf and this reader both take and that differs (one may read a copy
  the other refuses);
* `tools/differential_ots.py` changes every OpenTimestamps proof in the
  fixtures 500 ways: of 6,500 changed proofs, the reference library and this
  verifier refuse the same ones and read the rest alike (digest, Bitcoin
  attestations, commitments);
* the Provenance Ledger session's own fixtures, made by its TypeScript code,
  verify here: its 19 chains with their codes and positions, its authorship
  map byte for byte, its journal replayed, its certificate through all seven
  steps (`FM_LEDGER_REPO`; its repository is private and its fixtures are
  not copied here); and the reverse, `tools/ledger_crosscheck/run.mts` runs
  its validator over these fixtures. With its branch carrying the proposed
  v0.1 (27cec9a, 16 October 2026), it agreed on 14 of 16 chains (the other
  two, no events at all and a version neither reads, it calls invalid and
  this verifier indeterminate), on all 21 certificate proofs, and on both
  authorship map hashes, v0 and v0.1;
* the Ledger's anchoring work (its branch of 16 October 2026): its recorded
  DigiCert and Sectigo responses and OpenTimestamps proof verify here; this
  verifier's schema check gives the published `anchor-manifest/v0` schema's
  answer on every mutation tested; and `tools/ledger_crosscheck/anchors.mts`
  runs its anchor verifier over these anchor fixtures: it reaches the same
  outcome on 15 of 19. The four that differ do so by design, and are named in
  `docs/decisions.d/2026-10-16-verify-anchor-manifest.md`, as is one case
  where only this verifier warns;
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
