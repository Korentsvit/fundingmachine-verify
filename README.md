# fundingmachine-verify

`fm-verify` checks a FundingMachine anchor or certificate without trusting
FundingMachine. It is a command-line tool and a Python library, Apache-2.0,
and it is the proof: any page that shows a verification result is a
convenience on top of it.

## What it checks

| Kind | Command | Status |
| --- | --- | --- |
| Merkle inclusion proof (RFC 9162, or an explicit path) | `fm-verify merkle` | done |
| OpenTimestamps proof against Bitcoin block headers | `fm-verify ots` | done |
| RFC 3161 time-stamp token against the authority's certificate chain | `fm-verify rfc3161` | done |
| A Provenance Ledger anchor (`docs/ANCHORING.md` layout): descriptor leaves, `root.preimage`, its OpenTimestamps proof and RFC 3161 tokens, and a checkout compared | `fm-verify anchors DIR --repo OWNER/NAME=PATH` | done from the published document; the manifest's own schema arrives with the Ledger's job (17 October) |
| An anchor batch in this verifier's own format (`batch.json`) | `fm-verify anchors` | done |
| Provenance Ledger certificate v0 (`ledger-certificate/v0`, JSON form): all seven steps of the Ledger's `docs/CERTIFICATE.md` (eddsa-jcs-2022 proof, scope statement, exported file, signed hourly root, inclusion, anchor, and with `--events` the chain and the authorship map) | `fm-verify certificate` | done, JSON or PDF form (the embedded `certificate.json`), with the HTML report (`--html`) |
| Provenance Ledger event chain (`ledger-event/v0`): every chain rule, in the contract's order, with the contract's failure codes | `fm-verify chain` | done |

The plan, with dates, is in [docs/PLAN.md](docs/PLAN.md). The input formats
are in [docs/INPUTS.md](docs/INPUTS.md). Programs and pages call one function,
`fmverify.api.verify`, JSON in and verdict out, with no disk or network
access: see [docs/API.md](docs/API.md).

## Independence

* **No private dependency.** The verifier needs the Python standard library
  and one public library, [`cryptography`](https://cryptography.io/)
  (Apache-2.0 or BSD), for signatures and certificates. Merkle and
  OpenTimestamps checks use the standard library alone.
* **No trust chosen for you.** No certificate authority is built in. You
  pass the roots you trust; the verdict names the root a chain reached and
  its SHA-256 fingerprint, for you to compare with the authority's own
  publication.
* **No phoning home.** The verifier opens no network connection unless you
  pass `--explorer`. A test replaces the socket layer with one that refuses,
  then runs every fixture through the command line.
* **Offline when given block headers.** With a headers file, an
  OpenTimestamps proof is checked with no network at all.
* **Reliance stated.** Every verdict lists what it had to take on trust: a
  headers file being Bitcoin's most-work chain, an explorer telling the
  truth, a certificate authority you chose to trust, a revocation the
  verifier could not see offline.

## Verdicts

A verdict is never a bare pass. Each one gives:

* an outcome and the statement it supports, for example "The sha256 digest
  ... existed no later than Bitcoin block 840000 (...), whose header gives the
  time 2024-04-20T00:09:27Z";
* every check, with its status (`pass`, `fail`, `warn`, `not_checked`,
  `info`) and reasons;
* what the verifier relied on;
* what the verdict does not establish: who wrote the content or how, that it
  is true, original or free of AI assistance, or that it did not exist
  earlier than the anchor.

| Outcome | Meaning | Exit status |
| --- | --- | --- |
| `valid` | every required check passed; the statement holds, given the reliance listed | 0 |
| `invalid` | something supplied contradicts something else: the file and the proof, the proof and the block header, two header sources, a signature and its key, a chain and the roots you trust | 1 |
| `indeterminate` | nothing contradicts, but something needed could not be checked: no header for the block, a proof still pending, a header too weak to rely on, no trusted root given | 2 |
| usage error | a file could not be read, an argument is malformed | 64 |

`--json` prints the same verdict as JSON. `--html PATH` also writes it as a
self-contained page (no script, no external resource); for a certificate the
page adds the authorship map (by document, section and capture fidelity) and
the evidence coverage, each figure labelled as recomputed from the chain or
read from the certificate, with the certificate's scope statement near the
top.

## Use

```sh
python -m pip install .

# An OpenTimestamps proof, against a sparse headers file (each header checked alone)
fm-verify ots document.pdf.ots --file document.pdf --headers headers.txt

# against a contiguous headers file, checked by Bitcoin's header rules from its first header
fm-verify ots document.pdf.ots --file document.pdf --headers-chain blockchain_headers@0

# against a public explorer, when you accept trusting it (the verdict says so)
fm-verify ots document.pdf.ots --file document.pdf --explorer https://mempool.space/api

# An RFC 3161 time-stamp token, against a root you trust
fm-verify rfc3161 document.pdf.tsr --file document.pdf --roots authority-root.pem [--chain intermediates.pem] [--crl issuer.crl]

# An anchor batch, compared with a checkout, against headers and a trusted authority root
fm-verify anchors anchors/2026-10-31 --repo-root . --headers-chain blockchain_headers --roots authority-root.pem

# A Provenance Ledger certificate, with the exported document it covers (and, for step 7, the document's events)
fm-verify certificate certificate.json --file proposal.pdf [--events events.json] --headers-chain blockchain_headers --roots digicert-root.pem --roots sectigo-root.pem

# A Provenance Ledger event chain
fm-verify chain events.json

# A Merkle inclusion proof, with the root you hold from the anchored record
fm-verify merkle proof.json --leaf-file document.pdf --root 6f1c...
```

### Where block headers come from

| Source | Checked | Relied on |
| --- | --- | --- |
| `--headers-chain FILE[@START]`: 80-byte headers back to back (Electrum's `blockchain_headers` has this layout) | linkage, proof of work, difficulty retargets and median time past, from `START`; from 0, the genesis hash | that the file is on Bitcoin's most-work chain; headers before `START` |
| `--headers FILE`: lines `HEIGHT HEX`, or JSON | each header's proof of work alone, against a floor of 2^70 expected hashes (`--min-work-bits`); links between neighbours in the file | that each header is the block at its height on the most-work chain |
| `--explorer URL`: an Esplora API | the header hashes to the block id the explorer gave, and meets its proof of work | that the explorer told the truth about which block is at that height |

Several sources may be given; if they disagree about a height, the verdict
is `invalid`. A Bitcoin block time is set by the miner and is only roughly
accurate (within about two hours); the verdict quotes it as the header's
time, not as a precise moment.

## Fixtures and the conformance suite

`fixtures/` holds the cases the test suite runs, each with the outcome the
verifier must reach, and `fixtures/SHA256SUMS`. They are rebuilt offline,
byte for byte, by `python tools/make_fixtures.py`. `fm-verify conformance
fixtures` checks the manifest and runs every case; the format is in
[docs/CONFORMANCE.md](docs/CONFORMANCE.md), for other implementations too.

* `ots/mainnet-840000-*`: a real proof built from public Bitcoin data only.
  The "file" is the single SHA-256 of block 840000's coinbase transaction,
  so the proof's file hash is the transaction id, and the path is the
  block's own Merkle branch. Only hashes and headers are kept; no
  transaction content. `tools/fetch_mainnet.py` captured them.
* `ots/regtest-*`: valid, tampered file, tampered proof, back-dated, pending
  only, truncated and trailing-byte proofs on a regtest chain mined by the
  fixture builder.
* `ledger-anchors/*`: anchors in the Provenance Ledger's layout over a
  synthetic repository (made-up rulings file, log and fragment): valid; a
  later checkout (a warning); a descriptor altered or dropped; one authority
  only (a warning); proofs over another root.
* `anchors/*`: batches over a synthetic four-file repository (no
  FundingMachine content): valid; checkout changed (a warning); a named file
  changed, files re-ordered, a file dropped, a back-dated token, a proof over
  another root (failures); a pending proof beside a valid token (valid, with
  the anchor-everything warning).
* `chain/*`: `ledger-event/v0` chains written by `tools/chain_fixtures.py`
  (two sessions, every event type, keyed hashes, no text): valid; tampered;
  a tool's text relabelled as a person's; one event back-dated; the whole
  chain back-dated and re-signed with the client keys (valid: the chain alone
  cannot tell, which is what anchors are for); re-ordered; re-ordered and
  re-signed; an event dropped; an event after its session closed; the wrong
  session's key; text in a payload.
* `certificate/*`: `ledger-certificate/v0` credentials issued by the fixture
  builder from the Ledger session's published documents, with this
  repository's own test keys, over the fixture chain: valid (anchored, not
  yet anchored, and with the chain for step 7); a total crediting the tool's
  text to the person, and a certificate omitting the tool (both caught only
  by step 7); the events of another document; wrong
  file; changed after signing; signed by another key; and an issuer that
  signs falsehoods (altered scope statement, inconsistent percentages, a
  root record signed by another key, a wrong inclusion path, an anchor time
  earlier than the authority's token, a token over another root, a Bitcoin
  block the proof does not hold); an unknown contract version.
* `certificate/pdf-*`: the PDF form: a classic file; PDF 1.5 with object and
  cross-reference streams and a deflated attachment; two attachments under
  one name (refused); an incremental update replacing the attachment (the
  current one is checked); no attachment. pypdf and poppler's `pdfdetach`
  take the same bytes from each.
* `rfc3161/*`: tokens from a test PKI (a root, an issuing CA, RSA, P-256 and
  Ed25519 authorities): valid with PKCS#1 v1.5, PSS, ECDSA and Ed25519; no
  root, wrong root, chain missing, tampered file, back-dated, tampered
  signature, wrong ESS certificate, missing or shared EKU, expired at the
  stated time, and a refused request; and revocation cases from CRLs: clean,
  key compromise (voids the token whenever revoked, RFC 3161 section 4),
  superseded after the token's time (stands), revoked before it, a CRL too
  old to tell, and a forged CRL. Every key is derived from a seed
  published in `tools/tsa_fixtures.py`: they protect nothing, and no key
  file is committed.

Independent implementations check the same fixtures in CI:

* the reference OpenTimestamps library (`tests/test_interop.py`) must reach
  the same commitments and reject the same malformed proofs;
* OpenSSL's `ts -verify` (`tests/test_interop_openssl.py`) must agree on
  every RFC 3161 case it supports (revocation cases aside: OpenSSL treats
  any listed serial as revoked, whatever its date and reason). OpenSSL 3.0
  cannot check RSASSA-PSS
  through `ts` nor Ed25519 in CMS at all, so those two tokens are checked
  with `openssl cms -verify` and with the reference Ed25519 algorithm of
  RFC 8032, written out in the test. A token made by OpenSSL's own
  time-stamping code must verify here.

* the Provenance Ledger session's own fixtures, made by its TypeScript code,
  must verify here: its 19 event chains with their codes and positions, its
  authorship map byte for byte, its certificate through all seven steps
  (`tests/test_chain.py`, `tests/test_certificate.py`, run when
  `FM_LEDGER_REPO` points at a checkout of fundingmachine-ledger, which is
  private; its fixtures are not copied into this public repository);
* and the reverse: `tools/ledger_crosscheck/run.mts` runs the Ledger's own
  validator over this repository's chain and certificate fixtures. On
  16 October 2026 it agreed on all 11 chains, on the proof of all 17
  certificates, and on the authorship map hash.

Those tools are test-time only; the verifier never imports them.

## What the verifier cannot detect

[docs/SECURITY_NOTE.md](docs/SECURITY_NOTE.md), a first version of the note
due 14 November. In short: an anchor shows that a digest existed no later
than a time, not who made the content, that it is true, or that it did not
exist earlier. An event chain records what the capture client observed and
signed; whoever holds the client keys can record any history, and only an
anchor bounds its time. Headers, authority roots and revocation lists are
the reader's evidence, and every verdict says which it relied on.

## Licence

Apache-2.0, see [LICENSE](LICENSE).
