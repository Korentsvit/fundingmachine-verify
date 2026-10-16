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
| RFC 3161 time-stamp token against the authority's certificate chain | `fm-verify rfc3161` | next |
| An anchor batch: Merkle root, its OpenTimestamps proof and its RFC 3161 tokens together | `fm-verify anchors` | queued, for 18 October |
| Certificate v0: ed25519 signatures, event chain, Merkle roots, anchors | `fm-verify certificate` | queued, for 31 October |

The plan, with dates, is in [docs/PLAN.md](docs/PLAN.md). The input formats
are in [docs/INPUTS.md](docs/INPUTS.md).

## Independence

* **No private dependency.** Today the verifier uses the Python standard
  library only. Signature checks (RFC 3161, ed25519) will add one public
  library, `cryptography`, and nothing from FundingMachine.
* **No phoning home.** The verifier opens no network connection unless you
  pass `--explorer`. A test replaces the socket layer with one that refuses,
  then runs every fixture through the command line.
* **Offline when given block headers.** With a headers file, an
  OpenTimestamps proof is checked with no network at all.
* **Reliance stated.** Every verdict lists what it had to take on trust: a
  headers file being Bitcoin's most-work chain, an explorer telling the
  truth, a certificate authority you chose to trust.

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
| `invalid` | something supplied contradicts something else: the file and the proof, the proof and the block header, two header sources, a signature and its key | 1 |
| `indeterminate` | nothing contradicts, but something needed could not be checked: no header for the block, a proof still pending, a header too weak to rely on | 2 |
| usage error | a file could not be read, an argument is malformed | 64 |

`--json` prints the same verdict as JSON.

## Use

```sh
python -m pip install .

# An OpenTimestamps proof, against a sparse headers file (each header checked alone)
fm-verify ots document.pdf.ots --file document.pdf --headers headers.txt

# against a contiguous headers file, checked by Bitcoin's header rules from its first header
fm-verify ots document.pdf.ots --file document.pdf --headers-chain blockchain_headers@0

# against a public explorer, when you accept trusting it (the verdict says so)
fm-verify ots document.pdf.ots --file document.pdf --explorer https://mempool.space/api

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

## Fixtures

`fixtures/` holds the cases the test suite runs, each with the outcome the
verifier must reach, and `fixtures/SHA256SUMS`. They are rebuilt offline,
byte for byte, by `python tools/make_fixtures.py`.

* `ots/mainnet-840000-*`: a real proof built from public Bitcoin data only.
  The "file" is the single SHA-256 of block 840000's coinbase transaction,
  so the proof's file hash is the transaction id, and the path is the
  block's own Merkle branch. Only hashes and headers are kept; no
  transaction content. `tools/fetch_mainnet.py` captured them.
* `ots/regtest-*`: valid, tampered file, tampered proof, back-dated, pending
  only, truncated and trailing-byte proofs on a regtest chain mined by the
  fixture builder.

The OpenTimestamps fixtures are also read by the reference OpenTimestamps
library in CI (`tests/test_interop.py`), which must reach the same
commitments and reject the same malformed proofs. That library is a
test-time tool only; the verifier never imports it.

## What the verifier cannot detect

A full security note is due by 14 November. In short: an anchor shows that a
digest existed no later than a time. It does not show who made the content,
that it is true, or that it did not exist earlier. A headers file or explorer
you are given could describe a chain other than Bitcoin's most-work chain;
the verdict says which you relied on.

## Licence

Apache-2.0, see [LICENSE](LICENSE).
