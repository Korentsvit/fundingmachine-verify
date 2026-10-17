# Conformance suite

```sh
fm-verify conformance fixtures      # exit 0 only if the fixtures are the published ones and every case conforms
fm-verify conformance fixtures --json
```

Every verdict the suite produces is valid under `docs/verdict.schema.json`.
The suite first checks `fixtures/SHA256SUMS`, so a run says whether it used
the published fixtures, then runs every case and compares the verdict with
the case's `expected.json`. Another implementation can be run over the same
cases with `--implementation` (below).

## Running another implementation

```sh
fm-verify conformance fixtures --implementation "your-verifier --some-option"
fm-verify conformance fixtures --implementation "your-verifier" --kind rfc3161 --kind ots
```

For each case the runner calls the command with two more arguments, the
case's kind (the directory it sits under: `ots`, `rfc3161`, `merkle`,
`anchors`, `ledger-anchors`, `certificate`, `chain`, `roots`) and the case
directory's absolute path. The command reads the inputs the case's
`expected.json` names (below), and prints its verdict as one JSON object on
standard output, holding at least `outcome` (`valid`, `invalid` or
`indeterminate`); its exit status is not read. The runner compares the
outcome with the case's. An implementation that uses this verifier's check
ids (`docs/verdict.schema.json`) can add `--check-ids`, and its `checks`
with status `fail` and `warn` are compared with `failing` and `warning`
too. `--kind` (repeatable) runs only the formats an implementation covers;
`--timeout` sets the seconds allowed per case (default 60). No shell is
involved: the command is split as a POSIX shell would split it, and run
directly.

`fm-verify conformance-case KIND CASE_DIR` is the reference for this
contract: this verifier, one case at a time, printing its verdict as JSON.
Run as an outside program, it conforms on every case with `--check-ids`; a
command answering `valid` to everything conforms on 45 of the 136 cases.

## Layout

```
fixtures/
  SHA256SUMS                 SHA-256 of every fixture file
  bitcoin/mainnet/           public Bitcoin headers and the data behind the mainnet proof
  bitcoin/regtest/           regtest header chains mined by the fixture builder
  ots/<case>/                proof.ots, the subject file, expected.json
  rfc3161/<case>/            token.tsr, document.txt, expected.json
  rfc3161/pki/, rfc3161/crl/ the test PKI's certificates and revocation lists
  anchors/<case>/            batch.json, root.ots, root.test-tsa.tsr, expected.json
  anchors/repo/, repo-changed/  the synthetic repository the batches list, as anchored and as later changed
  certificate/<case>/        certificate.json, exported.txt, events.json where step 7 runs, expected.json
  chain/<case>/              events.json ({"contract", "events"}), disclosure.json where the text is disclosed, expected.json
  roots/<case>/              roots.json ({"records"}), expected.json (with the tenant's did:key as "key")
  merkle/<case>/             proof.json, leaf.txt, expected.json (with "leaf_file" and, optionally, the anchored "root" and "tree_size")
  ledger-anchors/<case>/     manifest.json, root.preimage and its proofs, expected.json
  ledger-anchors/set-*/      an anchors directory: index.jsonl and anchors under YYYY/MM/DD/HHMMSSZ/, expected.json
```

## expected.json

| Field | Meaning |
| --- | --- |
| `description` | what the case is |
| `outcome` | `valid`, `invalid` or `indeterminate` |
| `failing` | the check ids that must fail, in order, and no others (default none) |
| `warning` | check ids that must warn, at least (default none) |
| `network` | `mainnet` or `regtest` |
| `file` | the subject file, relative to the case (`ots`, `rfc3161`) |
| `headers` | sparse header files, relative to the case |
| `headers_chain` | contiguous header files: `{"path", "start"}` |
| `roots`, `chain`, `crls` | PEM files: trusted roots, extra certificates, revocation lists |
| `repo_root`, `files` | for anchor batches: a checkout to compare, and files a reader holds (relative to `repo_root`) |
| `events` | for certificates: the event chain file, for step 7 |
| `index`, `code` | for chains: the position of the first bad event and the contract's failure code |
| `disclosure` | for chains: a disclosure file (document key and inserted texts) to replay |
| `repos` | for Ledger anchors: checkouts to compare, `{"OWNER/NAME": path}` |
| `all` | for Ledger anchors: the case is a whole anchors directory, verified as a set (`fm-verify anchors DIR --all`) |

Check ids are this verifier's; another implementation is asked to match
`outcome`, and may map its own reasons to `failing` as it sees fit.

## What the cases cover

136 cases, on 17 October 2026:

* OpenTimestamps (12): a real mainnet proof (sparse headers, a header chain,
  no headers, the wrong file, a forged header) and regtest proofs (valid,
  tampered file, tampered proof, back-dated, pending only, truncated,
  trailing bytes).
* RFC 3161 (21): valid tokens under four signature schemes; trust (no root,
  wrong root, chain missing); tampering (file, back-dated time, signature,
  ESS); certificate rules (EKU missing or shared, expired); a refused
  request; and revocation (clean, key compromise, superseded later, revoked
  before, stale and forged CRLs).
* Merkle inclusion proofs (8): RFC 9162 valid, the wrong leaf, the wrong
  index, another root, a path too long, the tree size held, a size of the
  same shape claimed; the explicit scheme (a warning).
* Anchor batches (8): valid; a changed checkout; a changed file a reader holds;
  re-ordered and dropped files; a pending proof; a back-dated token; a
  proof over another root.
* Provenance Ledger anchors (22, `anchor-manifest/v0`): valid; checkouts later
  changed or with the fragment assembled into the log; a descriptor altered
  or dropped; a leaf hash wrong; leaves out of order; the manifest misstating
  a token; a schema violation; a source not read; one token missing; tokens
  from one organisation; an authority misnamed; an unknown contract; no
  contract; proofs over another root; sets with `index.jsonl` (valid, a
  broken link, an anchor not listed); and the anchors naming one content
  hash (`prove_sha256`: the earliest that holds, a later one only, none).
* Certificates (27, `ledger-certificate/v0`), over `ledger-event/v0` and v0.1
  chains: valid, anchored or not (and issued before its hour has a root),
  with and without the chain; in PDF form (classic, compressed, updated, no
  attachment, two attachments); changed after signing; another key; the
  wrong file; and an issuer signing falsehoods, from the scope statement to
  the authorship totals and the anchor's times, or signing a position as a
  string.
* Event chains (32, `ledger-event/v0` and v0.1): valid, tampered, back-dated
  (one event, and the whole chain consistently, which the chain alone cannot
  detect), re-ordered (plainly, and re-signed), dropped, after close, wrong
  key, text in a payload, no events at all; a `capture.resync` (valid, not
  first, emptying the document); a version this verifier does not read
  (indeterminate); and disclosures (valid, one word changed, the wrong key,
  one event given twice, text no hash covers, the signer's name changed);
  and nine rule pairs, `pair-FIRST-over-SECOND` (below).
* Hourly root records (6, `ledger-root/v0`): valid, an hour dropped, two
  swapped, one altered, another key, a later stretch alone.

## The Provenance Ledger's suite

The Provenance Ledger session's `validation-conformance/v0` names 28 cases
for a verifier. Two kinds of them run here, in CI on every pull request, on
main and nightly (`.github/workflows/conformance.yml`):

* **Rule pairs (its CS-22).** Where one event breaks two chain rules, the
  code reported is the one of the rule listed first in the contract's chain
  rules table. The nine `chain/pair-*` cases are the five pairs of its CT-02
  (a repeated `event_id` with each of the five rules before it) and the four
  other pairs of the Ledger's own order test. `tools/chain_fixtures.py`
  writes them from this repository's own chain, re-signing the changed event
  and relinking the ones after it, so that nothing breaks but the two rules.
  `tests/test_chain_pairs.py` checks that each rule broken alone gives its
  own code. The Ledger's own validator gave the same answer on every pair
  and every single-rule variant (its main 8711ff9, 17 October 2026, through
  `tools/ledger_crosscheck/run.mts`).
* **Live anchors (its CS-42 and CS-43)**, on the Ledger's public mirror at
  its current head: `tools/mirror_conformance.py`. CS-42 requires every
  anchor to hold, with its proofs and the link to the one before it; an
  anchor whose Bitcoin proof is still pending must hold on everything else.
  CS-43 changes one leaf's `sha256` in a copy of the newest confirmed anchor;
  that anchor must be invalid, with the check that failed.

The other cases run on fixtures in the Ledger's repository, which is
private; they are run in this session's checkout, not in CI.

## Versioned releases

A release of the suite is one file, `fm-verify-fixtures-VERSION.tar`, made by
`python tools/fixture_archive.py VERSION` from the tagged commit. The archive
is reproducible: POSIX ustar entries in path order, every timestamp 0, owner
0, fixed modes, and no compression, so the same commit gives the same bytes
on any machine (checked with Python 3.11, 3.12 and 3.13, and in the tests).
To check a release without trusting whoever published it, rebuild the
archive from the tag and compare SHA-256 values, then run:

```sh
tar xf fm-verify-fixtures-VERSION.tar
fm-verify conformance fm-verify-fixtures-VERSION
```

A release's version changes when a case's expected verdict changes (major),
when cases are added (minor), or when bytes change without changing any
verdict (patch).
