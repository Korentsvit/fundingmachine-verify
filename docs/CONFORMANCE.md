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
`anchors`, `ledger-anchors`, `certificate`, `record-certificate`, `chain`, `roots`) and the case
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
command answering `valid` to everything conforms on 55 of the 262 cases.

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
  record-certificate/<case>/ certificate.json and certificate.sig, or certificate.pdf ("certificate"), events.json and index.json where given, expected.json
  chain/<case>/              events.json ({"contract", "events"}), disclosure.json where the text is disclosed, expected.json
  roots/<case>/              roots.json ({"records"}), expected.json (with the tenant's did:key as "key")
  acceptance/<case>/         acceptance.json, root-record.json and hour.json where given, expected.json ("key", "proof", "root_record", "hour")
  merkle/<case>/             proof.json, leaf.txt, expected.json (with "leaf_file" and, optionally, the anchored "root" and "tree_size")
  ledger-anchors/<case>/     manifest.json, root.preimage and its proofs, expected.json
  ledger-anchors/set-*/      an anchors directory: index.jsonl and anchors under YYYY/MM/DD/HHMMSSZ/, expected.json
  ledger-conformance/        the Provenance Ledger suite's pair fixtures, unchanged, with their LICENSE (below)
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
| `key` | for root records and acceptance proofs: the tenant's did:key; without it the signatures are not checked |
| `proof`, `root_record`, `hour` | for acceptance proofs: what `GET /api/acceptance` answered, the hour's `ledger-root/v0` record, and what `GET /api/anchors?hour=` answered, each a file in the case |

Check ids are this verifier's; another implementation is asked to match
`outcome`, and may map its own reasons to `failing` as it sees fit.

## What the cases cover

262 cases, on 20 October 2026:

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
* Certificates (31, `ledger-certificate/v0` and v0.1), over `ledger-event/v0`
  and v0.1 chains: valid, anchored or not (and issued before its hour has a
  root), with and without the chain; in PDF form (classic, compressed,
  updated, no attachment, two attachments); changed after signing; another
  key; the wrong file; and an issuer signing falsehoods, from the scope
  statement to the authorship totals and the anchor's times, or signing a
  position as a string. For v0.1, the signature's meaning and the printed
  name's hash: as the chain records them, the meaning missing, the hash
  malformed, and a meaning the sign event does not record.
* Record certificates (20, `record-certificate/v0`): valid, in JSON with its
  signature and in PDF form, with and without the events; no Bitcoin source
  of the reader's own (indeterminate); changed after signing; not in RFC 8785
  form; signed by another key; the scope statement altered; the head's steps
  claimed for another leaf; the hour's root record signed by another key; a
  token for another root; steps to the merkle root that are not the proof's;
  a block time misstated; another block's header; an unknown version; the
  tokens' times written as the same instants otherwise (valid); a proof path
  with an operation the steps cannot write; and the certificate's entry in
  the public submission index (matching, misstating, not listed).
* Event chains (32, `ledger-event/v0` and v0.1): valid, tampered, back-dated
  (one event, and the whole chain consistently, which the chain alone cannot
  detect), re-ordered (plainly, and re-signed), dropped, after close, wrong
  key, text in a payload, no events at all; a `capture.resync` (valid, not
  first, emptying the document); a version this verifier does not read
  (indeterminate); and disclosures (valid, one word changed, the wrong key,
  one event given twice, text no hash covers, the signer's name changed);
  and nine rule pairs, `pair-FIRST-over-SECOND` (below).
* The Provenance Ledger suite's rule pairs (88, `chain/ledger-pair/*`), its
  own fixture files, run as chain cases (below).
* Hourly root records (6, `ledger-root/v0`): valid, an hour dropped, two
  swapped, one altered, another key, a later stretch alone.
* Acceptance proofs (14, `ledger-acceptance/v0`): valid with the root
  record and the anchored hour's proofs, the answer alone, and an hour not
  yet anchored; no tenant key and an hour with no acceptance record
  (indeterminate); the time one microsecond later, written in milliseconds,
  and outside its hour; the record altered and signed by another key;
  another tenant's root record; an hour record of another root; an
  authority stamping the root before the acceptance time; and a token's
  time misstated.

## The Provenance Ledger's suite

The Provenance Ledger session's `validation-conformance/v0` names 39 cases
for a verifier (its main c8fcfee). Two kinds of them run here, in CI on every
pull request, on main and nightly (`.github/workflows/conformance.yml`):

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
* **Its own pair fixtures (CS-22 as it writes it).** Since 18 October 2026 the
  suite's fixture files are licensed Apache-2.0 (copyright NW PharmaTech Ltd),
  and its 88 pair files are under `fixtures/ledger-conformance/`, unchanged
  from the Ledger's `docs/validation/conformance/fixtures/` at e64f356, with
  their LICENSE and a README naming the source. `fm-verify conformance` runs
  each as the chain case `chain/ledger-pair/<name>`: invalid, only
  `chain.rules` failing, and the chain stopping at the file's `expect.index`
  with its `expect.code`. All 88 conform. With `--implementation`, another
  implementation is given each as a chain case directory. The two pairs of
  the Ledger's finding F-14 (`session_unknown` with `key_mismatch`, and with
  `bad_signature`) were added on 20 October, when its contract stated that
  order; this verifier always reported `session_unknown` first.
* **Live anchors (its CS-42 and CS-43)**, on the Ledger's public mirror at
  its current head: `tools/mirror_conformance.py`. CS-42 requires every
  anchor to hold, with its proofs and the link to the one before it; an
  anchor whose Bitcoin proof is still pending must hold on everything else.
  CS-43 changes one leaf's `sha256` in a copy of the newest confirmed anchor;
  that anchor must be invalid, with the check that failed.

* **Certificate cases its recipes let a verifier derive (its CS-03, CS-08,
  CS-11 and CS-12)**, from its `fixtures/certificate/v0/basic.certificate.json`
  read in a checkout of its repository, not copied
  (`tests/test_ledger_suite_certificate.py`, with `FM_LEDGER_REPO`):
  * CS-03 and CS-08: the exported file is the bytes its fixture script signs,
    checked against the certificate's `exported_sha256` and `byte_length`
    before use. CS-08 changes one byte: `certificate.file` fails, nothing
    else does.
  * CS-11 and CS-12: the certificate gains an anchor (a pending
    OpenTimestamps proof and two RFC 3161 tokens for the anchored root, from
    this repository's two test authorities) and is re-signed with the
    fixture's issuer key, which is a published test vector (RFC 8032
    section 7.1, its `keys.json` "tenant"). Re-signing the unchanged
    certificate gives its own proof byte for byte, so the signing is the
    issuer's. CS-11 is valid with the pending proof not checked and not
    failing; in CS-12 the token for another digest fails.
  * All four agree, on the Ledger's main fc5ee1e (19 October 2026).

* **Record certificate cases on its test vector (its CS-71, and CS-61 to
  CS-69 derived from it)**, from `fixtures/record-certificate/v0` in a
  checkout of its repository, not copied (`tests/test_ledger_suite_record.py`,
  with `FM_LEDGER_REPO`):
  * The vector is synthetic: issuer, root record and acceptance record
    signed with its `keys.json` "tenant" (RFC 8032 TEST 3), tokens from two
    test authorities whose roots it carries, and a regtest block
    (`headers.txt`). Re-signing it unchanged gives its own signature.
  * CS-71 is valid with every check passing; without the header file the
    block is not run, and the verdict is indeterminate.
  * Each derived case fails exactly the checks its table names. CS-63 (the
    head stated as another leaf) fails `head_to_root`. CS-64 (a root record
    signed by another key) fails `root_record` and `record_to_anchor`,
    since the anchored root commits to the issuer's record. CS-66 (the
    token times without fractional seconds) holds. CS-69 (an unknown
    version) is not verified.
  * All agree, on the Ledger's main of 20 October 2026. Its CS-60 and CS-61
    ran on the first certificate the live Ledger issued (17 October).

The other cases run on fixtures in the Ledger's repository, which is
private; they are run in this session's checkout, not in CI.

Its record certificate cases (CS-60 to CS-70) name one result per check of
the contract's own list. This verifier reports them as these check ids:

| The suite's check | fm-verify check ids |
| --- | --- |
| form and signature | `record_certificate.form`, `record_certificate.schema`, `record_certificate.signature` |
| scope | `record_certificate.scope_statement` |
| inclusion | `record_certificate.head_to_root`, `record_certificate.record_to_anchor` |
| root record | `record_certificate.root_record` |
| rfc3161 | `record_certificate.rfc3161.N`, one per token |
| opentimestamps | `record_certificate.opentimestamps` |
| header | `record_certificate.block_header` |
| block | `record_certificate.bitcoin_block` (not run, and the verdict indeterminate, without a source of the reader's own) |
| index, match (CS-70) | `record_certificate.index` |

An unknown contract version (CS-69) is `record_certificate.contract`, not
run: the verdict is indeterminate, not invalid.

Two optional checks are this verifier's own and have no case in the suite:
`record_certificate.chain`, when the document's events are given, and
`record_certificate.pseudonym`, which passes when the tenant pseudonym is the
one the contract derives from the issuer's key id and is information
otherwise (a tenant that rotated its key keeps the pseudonym of its first).

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

From v0.3.0 a release also carries `fm-verify-scoreboard-VERSION.json`
(`fm-verify-scoreboard/v0`, `tools/scoreboard.py`): the newest anchor
verdict committed at the tag (anchors named, confirmed in Bitcoin, pending,
failed), every certificate verdict committed there, and this suite's cases
passing, run by the release's own wheel on its fixture archive. It holds no
time of its own, so it rebuilds byte for byte:

```sh
python -m pip install fundingmachine_verify-VERSION-py3-none-any.whl
python tools/scoreboard.py VERSION OUT --commit TAGGED_COMMIT --fixtures fm-verify-fixtures-VERSION --run RUN_ID   # from a checkout of the tag
```

Each figure names the run it traces to (`trace`, and `run_id` on each
section and certificate): the conformance run on main at the tagged commit,
which existed before the release. Its log shows the passing count, the
newest anchor verdict with its counts, and each certificate verdict filed
(`tools/verdict_summary.py`). The release finds that run, records its id,
and refuses to publish unless the run's log shows every figure
(`tools/scoreboard.py --check-log LOG FILE`).

The Provenance Ledger's own suite is not in it: that runs from a checkout of
the Ledger's repository, which a release does not depend on.

A release's version changes when a case's expected verdict changes (major),
when cases are added (minor), or when bytes change without changing any
verdict (patch).
