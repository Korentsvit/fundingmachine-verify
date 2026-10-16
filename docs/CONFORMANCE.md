# Conformance suite

```sh
fm-verify conformance fixtures      # exit 0 only if the fixtures are the published ones and every case conforms
fm-verify conformance fixtures --json
```

Every verdict the suite produces is valid under `docs/verdict.schema.json`.
The suite first checks `fixtures/SHA256SUMS`, so a run says whether it used
the published fixtures, then runs every case and compares the verdict with
the case's `expected.json`. Another implementation can use the same cases:
read the inputs named below, and compare its outcome with `outcome`.

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
  merkle/<case>/             proof.json, leaf.txt, expected.json (with "leaf_file" and, optionally, the anchored "root")
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

* OpenTimestamps: a real mainnet proof (sparse headers, a header chain, no
  headers, the wrong file, a forged header) and regtest proofs (valid,
  tampered file, tampered proof, back-dated, pending only, truncated,
  trailing bytes).
* RFC 3161: valid tokens under four signature schemes; trust (no root, wrong
  root, chain missing); tampering (file, back-dated time, signature, ESS);
  certificate rules (EKU missing or shared, expired); a refused request; and
  revocation (clean, key compromise, superseded later, revoked before, stale
  and forged CRLs).
* Anchor batches: valid; a changed checkout; a changed file a reader holds;
  re-ordered and dropped files; a pending proof; a back-dated token; a
  proof over another root.
* Provenance Ledger anchors (`anchor-manifest/v0`): valid; checkouts later
  changed or with the fragment assembled into the log; a descriptor altered
  or dropped; a leaf hash wrong; leaves out of order; the manifest misstating
  a token; a schema violation; a source not read; one token missing; an
  unknown contract; no contract; proofs over another root; and sets with
  `index.jsonl` (valid, a broken link, an anchor not listed).

* Certificates (`ledger-certificate/v0`): valid, anchored or not, with and
  without the chain; changed after signing; another key; and an issuer
  signing falsehoods, from the scope statement to the authorship totals.
* Event chains (`ledger-event/v0`): valid, tampered, back-dated (one event,
  and the whole chain consistently, which the chain alone cannot detect),
  re-ordered (plainly, and re-signed), dropped, after close, wrong key, text
  in a payload.

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
