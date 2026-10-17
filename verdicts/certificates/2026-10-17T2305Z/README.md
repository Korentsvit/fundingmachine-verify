# Record certificate, 17 October 2026, 23:05 UTC

The second record certificate the live Provenance Ledger issued, verified by
fm-verify.

**Verdict: valid.** The issuer's key signed the certificate for record
`9196354d75f45991c3792bd3c17e4e61b90cc91f7c2d4c2957c08e4fbd184135` (28
events, head at seq 28). Every hash link from the record's head to Bitcoin
block 971906 holds:

1. the head to the hour's root (the hour holds this one event);
2. the hour's signed root record;
3. the anchored root;
4. two RFC 3161 tokens;
5. the OpenTimestamps path;
6. the block header.

The JSON and the PDF form give the same verdict. Only the verdict's subject
line differs.

## Source

* **The certificate.** `urn:uuid:ed65828a-9107-416d-924d-1b907e29702b`,
  contract `record-certificate/v0` (the Ledger's
  `docs/RECORD_CERTIFICATE.md`), issued at 2026-10-17T23:01:23.851Z.
* **Where it came from.** The Ledger session passed it on as the artifact of
  the `ledger-admin` workflow's `record-certificate` job in the Ledger's
  repository (run 39077366815). This session read the artifact through its
  own access to that repository.
* **Files received.** [`certificate.sha256`](certificate.sha256) gives the
  SHA-256 of each of the four files received: `certificate.json`,
  `certificate.sig`, `certificate.pdf` and `verify.sh`. Each matches the
  hash the Ledger session reported.
* **Not committed.** The certificate is the tenant's to share. As agreed
  with the Ledger session, only this verdict and the SHA-256 values are
  committed.
* **Cross-check: the public submission index.**
  * Read from https://fundingmachine-ledger.vercel.app/api/submission-index at
    23:04 UTC. Its contract is `submission-index/v0`, it held two entries,
    and the copy read had SHA-256
    `894002d09f4655a2dee66855d03fbbc1a90751f954287429b1187e533e1ae8a9`.
  * The index lists this certificate's SHA-256 once, after the
    [first certificate](../2026-10-17T2110Z), in issue order. The entry gives
    the same record, tenant pseudonym, event count, head, hour, anchored root
    and block as the certificate, and no other field (check
    `record_certificate.index`).
  * The index grows as certificates are issued, so a later copy will have a
    different SHA-256. The entry is what to compare.
* **The Ledger's own run.** The artifact also holds the Ledger's `verify.log`
  from running `verify.sh`. This verdict did not run that script and did not
  compare its commands. It checked every step with this repository's own
  code.

## What the verdict relied on

* **The Bitcoin block header.** [`headers.txt`](headers.txt) holds one
  header, at height 971906.
  * Fetched at 23:04 UTC from mempool.space and from blockstream.info. Both
    gave the same bytes.
  * It hashes to block
    `00000000000000000000815765314ea275621058cf1885debd0b11ca7c7764b8`, and
    fm-verify checked its proof of work.
  * It is the same header the certificate carries. The verdict requires this
    second source of the reader's own; the header the issuer supplies is not
    the chain's word.
  * A reader with a Bitcoin node can check the header themselves.
* **Roots of trust for the RFC 3161 tokens.** The operating system's
  `/etc/ssl/certs/ca-certificates.crt`.
  * DigiCert's token chains to DigiCert Trusted Root G4 (SHA-256
    `552f7bdc...`).
  * Sectigo's token chains to USERTrust RSA Certification Authority
    (`e793c9b0...`).
* **Revocation.** Not checked; no revocation lists were given.
* **The issuer's key.** The key is
  `d2f48067c29393ada201fee5de79f502f821e5e3e22e2d84253f043e0ce5a64a`, with
  key id `ad0cda7b...`. It is the same key that signed the first
  certificate.
  * The certificate names the tenant by the pseudonym
    `tp-06e272def2eb0da0477415b7c1c7e140`. That is the pseudonym the
    contract derives from this key id (`record_certificate.pseudonym`).
  * The issuer writes both the key and the pseudonym. So this check shows
    they are consistent; it does not show that the key is the tenant's.
  * To establish that, compare the key with one the tenant publishes.

## Reading the times

* Both authorities stamped the anchored root at 2026-10-17T20:07:23Z.
* Bitcoin block 971906's header gives the time 2026-10-17T20:45:01Z. A
  header's time is set by its miner. Consensus keeps it later than the median
  of the 11 blocks before it, and no more than two hours ahead of the
  network's clock.
* All of these bound the record's head from above: the head existed no later
  than each of them.
* The head's own times (`ts`, as the client wrote it, and `received_at`, the
  Ledger's clock) are the issuer's statements, inside the signed
  certificate. No proof covers them.

## What the verdict does not establish

* Who wrote the document, or how. A record certificate states the record's
  shape, not its authorship.
* That the document's content is true, original, or free of AI assistance.
* The record's own statements (its events, sessions and head).
  * The document's events stay with the tenant and were not given, so the
    chain was not replayed. `record_certificate.chain` is optional and is
    reported as not checked.
* That the issuer's key is the tenant's.
* That the printed commands (`procedure`, `verify.sh`) do what this verdict
  did.

The hour's root record inside the certificate carries the tenant's id, as the
Ledger signed it. This verdict does not repeat it.

## Reproduce

With the certificate from its holder:

```sh
sha256sum -c certificate.sha256        # the files are the ones verified here
curl -s https://fundingmachine-ledger.vercel.app/api/submission-index > index.json
python tools/fetch_headers.py certificate.json headers.txt   # two explorers, compared
fm-verify record-certificate certificate.json --headers headers.txt \
    --roots /etc/ssl/certs/ca-certificates.crt --index index.json
fm-verify record-certificate certificate.pdf --headers headers.txt \
    --roots /etc/ssl/certs/ca-certificates.crt --index index.json
```

`--json` gives the machine-readable verdict. With the document's events,
`--events events.json` also replays the chain.
