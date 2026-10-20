# Ledger certificate, 20 October 2026, 16:00:39 UTC

A `ledger-certificate/v0` the live Provenance Ledger issued for a document
written in the Google Docs capture client, verified by fm-verify 0.2.0, the
published release.

**Verdict: valid, for what the certificate carries.** The issuer's key signed
the certificate for sign event seq 36
(`0eb0c9b266ec970762eeba64f2090ca17de5d02411d42395e166b2b1abad5b04`) of
document `9edf6777-bf47-477e-8800-48b88a7ad653`, and its scope statement and
authorship figures hold.

* The certificate was issued before its hour's root was signed
  (`ledger_root` is null). So steps 4 to 6 (the root record, the sign
  event's inclusion, the anchor) did not run.
* Nothing anchors the sign event's time: it is the issuer's and the capture
  client's claim.

The JSON and the PDF form give the same verdict. The PDF's verdict adds
only the row saying where it took the JSON from.

## Source

* **The certificate.** `urn:uuid:e1893278-ef09-4ab0-868d-fed0b27007cf`,
  contract `ledger-certificate/v0` (the Ledger's `docs/CERTIFICATE.md`),
  valid from 2026-10-19T16:37:39.260Z, the time of its proof: the first certificate issued for this document, at the sign event of 19 October.
  * The document's chain had 36 events in 5 sessions of
    `capture-gdocs` 0.1.0 at the sign event, and the exported file it names
    has SHA-256 `754da3f1...`.
  * Its signed block names no tool, and its `declaration_hash` is null.
* **Where it came from.**
  * The Ledger session exported it with the `ledger-admin` workflow's
    certificate export job (run 39452555671, tenant demo), kept as the run's
    artifact.
  * This session read the artifact through its own access to the Ledger's
    repository.
* **Files received.** [`certificate.sha256`](certificate.sha256) gives the
  SHA-256 of the two files received: `certificate.json`, the RFC 8785 form,
  and `certificate.pdf`. Each matches the hash the Ledger session reported.
  * The PDF's embedded `certificate.json` is the same credential, written
    out with indentation (5,787 bytes, SHA-256 `cd135fcf...`).
  * Put in RFC 8785 form, the embedded copy is byte for byte the exported
    `certificate.json`.
* **Not published.** The certificate is the tenant's to share, and its
  holder has not said it may be published. So only this verdict and the
  SHA-256 values are committed.

## What the verdict relied on

* **The issuer's key.**
  * The certificate names its issuer as
    `did:key:z6MktejuBN555Bs4mm2rjsBDvujSMp1kVXWnMr1ptSLyzyVB`, the same key
    that signed the other Docs certificates and the two record certificates
    of 17 October.
  * The certificate names the key; nothing outside it vouches that the key
    is the tenant's. To establish that, compare the key with one the
    tenant publishes.
* **No block headers and no roots of trust.** With no hourly root and no
  anchor, the verdict relied on nothing beyond the certificate.

## What the verdict does not establish

* Who wrote the document, or how. The certificate states how it was
  written in this environment, as the capture client recorded it.
* That the document's content is true, original, or free of AI assistance.
* That the exported file is any file you hold: none was presented
  (`--file` runs step 3).
* The record's own statements against its events. The document's events
  stay with the tenant and were not given, so step 7 did not run
  (`--events`).
* When the document was signed: no root record or anchor binds the time.

## Reproduce

With the certificate (from its holder) in this directory, and fm-verify
0.2.0 installed from its release:

```sh
sha256sum -c --ignore-missing certificate.sha256   # the files are the ones verified here
fm-verify certificate certificate.json
fm-verify certificate certificate.pdf
```

`--json` gives the machine-readable verdict.
