# Plan

Owner: the Verifier session. Scope: this repository only. Not building the
ledger, capture, capital, or the website.

## Gates

| Date | Gate |
| --- | --- |
| 18 October 2026 | Verify the anchor-everything proofs the Provenance Ledger session commits under `anchors/` in fundingmachine-core, Knowledge-goblin and fundingmachine-web: Merkle paths, OpenTimestamps proofs against Bitcoin block headers (offline headers file, optional public explorer, reliance stated), RFC 3161 tokens against the authorities' certificate chains. Until those proofs exist, against fixtures of our own. |
| 31 October 2026 | Certificate v0 end to end (ed25519 signatures, event chain, Merkle roots, anchors) against the Ledger session's `docs/CERTIFICATE.md` in fundingmachine-ledger; the authorship map and evidence coverage rendered as a static HTML report; a library entry point the hosted page can call. |
| 14 November 2026 | A conformance suite any third party can run; published fixtures for valid, tampered, back-dated and re-ordered chains; a security note on what the verifier cannot detect. |

## Queue

| Item | What | State |
| --- | --- | --- |
| V-1 | Skeleton, verdict model, RFC 9162 Merkle proofs, OpenTimestamps parser and Bitcoin header sources (contiguous, sparse, explorer), fixtures from public chain data and regtest, offline test, reference cross-check, CI | #1 |
| V-2 | RFC 3161 tokens: DER reader, CMS SignedData and TSTInfo, ESS signing certificate, signature (RSA PKCS#1 v1.5 and PSS, ECDSA, Ed25519), chain to roots the caller supplies, validity at the time-stamp, EKU; fixtures from a test authority; cross-check with `openssl ts -verify` | #2 |
| V-3 | Anchor batches: one command over a batch directory (leaves, Merkle root, `.ots`, `.tsr`), leaf encodings, combined verdict, checkout comparison, inclusion proofs per file; `docs/INPUTS.md` proposal reconciled with the Ledger session's format once published | this pull request |
| V-4 | Read the first real `anchors/` proofs in fundingmachine-core and fundingmachine-web as soon as they land; record any format gap as a named finding | queued, waits on the Ledger session |
| V-5 | Revocation evidence for authority chains: CRLs supplied by the caller, checked at the time-stamp; stated as not checked when absent | this pull request |
| V-6 | Library entry point: one JSON-in, JSON-out function for the hosted page; pure Python apart from `cryptography`, so it can also run in the browser under Pyodide (`docs/API.md`) | this pull request |
| V-6b | Run the API under Pyodide in CI, so the browser claim is tested rather than stated | queued |
| V-7 | Certificate v0 against the Ledger session's `docs/CERTIFICATE.md` (published 16 October): steps 1 to 6 (proof, scope statement, file, root record, inclusion, anchor) | this pull request |
| V-7b | Certificate step 7: the `ledger-event/v0` chain rules (the 18 invalid fixtures' codes) and the authorship map recomputed and hashed to `map_sha256` | next |
| V-7c | The PDF form: extract the embedded `certificate.json` and verify it | queued |
| V-3b | The Ledger session's anchor layout (`docs/ANCHORING.md`: RFC 8785 descriptor leaves, `root.preimage`, the `anchors` branch, `anchor-manifest/v0` arriving with the job on 17 October) beside the verifier's own batch format | next, as soon as the schema lands |
| V-8 | Static HTML report: authorship map and evidence coverage, no script from any third party | queued |
| V-9 | Conformance suite and published fixtures: valid, tampered, back-dated, re-ordered chains; runner any third party can use. Runner and anchor fixtures: this pull request (`docs/CONFORMANCE.md`); certificate chains wait on V-7 | in progress |
| V-10 | Security note: what the verifier cannot detect | queued |
| V-11 | A local Bitcoin Core node as a header source (`getblockheader` over RPC), the strongest source short of a full headers file | queued |

## Not available yet

* Knowledge-goblin is not among the repositories this account can reach
  from this session; its anchors will be read once it is.
* The Provenance Ledger session published its contracts v0 on 16 October
  2026 (events, authorship map, certificate, hourly roots, anchoring). Its
  artefact anchors start on the `anchors` branch with the anchor-everything
  job, due 17 October; none exist yet.
