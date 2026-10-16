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
| V-7 | Certificate v0: ed25519 signatures, event chain order and linkage, Merkle roots, anchors, against `docs/CERTIFICATE.md` | queued, waits on the Ledger session's document |
| V-8 | Static HTML report: authorship map and evidence coverage, no script from any third party | queued |
| V-9 | Conformance suite and published fixtures: valid, tampered, back-dated, re-ordered chains; runner any third party can use. Runner and anchor fixtures: this pull request (`docs/CONFORMANCE.md`); certificate chains wait on V-7 | in progress |
| V-10 | Security note: what the verifier cannot detect | queued |
| V-11 | A local Bitcoin Core node as a header source (`getblockheader` over RPC), the strongest source short of a full headers file | queued |

## Not available yet

* Knowledge-goblin is not among the repositories this account can reach
  from this session; its `anchors/` will be read once it is.
* No `anchors/` directory exists yet in fundingmachine-core, and
  fundingmachine-ledger holds only a README (no `docs/CERTIFICATE.md`), as of
  16 October 2026 00:20 UTC.
