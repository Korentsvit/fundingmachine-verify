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
| V-6b | Run the API under Pyodide in CI, so the browser claim is tested rather than stated | this pull request |
| V-7 | Certificate v0 against the Ledger session's `docs/CERTIFICATE.md` (published 16 October): steps 1 to 6 (proof, scope statement, file, root record, inclusion, anchor) | this pull request |
| V-7b | Certificate step 7: the `ledger-event/v0` chain rules and the authorship map recomputed and hashed to `map_sha256`; `fm-verify chain`; chain fixtures (valid, tampered, back-dated, re-ordered) | this pull request |
| V-7c | The PDF form: extract the embedded `certificate.json` and verify it | this pull request |
| V-3b | The Ledger session's anchor layout (`docs/ANCHORING.md`: RFC 8785 descriptor leaves, `root.preimage`, proofs over it) and its `anchor-manifest/v0` schema, read from its anchoring branch of 16 October; its recorded DigiCert, Sectigo and OpenTimestamps responses verify here, and its anchor verifier was run over these fixtures. To recheck when the job merges: any change to the schema | this pull request |
| V-8 | Static HTML report: authorship map and evidence coverage, no script at all (`--html`, and `render: html` in the API) | this pull request |
| V-9 | Conformance suite and published fixtures: valid, tampered, back-dated, re-ordered chains; runner any third party can use (`docs/CONFORMANCE.md`). Runner, fixtures for every kind, and a reproducible release archive (`tools/fixture_archive.py`): this pull request. To finish: the owner's tag and release | waits on a tag |
| V-10 | Security note: what the verifier cannot detect (`docs/SECURITY_NOTE.md`, first version in this pull request; final by 14 November) | in progress |
| V-11 | A local Bitcoin Core node as a header source (`getblockheader` over RPC), the strongest source short of a full headers file (`--bitcoind`) | this pull request |
| V-12 | Disclosure: with the document key and the inserted texts, replay a chain and check every keyed hash (`fm-verify chain --disclosure`) | this pull request |
| V-13 | A tenant's hourly root records as a chain of their own (`prev_root` linkage, signatures): a dropped hour shows (`fm-verify roots`) | this pull request |
| V-14 | The `anchors` branch's `index.jsonl`: every line names an anchor with its time, root and size, times increase, each manifest links to the line before, every anchor directory listed (`--all`) | this pull request |
| V-18 | Release manifests at tags: compare `release_manifest` descriptors with a checkout of the tag (`--repo OWNER/NAME@TAG=PATH`) | this pull request |
| V-19 | When did this file exist: every anchor naming a content hash, earliest first, each verified (`fm-verify anchors DIR --prove FILE`, `--prove-sha256`) | this pull request |
| V-20 | A Ledger anchor through the library entry point (`kind: ledger-anchor`, files as base64), run under Pyodide in CI | this pull request |
| V-21 | `ledger-event/v0.1` (proposed on the Ledger's branch): `capture.resync`, paste of unknown source, sign meaning and signer name hash; unknown versions indeterminate; disclosure checks quotations, declarations and names. To recheck when it merges | this pull request |
| V-22 | Tenant key rotation: follow `ledger-key-event/v0` handovers (the previous key signs `retired` and `activated`) so root records and certificates signed across a rotation verify. Waits: the Ledger's `docs/KEYS.md` (branch, 16 October) describes the statement in prose only, with no schema, fixture or published location; certificate v0.1 is to carry the chain | waits on the Ledger |
| V-23 | A certificate fixture over a v0.1 chain (a resync's imported, reconstructed characters in the authorship map), so step 7 is tested on v0.1 | this pull request |
| V-24 | The Ledger's submission index (`docs/SUBMISSION_INDEX.md`, its branch of 16 October): with the tenant's disclosure, check that each printed statement is the statement the certificate's chain holds at its sign event. The PDF alone cannot show that: the signed record holds keyed hashes of text only | waits on the format reaching the Ledger's main |
| V-17 | A guide for a reader holding a certificate (`docs/HOW_TO_VERIFY.md`): where to get headers, roots and revocation lists independently | this pull request |

## Not available yet

* Knowledge-goblin is attached to this session read-only since
  16 October; its decisions log and published manifests were rehearsed
  against, and its anchors will be read when the Ledger's job writes them.
* The Provenance Ledger session published its contracts v0 on 16 October
  2026 (events, authorship map, certificate, hourly roots, anchoring). Its
  artefact anchors start on the `anchors` branch with the anchor-everything
  job, due 17 October; none exist yet.
