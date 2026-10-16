# What the verifier cannot detect

A first version, 16 October 2026, for the security note due 14 November 2026.
Each limit below is one the verdicts already state, under "Relied on" or
"Does not establish"; where a published fixture shows the limit, it is named.

## What every verdict is about

`fm-verify` checks that what it is given is consistent with itself and with
the evidence it is given (block headers, roots of trust, revocation lists,
the event chain). It does not, and cannot:

* say who wrote a document, or that a person and not a tool wrote it. The
  record shows how a document was written in this environment; it never
  detects AI, certifies originality or proves what an author read elsewhere
  (standing ruling `shows-the-work-never-proves-no-AI`);
* say that a document's content is true, or that a cited source says what is
  claimed: an evidence binding's page hash and quote hash are compared with
  the chain, but the verifier fetches no source and reads no quote;
* show that something did not exist earlier than its anchor: an anchor
  bounds existence from above only.

## Event chains and authorship

* **The capture client is trusted for what it observes.** Session keys are
  held by the client. Whoever holds them can write a chain that follows
  every rule and records any history: text a tool wrote elsewhere, typed in
  by hand, is "typed by a person in this environment". `capture_fidelity`
  is the client's own statement of how it observed each change.
* **Times in the chain are the client's claims.** A chain moved in time and
  re-signed with the client keys is valid (fixture
  `chain/back-dated-consistently`). Only an anchor of the hour's root bounds
  when the chain existed.
* **Keyed hashes are checked only on disclosure.** Without the document key
  and the text, the verifier cannot check `content_hash`, `doc_hash` or
  `removed_hash`, nor that an event's `length` matches its text. A tenant can
  disclose both to an auditor: `fm-verify chain --disclosure` replays the
  chain and checks every one (fixtures `chain/disclosure-*`). Prompt,
  paste-source and declaration hashes need texts beyond that disclosure and
  stay unchecked.
* **Imported means imported.** Text pasted from anywhere, including from a
  tool outside the environment, is `imported`; the map cannot say where it
  was written.
* **Counts are code points.** The authorship map counts characters, not
  ideas, effort or meaning.

## Certificates

* **The issuer key is named by the certificate itself.** A `did:key` needs no
  network and proves nothing about who holds the key. That a key belongs to
  a tenant, or to FundingMachine, must come from somewhere else: a
  publication the reader trusts. The verdict says so.
* **An unanchored certificate has no time bound** beyond the issuer's claim.
* **Fields the verifier does not understand** are listed as a warning: they
  are covered by the signature but not checked.
* **The PDF form** is a rendering; the verifier checks the JSON the PDF
  carries as `certificate.json`, not what the pages show. It takes the
  current version after incremental updates, and refuses a PDF carrying two
  different `certificate.json` files. Text on the pages that disagrees with
  the JSON is not detected.

## OpenTimestamps

* **The header chain is relied on.** With a contiguous headers file, the
  verifier checks Bitcoin's header rules from the file's first header, but
  cannot know whether a heavier chain exists. With a sparse file, each header
  is checked against its own proof of work and a floor of 2^70 expected
  hashes, not against its neighbours (fixture `ots/mainnet-forged-header`
  shows a header that fails). With an explorer, the explorer's answer is
  trusted.
* **Block times are approximate.** A miner sets the header time; Bitcoin
  accepts blocks up to two hours ahead of network time.
* **Pending attestations are not followed.** The verifier never contacts a
  calendar; a pending proof is reported as such (fixture
  `ots/regtest-pending-only`).
* **Hash functions.** Proof paths rely on the second-preimage resistance of
  every hash they use; SHA-1 on a path is warned about.
* **Re-organisations.** A proof naming a block that was later orphaned fails
  against the main chain's header at that height.

## RFC 3161

* **Trust in the authority is the reader's choice.** No root is built in. A
  valid verdict names the root reached and its fingerprint, to be compared
  with the authority's own publication. The authority is trusted to have
  stated the time honestly, within its stated accuracy.
* **Revocation is seen only through CRLs the reader supplies.** No CRL is
  fetched and no OCSP responder asked. Without a fresh CRL, a key compromise
  the authority has announced is invisible (fixtures `rfc3161/crl-*`).
* **Policy identifiers are reported, not interpreted.**

## The implementation

* The cryptographic primitives (Ed25519, RSA, ECDSA, SHA-2) come from the
  `cryptography` library. The parsers for DER, OpenTimestamps, RFC 8785 JSON
  and the event contract are this repository's, checked against published
  test vectors and against independent implementations (the reference
  OpenTimestamps library, OpenSSL, RFC 8032's reference Ed25519, and the
  Provenance Ledger session's own TypeScript, in both directions).
* The verifier holds no secret, so timing side channels do not apply.
* Verify the verifier: run `fm-verify conformance fixtures`, which first
  checks the fixtures against `fixtures/SHA256SUMS`, and rebuild the
  fixtures with `python tools/make_fixtures.py`, which must give the same
  bytes.

## Reporting a problem

Report a suspected vulnerability privately through GitHub's private
vulnerability reporting for this repository where it is enabled; otherwise
open an issue describing the impact, without a working exploit.
