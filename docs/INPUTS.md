# Inputs the verifier reads

The Provenance Ledger session owns the format of what it publishes under
`anchors/` and in `docs/CERTIFICATE.md`. This file describes what the
verifier reads today, and a proposal for anchor batches that the verifier
will reconcile with the Ledger session's format once it is published. Where
they differ, the Ledger session's format wins and the verifier adapts.

## OpenTimestamps proofs

The detached `.ots` format of the OpenTimestamps client, major version 1:
the magic header, the file hash operation (`sha256`, `sha1`, `ripemd160` or
`keccak256`) and digest, then the tree of operations and attestations.
Bitcoin attestations are checked; pending attestations are reported as not
yet anchored (the verifier never contacts a calendar); Litecoin and unknown
attestations are reported and not relied on.

## Block headers

* Contiguous: 80-byte headers back to back, the first at a height the caller
  states (`FILE@START`, default 0).
* Sparse, text: one `HEIGHT HEX` per line, `#` starts a comment.
* Sparse, JSON: `{"network": "bitcoin-mainnet", "headers": [{"height": 840000, "hex": "..."}]}`
  or `{"840000": "..."}`.

## Merkle inclusion proofs (JSON)

RFC 9162, recommended:

```json
{"scheme": "rfc9162-sha256", "leaf_index": 2, "tree_size": 3,
 "path": ["<hex, sibling nearest the leaf first>"], "root": "<hex>"}
```

The leaf is the leaf data before leaf hashing; the leaf hash is
SHA-256(0x00 || leaf) and a node is SHA-256(0x01 || left || right).

Explicit path, accepted with a warning:

```json
{"scheme": "explicit-sha256", "leaf_prefix": "", "node_prefix": "",
 "steps": [{"side": "left", "hash": "<hex>"}], "root": "<hex>"}
```

## The Provenance Ledger's formats

Published by the Provenance Ledger session on 16 October 2026 in
fundingmachine-ledger, and read by this verifier from those documents:

* `ledger-certificate/v0` (`docs/CERTIFICATE.md`): `fm-verify certificate`,
  steps 1 to 6; step 7 next.
* Artefact anchoring (`docs/ANCHORING.md`): `fm-verify anchors DIR` reads an
  anchor directory (`manifest.json`, `root.preimage`, `root.preimage.ots`,
  `root.preimage.<authority>.tsr`). Leaves are the RFC 8785 JSON of each
  descriptor `{kind, path, ref, repo, sha256}`, sorted in UTF-16 code unit
  order; the anchored digest is the SHA-256 of `root.preimage`. Until the
  manifest's schema (`anchor-manifest/v0`, with the Ledger's job on
  17 October) is published, descriptors are found in the manifest by their
  documented shape, and the verdict says the schema was not checked.
  `--repo OWNER/NAME=PATH` compares a checkout: files by hash, and log
  entries by the hash of a single line (an entry spanning several lines is
  reported as not present).

## Anchor batches (`fm-verify anchors`)

The verifier's own batch format, written before the Ledger session
published its layout, and kept for the verifier's fixtures and for anyone
anchoring a set of files themselves. Where the Ledger's layout differs, the
Ledger's governs for FundingMachine's anchors.

```
anchors/<batch>/
  batch.json        the leaves, the tree, the root
  root.ots          an OpenTimestamps proof whose digest is the root itself
  root.<tsa>.tsr    one RFC 3161 response per authority, whose message imprint is the root itself (SHA-256)
```

`batch.json`:

```json
{"format": "fm-anchor-batch/0",
 "tree": "rfc9162-sha256",
 "leaf_encoding": "sha256-path-v0",
 "leaves": [{"path": "docs/STANDING_RULINGS.md", "sha256": "<hex>"}],
 "root": "<hex>",
 "ots": ["root.ots"],
 "rfc3161": ["root.<tsa>.tsr"]}
```

* `sha256-path-v0`: each leaf is the UTF-8 bytes of
  `<sha256 hex of the file> <space> <repository-relative path>`, so a leaf
  binds both the content and the name, and the RFC 9162 tree binds the
  order. `sha256-v0` (the 32-byte digest alone) is accepted with a warning:
  it binds content, not names.
* Paths are plain repository-relative POSIX paths: no leading `/`, no `..`,
  no backslash, none listed twice.
* `ots` and `rfc3161` name the anchor files; when absent, every `*.ots` and
  `*.tsr` in the directory is read.

For any listed file the verifier then shows: its digest is a leaf at a
stated index of a tree of stated size; that tree's root existed no later
than a Bitcoin block; and each authority signed a time for the same root.
`fm-verify anchors BATCH --emit-proof PATH` prints the inclusion proof for
one file, which `fm-verify merkle` checks on its own.

Comparing with a checkout (`--repo-root`): files that match pass; files that
changed since anchoring are a warning (a decision fragment or a rulings file
can change, or be removed, after its batch), or a failure with
`--strict-files`. A file a reader holds and names (`--file`) must match.
