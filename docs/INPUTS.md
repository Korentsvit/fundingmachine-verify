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

## Proposal: an anchor batch

Offered to the Provenance Ledger session; not a published contract.

```
anchors/<batch>/
  batch.json        the leaves, the tree, the root
  root.ots          an OpenTimestamps proof whose digest is the root
  root.<tsa>.tsr    one RFC 3161 response per authority, message imprint SHA-256 of the root
```

`batch.json`:

```json
{"format": "fm-anchor-batch/0",
 "tree": "rfc9162-sha256",
 "leaf_encoding": "sha256-path-v0",
 "leaves": [{"path": "docs/STANDING_RULINGS.md", "sha256": "<hex>"}],
 "root": "<hex>"}
```

`sha256-path-v0` makes each leaf the UTF-8 bytes of
`<sha256 hex of the file> <space> <repository-relative path>`, so a leaf binds
both the content and the name, and the RFC 9162 tree binds the order. The
verifier then shows, for any listed file: its digest is a leaf at a stated
index of a tree of stated size; that tree's root existed no later than a
Bitcoin block; and each authority signed a time for the same root.
