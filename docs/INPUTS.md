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
`leaf_index` and `tree_size` are the proof's own statements: a path of the
same shape verifies under another size (leaf 5 of 7 and of 8), so the
position is reported as shown only when the size held with the root is
given too (`--tree-size`, or `tree_size` in the API).

Explicit path, accepted with a warning:

```json
{"scheme": "explicit-sha256", "leaf_prefix": "", "node_prefix": "",
 "steps": [{"side": "left", "hash": "<hex>"}], "root": "<hex>"}
```

## The Provenance Ledger's formats

Published by the Provenance Ledger session on 16 October 2026 in
fundingmachine-ledger, and read by this verifier from those documents:

* `ledger-certificate/v0` and its addition v0.1 (`docs/CERTIFICATE.md`,
  Version 0.1, on the Ledger's main from 19 October 2026): `fm-verify
  certificate`, all seven steps (step 7 with `--events`), JSON or PDF form.
  For v0.1, `certificate.meaning` checks the signature's meaning and the
  printed name's keyed hash, and step 7 compares both with the sign event.
  The printed name itself needs the document key, which the verifier does
  not hold.
* `ledger-event/v0` (`docs/EVENT_CONTRACT.md`): `fm-verify chain`, every chain
  rule in the contract's order with its code. Its addition `ledger-event/v0.1`
  (proposed 16 October 2026 on the Ledger's branch, not yet on its main) is
  read too: `capture.resync` with `resync_not_first` and `document_empty`, a
  paste of `unknown` source, a `sign` with `meaning` and `signer_name_hash`,
  and the reserved actor `person:unattributed`, which never signs. A chain
  may mix versions; each event is checked against its own. An event naming
  another version stops the check, indeterminate. With `--disclosure`, the
  journal's resync texts, quotations, declaration and signer's name are
  checked against their hashes as well.
* Artefact anchoring (`docs/ANCHORING.md`): `fm-verify anchors DIR` reads an
  anchor directory (`manifest.json`, `root.preimage`, `root.preimage.ots`,
  `root.preimage.<authority>.tsr`). Leaves are the RFC 8785 JSON of each
  descriptor `{kind, path, ref, repo, sha256}`, sorted in UTF-16 code unit
  order; the anchored digest is the SHA-256 of `root.preimage`. A manifest
  declaring `anchor-manifest/v0` is checked against that schema field by
  field (written out in `ledger_anchors.v0_problems`; the tests compare it
  with the Ledger's `schemas/anchor-manifest-v0.schema.json` on every
  mutation): the leaves in the order listed, each `leaf_hash`, `size` and
  `root`; `root.preimage` as the root node; the leaves' documented order (a
  warning if not); the genTime, serial and policy it states for each token,
  against the token; the sources it could not read (a warning); and its
  `previous` link. Another contract is not read (indeterminate); a manifest
  with no contract has its descriptors found by their documented shape.
  `--all` on an anchors directory also checks `index.jsonl`: every line names
  an anchor here with its time, root and size, times increase, each manifest
  links to the line before, and every anchor directory is listed.
  `--repo OWNER/NAME=PATH` compares a checkout: files by hash, and log
  entries by the hash of every run of up to 40 consecutive lines of the log
  (an entry is "its line or lines"). A fragment no longer in the checkout is
  looked for in `docs/DECISIONS_LOG.md` as fundingmachine-core's daily
  assembly leaves it: its rows appended, with the pull request number written
  over "this pull request". Only an exact SHA-256 match counts, and the
  verdict names the lines. `--repo OWNER/NAME@TAG=PATH` compares the
  descriptors read at a tag (release manifests in the tagged tree) with a
  checkout of that tag, for example one made with
  `git worktree add ../core-R1 R1`; a release asset (`release-asset:NAME`) is
  looked for by name in the same directory. A descriptor path that is
  absolute or climbs out of the checkout is not read.

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
