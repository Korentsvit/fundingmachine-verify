# Ledger anchors, 17 October 2026, 09:25 UTC

The Provenance Ledger's anchors, verified by fm-verify from the Ledger's
public record.

**Verdict: 20 anchors valid, confirmed in Bitcoin.** One more anchor holds
on its RFC 3161 tokens; its Bitcoin proof is still pending, so it has no
verdict yet.

## Source

* **The record.** https://fundingmachine-ledger.vercel.app/api/anchors, public
  and needing no login. It is the source since 17 October, 00:56 UTC, by the
  owner's direction.
* **The listing read.** [`listing.json`](listing.json), SHA-256
  `2c5ceef7b92a20b5cab39760cbdfafafcb79ac1e7e6fe25ede06cc42e370bdac`. It names
  21 anchors and 111 files. Every file was fetched at the version the listing
  names, and kept only if its SHA-256 and size matched the listing and the
  server's header.
* **Cross-check.** The same 111 files were compared with the `anchors` branch
  of the Ledger's own repository (commit 9c84430), read through this
  session's access to it.
  * All the files the two share are identical, except `index.jsonl`.
  * The branch was one anchor ahead: 2026/10/17/092449Z, written after this
    listing was published. That one line is the whole difference in
    `index.jsonl`.

## What the verdict relied on

* **Bitcoin block headers:** [`headers.txt`](headers.txt), heights 971782 to
  971818.
  * Fetched at 09:25 UTC from mempool.space and from blockstream.info. Both
    gave the same bytes for every header.
  * Each header hashes to the block hash it was given for, and fm-verify
    checked each header's proof of work.
  * The verdict relies on those two explorers for which block is at each
    height. A reader with a Bitcoin node can check the headers themselves.
* **Roots of trust for the RFC 3161 tokens:** the operating system's
  `/etc/ssl/certs/ca-certificates.crt`, not the Ledger's own copies. The
  tokens chain to DigiCert Trusted Root G4 (SHA-256 `552f7bdc...`) and to
  USERTrust RSA Certification Authority (`e793c9b0...`).
* **Revocation:** not checked; no revocation lists were given.

## Results

| Anchor | Root | Files | Verdict | Earliest Bitcoin block (its header's time) | RFC 3161 time (DigiCert) |
| --- | --- | --- | --- | --- | --- |
| 2026/10/16/232709Z | 052e617f2adb... | 412 | valid | 971782 (2026-10-16T23:35:57Z) | 2026-10-16T23:27:10Z |
| 2026/10/16/233452Z | e7eefd05671a... | 427 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:34:53Z |
| 2026/10/16/234029Z | f81ac6b63c86... | 434 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:40:34Z |
| 2026/10/16/234111Z | 3824a570d347... | 435 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:41:13Z |
| 2026/10/16/234518Z | 17aa63f3d2ab... | 440 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:45:20Z |
| 2026/10/16/234552Z | f7ec96cbaebd... | 442 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:45:53Z |
| 2026/10/17/001612Z | 9f3d56897400... | 504 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:16:14Z |
| 2026/10/17/001953Z | db737595b9f0... | 507 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:19:54Z |
| 2026/10/17/002826Z | 53a2ad653f6a... | 511 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:28:27Z |
| 2026/10/17/003200Z | a809b58d68f0... | 512 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:32:02Z |
| 2026/10/17/003729Z | 1a51c65b0bdf... | 521 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:37:30Z |
| 2026/10/17/004503Z | 82e867bb7a55... | 528 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:45:04Z |
| 2026/10/17/004730Z | eeae96132d4f... | 530 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:47:31Z |
| 2026/10/17/005019Z | 00b76714d985... | 533 | valid | 971786 (2026-10-17T01:09:27Z) | 2026-10-17T00:50:20Z |
| 2026/10/17/005158Z | eca6ec60f50e... | 535 | valid | 971786 (2026-10-17T01:09:27Z) | 2026-10-17T00:52:00Z |
| 2026/10/17/005526Z | fd5ea1cdf2d0... | 536 | valid | 971788 (2026-10-17T01:32:06Z) | 2026-10-17T00:55:28Z |
| 2026/10/17/005854Z | b3a00cc21931... | 537 | valid | 971788 (2026-10-17T01:32:06Z) | 2026-10-17T00:58:55Z |
| 2026/10/17/005947Z | d65f99c19ce3... | 538 | valid | 971788 (2026-10-17T01:32:06Z) | 2026-10-17T00:59:49Z |
| 2026/10/17/044207Z | c7f0d4989b52... | 573 | valid | 971813 (2026-10-17T05:42:00Z) | 2026-10-17T04:42:11Z |
| 2026/10/17/055804Z | 534a5198551b... | 576 | valid | 971817 (2026-10-17T06:17:44Z) | 2026-10-17T05:58:05Z |
| 2026/10/17/092037Z | 2856629c2c93... | 591 | pending: no verdict yet (its RFC 3161 tokens hold) | pending at the calendars | 2026-10-17T09:20:42Z |

**Reading the times.** An anchor's time proofs bound when its files existed
from above: the files existed no later than that time. A Bitcoin block's
header time is set by its miner. Consensus keeps it later than the median of
the 11 blocks before it, and no more than two hours ahead of the network's
clock.

**Index and links.** [`verdict.txt`](verdict.txt) holds the verdict on the
whole set, including `index.jsonl` and the link from each anchor to the one
before it.
* The index lists all 21 anchors in time order.
* Each manifest's link to the anchor before it holds.
* These links are the manifests' own statements. No proof covers them.

**Per-anchor verdicts.** Each anchor's full verdict is under
[`anchors/`](anchors), with every check, its reasons, what it relied on and
what it does not establish.

## What these verdicts do not establish

* who wrote the content, or how it was written;
* that the content is true, original, or free of AI assistance;
* that the content did not exist earlier than the anchor.

## Reproduce

```sh
python tools/fetch_ledger_record.py record              # the public record, every file checked
python tools/fetch_headers.py record/anchors headers.txt # two explorers, compared
fm-verify anchors record/anchors --all --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt
```

* The record keeps every published version. The files this verdict read can
  be fetched again, exactly, by the SHA-256 values in `listing.json`, with
  `?path=P&sha256=H`.
* `--json` gives the machine-readable verdict, about 1.5 MB. It is not
  committed: it repeats each anchor's 412 to 591 leaves.
