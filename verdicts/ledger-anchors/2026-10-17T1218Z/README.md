# Ledger anchors, 17 October 2026, 12:18 UTC

The Provenance Ledger's anchors, verified by fm-verify from the Ledger's
public mirror repository.

**Verdict: 31 anchors valid, confirmed in Bitcoin.** One more anchor holds
on its RFC 3161 tokens. Its Bitcoin proof is still pending, so it has no
verdict yet.

Since the [09:25 UTC verdict](../2026-10-17T0925Z), 12 anchors have a verdict
for the first time, marked "new" below: 2026/10/17/092037Z, then pending, and
the 11 anchors written after it.

## Source

* **The mirror.** https://github.com/Korentsvit/fundingmachine-anchors, a
  public repository needing no login. It holds the Ledger's `anchors` branch
  with its whole history. This verdict is the first to take it as the source,
  as the owner directed; the HTTP record is now the cross-check.
* **The commit read.** `98e2443bacfafb4dc46c9d4f7f28053867c4f9f6`, from a fresh
  clone. It has 32 commits, the first being
  `da6c9ce201fa7f7c579ce2577e54c92b9a8864d2`. Under `anchors/` it names 32
  anchors.
* **Cross-checks.**
  * The Ledger's HTTP record, https://fundingmachine-ledger.vercel.app/api/anchors,
    read at the same time.
    * Its listing is [`listing.json`](listing.json), SHA-256
      `170f1e5914a187399fd9843ac1ca6a30c859a28e830b4765fdeabeff263adbf6`. It
      names the same 32 anchors and 166 files.
    * Every file was fetched at the version the listing names. Each matched
      the listing and the server's hash.
    * All 166 files are identical, byte for byte, to the mirror's files at
      that commit. The mirror holds two more: the authorities' root
      certificates under `anchors/tsa/`. This verdict did not use them.
  * The `anchors` branch of the Ledger's own repository, read through this
    session's access to it, is at the same commit, `98e2443`.

## What the verdict relied on

* **Bitcoin block headers:** [`headers.txt`](headers.txt), 14 headers at
  heights 971782 to 971849.
  * Fetched at 12:18 UTC from mempool.space and from blockstream.info. Both
    gave the same bytes for every header.
  * Each header hashes to the block hash it was given for, and fm-verify
    checked each header's proof of work.
  * The verdict relies on those two explorers for which block is at each
    height. A reader with a Bitcoin node can check the headers themselves.
* **Roots of trust for the RFC 3161 tokens:** the operating system's
  `/etc/ssl/certs/ca-certificates.crt`, not the Ledger's copies. The tokens
  chain to DigiCert Trusted Root G4 (SHA-256 `552f7bdc...`) and to USERTrust
  RSA Certification Authority (`e793c9b0...`).
  * The mirror's `anchors/tsa/digicert.pem` and `sectigo.pem` have those same
    two fingerprints.
  * Verified against those two files instead, the outcome is the same.
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
| 2026/10/17/092037Z (new) | 2856629c2c93... | 591 | valid | 971835 (2026-10-17T09:29:06Z) | 2026-10-17T09:20:42Z |
| 2026/10/17/092449Z (new) | 26efb66740e8... | 594 | valid | 971836 (2026-10-17T09:35:00Z) | 2026-10-17T09:24:51Z |
| 2026/10/17/092636Z (new) | 7d5469263da2... | 596 | valid | 971836 (2026-10-17T09:35:00Z) | 2026-10-17T09:26:38Z |
| 2026/10/17/092720Z (new) | 25b5ebf022f0... | 598 | valid | 971836 (2026-10-17T09:35:00Z) | 2026-10-17T09:27:22Z |
| 2026/10/17/093026Z (new) | 1b16f6f275f6... | 599 | valid | 971838 (2026-10-17T09:58:58Z) | 2026-10-17T09:30:27Z |
| 2026/10/17/093420Z (new) | a56bffbd12d9... | 601 | valid | 971838 (2026-10-17T09:58:58Z) | 2026-10-17T09:34:22Z |
| 2026/10/17/094450Z (new) | 75027ac2ca82... | 606 | valid | 971838 (2026-10-17T09:58:58Z) | 2026-10-17T09:44:51Z |
| 2026/10/17/111126Z (new) | 72d3c273c9c1... | 629 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:11:28Z |
| 2026/10/17/111302Z (new) | 13f113cfd763... | 631 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:13:03Z |
| 2026/10/17/111338Z (new) | d5ffda5228d8... | 632 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:13:40Z |
| 2026/10/17/111706Z (new) | f35568c3d81c... | 633 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:17:08Z |
| 2026/10/17/120758Z (new) | a3549c327f64... | 640 | pending: no verdict yet (its RFC 3161 tokens hold) | pending at the calendars | 2026-10-17T12:08:00Z |

**Agreement with the earlier verdict.** The 20 anchors that were valid at
09:25 UTC are valid here too, with the same earliest blocks and times.

**Reading the times.** An anchor's time proofs bound when its files existed
from above: the files existed no later than that time. A Bitcoin block's
header time is set by its miner. Consensus keeps it later than the median of
the 11 blocks before it, and no more than two hours ahead of the network's
clock.

**Index and links.** [`verdict.txt`](verdict.txt) holds the verdict on the
whole set, including `index.jsonl` and the link from each anchor to the one
before it.
* The index lists all 32 anchors in time order.
* Each manifest's link to the anchor before it holds.
* These links are the manifests' own statements. No proof covers them.
* The mirror's history adds a record the links lack. Across its 32 commits,
  no file is removed, and only two kinds of file change:
  * `index.jsonl` changes 31 times, and each version begins with the whole of
    the one before it.
  * `root.preimage.ots` changes once in each of 31 anchors, when the pending
    proof is replaced by one holding a Bitcoin attestation.
* That history is only as good as its host. Clone it fresh later and compare
  it with the commit named above; a rewrite would show.

**Per-anchor verdicts.** Each anchor's full verdict is under
[`anchors/`](anchors), with every check, its reasons, what it relied on and
what it does not establish.

## What these verdicts do not establish

* who wrote the content, or how it was written;
* that the content is true, original, or free of AI assistance;
* that the content did not exist earlier than the anchor.

## Reproduce

```sh
git clone https://github.com/Korentsvit/fundingmachine-anchors
git -C fundingmachine-anchors checkout 98e2443bacfafb4dc46c9d4f7f28053867c4f9f6
python tools/fetch_headers.py fundingmachine-anchors/anchors headers.txt   # two explorers, compared
fm-verify anchors fundingmachine-anchors/anchors --all --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt
python tools/fetch_ledger_record.py record   # the HTTP record, for the cross-check
diff -r record/anchors fundingmachine-anchors/anchors   # only anchors/tsa differs
```

* The HTTP record keeps every published version. The files this verdict read
  can be fetched again, exactly, by the SHA-256 values in `listing.json`, with
  `?path=P&sha256=H`.
* `--json` gives the machine-readable verdict. It is not committed: it repeats
  each anchor's 412 to 640 leaves.
