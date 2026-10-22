# Ledger anchors, 22 October 2026, 06:04 UTC

The Provenance Ledger's anchors, verified by fm-verify from the Ledger's
public mirror repository.

**Verdict: 119 anchors valid, confirmed in Bitcoin.**

Since the [20 October, 16:15 UTC verdict](../2026-10-20T1615Z), 11 anchors have a verdict for the first time, marked "new" below.

## Source

* **The mirror.** https://github.com/Korentsvit/fundingmachine-anchors, a public repository needing no login. It holds
  the Ledger's `anchors` branch with its whole history.
* **The commit read.** `71ff731adbabfedf60cab1b4bf20e7804ffc5c8c`, from a checkout. It has
  124 commits, the first being `da6c9ce201fa7f7c579ce2577e54c92b9a8864d2`. Under `anchors/`
  it names 119 anchors.
* **Cross-check: the Ledger's HTTP record.**
  * https://fundingmachine-ledger.vercel.app/api/anchors, copied by `tools/fetch_ledger_record.py`, which keeps a file only
    if it matches the listing and the server's hash.
  * Its listing is [`listing.json`](listing.json), SHA-256
    `a160d5a672bcbd4a7a91cffbece8050b1eab3dcc6c5c869bc430132a93a850d2`. It names 119 anchors and 625 files.
  * 625 of those files are identical, byte for byte, to the mirror's at that commit.
  * The mirror holds 2 more files: `anchors/tsa/digicert.pem`, `anchors/tsa/sectigo.pem`. This verdict did not use them.

## What the verdict relied on

* **Bitcoin block headers:** [`headers.txt`](headers.txt), 68 headers at heights 971782 to 972369.
  * Bitcoin block headers fetched 2026-10-22T05:59:18Z from https://mempool.space/api and https://blockstream.info/api; every explorer gave the same header, and each hashes to the block hash given. The verdict relies on these explorers for which block is at each height.
  * fm-verify checked each header's proof of work and that it hashes to the block it is given for.
  * A reader with a Bitcoin node can check the headers themselves.
* **Roots of trust for the RFC 3161 tokens:** `/etc/ssl/certs/ca-certificates.crt`.
  * Tokens chain to CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US (SHA-256 `552f7bdc...`); the mirror's `anchors/tsa/digicert.pem` has the same fingerprint.
  * Tokens chain to CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US (SHA-256 `e793c9b0...`); the mirror's `anchors/tsa/sectigo.pem` has the same fingerprint.
* **Revocation:** not checked; no revocation lists were given.

## Results

| Anchor | Root | Files | Verdict | Earliest Bitcoin block (its header's time) | Earliest RFC 3161 time |
| --- | --- | --- | --- | --- | --- |
| 2026/10/16/232709Z | 052e617f2adb... | 412 | valid | 971782 (2026-10-16T23:35:57Z) | 2026-10-16T23:27:10Z (DigiCert, Inc.) |
| 2026/10/16/233452Z | e7eefd05671a... | 427 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:34:53Z (DigiCert, Inc.) |
| 2026/10/16/234029Z | f81ac6b63c86... | 434 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:40:34Z (DigiCert, Inc.) |
| 2026/10/16/234111Z | 3824a570d347... | 435 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:41:13Z (DigiCert, Inc.) |
| 2026/10/16/234518Z | 17aa63f3d2ab... | 440 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:45:20Z (DigiCert, Inc.) |
| 2026/10/16/234552Z | f7ec96cbaebd... | 442 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-16T23:45:53Z (DigiCert, Inc.) |
| 2026/10/17/001612Z | 9f3d56897400... | 504 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:16:14Z (DigiCert, Inc.) |
| 2026/10/17/001953Z | db737595b9f0... | 507 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:19:54Z (DigiCert, Inc.) |
| 2026/10/17/002826Z | 53a2ad653f6a... | 511 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:28:27Z (DigiCert, Inc.) |
| 2026/10/17/003200Z | a809b58d68f0... | 512 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:32:02Z (DigiCert, Inc.) |
| 2026/10/17/003729Z | 1a51c65b0bdf... | 521 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:37:30Z (DigiCert, Inc.) |
| 2026/10/17/004503Z | 82e867bb7a55... | 528 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:45:04Z (DigiCert, Inc.) |
| 2026/10/17/004730Z | eeae96132d4f... | 530 | valid | 971785 (2026-10-17T00:52:05Z) | 2026-10-17T00:47:31Z (DigiCert, Inc.) |
| 2026/10/17/005019Z | 00b76714d985... | 533 | valid | 971786 (2026-10-17T01:09:27Z) | 2026-10-17T00:50:20Z (DigiCert, Inc.) |
| 2026/10/17/005158Z | eca6ec60f50e... | 535 | valid | 971786 (2026-10-17T01:09:27Z) | 2026-10-17T00:52:00Z (DigiCert, Inc.) |
| 2026/10/17/005526Z | fd5ea1cdf2d0... | 536 | valid | 971788 (2026-10-17T01:32:06Z) | 2026-10-17T00:55:28Z (DigiCert, Inc.) |
| 2026/10/17/005854Z | b3a00cc21931... | 537 | valid | 971788 (2026-10-17T01:32:06Z) | 2026-10-17T00:58:55Z (DigiCert, Inc.) |
| 2026/10/17/005947Z | d65f99c19ce3... | 538 | valid | 971788 (2026-10-17T01:32:06Z) | 2026-10-17T00:59:49Z (DigiCert, Inc.) |
| 2026/10/17/044207Z | c7f0d4989b52... | 573 | valid | 971813 (2026-10-17T05:42:00Z) | 2026-10-17T04:42:11Z (DigiCert, Inc.) |
| 2026/10/17/055804Z | 534a5198551b... | 576 | valid | 971817 (2026-10-17T06:17:44Z) | 2026-10-17T05:58:05Z (DigiCert, Inc.) |
| 2026/10/17/092037Z | 2856629c2c93... | 591 | valid | 971835 (2026-10-17T09:29:06Z) | 2026-10-17T09:20:42Z (DigiCert, Inc.) |
| 2026/10/17/092449Z | 26efb66740e8... | 594 | valid | 971836 (2026-10-17T09:35:00Z) | 2026-10-17T09:24:51Z (DigiCert, Inc.) |
| 2026/10/17/092636Z | 7d5469263da2... | 596 | valid | 971836 (2026-10-17T09:35:00Z) | 2026-10-17T09:26:38Z (DigiCert, Inc.) |
| 2026/10/17/092720Z | 25b5ebf022f0... | 598 | valid | 971836 (2026-10-17T09:35:00Z) | 2026-10-17T09:27:22Z (DigiCert, Inc.) |
| 2026/10/17/093026Z | 1b16f6f275f6... | 599 | valid | 971838 (2026-10-17T09:58:58Z) | 2026-10-17T09:30:27Z (DigiCert, Inc.) |
| 2026/10/17/093420Z | a56bffbd12d9... | 601 | valid | 971838 (2026-10-17T09:58:58Z) | 2026-10-17T09:34:22Z (DigiCert, Inc.) |
| 2026/10/17/094450Z | 75027ac2ca82... | 606 | valid | 971838 (2026-10-17T09:58:58Z) | 2026-10-17T09:44:51Z (DigiCert, Inc.) |
| 2026/10/17/111126Z | 72d3c273c9c1... | 629 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:11:28Z (DigiCert, Inc.) |
| 2026/10/17/111302Z | 13f113cfd763... | 631 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:13:03Z (DigiCert, Inc.) |
| 2026/10/17/111338Z | d5ffda5228d8... | 632 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:13:40Z (DigiCert, Inc.) |
| 2026/10/17/111706Z | f35568c3d81c... | 633 | valid | 971847 (2026-10-17T11:26:36Z) | 2026-10-17T11:17:08Z (DigiCert, Inc.) |
| 2026/10/17/120758Z | a3549c327f64... | 640 | valid | 971858 (2026-10-17T12:20:03Z) | 2026-10-17T12:08:00Z (DigiCert, Inc.) |
| 2026/10/17/134912Z | 066825d3889f... | 644 | valid | 971870 (2026-10-17T14:03:42Z) | 2026-10-17T13:49:14Z (DigiCert, Inc.) |
| 2026/10/17/152102Z | e8b273cde45d... | 645 | valid | 971884 (2026-10-17T16:55:58Z) | 2026-10-17T15:21:03Z (DigiCert, Inc.) |
| 2026/10/17/152800Z | 0c7b486595cf... | 646 | valid | 971884 (2026-10-17T16:55:58Z) | 2026-10-17T15:28:01Z (DigiCert, Inc.) |
| 2026/10/17/153234Z | 8b3a06530548... | 647 | valid | 971884 (2026-10-17T16:55:58Z) | 2026-10-17T15:32:35Z (DigiCert, Inc.) |
| 2026/10/17/155317Z | 7c56ccb22e8e... | 648 | valid | 971884 (2026-10-17T16:55:58Z) | 2026-10-17T15:53:18Z (DigiCert, Inc.) |
| 2026/10/17/160404Z | 0ca6b5f7c4e9... | 649 | valid | 971884 (2026-10-17T16:55:58Z) | 2026-10-17T16:04:05Z (DigiCert, Inc.) |
| 2026/10/17/160703Z | 8dd8b59e19cc... | 650 | valid | 971884 (2026-10-17T16:55:58Z) | 2026-10-17T16:07:04Z (DigiCert, Inc.) |
| 2026/10/17/161244Z | 7ca1b6f12177... | 651 | valid | 971885 (2026-10-17T16:54:57Z) | 2026-10-17T16:12:45Z (DigiCert, Inc.) |
| 2026/10/17/182238Z | 3f0de2b26432... | 652 | valid | 971901 (2026-10-17T19:55:21Z) | 2026-10-17T18:22:39Z (DigiCert, Inc.) |
| 2026/10/17/191225Z | bbdc2b9025f9... | 653 | valid | 971901 (2026-10-17T19:55:21Z) | 2026-10-17T19:12:27Z (DigiCert, Inc.) |
| 2026/10/17/194259Z | cd05d16fd226... | 655 | valid | 971902 (2026-10-17T20:02:55Z) | 2026-10-17T19:43:01Z (DigiCert, Inc.) |
| 2026/10/17/195058Z | ff9362770a4f... | 660 | valid | 971902 (2026-10-17T20:02:55Z) | 2026-10-17T19:51:00Z (DigiCert, Inc.) |
| 2026/10/17/195437Z | 1e84dc098adc... | 663 | valid | 971902 (2026-10-17T20:02:55Z) | 2026-10-17T19:54:38Z (DigiCert, Inc.) |
| 2026/10/17/200715Z | 64fff1bd3071... | 669 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:07:16Z (DigiCert, Inc.) |
| 2026/10/17/201032Z | 2b21d61a3115... | 673 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:10:34Z (DigiCert, Inc.) |
| 2026/10/17/201535Z | 18563b3d2106... | 678 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:15:37Z (DigiCert, Inc.) |
| 2026/10/17/201829Z | 8a43c7ec7441... | 680 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:18:31Z (DigiCert, Inc.) |
| 2026/10/17/201941Z | 646bc281d9dc... | 685 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:19:42Z (DigiCert, Inc.) |
| 2026/10/17/202232Z | 22024fde1bb0... | 689 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:22:34Z (DigiCert, Inc.) |
| 2026/10/17/202900Z | 26f9fc28a4c1... | 692 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:29:01Z (DigiCert, Inc.) |
| 2026/10/17/203225Z | a27b8923b4ed... | 694 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:32:26Z (DigiCert, Inc.) |
| 2026/10/17/203313Z | 82765fcb6ec8... | 695 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:33:15Z (DigiCert, Inc.) |
| 2026/10/17/203711Z | f703303da434... | 697 | valid | 971906 (2026-10-17T20:45:01Z) | 2026-10-17T20:37:14Z (DigiCert, Inc.) |
| 2026/10/17/204017Z | 0e953d6abbb8... | 699 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T20:40:19Z (DigiCert, Inc.) |
| 2026/10/17/204443Z | 0b64934ef295... | 701 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T20:44:45Z (DigiCert, Inc.) |
| 2026/10/17/204712Z | 3a130c9809ee... | 702 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T20:47:13Z (DigiCert, Inc.) |
| 2026/10/17/205021Z | 0f3a68777c04... | 704 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T20:50:22Z (DigiCert, Inc.) |
| 2026/10/17/205529Z | 20c88c496bf2... | 705 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T20:55:31Z (DigiCert, Inc.) |
| 2026/10/17/210303Z | f3c9d14c2bcc... | 707 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T21:03:04Z (DigiCert, Inc.) |
| 2026/10/17/211735Z | 3a9105e7e613... | 709 | valid | 971910 (2026-10-17T22:19:38Z) | 2026-10-17T21:17:37Z (DigiCert, Inc.) |
| 2026/10/17/222751Z | 5cb12bcfa516... | 724 | valid | 971914 (2026-10-17T23:15:22Z) | 2026-10-17T22:27:52Z (DigiCert, Inc.) |
| 2026/10/17/230555Z | 70cfc6da4ce1... | 731 | valid | 971914 (2026-10-17T23:15:22Z) | 2026-10-17T23:05:56Z (DigiCert, Inc.) |
| 2026/10/18/000107Z | 2422a3559368... | 736 | valid | 971922 (2026-10-18T00:27:47Z) | 2026-10-18T00:01:09Z (DigiCert, Inc.) |
| 2026/10/18/000656Z | 659066641b43... | 743 | valid | 971922 (2026-10-18T00:27:47Z) | 2026-10-18T00:06:57Z (DigiCert, Inc.) |
| 2026/10/18/001521Z | d505f7143add... | 745 | valid | 971922 (2026-10-18T00:27:47Z) | 2026-10-18T00:15:23Z (DigiCert, Inc.) |
| 2026/10/18/011339Z | 9725cebaa3ef... | 749 | valid | 971932 (2026-10-18T02:34:32Z) | 2026-10-18T01:13:40Z (DigiCert, Inc.) |
| 2026/10/18/031348Z | 4bc15eaaca3f... | 764 | valid | 971941 (2026-10-18T03:45:01Z) | 2026-10-18T03:13:49Z (DigiCert, Inc.) |
| 2026/10/18/041240Z | 44c5f60d3e38... | 768 | valid | 971945 (2026-10-18T04:29:48Z) | 2026-10-18T04:12:42Z (DigiCert, Inc.) |
| 2026/10/18/053052Z | c87ad8edebd3... | 769 | valid | 971954 (2026-10-18T06:41:39Z) | 2026-10-18T05:30:53Z (DigiCert, Inc.) |
| 2026/10/18/060452Z | e8852443a8fd... | 770 | valid | 971954 (2026-10-18T06:41:39Z) | 2026-10-18T06:04:53Z (DigiCert, Inc.) |
| 2026/10/18/112443Z | 13f576ce12f9... | 779 | valid | 971987 (2026-10-18T11:37:39Z) | 2026-10-18T11:24:45Z (DigiCert, Inc.) |
| 2026/10/18/184352Z | 5a65cec37976... | 791 | valid | 972039 (2026-10-18T19:07:21Z) | 2026-10-18T18:43:55Z (DigiCert, Inc.) |
| 2026/10/18/213628Z | a35f11313152... | 795 | valid | 972061 (2026-10-18T21:37:52Z) | 2026-10-18T21:36:30Z (DigiCert, Inc.) |
| 2026/10/19/105743Z | 1728440daf2d... | 802 | valid | 972137 (2026-10-19T11:17:20Z) | 2026-10-19T10:57:45Z (DigiCert, Inc.) |
| 2026/10/19/173528Z | fdea75d0fae6... | 809 | valid | 972187 (2026-10-19T17:49:13Z) | 2026-10-19T17:35:30Z (DigiCert, Inc.) |
| 2026/10/19/222954Z | 09b4b4349251... | 811 | valid | 972220 (2026-10-19T23:00:20Z) | 2026-10-19T22:29:56Z (DigiCert, Inc.) |
| 2026/10/19/231156Z | 3e1b20c6277f... | 831 | valid | 972226 (2026-10-19T23:41:31Z) | 2026-10-19T23:11:57Z (DigiCert, Inc.) |
| 2026/10/19/231244Z | 99b872db5f18... | 832 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:12:45Z (DigiCert, Inc.) |
| 2026/10/19/231613Z | 75c5b39d703a... | 835 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:16:17Z (DigiCert, Inc.) |
| 2026/10/19/231925Z | 947aeac1106a... | 837 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:19:27Z (DigiCert, Inc.) |
| 2026/10/19/232236Z | f83467ab2175... | 839 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:22:37Z (DigiCert, Inc.) |
| 2026/10/19/232522Z | 91758f4d33b7... | 844 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:25:23Z (DigiCert, Inc.) |
| 2026/10/19/233007Z | 369357c95622... | 845 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:30:10Z (DigiCert, Inc.) |
| 2026/10/19/233145Z | f7667e7eb5f8... | 846 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:31:50Z (DigiCert, Inc.) |
| 2026/10/19/233751Z | bb9397403587... | 850 | valid | 972227 (2026-10-19T23:42:01Z) | 2026-10-19T23:37:52Z (DigiCert, Inc.) |
| 2026/10/19/234227Z | 42602c7db867... | 854 | valid | 972228 (2026-10-19T23:43:48Z) | 2026-10-19T23:42:29Z (DigiCert, Inc.) |
| 2026/10/19/234658Z | 643793a17c6a... | 855 | valid | 972230 (2026-10-19T23:55:28Z) | 2026-10-19T23:47:01Z (DigiCert, Inc.) |
| 2026/10/19/235613Z | d960782325ca... | 856 | valid | 972232 (2026-10-20T00:05:53Z) | 2026-10-19T23:56:15Z (DigiCert, Inc.) |
| 2026/10/20/000055Z | 988b7d506957... | 858 | valid | 972233 (2026-10-20T00:27:10Z) | 2026-10-20T00:00:56Z (DigiCert, Inc.) |
| 2026/10/20/000821Z | 133471a89d57... | 862 | valid | 972234 (2026-10-20T00:38:03Z) | 2026-10-20T00:08:23Z (DigiCert, Inc.) |
| 2026/10/20/001713Z | 29f310b15340... | 865 | valid | 972234 (2026-10-20T00:38:03Z) | 2026-10-20T00:17:14Z (DigiCert, Inc.) |
| 2026/10/20/001801Z | 0e6c045e206b... | 866 | valid | 972234 (2026-10-20T00:38:03Z) | 2026-10-20T00:18:03Z (DigiCert, Inc.) |
| 2026/10/20/002212Z | ccbcffed81c9... | 867 | valid | 972234 (2026-10-20T00:38:03Z) | 2026-10-20T00:22:13Z (DigiCert, Inc.) |
| 2026/10/20/002442Z | 6962bd86f6f3... | 869 | valid | 972234 (2026-10-20T00:38:03Z) | 2026-10-20T00:24:44Z (DigiCert, Inc.) |
| 2026/10/20/003445Z | a97e33623b75... | 872 | valid | 972237 (2026-10-20T01:36:51Z) | 2026-10-20T00:34:46Z (DigiCert, Inc.) |
| 2026/10/20/003815Z | fe0c94ef7b4e... | 873 | valid | 972237 (2026-10-20T01:36:51Z) | 2026-10-20T00:38:20Z (DigiCert, Inc.) |
| 2026/10/20/004257Z | e247796037e5... | 874 | valid | 972237 (2026-10-20T01:36:51Z) | 2026-10-20T00:42:59Z (DigiCert, Inc.) |
| 2026/10/20/004609Z | 254d378a1964... | 876 | valid | 972237 (2026-10-20T01:36:51Z) | 2026-10-20T00:46:10Z (DigiCert, Inc.) |
| 2026/10/20/004741Z | e875259f29b0... | 876 | valid | 972237 (2026-10-20T01:36:51Z) | 2026-10-20T00:47:43Z (DigiCert, Inc.) |
| 2026/10/20/005158Z | 22d53a154f99... | 878 | valid | 972237 (2026-10-20T01:36:51Z) | 2026-10-20T00:51:59Z (DigiCert, Inc.) |
| 2026/10/20/015613Z | f640441a357d... | 881 | valid | 972242 (2026-10-20T01:59:52Z) | 2026-10-20T01:56:15Z (DigiCert, Inc.) |
| 2026/10/20/074549Z | a8ac564ac833... | 890 | valid | 972288 (2026-10-20T07:53:24Z) | 2026-10-20T07:45:50Z (DigiCert, Inc.) |
| 2026/10/20/124432Z | db22f7700b7e... | 913 | valid | 972330 (2026-10-20T12:56:30Z) | 2026-10-20T12:44:34Z (DigiCert, Inc.) |
| 2026/10/20/124948Z | b439fb39f64b... | 914 | valid | 972331 (2026-10-20T13:08:09Z) | 2026-10-20T12:49:49Z (DigiCert, Inc.) |
| 2026/10/20/125427Z | 3a8cf0915807... | 915 | valid | 972331 (2026-10-20T13:08:09Z) | 2026-10-20T12:54:29Z (DigiCert, Inc.) |
| 2026/10/20/130442Z | ffe30b7535a9... | 915 | valid | 972334 (2026-10-20T13:55:20Z) | 2026-10-20T13:04:43Z (DigiCert, Inc.) |
| 2026/10/20/154305Z (new) | 3a41a6eaca3c... | 929 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T15:43:06Z (DigiCert, Inc.) |
| 2026/10/20/154459Z (new) | 7f1f8e8983cb... | 930 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T15:45:03Z (DigiCert, Inc.) |
| 2026/10/20/154755Z (new) | 7a64a0c61c6c... | 932 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T15:47:57Z (DigiCert, Inc.) |
| 2026/10/20/155118Z (new) | b9b14824928e... | 935 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T15:51:19Z (DigiCert, Inc.) |
| 2026/10/20/155325Z (new) | c67fc2ae2876... | 937 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T15:53:27Z (DigiCert, Inc.) |
| 2026/10/20/160024Z (new) | c99393fae7f7... | 943 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T16:00:26Z (DigiCert, Inc.) |
| 2026/10/20/160316Z (new) | c12b5828e470... | 946 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T16:03:17Z (DigiCert, Inc.) |
| 2026/10/20/160902Z (new) | 96714e6d8f61... | 948 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T16:09:04Z (DigiCert, Inc.) |
| 2026/10/20/162022Z (new) | 212be186ddac... | 955 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T16:20:23Z (DigiCert, Inc.) |
| 2026/10/20/163404Z (new) | e5f7b4a59204... | 1117 | valid | 972354 (2026-10-20T16:40:46Z) | 2026-10-20T16:34:05Z (DigiCert, Inc.) |
| 2026/10/20/183311Z (new) | f5364b64ddf6... | 1120 | valid | 972369 (2026-10-20T19:31:27Z) | 2026-10-20T18:33:12Z (DigiCert, Inc.) |

**Agreement with the earlier verdict.** The 108 anchors valid at 20 October, 16:15 UTC are valid here too, with the same earliest blocks and times.

**Reading the times.** An anchor's time proofs bound when its files existed
from above: the files existed no later than that time. A Bitcoin block's
header time is set by its miner. Consensus keeps it later than the median of
the 11 blocks before it, and no more than two hours ahead of the network's
clock.

**Index and links.** [`verdict.txt`](verdict.txt) holds the verdict on the
whole set, including `index.jsonl` and the link from each anchor to the one
before it.
* `anchor_set.index`, pass: index.jsonl lists all 119 anchors in time order, and each manifest links to the anchor before it.
* These links are the manifests' own statements. No proof covers them.
* The mirror's history adds a record the links lack. Across its 124 commits,
  no file is removed, and only two kinds of file change:
  * `index.jsonl` changes 118 times, and each version begins with the whole of the one before it.
  * `root.preimage.ots` changes once in each of 119 anchors, when the pending proof is replaced by one over the same digest holding a Bitcoin attestation.
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
git -C fundingmachine-anchors checkout 71ff731adbabfedf60cab1b4bf20e7804ffc5c8c
python tools/fetch_headers.py fundingmachine-anchors/anchors headers.txt   # two explorers, compared
fm-verify anchors fundingmachine-anchors/anchors --all --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt
```

`tools/anchor_verdict.py` writes this directory from the same inputs. `--json`
gives the machine-readable verdict; it is not committed, since it repeats every leaf.
