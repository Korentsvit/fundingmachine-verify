# The Provenance Ledger conformance suite's pair fixtures

* **What they are.** The 86 pair fixtures of the Provenance Ledger
  conformance suite (`validation-conformance/v0`, case CS-22: where an event
  breaks two rules, the earlier rule's code). Each is a `ledger-event/v0`
  chain. The event at `expect.seq` breaks the two rules named in `breaks`,
  and `expect.code` is the code of the rule listed first in the contract's
  table.
* **Source.** `docs/validation/conformance/fixtures/` of the repository
  Korentsvit/fundingmachine-ledger, at commit
  `0e5d016d26555f86b1892da4dc8bf24bf8a130ad` (its main, 18 October 2026).
  * `LICENSE` and every file under `ledger-event/` are copied unchanged, byte
    for byte the files at that commit.
  * This README is fundingmachine-verify's own.
* **Licence.** Copyright 2026 NW PharmaTech Ltd, licensed under the Apache
  License, Version 2.0. [`LICENSE`](LICENSE) gives the licence and its
  scope.
  * The licence is the owner's decision of 18 October 2026, recorded in the
    Ledger's `docs/decisions.d/2026-10-18-validation-fixtures-licence.md`.
  * Nothing else of that repository is copied here; the rest of it is all
    rights reserved.
* **Keys.** The descriptions name `fixtures/ledger-event/v0/keys.json` of the
  Ledger's repository, which is not copied. Each chain carries its sessions'
  public keys, so this verifier reads nothing beyond the fixture file.
* **Not here.** The two pairs the Ledger suite does not write (its finding
  F-14) are not among these files.

## How they run

`fm-verify conformance fixtures` runs each file as a chain case, reported as
`chain/ledger-pair/<name>`. A case conforms when the chain is invalid, only
`chain.rules` fails, and the chain stops at `expect.index` with
`expect.code`.

With `--implementation`, another implementation is given each file as a
chain case directory: `expected.json` in this suite's terms, and the fixture
itself as `events.json`.
