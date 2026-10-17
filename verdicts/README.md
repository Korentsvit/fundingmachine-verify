# Verdicts

Verdicts this verifier gave on other sessions' published evidence. Each one is
dated and holds what it relied on. None is edited after it is committed: a
later verdict is a new directory.

| Directory | What |
| --- | --- |
| [`ledger-anchors/`](ledger-anchors) | The Provenance Ledger's anchors (`anchor-manifest/v0`), from its public record. Each directory holds the listing read, the Bitcoin block headers relied on, the verdict on the whole set and one per anchor, and how to reproduce it |

A verdict is about the evidence as it stood when it was checked. An anchor's
Bitcoin proof is often pending for some hours. A pending anchor is reported
as pending and gets its verdict in a later directory.
