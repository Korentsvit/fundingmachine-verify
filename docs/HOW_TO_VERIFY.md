# How to verify a Provenance Ledger certificate yourself

For anyone holding a certificate (its PDF or its JSON) and wanting to check
it without trusting FundingMachine. Every step names what you have to supply
and where you can get it independently.

## 1. Install the verifier

Python 3.10 or later:

```sh
python -m pip install "git+https://github.com/Korentsvit/fundingmachine-verify"
fm-verify --version
```

To check the verifier itself first, clone the repository and run its
conformance suite: `fm-verify conformance fixtures` (it checks the fixtures
against `fixtures/SHA256SUMS`, then every case).

## 2. Check the certificate alone

```sh
fm-verify certificate certificate.pdf
```

This checks the issuer's signature over the certificate, the scope statement,
the hourly root record and the sign event's place in it. The issuer is named
by a `did:key` in the certificate itself: compare it with a key the tenant
publishes somewhere you trust. The verdict says this is relied on.

## 3. Add the document

Give the exported document the certificate covers:

```sh
fm-verify certificate certificate.pdf --file proposal.pdf
```

The verifier checks its SHA-256 and size against the certificate.

## 4. Add the time anchors

A certificate issued after its hour was anchored carries an OpenTimestamps
proof and RFC 3161 tokens. To check them you supply evidence of your own.

**Bitcoin block headers**, one of:

* your own Bitcoin Core node: `--bitcoind http://127.0.0.1:8332 --bitcoind-cookie ~/.bitcoin/.cookie`
  (the strongest; credentials are never printed);
* a window of consecutive headers around the block, exported from a node
  and checked by Bitcoin's header rules from its first header (the verdict
  states that headers before it were not checked):

  ```sh
  for h in $(seq 839990 840009); do bitcoin-cli getblockheader "$(bitcoin-cli getblockhash $h)" false; done | xxd -r -p > window.bin
  fm-verify ... --headers-chain window.bin@839990
  ```
* the header of the block the proof names, written as one line `HEIGHT HEX`
  in a file, after comparing it between two explorers you choose:
  `--headers headers.txt`;
* an explorer, trusted outright, as the verdict will say: `--explorer https://mempool.space/api`.

**The time-stamping authorities' roots.** The Provenance Ledger uses DigiCert
and Sectigo (its `docs/ANCHORING.md`). Their roots are in the trust bundles
operating systems ship, so you can pass your system's bundle:

```sh
--roots /etc/ssl/certs/ca-certificates.crt          # Debian, Ubuntu
--roots /etc/pki/tls/certs/ca-bundle.crt            # Fedora, RHEL
```

The verdict names the root a token chained to and its SHA-256 fingerprint;
compare it with the authority's own publication. Passing a whole bundle
trusts every authority in it, and the verdict says which one was reached.

**Revocation lists**, if you want revocation checked: download the CRLs the
authorities publish (their certificates name the URLs) and pass them with
`--crl`. Without them, the verdict says revocation was not checked.

Together:

```sh
fm-verify certificate certificate.pdf --file proposal.pdf \
    --bitcoind http://127.0.0.1:8332 --bitcoind-cookie ~/.bitcoin/.cookie \
    --roots /etc/ssl/certs/ca-certificates.crt --html report.html
```

## 5. Add the event chain (step 7)

If the tenant gives you the document's events, the verifier checks the
chain, recomputes the authorship map and compares it, and every other
statement the certificate makes about the chain:

```sh
fm-verify certificate certificate.pdf --file proposal.pdf --events events.json ...
```

If the tenant also discloses the document key and the text (an audit), every
keyed hash in the chain can be replayed; the text is never printed:

```sh
fm-verify chain events.json --disclosure journal.json
```

## 6. When did a published file exist?

FundingMachine anchors its standing rulings, decisions logs, every decisions
entry and its release manifests (the Ledger's `docs/ANCHORING.md`). The
Ledger keeps the anchors in an `anchors/` directory on a branch of its own
repository. With a copy of that directory, give the verifier the directory
and the file you hold:

```sh
fm-verify anchors anchors/ --prove STANDING_RULINGS.md \
    --bitcoind http://127.0.0.1:8332 --bitcoind-cookie ~/.bitcoin/.cookie \
    --roots /etc/ssl/certs/ca-certificates.crt
```

It finds every anchor whose leaves name that content, verifies each, and
states the earliest that holds. A single decisions entry is anchored by the
SHA-256 of its text without the final newline: pass that with
`--prove-sha256`. The roots in the branch's `anchors/tsa/` are
FundingMachine's copies; use your own system's bundle, as above.

## 7. When did the ledger accept an event?

A certificate's times are the capture client's (`ts`). The time the ledger
itself accepted each event, by its own clock, is bound by the hour's
acceptance record (`ledger-acceptance/v0`, hours sealed from 20 October
2026), signed with the tenant key and anchored with the hour. The tenant
asks the ledger for one event's proof, and anyone can fetch the anchored
hour's public record:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
    "https://fundingmachine-ledger.vercel.app/api/acceptance?event_hash=$EVENT" > acceptance.json
curl -s "https://fundingmachine-ledger.vercel.app/api/anchors?hour=2026-10-20T09:00:00Z" > hour.json
fm-verify acceptance acceptance.json --key did:key:z6Mk... --root-record certificate.json --hour hour.json \
    --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt
```

The verdict checks the record's signature with the key a certificate of
the tenant names, the event's time as a leaf of the signed
`accepted_root`, that time inside the record's hour, the record as a leaf
of the hour's anchored root, the anchored root's tokens and proof, and that
no authority stamped the root before the event's time. It establishes that
the ledger stated the time no later than the earliest token's; that the
ledger's clock was right stays the ledger's claim.

## 8. Read the verdict

* `VALID` (exit 0): the statement holds, given what the verdict lists as
  relied on.
* `INVALID` (exit 1): something you supplied contradicts something else; the
  failing checks say what.
* `INDETERMINATE` (exit 2): nothing contradicts, but something needed was
  missing; the checks not run say what.

Every verdict ends with what it does not establish. A certificate records how
a document was written in this environment; it never detects AI, certifies
originality, or proves what the author read elsewhere.
