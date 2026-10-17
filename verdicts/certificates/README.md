# Certificate verdicts

Verdicts on certificates the live Provenance Ledger issues, of either
contract:

* `ledger-certificate/v0`: a document at its sign event (the Ledger's
  `docs/CERTIFICATE.md`);
* `record-certificate/v0`: a document's record at its head, with every hash
  link to the Bitcoin block (the Ledger's `docs/RECORD_CERTIFICATE.md`, since
  17 October 2026).

None has reached this repository yet. The service issues a certificate only
to the tenant that asks for it, and the Ledger session passes the first ones
on. Each is verified the day it arrives, and its verdict is committed here.

Each verdict is a directory named by the UTC time it was checked, holding:

* `verdict.txt`: the verdict as `fm-verify certificate` or
  `fm-verify record-certificate` prints it, every step reported on its own;
* `headers.txt`: the Bitcoin block headers it relied on, when the
  certificate's root is anchored;
* `certificate.sha256`: the SHA-256 of the certificate as received, JSON or
  PDF. The certificate itself is committed only if its holder agrees, since
  it names a tenant's document by its identifiers;
* `README.md`: where the certificate came from, what the verdict relied on,
  what it does not establish, and how to reproduce it.

## Reproduce

A `ledger-certificate/v0`:

```sh
python tools/fetch_headers.py certificate.pdf headers.txt   # the heights its anchor proof names, from two explorers
fm-verify certificate certificate.pdf --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt \
    [--file the-exported-document] [--events events.json]
```

A `record-certificate/v0` (`certificate.json` and `certificate.sig`, or the
PDF that carries both):

```sh
python tools/fetch_headers.py certificate.json headers.txt
fm-verify record-certificate certificate.json --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt \
    [--events events.json]
```

* The record certificate carries its block's header itself. The headers
  fetched are the reader's own source for the block at that height, which
  the verdict requires.

* `--file` runs step 3: the exported document's SHA-256 against the one the
  certificate states.
* `--events` runs step 7: the chain up to the sign event, and the authorship
  map recomputed from it.
* Without them, those steps are reported as not run, with the reason.
* A certificate with no hourly root yet, or with a root not yet anchored,
  says so in steps 4 to 6. Issuing it again later gives a new certificate
  with the proofs.
