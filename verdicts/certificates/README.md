# Certificate verdicts

Verdicts on Provenance Ledger certificates (`ledger-certificate/v0`) issued by
the live service. None has been issued yet: the service issues a certificate
only to a tenant that asks for one (`POST /api/certificates`), and the first
real one has not reached this repository. When it does, it is verified the
same day and its verdict is committed here.

Each verdict is a directory named by the UTC time it was checked, holding:

* `verdict.txt`: the verdict as `fm-verify certificate` prints it, every step
  of the Ledger's `docs/CERTIFICATE.md` reported on its own;
* `headers.txt`: the Bitcoin block headers it relied on, when the
  certificate's root is anchored;
* `certificate.sha256`: the SHA-256 of the certificate as received, JSON or
  PDF. The certificate itself is committed only if its holder agrees, since
  it names a tenant's document by its identifiers;
* `README.md`: where the certificate came from, what the verdict relied on,
  what it does not establish, and how to reproduce it.

## Reproduce

```sh
python tools/fetch_headers.py certificate.pdf headers.txt   # the heights its anchor proof names, from two explorers
fm-verify certificate certificate.pdf --headers headers.txt --roots /etc/ssl/certs/ca-certificates.crt \
    [--file the-exported-document] [--events events.json]
```

* `--file` runs step 3: the exported document's SHA-256 against the one the
  certificate states.
* `--events` runs step 7: the chain up to the sign event, and the authorship
  map recomputed from it.
* Without them, those steps are reported as not run, with the reason.
* A certificate with no hourly root yet, or with a root not yet anchored,
  says so in steps 4 to 6. Issuing it again later gives a new certificate
  with the proofs.
