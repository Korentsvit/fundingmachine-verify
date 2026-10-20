# The hosted verifier page

Specification `hosted-page/0` for verify.fundingmachine.ai, written by the
Verifier session for the website side to build. Its purpose is that the page
shows what `fm-verify` shows for the same inputs and says what that verdict
rests on. The command line remains the proof; the page is a convenience
(`docs/decisions.d/2026-10-16-verify-report.md`).

"Must" and "must not" are requirements. Everything else is advice.

## 1. Where the verifying happens

1. The page runs this repository's library entry point (`fmverify.api.verify`,
   [API.md](API.md)) in the reader's browser under Pyodide. No server verifies
   anything, and the page has no "verify on our server" mode.
2. Nothing the reader gives leaves the browser tab: not the file, its hash or
   the verdict. Inputs are not written to local storage, IndexedDB or cookies,
   and a reload forgets them.
3. The page has no analytics, error reporting, tracking or third-party embed,
   and keeps no record of what was verified.
4. The page passes each file as the bytes the reader picked. It does not take
   `certificate.json` out of a PDF itself, re-encode JSON or change line
   endings. A certificate goes in as `certificate_file`, so this verifier's
   reader decides what the PDF holds: two readers can take different
   certificates from one damaged file (V-28 in [PLAN.md](PLAN.md)).

## 2. What it loads

Everything comes from the page's own origin. No script, stylesheet, font or
image is loaded from anywhere else.

| Files | Source | Pinned by |
| --- | --- | --- |
| The page's own HTML, scripts and styles | the website side | its build |
| Pyodide: `pyodide.mjs`, `pyodide.asm.js`, `pyodide.asm.wasm`, `python_stdlib.zip`, `pyodide-lock.json` | the `pyodide` npm package of the pinned version | the page's npm lock file |
| `cryptography` and what it depends on (for Pyodide 0.27.7: cffi, openssl, pycparser, six) | Pyodide's distribution for that version | the SHA-256 values in `pyodide-lock.json`; `tools/pyodide/policy/fetch_packages.py` keeps no other file |
| The fm-verify wheel | the wheel published with a tagged release of this repository, built there by `tools/build_release.py` | its SHA-256, which anyone can rebuild; the anchors page's build pins it (section 11.7) |
| `NOTICE`, and the licence texts it names that a package does not carry (Pyodide's, CPython's and OpenSSL's) | each project's own repository, at the version served | the SHA-256 values in `tools/build_page.py` (section 11.3) |

* The tested combination is Pyodide 0.27.7 (Python 3.12) with cryptography
  42.0.5, the oldest version the package accepts. Before another version of
  either ships, the page's CI must pass section 8 with it.
* Next to every verdict the page shows fm-verify's version and tag, the
  wheel's SHA-256 and the Pyodide version, and links to how the wheel is
  rebuilt (README, "Independence"). A reader who does not trust the
  host can compare that hash with a build of their own, or use the command
  line.
* The page pins a tagged release. v0.1.0 (18 October 2026) predates the
  anchors page and lacks what it imports, so the first release the anchors
  page can pin is v0.2.0 (section 11.7).

Loading takes three calls: `loadPyodide({indexURL})` with the page's own
path, `loadPackage(["cryptography"])` (resolved through the lock file, from
the same origin), and `unpackArchive(wheelBytes, "wheel")`. No micropip and
no package index. `tools/pyodide/policy/app.mjs` shows the sequence.

## 3. Content Security Policy

The page must send this policy as an HTTP header on every response (a meta
tag cannot set `frame-ancestors`):

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' https://mempool.space https://blockstream.info; style-src 'self' STYLE_HASH; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

* `STYLE_HASH` is `fmverify.report.CSP_STYLE_HASH` of the shipped version,
  the hash of the HTML report's one `<style>` element. The report has no other
  style, no script and no external resource (`tests/test_report.py`).
* There is no `'unsafe-eval'` and no `'unsafe-inline'`. The verifier, Pyodide
  0.27.7 and cryptography 42.0.5 run without them.
  * `tools/pyodide/policy/check.mjs` was run on 16 October 2026 in Chromium
    141.0.7390.37. It found no violation and the outcomes the fixtures
    expect, and the report frame rendered with its styles.
  * Built from the code before the report's bar became SVG, the same check
    fails on the report's inline styles.
  * CI's `pyodide` job runs the check in Chrome on every change.
* The page's own styles are files from its origin. If the page needs any
  other source, that is a change to this specification, made here first.
* The page must also send `Referrer-Policy: no-referrer` and
  `X-Content-Type-Options: nosniff`, and a `Permissions-Policy` that denies
  camera, microphone, geolocation and payment.

## 4. Inputs

| The reader gives | Request field |
| --- | --- |
| The certificate, PDF or JSON, as received | `certificate_file` (base64) |
| The document the certificate covers (optional) | `file` |
| The document's events, if the tenant gave them (optional) | `events` |
| Bitcoin block headers (section 5) | `headers` |
| Roots for the time-stamping authorities (section 6) | `roots` |
| Revocation lists the reader holds (optional) | `crls` |

The page always asks for `render: "html"`.

The page may also offer one OpenTimestamps proof with its file
(`kind: ots`), one RFC 3161 token with its file (`kind: rfc3161`), and an
event chain (`kind: chain`), optionally with a disclosure. The page never
shows text from a disclosure, and the verdict never repeats it.

Not in `hosted-page/0`:

* Provenance Ledger anchors (`kind: ledger-anchor`, or "when did this file
  exist"). None is published yet. Also, the conformance kind `ledger-anchors`
  includes checkout comparisons and whole-tree searches the entry point
  cannot take. They come in a later version. (Since 17 October 2026 they are
  published; `hosted-page/1` adds a page for them, section 11.)
* Fetching a certificate from a URL.

The page must refuse a file over 64 MiB before reading it, with a message
rather than a verdict. That matches the verifier's own bound on a PDF's
decoded content.

Running Pyodide in a Web Worker keeps the page responsive. A worker falls
under the same policy (`worker-src` falls back to `script-src 'self'`). The
tested run is on the main thread.

## 5. Block headers

OpenTimestamps proofs are checked against Bitcoin block headers. The reader
supplies them, or the page fetches them, but only when the reader asks. The
page offers three sources, strongest first:

1. **A headers file the reader holds**: `HEIGHT HEX` lines, or consecutive
   80-byte headers with the first header's height. It is passed as
   `{"kind": "sparse"}` or `{"kind": "chain"}`, with `name` set to the file
   name.
2. **Two explorers compared**, the default once the reader agrees to a fetch.
   * For each block the proof names, the page fetches the header from
     mempool.space and from blockstream.info, through their Esplora API:
     `GET /api/block-height/{height}`, then `GET /api/block/{hash}/header`.
   * It passes the two answers as two sparse sources, each named by its origin
     (for example `mempool.space, fetched by this page`).
   * The verifier finds any disagreement and gives an invalid verdict. The page
     never chooses between the two answers itself.
3. **One explorer, trusted outright**, only if the reader picks it. The
   verdict's reliance names that explorer.

Before fetching, the page says what the explorers learn:

* the block heights, which show roughly when the anchor was made;
* the reader's IP address;
* that the request comes from this page (browsers send the page's origin with
  a cross-origin request).

They learn nothing else about the document.

Both explorers allowed cross-origin reads (`Access-Control-Allow-Origin: *`)
when checked on 16 October 2026 at 23:27 UTC. They also returned identical
headers for blocks 971642 and 971659. If either stops serving the page, the
page offers the other alone, stated as one explorer trusted.

The page never passes `explorer`, which the entry point refuses. It fetches
nothing by transaction id, commitment or document hash, and it contacts no
OpenTimestamps calendar.

## 6. Roots and revocation

Browsers do not expose their trust store to a page. So the page ships the
roots of the authorities the Provenance Ledger uses (DigiCert and Sectigo, its
`docs/ANCHORING.md`).

* Each root is taken from the authority's own publication. Its URL, retrieval
  date and SHA-256 fingerprint are shown beside the verdict.
* The verdict names the root a token chained to.
* The page says these roots were chosen by the page, and lets the reader
  replace them with PEM files of their own.

The page does not fetch revocation lists. The reader may add lists they hold
(`crls`). Without them, the verdict says revocation was not checked, and the
page shows that.

## 7. Showing the answer

1. **The outcome.** The page shows the outcome word exactly as the verifier
   gives it: VALID, INVALID or INDETERMINATE.
   * The verdict's statement is always beside it.
   * The "Relied on" and "Does not establish" lists are on the same screen,
     without a click.
   * There is never a tick, seal or colour on its own; every status is spelt
     out in words.
2. **Every check**, with its id, status, summary and reasons. Checks may be
   folded, but warnings and failures start unfolded.
3. **The report.** The `html` the entry point returns is shown in an
   `<iframe sandbox srcdoc="...">`. The `sandbox` attribute is empty: no
   scripts, no same origin, no forms, no navigation. The report and the
   verdict's JSON can each be saved as they are.
4. **Errors.**
   * An answer with `error` is shown as "Could not check" with the error text,
     never as a verdict.
   * An answer with `internal: true` is a fault in the verifier. The page says
     so and links to [SECURITY_NOTE.md](SECURITY_NOTE.md), "Reporting a
     problem".
5. **The equivalent command line**, built from the file names the reader
   gave, so the result can be reproduced without the page:
   `fm-verify certificate certificate.pdf --file proposal.pdf --headers headers.txt --roots roots.pem`.
6. **The issuer key.** The certificate's issuer key (`did:key`) is shown with
   "compare it with a key the tenant publishes somewhere you trust".
   * The page keeps no list of tenants' keys and never names the holder of a
     key.
   * Doing either would make FundingMachine the authority the certificate is
     checked against.
7. **The words.** These follow standing ruling
   `shows-the-work-never-proves-no-AI`.
   * The page never calls a document human-written, authentic, original, free
     of AI, or verified by FundingMachine.
   * The certificate's scope statement is printed word for word, as the report
     prints it.
8. **The clock.** The verdict's `checked_at` comes from the reader's clock, and
   the page says so.
9. **Layout.** The page fits a 390-pixel screen without sideways scrolling,
   works in light and dark, and can be used from the keyboard.

## 8. Conformance of the page

Before each deploy, the page's CI must do three things:

1. **The policy check.** Run `tools/pyodide/policy/check.mjs`, or its
   equivalent in the page's own test framework, against the build as it will
   be served: the same files, under the production policy header. It must find
   the expected outcomes, no policy violation, and the report frame rendered.
2. **The conformance suite, through the page.** Run
   `fm-verify conformance fixtures --implementation ADAPTER --kind certificate --kind ots --kind rfc3161 --kind chain --check-ids`.
   * `ADAPTER` takes `KIND CASE_DIR` ([CONFORMANCE.md](CONFORMANCE.md)) and
     turns the case into the page's request.
   * It runs that request in the built page, in a headless browser, and prints
     the verdict JSON.
   * Every case must conform.
3. **The wheel.** Check that the fm-verify wheel it ships has the SHA-256 of
   the release it names.

Any failure blocks the deploy.

## 9. What the page cannot show

Everything in [SECURITY_NOTE.md](SECURITY_NOTE.md) applies, plus three limits
of the page itself:

* **The host.** A reader using the page trusts the host to serve the wheel the
  page names, and the hash on display comes from that same host. The
  independent checks are rebuilding the wheel, or the command line on the
  reader's own machine.
* **The explorers.** Headers from explorers are only as good as the explorers,
  compared (section 5).
* **The roots.** They are the page's choice unless the reader replaces them
  (section 6).

## 10. Changes

* An addition keeps the version.
* A new version is needed for any change that alters what the page shows for
  a given verdict, or that loosens sections 1 to 3. It is made here first.
* Questions from the website side reach the Verifier session through
  Filipp's daily batch.

## 11. The anchors page (`hosted-page/1`)

`hosted-page/1` adds a second page: the Provenance Ledger's anchors, checked
from its public mirror at a commit the reader names. Its implementation is
`page/index.html` in this repository, assembled into a static site by
`tools/build_page.py`. Sections 1, 2 and 4 to 10 apply to it with the
changes below. The certificate page of `hosted-page/0` is unchanged.

### 11.1 What it fetches

1. **The mirror at the commit named**, a commit of
   `Korentsvit/fundingmachine-anchors` given as 40 hexadecimal characters,
   from `https://raw.githubusercontent.com/Korentsvit/fundingmachine-anchors/COMMIT/anchors/`:
   * `index.jsonl`;
   * for each anchor it lists, `manifest.json`;
   * the files the manifest names (`root.preimage` and its proof files).
     The page fetches only names beginning `root.preimage`.

   The page states that this relies on GitHub to serve that commit's files.
2. **The second source**, unless the reader turns it off: the Ledger's own
   record at `https://fundingmachine-ledger.vercel.app/api/anchors`.
   * The page asks the record for each file by its path and SHA-256
     (`?path=P&sha256=H`).
   * It shows whether the record held the same bytes for every file, and
     lists every file it did not.
   * The verdict is always on the mirror's bytes; the record's are only
     compared.
3. **Block headers**, as section 5, for the heights the proofs name
   (`fmverify.api.bitcoin_heights`) and no others.

The page asks GitHub's API for nothing, so the reader names the commit. The
page's default is the commit of the newest verdict under
`verdicts/ledger-anchors/` when the page was built.

### 11.2 Verifying

The page passes the files to the library entry point's `ledger-anchor-set`
kind ([API.md](API.md)). That gives the verdict `fm-verify anchors DIR --all`
gives on a checkout of the same commit:
* `tests/test_anchor_set_api.py` checks the two agree on the fixtures;
* on the mirror at 0a6189f, with the same headers and roots, they were
  identical on 17 October 2026.

### 11.3 What it loads, and the policy

* **One HTML file.** Its own script and style are inline, one of each, and
  allowed by their hashes. There is no other inline script or style.
* **Beside it, from its own origin:**
  * Pyodide's files, cryptography and what it depends on (section 2);
  * the fm-verify wheel of the release it pins (section 11.7);
  * `site.json`, which names the wheel with its SHA-256 and its address in
    the release, the versions, the roots with their provenance and the
    default commit;
  * `roots.pem`;
  * `NOTICE`: every third-party file served, its version, the licence its
    own package states, where its licence text is, and its source. The
    wheels carry their licence files inside them. For the files that do
    not, the build fetches `LICENSE-pyodide.txt`, `LICENSE-python.txt` and
    `LICENSE-openssl.txt` from each project's own repository at the version
    served (Pyodide 0.27.7, CPython 3.12.7, OpenSSL 1.1.1w), keeping each
    only if its SHA-256 is the one pinned in `tools/build_page.py`. The
    build refuses a Pyodide whose lock file states other versions. No
    licence text accompanies the two roots at their publishers' addresses;
    `NOTICE` says so, and serves them by the owner's decision of 19 October
    2026.

The page must send this policy as an HTTP header:

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval' SCRIPT_HASH; connect-src 'self' https://raw.githubusercontent.com https://fundingmachine-ledger.vercel.app https://mempool.space https://blockstream.info; style-src PAGE_STYLE_HASH REPORT_STYLE_HASH; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

* `SCRIPT_HASH` and `PAGE_STYLE_HASH` are the hashes of the page's inline
  script and style. `REPORT_STYLE_HASH` is `fmverify.report.CSP_STYLE_HASH`.
* `tools/build_page.py` writes the filled policy to `csp.txt` and `_headers`,
  with the other headers of section 3.
* Against `hosted-page/0`, this is the loosening that makes it a new version:
  * `connect-src` adds GitHub's raw host and the Ledger's record;
  * the page's own script and style are inline by hash rather than files.

  `style-src` no longer allows `'self'`. There is still no `'unsafe-eval'`
  and no `'unsafe-inline'`.

### 11.4 Roots

The build fetches each root from its authority's own publication. It keeps
a root only if its SHA-256 is the one pinned in `tools/build_page.py`:

| Root | From | SHA-256 |
| --- | --- | --- |
| DigiCert Trusted Root G4 | `https://cacerts.digicert.com/DigiCertTrustedRootG4.crt` | `552f7bdc...` |
| USERTrust RSA Certification Authority | `http://crt.usertrust.com/USERTrustRSACertificationAuthority.crt`, Sectigo's address for it, served over HTTP | `e793c9b0...` |

* For the second root, the pin is what is trusted, not the transport.
* The roots are third-party files, so they are fetched at build time and not
  committed.
* The page lists each root with its address, retrieval date and fingerprint,
  says they are its choice, and lets the reader use PEM files of their own
  (section 6).

### 11.5 What it shows

Everything section 7 requires, and:

1. **The source:** the commit, and the result of the record comparison.
2. **The headers relied on:** for each one, its height, its block hash
   (computed by the page) and the header itself, offered for saving as
   files the command line takes.
3. **One row per anchor:** its outcome, and either its earliest Bitcoin
   block with that block's header time, or "pending".
4. **Every check,** with the checks of any anchor that has a warning or a
   failure.
5. **The command line,** with `roots.pem` and the header files offered for
   saving:

```sh
git clone https://github.com/Korentsvit/fundingmachine-anchors
git -C fundingmachine-anchors checkout COMMIT
fm-verify anchors fundingmachine-anchors/anchors --all --headers headers-mempool.space.txt --headers headers-blockstream.info.txt --roots roots.pem
```

### 11.6 Conformance of the page

The `page` job in `.github/workflows/tests.yml` builds the site and runs
`tools/pyodide/page/check.mjs` in Chrome, under the site's own policy. Its
inputs are the mirror at 98e2443 and the headers committed with
`verdicts/ledger-anchors/2026-10-17T1218Z`, and it answers the four hosts
from those copies. It checks five cases:

* the plain run: valid, with the record comparison stated;
* one explorer giving another block's header: invalid;
* the record lacking a file: the difference shown;
* a commit the mirror lacks: "Could not check";
* a 390-pixel screen: no sideways scrolling.

On 17 October 2026 the built page also ran against the real hosts, from the
Verifier session. It reached the command line's verdict (32 anchors, 31
confirmed in Bitcoin), the record holding the same bytes for all 161
files, in 26 seconds and with no policy violation.

### 11.7 Release

The page stays in this repository until the owner releases it. Nothing here
deploys it.

A released page serves a tagged release's own wheel, not a build of a
checkout:

1. After the release is published, `page/release.json` is committed by pull
   request. It names the tag, the full commit it is on, the wheel's file
   name and the SHA-256 of the wheel the release published.
2. The site is built with the pin:

   ```sh
   python tools/build_page.py SITE --pyodide DIR --release page/release.json [--wheel FILE]
   ```

   The build downloads the wheel from the release's own address (or takes
   the local copy given with `--wheel`). It refuses the wheel unless its
   name and SHA-256 are the pinned ones. It also refuses a release whose
   wheel does not define what the page imports (`verify_json` and
   `bitcoin_heights` in `fmverify/api.py`, read without running it).
3. The page then shows the release by its tag, its address and its commit.
   Its command line installs that wheel by its address with the pinned hash
   (`pip install "URL#sha256=HASH"`), which pip refuses if the bytes differ.

Without `--release` the build makes the wheel from the checkout, and the
page says it is not a tagged release. CI builds and checks the page that
way (section 11.6). On 19 October 2026 the release path passed the five
cases of section 11.6 in Chromium from the Verifier session, with a wheel
built from main given by `--wheel`. The same day the build refused
v0.1.0's published wheel, which lacks `bitcoin_heights`.

Since 20 October 2026 `page/release.json` pins v0.2.0 (commit c29b66d,
wheel SHA-256 `c115240d...`), the first release the page can run. CI also
builds the page with that pin, the wheel taken from the release's own
address, and runs the five cases on it. For a pinned page the first case
also requires the page to name the release by its tag, address and commit,
to find the pinned hash in the wheel it loaded, and to give the install
line with the release's address and hash.
