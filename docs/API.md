# Library entry point

```python
from fmverify.api import verify, verify_json

answer = verify(request)          # dict in, dict out
text = verify_json(request_text)  # JSON text in, JSON text out
```

`verify` reads nothing from disk and opens no network connection: every
input is in the request, binary data as base64, certificates as PEM text. It
never raises for a malformed request; the answer then carries `error`.
A hosted page can call it server-side, or in the browser under Pyodide (the
package is pure Python apart from `cryptography`, which Pyodide ships). CI
runs `tools/pyodide/check.mjs`, which loads the package into Pyodide 0.27.7
(Python 3.12, cryptography 42.0.5, the oldest version the package accepts)
and checks six fixture requests, a certificate with its HTML page among
them. The command line remains the proof.

## Request

Common fields:

| Field | Meaning |
| --- | --- |
| `api` | `fm-verify/0` (optional; any other value is refused) |
| `kind` | `ots`, `rfc3161`, `merkle`, `anchors`, `certificate` or `chain` |
| `label` | the subject's name, shown in the verdict (optional) |
| `network` | `mainnet` (default) or `regtest` |
| `headers` | block headers: `{"kind": "chain", "data": <base64 of 80-byte headers>, "start": 0, "name": ...}` or `{"kind": "sparse", "text": "HEIGHT HEX lines or JSON", "name": ...}` |
| `min_work_bits` | floor for headers checked alone (default 70 on mainnet) |
| `roots`, `chain` | PEM certificates: roots you trust, and intermediates not in a token |
| `crls` | PEM certificate revocation lists you hold, checked along the trusted path |
| `render` | `html` adds `html` to the answer: the verdict as a self-contained page (for a certificate, with its authorship map and evidence coverage) |

`explorer` is refused: this entry point makes no network call. A page that
fetches headers from an explorer passes them as sparse headers and names
their origin in `name`, so the verdict's reliance says where they came from.

By kind:

| Kind | Fields |
| --- | --- |
| `ots` | `proof` (base64 `.ots`); `file` (base64) or `digest` (hex), optional |
| `rfc3161` | `token` (base64 `.tsr` or token); `file` or `digest` with `digest_alg` (default `sha256`), optional |
| `merkle` | `proof` (the JSON object of `docs/INPUTS.md`); `leaf` (base64) unless the proof carries `leaf` (hex); `root` (hex), optional |
| `anchors` | `batch` (the parsed `batch.json`); `anchor_files` (file name to base64); `files` (listed path to base64 of a file the reader holds), optional |
| `certificate` | `certificate` (the certificate's JSON object); `file` (base64 of the exported document), optional; `events` (the document's ledger-event/v0 events), optional, for step 7 |
| `chain` | `events` (a list of ledger-event/v0 events) |

## Answer

The verdict, as the command line's `--json` prints it: `kind`, `subject`,
`outcome` (`valid`, `invalid`, `indeterminate`), `statement`, `checks` (each
with `id`, `status`, `summary`, `reasons`, `relies_on`, `required`, `data`),
`relies_on`, `does_not_establish`, `checked_at`, `tool`.

A malformed request: `{"api": "fm-verify/0", "error": "...", "tool": {...}}`.
