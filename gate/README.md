# Release gate

Nothing in this repository is released until two keys are recorded for the exact commit it publishes:

* **Key one:** the releasing session's pre-release checks passed on that commit.
* **Key two:** the release-gate session reviewed that same commit and reported "no issue".

Releases the owner keeps (`releases-with-owner`) also need the owner's go; the gate does not replace it. This
repository is public.
Ordinary pull requests are not gated: sessions merge their own green pull requests through auto-merge.

## Release paths here

| Path | What publishes | Where the gate sits |
| --- | --- | --- |
| `package` | A tag `v*` runs `.github/workflows/release.yml`, which publishes a GitHub release with the wheel, the source archive, the conformance fixture archive, the scoreboard and the scoreboard manifest (nothing goes to a package index), then its job `blob` copies the same files, with `LICENSE`, `ATTRIBUTION.txt`, `manifest.json` and `SHA256SUMS`, to `verify-<tag>/` in the Blob store `capital-graph-public`. Run by hand with `upload_tag`, only the `blob` job runs, for a release already published | Job `gate` (`release-gate.yml`, release name = the tag, or `upload_tag`) runs first; `build` needs `gate`, `publish` needs `build`, and `blob` needs `gate` and `publish` and runs only when `needs.gate.result == 'success'` |

The record for a tag `v0.1.0` is `gate/records/v0.1.0.json` with `path` set to `package`. Push the tag once, on the
recorded commit, and only after the record has merged: a release tag is never moved or deleted. A tag pushed early
fails its `gate` job and publishes nothing; re-running that run after the record merges reads main again.

## How a release goes

1. The Verifier session runs its pre-release checks on the commit to publish.
2. It opens a pull request adding `gate/records/<tag>.json` with `key1` filled in.
3. The release-gate session reviews that commit and posts its report. If it finds no issue, it adds `key2`.
4. The record merges to main, then the tag is pushed on the recorded commit.
5. The `gate` job reads the record from main; a missing or incomplete record, or one for another commit, stops the
   publish.

## The record

```json
{
  "release": "v0.1.0",
  "path": "package",
  "commit": "<full SHA of the commit the release publishes>",
  "key1": { "holder": "verifier", "passed": true, "evidence": "<link to the green run or pull request>" },
  "key2": { "holder": "release-gate", "verdict": "no issue", "commit": "<same SHA>", "report": "<link to the review>" }
}
```

The file name is the release name. Both links point into Korentsvit. The two holders differ. A record is never
edited after its release; a new release gets a new record.

## The public release location

The owner set it on 8 November 2026: releasable assets go to the public Vercel Blob store `capital-graph-public`,
one prefix per release (here `verify-<tag>/`, for example `verify-v0.4.1/`), each with `manifest.json`,
`SHA256SUMS`, the licence notice and the attribution lines, published by the tag workflow only after both keys. A
GitHub release is not that location.

For the gate this means:

* The job that writes to the Blob store `needs` the job that calls `release-gate.yml`, like every other publishing
  job.
* It takes the prefix and the commit from what the gate passed (`needs.gate.outputs.release` and
  `needs.gate.outputs.commit`, or the very expression the gate job was given), never from an input of its own, so a
  run cannot write one release's files under another release's prefix or from another commit. Here the `blob` job's
  `TAG` is the same expression as the gate's `release`, and it checks the record on main against the tag's commit.
* A release path that adds a Blob upload changes its row in the table above and needs a new record for its new
  commit; a record keyed before the upload existed does not cover it.

## Checks and rulesets

* **Required checks on main** are this repository's own CI only, from `.github/workflows/tests.yml`:
  `test (3.10)`, `test (3.13)`, `interop`, `release-build` and `pyodide`, with the branch up to date (ruleset
  "main"; the Verifier session names the set). No Vercel deployment check is required.
* **Proposed for the owner to apply:** a tag ruleset on `v*`, `atlas-*`, `awards-*` and `R*` that blocks deletion
  and updates, so a released tag cannot move.
* `release-gate.yml` runs on any pull request that touches `gate/` or a workflow: the gate's self-test, every record,
  and `node gate/check.mjs workflows`, which reads every job under `.github/workflows/` and fails when a job that
  publishes (a GitHub release, a Vercel deploy, a Blob write, a tag push, a package upload) does not wait for a job
  calling `release-gate.yml`, or can run after that job failed (`always()`, `!cancelled()` without `!failure()`). It
  finds publishing by command, so a write made inside a program stays covered by the table above and the review, and a
  job that runs when the gate is skipped must publish only under the gate's own condition, which the review checks. A
  path the owner has not yet decided to gate is listed, with the reason, in `gate/ungated.json`. It is not a required
  check.