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
| `package` | A tag `v*` runs `.github/workflows/release.yml`, which publishes a GitHub release with the wheel, the source archive and the conformance fixture archive (nothing goes to a package index) | Job `gate` (`release-gate.yml`, release name = the tag) runs first; `build` needs `gate` and `publish` needs `build` |

The record for a tag `v0.1.0` is `gate/records/v0.1.0.json` with `path` set to `package`. Push the tag only after the
record has merged: the tag ruleset on `v*` blocks deleting or moving a tag. A tag pushed early fails its `gate` job
and publishes nothing; re-running that run after the record merges reads main again.

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

## Checks and rulesets

* **Required checks** are this repository's own CI only, from `.github/workflows/` (today `test (3.10)`,
  `test (3.13)`, `interop`, `pyodide` and `release-build`; the Verifier session names the set). No Vercel
  deployment check is required.
* **Proposed for the owner to apply:** a tag ruleset on `v*` that blocks deletion and updates.
* `release-gate.yml` runs the gate's self-test on any pull request that touches `gate/`. It is not a required check.
