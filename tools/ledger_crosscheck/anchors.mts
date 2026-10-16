// Runs the Provenance Ledger session's own anchor verifier (src/anchor/verify.ts)
// over this repository's ledger-anchors fixtures: each anchor directory with
// verifyAnchor, each set (a directory with index.jsonl) with verifyAll. No
// authority roots are passed (tsaDir null): the fixtures' test authorities are
// not the Ledger's, so its OpenSSL signature step is skipped and everything
// else (leaves, root, preimage, the OpenTimestamps digest, token imprints and
// genTimes, index and links) is compared. From a checkout of fundingmachine-ledger
// with its dependencies installed:
//
//   npx tsx <this file> <path to fundingmachine-verify>/fixtures
//
// Prints one JSON line per case: this verifier's expected outcome beside the
// Ledger's answer.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const ledger = process.cwd();
const { verifyAnchor, verifyAll } = await import(resolve(ledger, "src/anchor/verify.ts"));
const base = join(process.argv[2], "ledger-anchors");

for (const name of readdirSync(base).sort()) {
  const dir = join(base, name);
  if (!existsSync(join(dir, "expected.json"))) continue;
  if (!existsSync(join(dir, "root.preimage")) && !existsSync(join(dir, "index.jsonl"))) continue; // a --prove case, not an anchor
  const expected = JSON.parse(readFileSync(join(dir, "expected.json"), "utf8")).outcome;
  let ok: boolean;
  let problems: string[];
  try {
    if (existsSync(join(dir, "index.jsonl"))) {
      const r = verifyAll(dir, null);
      ok = r.ok;
      problems = r.anchors.flatMap((a: { path: string; problems: string[] }) => a.problems.map((p) => `${a.path}: ${p}`));
    } else {
      const r = verifyAnchor(base, name, null);
      ok = r.ok;
      problems = r.problems;
    }
  } catch (err) {
    ok = false;
    problems = [`threw: ${(err as Error).message}`];
  }
  console.log(JSON.stringify({ case: name, expected, ledger_ok: ok, problems }));
}
