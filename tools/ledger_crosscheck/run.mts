// Runs the Provenance Ledger session's own TypeScript validator over this
// repository's chain and certificate fixtures: the reverse of the
// cross-check in tests/test_chain.py. Needs a checkout of fundingmachine-ledger
// with its dependencies installed (npm ci). From that checkout:
//
//   npx tsx <this file> <path to fundingmachine-verify>/fixtures   (an .mts file, so it runs as an ES module)
//
// Prints one JSON line per case; the expected outcome is beside the
// Ledger's answer.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";

const ledger = process.cwd();
const { verifyChain } = await import(resolve(ledger, "src/event/chain.ts"));
const { verifyCredential } = await import(resolve(ledger, "src/vc.ts"));
const { authorshipMap } = await import(resolve(ledger, "src/authorship.ts"));
const { canonicalize } = await import(resolve(ledger, "src/canonical.ts"));
const fix = process.argv[2];

for (const name of readdirSync(join(fix, "chain")).sort()) {
  const events = JSON.parse(readFileSync(join(fix, "chain", name, "events.json"), "utf8")).events;
  const exp = JSON.parse(readFileSync(join(fix, "chain", name, "expected.json"), "utf8"));
  if (exp.disclosure) continue; // these cases are about disclosed text; their chains are the valid one
  const r = verifyChain(events);
  const ledgerSays = r.ok ? ["valid", null, null] : ["invalid", r.error.index, r.error.code];
  const expected = [exp.outcome, exp.index ?? null, exp.code ?? null];
  console.log(JSON.stringify({ kind: "chain", name, expected, ledger: ledgerSays, agree: JSON.stringify(expected) === JSON.stringify(ledgerSays) }));
}
for (const name of readdirSync(join(fix, "certificate")).sort()) {
  const file = join(fix, "certificate", name, "certificate.json");
  if (!existsSync(file)) continue; // the PDF cases carry the same JSON inside a PDF
  const cred = JSON.parse(readFileSync(file, "utf8"));
  const exp = JSON.parse(readFileSync(join(fix, "certificate", name, "expected.json"), "utf8"));
  const proofShouldHold = !(exp.failing ?? []).includes("certificate.proof");
  const ledger = verifyCredential(cred);
  console.log(JSON.stringify({ kind: "certificate-proof", name, expected_proof_holds: proofShouldHold, ledger, agree: Boolean(ledger.ok) === proofShouldHold }));
}
for (const [chainCase, certCase] of [["valid", "valid-with-chain"], ["v01-resync-valid", "v01-valid-with-chain"]]) {
  const certFile = join(fix, "certificate", certCase, "certificate.json");
  if (!existsSync(certFile)) continue;
  const cert = JSON.parse(readFileSync(certFile, "utf8"));
  const all = JSON.parse(readFileSync(join(fix, "certificate", certCase, "events.json"), "utf8")).events;
  const r = verifyChain(all);
  if (!r.ok) { console.log(JSON.stringify({ kind: "authorship-map", name: certCase, agree: false, error: r.error })); continue; }
  const map = authorshipMap(r.state, r.head);
  const h = createHash("sha256").update(canonicalize(map)).digest("hex");
  console.log(JSON.stringify({ kind: "authorship-map", name: certCase, ledger_map_sha256: h,
    certificate_map_sha256: cert.credentialSubject.authorship.map_sha256, agree: h === cert.credentialSubject.authorship.map_sha256 }));
}
