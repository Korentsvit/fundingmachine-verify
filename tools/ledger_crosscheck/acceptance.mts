// Acceptance proofs (ledger-acceptance/v0) both ways between the Provenance Ledger's own code and this verifier.
// Needs a checkout of fundingmachine-ledger with its dependencies installed (npm ci). From that checkout:
//
//   npx tsx <this file> <path to fundingmachine-verify>/fixtures [HOURS]
//
// Prints one JSON line per item:
// * {"kind": "built", ...}: HOURS hours (default 40) built by the Ledger's buildRoot and buildAcceptance with its
//   published test key (keys.json "tenant", RFC 8032 section 7.1 TEST 3), each with one event's proof as
//   GET /api/acceptance answers it (src/store/store.ts) and the hour's root record, for this verifier to check;
// * {"kind": "fixture", ...}: the Ledger's verifyAcceptanceSig and verifyAcceptance, and its verifyInclusion for the
//   anchor, on each case of this repository's fixtures/acceptance, with the fixtures' own test key.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const ledger = process.cwd();
const { buildAcceptance, acceptancePath, acceptanceRecordHash, acceptanceLeaf, verifyAcceptance, verifyAcceptanceSig } =
  await import(resolve(ledger, "src/acceptance.ts"));
const { buildRoot, signedRecordHash } = await import(resolve(ledger, "src/root.ts"));
const { keyFromSeed } = await import(resolve(ledger, "src/event/sign.ts"));
const { auditPath, leafHash, rootFromLeafHashes, verifyInclusion } = await import(resolve(ledger, "src/merkle.ts"));
const fix = process.argv[2];
const hours = Number(process.argv[3] ?? 40);

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest();
const keys = JSON.parse(readFileSync(resolve(ledger, "fixtures/ledger-event/v0/keys.json"), "utf8"));
const tenant = keyFromSeed(Buffer.from(keys.ed25519.tenant.seed_hex, "hex"));

// A deterministic stream of numbers, so the run is the same each time.
let counter = 0;
const next = (n: number) => sha(`acceptance crosscheck ${counter++}`).readUInt32BE(0) % n;

for (let h = 0; h < hours; h++) {
  const start = new Date(Date.UTC(2026, 9, 20, 0, 0, 0) + h * 3_600_000);
  const window = { start: start.toISOString(), end: new Date(start.getTime() + 3_600_000).toISOString() };
  const n = 1 + next(h < 4 ? 3 : 40);
  const offsets = Array.from({ length: n }, () => next(3_600_000_000)).sort((a, b) => a - b);
  const accepted = offsets.map((us, i) => {
    const t = new Date(start.getTime() + Math.floor(us / 1000));
    const micro = String(us % 1000).padStart(3, "0");
    return { event_hash: sha(`event ${h} ${i}`).toString("hex"), received_at: t.toISOString().replace("Z", `${micro}Z`) };
  });
  const root = buildRoot("crosscheck", window, accepted.map((a) => a.event_hash), "0".repeat(64), tenant);
  const record = buildAcceptance("crosscheck", window, accepted, signedRecordHash(root), tenant);
  // The hour's anchored tree as the anchoring job builds it: this tenant's root record, then its acceptance record,
  // among other tenants' (by tenant_id: "another" before, "zz" after).
  const leaves = [sha("another tenant's root record"), Buffer.from(signedRecordHash(root), "hex"),
    Buffer.from(acceptanceRecordHash(record), "hex"), sha("zz tenant's root record")].map((b) => leafHash(b));
  const at = 2;
  const index = next(n);
  console.log(JSON.stringify({
    kind: "built", hour: window.start, root_record: root, key_hex: tenant.publicRaw.toString("hex"),
    proof: {
      event_hash: accepted[index].event_hash, received_at: accepted[index].received_at, record, leaf_index: index,
      audit_path: acceptancePath(accepted, index),
      anchor: { root: rootFromLeafHashes(leaves).toString("hex"), size: leaves.length, leaf_index: at,
        audit_path: auditPath(at, leaves).map((b: Buffer) => b.toString("hex")) },
    },
  }));
}

const fixtureKey = keyFromSeed(sha("fm-verify test tenant key"));
for (const name of readdirSync(join(fix, "acceptance")).sort()) {
  const p = JSON.parse(readFileSync(join(fix, "acceptance", name, "acceptance.json"), "utf8"));
  if (p.record === null) {
    console.log(JSON.stringify({ kind: "fixture", name, record: false }));
    continue;
  }
  let leaf: boolean;
  try {
    acceptanceLeaf({ event_hash: p.event_hash, received_at: p.received_at });
    leaf = verifyAcceptance({ event_hash: p.event_hash, received_at: p.received_at }, p.leaf_index, p.audit_path, p.record);
  } catch {
    leaf = false; // the Ledger refuses a time not written as the record binds it
  }
  const anchored = p.anchor === null ? null : verifyInclusion(leafHash(Buffer.from(acceptanceRecordHash(p.record), "hex")),
    p.anchor.leaf_index, p.anchor.size, p.anchor.audit_path.map((x: string) => Buffer.from(x, "hex")), Buffer.from(p.anchor.root, "hex"));
  console.log(JSON.stringify({ kind: "fixture", name, record: true, signature: verifyAcceptanceSig(p.record, fixtureKey.publicRaw),
    inclusion: leaf, anchor: anchored }));
}
