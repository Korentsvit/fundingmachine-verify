#!/usr/bin/env node
// The two-key release gate (gate/README.md). Node 18 or later, no dependencies, so the same file runs in a
// GitHub Actions job and in Vercel's ignored build step.
//
//   node gate/check.mjs release <name> [commit]   a release path runs this before it publishes; the commit
//                                                 defaults to the tag named <name>
//   node gate/check.mjs records                   every record under gate/records/ is complete
//   node gate/check.mjs vercel                    Vercel's ignored build step: exit 1 builds, exit 0 skips
//   node gate/check.mjs self-test                 the rules below against fixed cases
//
// A record is gate/records/<name>.json on main. Key one is the releasing session's pre-release checks on the
// exact commit; key two is the release-gate session's review of that same commit, with the verdict "no issue".

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

const RECORDS = "gate/records";
const SHA = /^[0-9a-f]{40}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const LINK = /^https:\/\/github\.com\/Korentsvit\/[A-Za-z0-9._-]+\/\S+$/;

const filled = (v) => typeof v === "string" && v.trim() !== "";

// Everything wrong with one record, as sentences; an empty list means both keys are present.
export function problems(record, name) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return ["the record is not a JSON object"];
  const out = [];
  const k1 = record.key1 && typeof record.key1 === "object" ? record.key1 : {};
  const k2 = record.key2 && typeof record.key2 === "object" ? record.key2 : {};
  if (record.release !== name) out.push(`release is ${JSON.stringify(record.release)} but the file is named ${name}`);
  if (!filled(record.path)) out.push("path (which release path this is) is missing");
  if (!SHA.test(record.commit ?? "")) out.push("commit is not a full 40-character SHA");
  if (!filled(k1.holder)) out.push("key1.holder (the releasing session) is missing");
  if (k1.passed !== true) out.push("key1.passed is not true");
  if (!LINK.test(k1.evidence ?? "")) out.push("key1.evidence is not a link to a run or pull request in Korentsvit");
  if (!filled(k2.holder)) out.push("key2.holder (the release-gate session) is missing");
  if (filled(k1.holder) && k1.holder === k2.holder) out.push("key1 and key2 have the same holder; the gate needs two");
  if (k2.verdict !== "no issue") out.push(`key2.verdict is ${JSON.stringify(k2.verdict)}, not "no issue"`);
  if (k2.commit !== record.commit) out.push("key2.commit differs from commit: the review was of another commit");
  if (!LINK.test(k2.report ?? "")) out.push("key2.report is not a link to the review in Korentsvit");
  return out;
}

// Vercel production builds only the commit that adds a complete record naming its first parent, so production
// moves to a reviewed tree plus the record and nothing else. Previews always build.
export function vercelDecision({ env, parent, changed, records }) {
  if (env !== "production") return { build: true, why: `${env || "no VERCEL_ENV"}, not production` };
  if (!parent) return { build: false, why: "no parent commit in this checkout" };
  const added = changed.filter((f) => f.startsWith(`${RECORDS}/`) && f.endsWith(".json"));
  if (added.length === 0 || added.length !== changed.length) {
    return { build: false, why: "this commit does not only add a gate record" };
  }
  for (const f of added) {
    const record = records[f];
    if (record && problems(record, basename(f, ".json")).length === 0 && record.commit === parent) {
      return { build: true, why: `${f} carries both keys for ${parent.slice(0, 7)}` };
    }
  }
  return { build: false, why: "no complete gate record names the parent commit" };
}

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
}

function read(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    return { unreadable: String(e.message || e) };
  }
}

function stop(message) {
  console.error(`gate: ${message}`);
  process.exit(1);
}

function release(name, commit) {
  if (!NAME.test(name ?? "")) stop(`${JSON.stringify(name)} is not a release name`);
  if (!filled(commit)) {
    try {
      commit = git("rev-parse", `refs/tags/${name}^{commit}`);
    } catch {
      stop(`no commit given and no tag named ${name}`);
    }
  }
  if (!SHA.test(commit)) stop(`${JSON.stringify(commit)} is not a full commit SHA`);
  const file = join(RECORDS, `${name}.json`);
  if (!existsSync(file)) stop(`no record ${file} on main: ${name} has not passed the gate`);
  const record = read(file);
  const found = problems(record, name);
  if (record.commit && record.commit !== commit) found.push(`the record is for ${record.commit}, the release is ${commit}`);
  if (found.length) stop(`${file}:\n  ${found.join("\n  ")}`);
  console.log(`gate: ${name} at ${commit.slice(0, 7)} has both keys (${record.key1.holder}, ${record.key2.holder})`);
}

function records() {
  if (!existsSync(RECORDS)) return console.log("gate: no records yet");
  const bad = [];
  let n = 0;
  for (const f of readdirSync(RECORDS).sort()) {
    if (f === "README.md" || f === ".gitkeep") continue;
    if (!f.endsWith(".json") || !NAME.test(basename(f, ".json"))) {
      bad.push(`${f}: a record is <release name>.json`);
      continue;
    }
    n += 1;
    for (const p of problems(read(join(RECORDS, f)), basename(f, ".json"))) bad.push(`${f}: ${p}`);
  }
  if (bad.length) stop(`incomplete records:\n  ${bad.join("\n  ")}`);
  console.log(`gate: ${n} records, each with both keys`);
}

function vercel() {
  const env = process.env.VERCEL_ENV;
  let parent = "";
  let changed = [];
  const recs = {};
  if (env === "production") {
    const head = process.env.VERCEL_GIT_COMMIT_SHA || git("rev-parse", "HEAD");
    try {
      parent = git("rev-parse", `${head}^1`);
      changed = git("diff", "--name-only", parent, head).split("\n").filter(Boolean);
    } catch {
      parent = "";
    }
    for (const f of changed) if (existsSync(f)) recs[f] = read(f);
  }
  const d = vercelDecision({ env, parent, changed, records: recs });
  console.log(`gate: ${d.build ? "build" : "skip"}: ${d.why}`);
  process.exit(d.build ? 1 : 0);
}

function selfTest() {
  const a = "a".repeat(40);
  const b = "b".repeat(40);
  const good = {
    release: "atlas-M2",
    path: "atlas-dataset",
    commit: a,
    key1: { holder: "atlas-curation", passed: true, evidence: "https://github.com/Korentsvit/fundingmachine-core/actions/runs/1" },
    key2: { holder: "release-gate", verdict: "no issue", commit: a, report: "https://github.com/Korentsvit/fundingmachine-core/pull/1#issuecomment-2" },
  };
  const variant = (change) => {
    const r = JSON.parse(JSON.stringify(good));
    change(r);
    return r;
  };
  const cases = [
    ["a complete record passes", problems(good, "atlas-M2").length === 0],
    ["a file name that differs fails", problems(good, "atlas-M3").length > 0],
    ["a short commit fails", problems(variant((r) => { r.commit = "abc1234"; r.key2.commit = "abc1234"; }), "atlas-M2").length > 0],
    ["key one not passed fails", problems(variant((r) => { r.key1.passed = false; }), "atlas-M2").length > 0],
    ["one holder for both keys fails", problems(variant((r) => { r.key2.holder = "atlas-curation"; }), "atlas-M2").length > 0],
    ["a verdict other than no issue fails", problems(variant((r) => { r.key2.verdict = "issues"; }), "atlas-M2").length > 0],
    ["a review of another commit fails", problems(variant((r) => { r.key2.commit = b; }), "atlas-M2").length > 0],
    ["a missing review link fails", problems(variant((r) => { delete r.key2.report; }), "atlas-M2").length > 0],
    ["a link outside Korentsvit fails", problems(variant((r) => { r.key1.evidence = "https://example.org/run"; }), "atlas-M2").length > 0],
    ["a missing key two fails", problems(variant((r) => { delete r.key2; }), "atlas-M2").length > 0],
    ["not an object fails", problems([], "atlas-M2").length > 0],
  ];
  const f = `${RECORDS}/atlas-M2.json`;
  const vd = (args) => vercelDecision({ env: "production", parent: a, changed: [f], records: { [f]: good }, ...args }).build;
  cases.push(
    ["a preview always builds", vercelDecision({ env: "preview", parent: "", changed: [], records: {} }).build === true],
    ["production builds the commit that adds a complete record for its parent", vd({}) === true],
    ["production skips a commit that changes anything else", vd({ changed: [f, "src/index.ts"] }) === false],
    ["production skips a record for another commit", vd({ parent: b }) === false],
    ["production skips an incomplete record", vd({ records: { [f]: variant((r) => { r.key2.verdict = "pending"; }) } }) === false],
    ["production skips without a parent", vd({ parent: "" }) === false],
    ["production skips an ordinary commit", vd({ changed: ["README.md"] }) === false],
  );
  const failed = cases.filter(([, ok]) => !ok);
  for (const [label, ok] of cases) console.log(`${ok ? "ok  " : "FAIL"} ${label}`);
  if (failed.length) stop(`${failed.length} of ${cases.length} self-test cases failed`);
  console.log(`gate: self-test, ${cases.length} cases passed`);
}

const [mode, ...rest] = process.argv.slice(2);
if (mode === "release") release(rest[0], rest[1]);
else if (mode === "records") records();
else if (mode === "vercel") vercel();
else if (mode === "self-test") selfTest();
else stop("usage: node gate/check.mjs release <name> [commit] | records | vercel | self-test");
