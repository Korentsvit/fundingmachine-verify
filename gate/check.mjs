#!/usr/bin/env node
// The two-key release gate (gate/README.md). Node 18 or later, no dependencies, so the same file runs in a
// GitHub Actions job and in Vercel's ignored build step.
//
//   node gate/check.mjs release <name> [commit]   a release path runs this before it publishes; the commit
//                                                 defaults to the tag named <name>
//   node gate/check.mjs records                   every record under gate/records/ is complete
//   node gate/check.mjs vercel                    Vercel's ignored build step: exit 1 builds, exit 0 skips
//   node gate/check.mjs workflows                 every job under .github/workflows/ that publishes runs only
//                                                 after a job that calls release-gate.yml
//   node gate/check.mjs self-test                 the rules below against fixed cases
//
// A record is gate/records/<name>.json on main. Key one is the releasing session's pre-release checks on the
// exact commit; key two is the release-gate session's review of that same commit, with the verdict "no issue".

import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

const RECORDS = "gate/records";
const WORKFLOWS = ".github/workflows";
const UNGATED = "gate/ungated.json";
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
// moves to a reviewed tree plus the record and nothing else. Preview and development builds always build; an
// unknown or missing VERCEL_ENV is treated as production, so the gate fails closed.
export function vercelDecision({ env, parent, changed, records }) {
  if (env === "preview" || env === "development") return { build: true, why: `${env}, not production` };
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

// What a job does that publishes, by the commands and actions it runs. Comments are not read.
const PUBLISH = [
  ["GitHub release", /\bgh\s+release\s+(create|upload|edit)\b|softprops\/action-gh-release|ncipollo\/release-action|\bgh\s+api\b[^\n]*\/releases\b[^\n]*(\s-X\s*(POST|PATCH)\b|--method\s+(POST|PATCH)\b|\s-[fF]\s)/],
  ["Vercel deploy", /\bvercel["']?\s+(deploy\b|--prod\b)|amondnet\/vercel-action|\bsecrets\.VERCEL_[A-Z0-9_]*TOKEN\b/],
  ["Blob store", /\bBLOB_READ_WRITE_TOKEN\b|@vercel\/blob\b/],
  ["tag push", /\bgit\s+push\b[^\n]*(--tags\b|refs\/tags\/)/],
  ["package registry", /\bnpm\s+publish\b|\btwine\s+upload\b|pypa\/gh-action-pypi-publish/],
];
const GATE_CALL = /(^|\/)\.github\/workflows\/release-gate\.ya?ml(@\S+)?$/;
const indentOf = (l) => l.match(/^ */)[0].length;
const blank = (l) => /^\s*(#.*)?$/.test(l);
const unquote = (v) => v.trim().replace(/^(["'])(.*)\1$/, "$2");

// The jobs of one workflow file: id, needs, uses, if and the text it runs. Reads the block YAML GitHub workflows
// are written in (no anchors, no flow mappings), which is enough to see which job depends on which.
export function workflowJobs(text) {
  const lines = text.replace(/\t/g, "  ").split(/\r?\n/);
  const start = lines.findIndex((l) => /^jobs:\s*(#.*)?$/.test(l));
  if (start < 0) return [];
  const raw = [];
  let indent = -1;
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (blank(l)) continue;
    const ind = indentOf(l);
    if (ind === 0) break;
    if (indent < 0) indent = ind;
    if (ind === indent) raw.push({ id: l.trim().replace(/:.*$/, "").replace(/^["']|["']$/g, ""), lines: [] });
    else if (raw.length) raw[raw.length - 1].lines.push(l);
  }
  return raw.map(({ id, lines: body }) => {
    const job = { id, needs: [], uses: "", if: "", body: "" };
    const content = body.filter((l) => !blank(l));
    const keyIndent = content.length ? Math.min(...content.map(indentOf)) : 0;
    for (let i = 0; i < body.length; i++) {
      const l = body[i];
      if (blank(l) || indentOf(l) !== keyIndent) continue;
      const m = l.trim().match(/^(needs|uses|if):\s*(.*)$/);
      if (!m) continue;
      let value = m[2].replace(/\s+#.*$/, "");
      const nested = [];
      for (let k = i + 1; k < body.length && (blank(body[k]) || indentOf(body[k]) > keyIndent); k++) {
        if (!blank(body[k])) nested.push(body[k].trim());
      }
      if (m[1] === "needs") {
        if (value.startsWith("[")) job.needs = value.replace(/^\[|\]$/g, "").split(",").map(unquote).filter(Boolean);
        else if (value !== "") job.needs = [unquote(value)];
        else job.needs = nested.filter((n) => n.startsWith("- ")).map((n) => unquote(n.slice(2)));
      } else if (m[1] === "uses") job.uses = unquote(value);
      else job.if = /^[|>][-+]?$/.test(value) ? nested.join(" ") : unquote(value);
    }
    job.body = body
      .filter((l) => !blank(l))
      .map((l) => l.replace(/(^|\s)#\s.*$/, ""))
      .join("\n");
    return job;
  });
}

// A workflow named in gate/ungated.json: a file name, where * stands for any run of characters but a slash.
export function listed(pattern, file) {
  const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`);
  return re.test(file);
}

// Every job that publishes, with the gate job it waits for, and what is wrong if it can publish without the keys.
export function gateFindings(jobs) {
  const byId = new Map(jobs.map((j) => [j.id, j]));
  const gates = new Set(jobs.filter((j) => GATE_CALL.test(j.uses)).map((j) => j.id));
  const above = (id, seen = new Set()) => {
    for (const n of byId.get(id)?.needs ?? []) {
      if (!seen.has(n)) {
        seen.add(n);
        above(n, seen);
      }
    }
    return seen;
  };
  const out = [];
  for (const j of jobs) {
    const kinds = PUBLISH.filter(([, re]) => re.test(j.body)).map(([k]) => k);
    if (kinds.length === 0 || gates.has(j.id)) continue;
    const before = above(j.id);
    const gate = [...before].find((a) => gates.has(a)) ?? "";
    let problem = "";
    if (!gate) problem = "publishes without the gate: no job it needs calls release-gate.yml";
    else {
      const ok = new RegExp(`needs\\.${gate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.result\\s*==\\s*'success'`);
      // A status function lets a job run after a failed job it needs, unless !failure() or the gate's result is
      // tested. The gate skipped (not failed) still lets the job run: what it then does is for the review to see.
      const runsAfterFailure = (c) =>
        /\b(always|failure|cancelled)\s*\(/.test(c) &&
        !ok.test(c) &&
        (/\bfailure\s*\(/.test(c.replace(/!\s*failure\s*\(\s*\)/g, "")) || !/!\s*failure\s*\(\s*\)/.test(c));
      const loose = [j.id, ...before].map((id) => byId.get(id)).find((x) => x && !gates.has(x.id) && runsAfterFailure(x.if));
      if (loose) problem = `job ${loose.id} runs on "if: ${loose.if}", so it can run when ${gate} fails`;
    }
    out.push({ job: j.id, kinds, gate, problem });
  }
  return out;
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
  // The release name and commit the gate passed, for the job that publishes: the Blob prefix is <release>/.
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `release=${name}\ncommit=${commit}\n`);
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
  if (env !== "preview" && env !== "development") {
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

function workflows() {
  if (!existsSync(WORKFLOWS)) return console.log("gate: no workflows");
  const known = existsSync(UNGATED) ? read(UNGATED) : [];
  if (!Array.isArray(known) || known.some((k) => !filled(k?.workflow) || !filled(k?.job) || !filled(k?.why))) {
    stop(`${UNGATED} is a JSON list of {"workflow", "job", "why"}`);
  }
  const used = new Set();
  const bad = [];
  let gated = 0;
  let ungated = 0;
  for (const f of readdirSync(WORKFLOWS).filter((x) => /\.ya?ml$/.test(x)).sort()) {
    for (const r of gateFindings(workflowJobs(readFileSync(join(WORKFLOWS, f), "utf8")))) {
      const where = `${f} job ${r.job} (${r.kinds.join(", ")})`;
      if (!r.problem) {
        gated += 1;
        console.log(`gated    ${where}, after ${r.gate}`);
        continue;
      }
      const k = known.findIndex((x) => listed(x.workflow, f) && x.job === r.job);
      if (k >= 0 && r.gate === "") {
        used.add(k);
        ungated += 1;
        console.log(`ungated  ${where}: listed in ${UNGATED}: ${known[k].why}`);
      } else bad.push(`${where}: ${r.problem}`);
    }
  }
  known.forEach((k, i) => {
    if (!used.has(i)) bad.push(`${UNGATED} lists ${k.workflow} job ${k.job}, which no longer publishes without the gate`);
  });
  if (bad.length) stop(`publishing outside the gate:\n  ${bad.join("\n  ")}`);
  console.log(`gate: ${gated} publishing jobs gated, ${ungated} ungated as ${UNGATED} lists`);
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
    ["a missing VERCEL_ENV is treated as production", vercelDecision({ env: undefined, parent: a, changed: ["README.md"], records: {} }).build === false],
    ["production builds the commit that adds a complete record for its parent", vd({}) === true],
    ["production skips a commit that changes anything else", vd({ changed: [f, "src/index.ts"] }) === false],
    ["production skips a record for another commit", vd({ parent: b }) === false],
    ["production skips an incomplete record", vd({ records: { [f]: variant((r) => { r.key2.verdict = "pending"; }) } }) === false],
    ["production skips without a parent", vd({ parent: "" }) === false],
    ["production skips an ordinary commit", vd({ changed: ["README.md"] }) === false],
  );
  const wf = (jobs) => gateFindings(workflowJobs(`on: push\njobs:\n${jobs}`));
  const gateJob = "  gate:\n    uses: ./.github/workflows/release-gate.yml\n    with:\n      release: x\n";
  const pub = (head) => `  release:\n${head}    runs-on: ubuntu-24.04\n    steps:\n      - run: gh release create "$TAG" out/*\n`;
  cases.push(
    ["a publishing job that needs the gate passes", wf(gateJob + pub("    needs: gate\n")).every((r) => r.gate === "gate" && !r.problem)],
    ["a publishing job without the gate fails", wf(pub("")).some((r) => r.problem)],
    ["needs as a list reaches the gate", wf(gateJob + pub("    needs: [check, gate]\n")).every((r) => !r.problem)],
    ["needs as a block list reaches the gate", wf(gateJob + pub("    needs:\n      - check\n      - gate\n")).every((r) => !r.problem)],
    ["a gate two jobs up still counts", wf(gateJob + "  build:\n    needs: gate\n    runs-on: x\n" + pub("    needs: build\n")).every((r) => !r.problem)],
    ["if: always() lets a job publish when the gate fails", wf(gateJob + pub("    needs: gate\n    if: always()\n")).some((r) => r.problem)],
    ["always() with the gate's result tested passes", wf(gateJob + pub("    needs: gate\n    if: always() && needs.gate.result == 'success'\n")).every((r) => !r.problem)],
    ["!cancelled() alone lets a job publish when the gate fails", wf(gateJob + pub("    needs: gate\n    if: ${{ !cancelled() }}\n")).some((r) => r.problem)],
    ["!failure() && !cancelled() passes", wf(gateJob + pub("    needs: gate\n    if: ${{ !failure() && !cancelled() }}\n")).every((r) => !r.problem)],
    ["a Blob upload without the gate fails", wf("  blob:\n    runs-on: x\n    env:\n      BLOB_READ_WRITE_TOKEN: ${{ secrets.T }}\n    steps:\n      - run: node publish.mjs\n").some((r) => r.problem)],
    ["a vercel deploy without the gate fails", wf("  deploy:\n    runs-on: x\n    steps:\n      - run: npx vercel deploy --prod\n").some((r) => r.problem)],
    ["a quoted vercel binary is still a deploy", wf("  deploy:\n    runs-on: x\n    steps:\n      - run: \"$D/.bin/vercel\" deploy site --prod\n").some((r) => r.problem)],
    ["an ungated listing with * covers a family of workflows", listed("corpus-shard*.yml", "corpus-shard-r7.yml") && listed("corpus-shard*.yml", "corpus-shard.yml")],
    ["an ungated listing matches the whole name only", !listed("corpus-shard*.yml", "corpus-shard.yml.bak") && !listed("a.yml", "axyml")],
    ["a malformed needs list does not stop the reader", (() => { try { return gateFindings(workflowJobs("jobs:\n  a:\n    needs: [b\n")).length === 0; } catch { return false; } })()],
    ["a command named only in a comment is not publishing", wf("  check:\n    runs-on: x\n    steps:\n      # gh release create is the release job's\n      - run: gh release view x  # not gh release create\n").length === 0],
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
else if (mode === "workflows") workflows();
else if (mode === "self-test") selfTest();
else stop("usage: node gate/check.mjs release <name> [commit] | records | vercel | workflows | self-test");
