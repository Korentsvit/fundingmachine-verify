// Runs the anchors verifier page (page/index.html, built by tools/build_page.py) in a real browser, served with
// the Content Security Policy the build wrote, and answers its requests to GitHub, the Ledger's record and the two
// explorers from local copies: a checkout of the public mirror at COMMIT and a headers file. Fails on a policy
// violation, a wrong outcome, or a page that does not say what it relied on. With playwright-core installed:
//
//   node check.mjs SITE MIRROR_CHECKOUT COMMIT HEADERS_FILE [chrome executable]
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { chromium } from "playwright-core";

const [site, mirror, commit, headersFile, chrome] = process.argv.slice(2);
const policy = readFileSync(join(site, "csp.txt"), "utf8").trim();
const types = { ".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm",
  ".json": "application/json", ".txt": "text/plain", ".zip": "application/zip", ".whl": "application/zip", ".pem": "text/plain" };
const server = createServer((req, res) => {
  const name = decodeURIComponent(new URL(req.url, "http://x").pathname.slice(1)) || "index.html";
  if (name.includes("/") || name.startsWith(".") || !existsSync(join(site, name))) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "Content-Type": types[extname(name)] || "application/octet-stream", "Content-Security-Policy": policy,
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" }).end(readFileSync(join(site, name)));
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const origin = `http://127.0.0.1:${server.address().port}`;

// The local copies.
const anchorsDir = join(mirror, "anchors");
const bySha = new Map();
const walk = (d) => { for (const n of readdirSync(d)) { const p = join(d, n); statSync(p).isDirectory() ? walk(p) : bySha.set(createHash("sha256").update(readFileSync(p)).digest("hex"), p); } };
walk(anchorsDir);
const heights = new Map();
for (const line of readFileSync(headersFile, "utf8").split("\n")) {
  const c = line.match(/^# (\d+): block ([0-9a-f]{64})/);
  const h = line.match(/^(\d+) ([0-9a-f]{160})$/);
  if (c) heights.set(c[1], { hash: c[2] });
  if (h) heights.get(h[1]).header = h[2];
}
const cors = { "Access-Control-Allow-Origin": "*" };

async function run(name, { query = `?commit=${commit}`, alter = {}, expect, viewport }) {
  const browser = await chromium.launch(chrome ? { executablePath: chrome } : { channel: "chrome" });
  const page = await browser.newPage(viewport ? { viewport } : {});
  const refused = [];
  const asked = new Set();
  page.on("console", (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) refused.push(m.text().slice(0, 200)); });
  page.on("pageerror", (e) => refused.push(`page error: ${String(e).slice(0, 200)}`));
  await page.route(/^https:\/\/raw\.githubusercontent\.com\//, (route) => {
    const u = new URL(route.request().url());
    asked.add("github");
    const m = u.pathname.match(/^\/Korentsvit\/fundingmachine-anchors\/([0-9a-f]{40})\/anchors\/(.+)$/);
    const file = m && m[1] === commit ? join(anchorsDir, ...m[2].split("/")) : null;
    if (!file || m[2].includes("..") || !existsSync(file)) return route.fulfill({ status: 404, headers: cors, body: "404: Not Found" });
    return route.fulfill({ status: 200, headers: { ...cors, "Content-Type": "text/plain; charset=utf-8" }, body: readFileSync(file) });
  });
  await page.route(/^https:\/\/fundingmachine-ledger\.vercel\.app\/api\/anchors/, (route) => {
    const u = new URL(route.request().url());
    asked.add("record");
    const path = u.searchParams.get("path");
    if (alter.recordMissing && path === alter.recordMissing) return route.fulfill({ status: 404, headers: cors, body: "{}" });
    const file = bySha.get(u.searchParams.get("sha256") || "");
    if (!file || file !== join(anchorsDir, ...path.split("/"))) return route.fulfill({ status: 404, headers: cors, body: "{}" });
    return route.fulfill({ status: 200, headers: cors, body: readFileSync(file) });
  });
  await page.route(/^https:\/\/(mempool\.space|blockstream\.info)\/api\//, (route) => {
    const u = new URL(route.request().url());
    asked.add(u.host);
    let m = u.pathname.match(/^\/api\/block-height\/(\d+)$/);
    if (m && heights.has(m[1])) return route.fulfill({ status: 200, headers: cors, body: heights.get(m[1]).hash });
    m = u.pathname.match(/^\/api\/block\/([0-9a-f]{64})\/header$/);
    const entry = m && [...heights.entries()].find(([, v]) => v.hash === m[1]);
    if (!entry) return route.fulfill({ status: 404, headers: cors, body: "Block not found" });
    let header = entry[1].header;
    // Another real header, with its proof of work, in place of this one: a disagreement, not a bad header.
    if (alter.headerHost === u.host && alter.headerHeight === entry[0]) header = [...heights.values()].find((v) => v.hash !== m[1]).header;
    return route.fulfill({ status: 200, headers: cors, body: header });
  });
  await page.goto(`${origin}/index.html${query}`);
  await page.waitForFunction(() => !document.getElementById("go").disabled, null, { timeout: 180000 });
  await page.click("#go");
  await page.waitForFunction(() => window.VERDICT, null, { timeout: 300000 });
  const verdict = await page.evaluate(() => window.VERDICT);
  const shown = await page.evaluate(() => ({
    text: document.getElementById("result").innerText,
    headerRows: document.querySelectorAll("#result table")[0] ? document.querySelectorAll("#result table")[0].querySelectorAll("tbody tr").length : 0,
    wide: document.documentElement.scrollWidth,
    widest: [...document.querySelectorAll("body *")].filter((e) => e.getBoundingClientRect().right > window.innerWidth + 1)
      .filter((e) => !e.closest(".scroll")).slice(0, 3).map((e) => `${e.tagName.toLowerCase()}.${e.className}: ${e.textContent.slice(0, 40)}`),
    frame: !!document.querySelector("#result iframe[sandbox='']"),
  }));
  await browser.close();
  const problems = [...refused.map((r) => `policy: ${r}`), ...expect(verdict, shown, asked)];
  console.log(problems.length ? `FAIL ${name}\n  ${problems.join("\n  ")}` : `ok   ${name}`);
  return problems.length;
}

const anchors = (v) => (v.checks || []).filter((c) => c.id.startsWith("anchor_set.") && c.data && c.data.verdict);
const confirmed = (v) => anchors(v).filter((c) => (c.data.verdict.checks || []).some((x) => x.id === "ledger_anchor.ots" && x.status === "pass"));
let failed = 0;
failed += await run("the mirror at the commit, both explorers, the record compared", {
  expect: (v, s, asked) => [
    ...(v.outcome === "valid" ? [] : [`outcome ${v.outcome || v.error}, expected valid`]),
    ...(s.text.includes("VALID") && s.text.includes("Relied on") && s.text.includes("Does not establish") ? [] : ["the outcome, Relied on or Does not establish is not shown"]),
    ...(s.text.includes("held the same bytes for all") ? [] : ["the record comparison is not stated"]),
    ...(s.headerRows === heights.size ? [] : [`${s.headerRows} header rows shown, ${heights.size} expected`]),
    ...(s.frame ? [] : ["no sandboxed report frame"]),
    ...(["github", "record", "mempool.space", "blockstream.info"].every((h) => asked.has(h)) ? [] : [`asked only ${[...asked]}`]),
    ...(console.log(`     ${anchors(v).length} anchors, ${confirmed(v).length} confirmed in Bitcoin, ${s.headerRows} headers`) || []),
  ],
});
failed += await run("one explorer gives another block's header: the verifier finds the disagreement", {
  alter: { headerHost: "blockstream.info", headerHeight: [...heights.keys()][0] },
  expect: (v) => (v.outcome === "invalid" ? [] : [`outcome ${v.outcome || v.error}, expected invalid`]),
});
failed += await run("the record lacks one file: the page says the sources differ", {
  alter: { recordMissing: "index.jsonl" },
  expect: (v, s) => [...(s.text.includes("The two sources differ") && s.text.includes("index.jsonl") ? [] : ["the difference is not shown"])],
});
failed += await run("a commit the mirror does not have: could not check, no verdict", {
  query: `?commit=${"0".repeat(40)}`,
  expect: (v, s) => [...(v.error && s.text.includes("Could not check") ? [] : ["no 'Could not check'"])],
});
failed += await run("on a 390-pixel screen, no sideways scrolling", {
  viewport: { width: 390, height: 844 },
  expect: (v, s) => [...(s.wide <= 390 ? [] : [`the page is ${s.wide} pixels wide: ${s.widest.join("; ")}`]), ...(v.outcome === "valid" ? [] : ["not valid"])],
});
server.close();
process.exit(failed ? 1 : 0);
