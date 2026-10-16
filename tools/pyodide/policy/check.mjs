// Runs fm-verify in a real browser under the Content Security Policy of
// docs/HOSTED_PAGE.md, every file served from one origin, and fails on any
// policy violation, a wrong outcome, or a report frame that did not render
// with its styles. Usage, from a directory holding the page (see the
// pyodide job in .github/workflows/tests.yml), with playwright-core
// installed:
//
//   node check.mjs <repo> <style hash source> [chrome executable]
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { extname, join } from "node:path";
import { chromium } from "playwright-core";

// The policy docs/HOSTED_PAGE.md requires; tests/test_hosted_page.py checks the two agree.
const POLICY = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; " +
  "connect-src 'self' https://mempool.space https://blockstream.info; style-src 'self' STYLE_HASH; " +
  "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const [repo, styleHash, chrome] = process.argv.slice(2);
const policy = POLICY.replace("STYLE_HASH", styleHash);
const b64 = (p) => readFileSync(join(repo, p)).toString("base64");
const text = (p) => readFileSync(join(repo, p), "utf8");
const cases = [
  ["certificate pdf-compressed, with its report", "valid", "pdf-compressed"],
  ["certificate pdf-updated-attachment", "invalid", "pdf-updated-attachment"],
].map(([name, outcome, c]) => [name, outcome, { kind: "certificate", network: "regtest",
  certificate_file: b64(`fixtures/certificate/${c}/certificate.pdf`), file: b64(`fixtures/certificate/${c}/exported.txt`),
  headers: [{ kind: "chain", data: b64("fixtures/bitcoin/regtest/certificate-headers-0-5.bin") }],
  roots: [text("fixtures/rfc3161/pki/root.pem")], ...(outcome === "valid" ? { render: "html" } : {}) }]);
cases.push(["ots mainnet-840000-sparse", "valid", { kind: "ots", proof: b64("fixtures/ots/mainnet-840000-sparse/proof.ots"),
  file: b64("fixtures/ots/mainnet-840000-sparse/subject.bin"),
  headers: [{ kind: "sparse", text: text("fixtures/bitcoin/mainnet/headers-sparse.txt"), name: "fixtures" }] }]);
writeFileSync("requests.json", JSON.stringify(cases.map((c) => c[2])));

const types = { ".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm",
  ".json": "application/json", ".txt": "text/plain", ".zip": "application/zip", ".whl": "application/zip" };
const server = createServer((req, res) => {
  const name = decodeURIComponent(new URL(req.url, "http://x").pathname.slice(1)) || "index.html";
  if (name.includes("/") || name.startsWith(".")) { res.writeHead(404).end(); return; }
  try {
    const body = readFileSync(name);
    res.writeHead(200, { "Content-Type": types[extname(name)] || "application/octet-stream", "Content-Security-Policy": policy,
      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" }).end(body);
  } catch { res.writeHead(404).end(); }
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));

const browser = await chromium.launch(chrome ? { executablePath: chrome } : { channel: "chrome" });
const page = await browser.newPage();
const refused = [];
page.on("console", (m) => { if (/Content Security Policy|Refused to/i.test(m.text())) refused.push(m.text().slice(0, 200)); });
page.on("pageerror", (e) => refused.push(`page error: ${String(e).slice(0, 200)}`));
await page.goto(`http://127.0.0.1:${server.address().port}/index.html`);
await page.waitForFunction(() => window.RESULT, null, { timeout: 180000 });
const result = await page.evaluate(() => window.RESULT);
await page.waitForTimeout(500);
const frame = page.frames().find((f) => f !== page.mainFrame());
const shown = frame && await frame.evaluate(() => {
  const rect = document.querySelector("svg.bar rect");
  return { scripts: document.scripts.length, filled: !!rect && getComputedStyle(rect).fill.startsWith("rgb"),
           styled: getComputedStyle(document.querySelector(".outcome")).borderTopStyle === "solid" };
});
console.log(`${browser.version()}, policy: ${policy}`);
await browser.close();
server.close();

let failed = 0;
const fail = (what) => { failed++; console.log(`FAIL ${what}`); };
if (result.error) fail(`the page stopped: ${result.error}`);
(result.outcomes || []).forEach((o, i) => o === cases[i][1] ? console.log(`ok   ${cases[i][0]}: ${o}`) : fail(`${cases[i][0]}: ${o}, expected ${cases[i][1]}`));
[...result.violations, ...refused].forEach((v) => fail(`policy: ${v}`));
if (!shown) fail("no report frame");
else if (shown.scripts !== 0 || !shown.filled || !shown.styled) fail(`report frame: ${JSON.stringify(shown)}`);
else console.log("ok   the report frame rendered with its styles and no script");
process.exit(failed ? 1 : 0);
