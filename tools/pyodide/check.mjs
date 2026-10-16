// Runs fmverify.api.verify inside Pyodide (CPython compiled to WebAssembly),
// as a browser would, on fixture requests, and compares the outcomes with
// what the fixtures expect. Usage, from a directory where the pyodide npm
// package is installed:
//
//   node <repo>/tools/pyodide/check.mjs <repo>
import { loadPyodide } from "pyodide";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const repo = process.argv[2];
const py = await loadPyodide();
await py.loadPackage(["cryptography"]);

function copyTree(src, dst) {
  py.FS.mkdirTree(dst);
  for (const name of readdirSync(src)) {
    const s = join(src, name);
    if (statSync(s).isDirectory()) { if (name !== "__pycache__") copyTree(s, dst + "/" + name); }
    else if (name.endsWith(".py")) py.FS.writeFile(dst + "/" + name, readFileSync(s));
  }
}
copyTree(join(repo, "src", "fmverify"), "/lib/fmverify/fmverify");

const b64 = (p) => readFileSync(join(repo, p)).toString("base64");
const text = (p) => readFileSync(join(repo, p), "utf8");
const json = (p) => JSON.parse(text(p));
const requests = [
  ["ots regtest-valid", "valid", { kind: "ots", network: "regtest", proof: b64("fixtures/ots/regtest-valid/proof.ots"),
     file: b64("fixtures/ots/regtest-valid/document.txt"),
     headers: [{ kind: "chain", data: b64("fixtures/bitcoin/regtest/headers-0-11.bin") }] }],
  ["ots mainnet-840000-sparse", "valid", { kind: "ots", proof: b64("fixtures/ots/mainnet-840000-sparse/proof.ots"),
     file: b64("fixtures/ots/mainnet-840000-sparse/subject.bin"),
     headers: [{ kind: "sparse", text: text("fixtures/bitcoin/mainnet/headers-sparse.txt") }] }],
  ["rfc3161 valid-ed25519", "valid", { kind: "rfc3161", token: b64("fixtures/rfc3161/valid-ed25519/token.tsr"),
     file: b64("fixtures/rfc3161/valid-ed25519/document.txt"), roots: [text("fixtures/rfc3161/pki/root.pem")] }],
  ["rfc3161 tampered-signature", "invalid", { kind: "rfc3161", token: b64("fixtures/rfc3161/tampered-signature/token.tsr"),
     file: b64("fixtures/rfc3161/tampered-signature/document.txt"), roots: [text("fixtures/rfc3161/pki/root.pem")] }],
  ["certificate valid-with-chain", "valid", { kind: "certificate", network: "regtest",
     certificate: json("fixtures/certificate/valid-with-chain/certificate.json"),
     file: b64("fixtures/certificate/valid-with-chain/exported.txt"),
     events: json("fixtures/certificate/valid-with-chain/events.json").events,
     headers: [{ kind: "chain", data: b64("fixtures/bitcoin/regtest/certificate-headers-0-5.bin") }],
     roots: [text("fixtures/rfc3161/pki/root.pem")], render: "html" }],
  ["chain re-ordered", "invalid", { kind: "chain", events: json("fixtures/chain/re-ordered/events.json").events }],
];

py.globals.set("REQUESTS", JSON.stringify(requests.map((r) => r[2])));
const answers = JSON.parse(await py.runPythonAsync(`
import sys, json
sys.path.insert(0, "/lib/fmverify")
from fmverify import api
json.dumps([api.verify(r) for r in json.loads(REQUESTS)])
`));
const pyVersion = py.runPython("import sys; sys.version.split()[0]");
const cryptoVersion = py.runPython("import cryptography; cryptography.__version__");
let ok = true;
answers.forEach((a, i) => {
  const [name, want] = requests[i];
  const pass = a.outcome === want && (!requests[i][2].render || (a.html || "").startsWith("<!doctype html>"));
  ok = ok && pass;
  console.log(`${pass ? "ok  " : "FAIL"} ${name}: ${a.outcome ?? a.error} (expected ${want})`);
});
console.log(`Pyodide with Python ${pyVersion}, cryptography ${cryptoVersion}`);
process.exit(ok ? 0 : 1);
