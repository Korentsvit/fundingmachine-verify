// Loads Pyodide, cryptography and the fm-verify wheel from this page's own
// origin, as docs/HOSTED_PAGE.md requires, answers the requests in
// requests.json and shows the first HTML report in a sandboxed frame.
import { loadPyodide } from "./pyodide.mjs";

const violations = [];
document.addEventListener("securitypolicyviolation", (e) => violations.push(`${e.violatedDirective} ${e.blockedURI}`));
try {
  const py = await loadPyodide({ indexURL: new URL(".", import.meta.url).href });
  await py.loadPackage(["cryptography"]);
  const wheel = (await (await fetch("wheel.txt")).text()).trim();
  py.unpackArchive(await (await fetch(wheel)).arrayBuffer(), "wheel");
  const answers = [];
  for (const request of await (await fetch("requests.json")).json()) {
    py.globals.set("REQUEST", JSON.stringify(request));
    answers.push(JSON.parse(py.runPython("from fmverify.api import verify_json\nverify_json(REQUEST)")));
  }
  const html = answers.find((a) => a.html)?.html;
  if (html) document.getElementById("report").srcdoc = html;
  window.RESULT = { outcomes: answers.map((a) => a.outcome || `error: ${a.error}`), violations };
} catch (e) {
  window.RESULT = { error: String(e), violations };
}
document.getElementById("state").textContent = "done";
