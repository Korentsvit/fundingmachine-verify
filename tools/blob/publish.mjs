// Upload one assembled release to the public Vercel Blob store, under its prefix.
//
//     node tools/blob/publish.mjs --dir OUT --prefix verify-v0.4.0 [--dry-run]
//
// OUT is what `python tools/blob_release.py assemble` wrote: the files manifest.json lists, manifest.json and
// SHA256SUMS, and nothing else. Every file is checked against SHA256SUMS before anything is sent. Each is put at
// PREFIX/NAME, public, under exactly that name (no random suffix) and never over another file: where a file of that
// name is already there, its bytes are fetched and must be the same, or the run stops. SHA256SUMS and manifest.json
// go last, so a prefix is complete once its manifest is there. The token is read from BLOB_READ_WRITE_TOKEN by the
// client and never printed. One JSON line is printed per file, then {"manifest_url": ...}.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const TYPES = {
  ".whl": "application/zip",
  ".gz": "application/gzip",
  ".tar": "application/x-tar",
  ".json": "application/json",
  ".txt": "text/plain; charset=utf-8",
};

function arg(name) {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : undefined;
}

function type(name) {
  if (name === "SHA256SUMS" || name === "LICENSE") return "text/plain; charset=utf-8";
  const dot = name.lastIndexOf(".");
  return TYPES[dot >= 0 ? name.slice(dot) : ""] || "application/octet-stream";
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const dir = arg("--dir");
const prefix = arg("--prefix");
const dry = process.argv.includes("--dry-run");
if (!dir || !prefix || !/^verify-v\d+\.\d+\.\d+$/.test(prefix)) {
  console.error("usage: node tools/blob/publish.mjs --dir OUT --prefix verify-vX.Y.Z [--dry-run]");
  process.exit(2);
}

const sums = new Map(readFileSync(join(dir, "SHA256SUMS"), "utf8").trim().split("\n").map((l) => {
  const [digest, name] = l.split("  ");
  return [name, digest];
}));
const present = readdirSync(dir).filter((n) => n !== "SHA256SUMS").sort();
const listed = [...sums.keys()].sort();
if (JSON.stringify(present) !== JSON.stringify(listed)) {
  console.error(`the directory holds ${present.join(", ")}; SHA256SUMS lists ${listed.join(", ")}`);
  process.exit(1);
}
for (const [name, digest] of sums) {
  if (sha256(readFileSync(join(dir, name))) !== digest) {
    console.error(`${name} is not the file SHA256SUMS names`);
    process.exit(1);
  }
}
const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
if (manifest.prefix !== prefix) {
  console.error(`manifest.json is for ${manifest.prefix}, not ${prefix}`);
  process.exit(1);
}

const order = [...listed.filter((n) => n !== "manifest.json"), "SHA256SUMS", "manifest.json"];
if (dry) {
  for (const name of order) console.log(JSON.stringify({ path: `${prefix}/${name}`, dry_run: true }));
  process.exit(0);
}
if (!process.env.BLOB_READ_WRITE_TOKEN) {
  console.error("BLOB_READ_WRITE_TOKEN is not set");
  process.exit(1);
}

const { put, head } = await import("@vercel/blob");
let manifestUrl = "";
for (const name of order) {
  const bytes = readFileSync(join(dir, name));
  const pathname = `${prefix}/${name}`;
  let url;
  const existing = await head(pathname).catch(() => null);
  if (existing) {
    const served = Buffer.from(await (await fetch(existing.url)).arrayBuffer());
    if (sha256(served) !== sha256(bytes)) {
      console.error(`${pathname} is already in the store with other bytes; nothing is overwritten`);
      process.exit(1);
    }
    url = existing.url;
  } else {
    ({ url } = await put(pathname, bytes, {
      access: "public", addRandomSuffix: false, allowOverwrite: false, contentType: type(name),
    }));
  }
  console.log(JSON.stringify({ path: pathname, url, sha256: sha256(bytes), existing: Boolean(existing) }));
  if (name === "manifest.json") manifestUrl = url;
}
console.log(JSON.stringify({ manifest_url: manifestUrl }));
