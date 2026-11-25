#!/usr/bin/env node
// Runs the CleiMesh release binary for this platform. On first use it is
// downloaded from the GitHub release matching this package's version and
// checked against the SHA-256 shipped in this package before it ever runs.
"use strict";
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const pkg = require("../package.json");
const TARGETS = {
  "linux-x64": "x86_64-unknown-linux-musl",
  "linux-arm64": "aarch64-unknown-linux-musl",
  "darwin-x64": "x86_64-apple-darwin",
  "darwin-arm64": "aarch64-apple-darwin",
  "win32-x64": "x86_64-pc-windows-msvc.exe",
};

function fail(msg) {
  process.stderr.write(`cleimesh (npm): ${msg}\n`);
  process.exit(1);
}

const target = TARGETS[`${process.platform}-${process.arch}`];
if (!target) fail(`no release binary for ${process.platform}-${process.arch}`);
const asset = `cleimesh-${target}`;
const expected = (pkg.cleimesh && pkg.cleimesh.sha256 || {})[asset];
if (!expected) fail(`this package has no checksum for ${asset}`);

const cache = path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "cleimesh-npm", pkg.version);
const bin = path.join(cache, process.platform === "win32" ? "cleimesh.exe" : "cleimesh");

function get(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "cleimesh-npm" } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(get(new URL(res.headers.location, url).toString(), redirects - 1));
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
    }).on("error", reject);
  });
}

async function ensure() {
  if (fs.existsSync(bin)) {
    const have = crypto.createHash("sha256").update(fs.readFileSync(bin)).digest("hex");
    if (have === expected) return;
  }
  const url = `https://github.com/cleitonaugusto/cleimesh/releases/download/v${pkg.version}/${asset}`;
  process.stderr.write(`cleimesh (npm): downloading ${asset} ${pkg.version}\n`);
  const body = await get(url);
  const got = crypto.createHash("sha256").update(body).digest("hex");
  if (got !== expected) fail(`checksum mismatch for ${asset}: expected ${expected}, got ${got}; nothing was run`);
  fs.mkdirSync(cache, { recursive: true });
  const tmp = `${bin}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, body, { mode: 0o755 });
  fs.renameSync(tmp, bin);
}

ensure()
  .then(() => {
    const r = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
    if (r.error) fail(r.error.message);
    process.exit(r.status === null ? 1 : r.status);
  })
  .catch((e) => fail(e.message));
