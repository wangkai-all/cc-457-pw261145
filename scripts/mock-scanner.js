#!/usr/bin/env node
// External scanner adapter used by SCAN_MODE=external / SCAN_CMD.
//
// Contract expected by src/scanner.js ExternalScanner:
//   - one JSON verdict on stdout, exit 0
//   - exit 75 when the scanner is unavailable (the gateway then keeps the file
//     in quarantine and schedules a retry instead of rejecting it)
//
// Usage:
//   node scripts/mock-scanner.js <file>
//   SCAN_CMD=node SCAN_ARGS="scripts/mock-scanner.js {path}"
//
// The verdict is deterministic for a given file hash, so retrying a file after
// an outage returns the same answer - which is what makes the retry path
// meaningful. Knobs (all optional):
//   SCANNER_INFECTED_RATE   0..1, default 0.05
//   SCANNER_SUSPICIOUS_RATE 0..1, default 0.03
//   SCANNER_FAIL            set to "unavailable" to always exit 75
//   SCANNER_FAIL_FIRST      fail the first N invocations (counter kept in a
//                           sidecar file next to the scanned file's directory
//                           is NOT used; use SCANNER_FAIL for a steady outage)
//   SCANNER_DELAY_MS        simulate scan latency, default 0
//
// This is a simulation, not a virus scanner: never use it as a security
// control for real attachments.

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { nowIso } from "../src/util.js";

const SIGNATURES = [
  "EICAR-Test-File",
  "Win.Test.Mock.Dropper",
  "Trojan.Mock.Agent",
  "Script.Mock.Macro",
  "PUA.Mock.Adware",
];

function envNumber(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function fail(message, detail = null) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 75; // "scanner unavailable" per the adapter contract
  process.stdout.write(JSON.stringify({ verdict: null, error: message, detail }));
}

async function hashFile(file) {
  const h = crypto.createHash("sha256");
  await new Promise((resolve, reject) => {
    const s = fs.createReadStream(file);
    s.on("data", (d) => h.update(d));
    s.on("error", reject);
    s.on("end", resolve);
  });
  return h.digest("hex");
}

async function main() {
  const file = process.argv[2];
  if (!file) return fail("用法：mock-scanner.js <file>");
  if (process.env.SCANNER_FAIL === "unavailable") {
    return fail("模拟扫描服务不可用（SCANNER_FAIL=unavailable）");
  }

  const delay = envNumber("SCANNER_DELAY_MS", 0);
  if (delay > 0) await new Promise((r) => setTimeout(r, delay));

  let sha256;
  try {
    sha256 = await hashFile(file);
  } catch (err) {
    return fail(`无法读取待扫描文件：${err.message}`);
  }
  // Same construction as the in-process mock so both engines agree on verdicts.
  const h = crypto.createHash("sha256").update(sha256).digest();
  const roll = h.readUInt32BE(0) / 0x100000000;
  const infectedRate = clampRate(envNumber("SCANNER_INFECTED_RATE", 0.05));
  const suspiciousRate = clampRate(envNumber("SCANNER_SUSPICIOUS_RATE", 0.03));
  const infected = roll < infectedRate;
  const suspicious = !infected && h[4] / 256 < suspiciousRate;
  const severity = infected ? (h[5] % 2 ? "high" : "critical") : suspicious ? "medium" : "none";
  const signature = infected
    ? `${SIGNATURES[h[6] % SIGNATURES.length]}.${(h[7] % 90) + 10}`
    : suspicious
      ? "Heuristic.Mock.Suspicious"
      : null;

  process.stdout.write(
    JSON.stringify({
      verdict: infected ? "infected" : suspicious ? "suspicious" : "clean",
      severity,
      engine: "mock-external/1.0",
      signature,
      checkedAt: nowIso(),
      sha256,
      file: path.basename(file),
      size: (await fsp.stat(file)).size,
      simulated: true,
    }),
  );
}

function clampRate(n) {
  return Math.min(1, Math.max(0, n));
}

main().catch((err) => {
  process.stderr.write(`扫描程序异常：${err?.stack ?? err}\n`);
  process.exitCode = 75;
});
