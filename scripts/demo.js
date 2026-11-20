#!/usr/bin/env node
// One-command demo: seeds a representative set of attachments into an isolated
// data directory, runs the real service against it and serves the dashboard.
//
//   npm run demo                 # seed + serve on http://127.0.0.1:4173
//   npm run demo -- --seed-only  # only create the dirs and drop the files
//   npm run demo -- --reset      # wipe ./data-demo first (demo dir only)
//
// Every fixture below maps to one of the behaviours the gateway promises:
// temp files, same-name replacement, nested archives, oversized files,
// simulated virus verdicts, duplicate content and normal parsing.
//
// The demo NEVER runs against ./data, so it can't disturb a real deployment:
// the data dir is always <cwd>/data-demo unless DEMO_DATA_DIR is set.

import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

import { loadConfig } from "../src/config.js";
import { createLogger } from "../src/log.js";
import { Service } from "../src/service.js";
import { createServer } from "../src/http.js";
import { makeZip } from "./lib/zip.js";
import { formatBytes } from "../src/util.js";

const args = new Set(process.argv.slice(2));
const seedOnly = args.has("--seed-only");
const reset = args.has("--reset");

const dataDir = path.resolve(process.env.DEMO_DATA_DIR ?? path.join(process.cwd(), "data-demo"));
if (reset) {
  // Guard: only ever remove a directory that is clearly the demo's.
  if (path.basename(dataDir) !== "data-demo") {
    console.error(`拒绝删除 ${dataDir}：--reset 只允许用于 data-demo 目录`);
    process.exit(1);
  }
  await fs.rm(dataDir, { recursive: true, force: true });
  console.log(`已清空演示目录 ${dataDir}`);
}

const log = createLogger({ level: process.env.LOG_LEVEL ?? "warn" });
const cfg = loadConfig({
  dataDir,
  port: Number(process.env.PORT ?? 4173),
  // Demo-sized limits so "oversized" is a few MB, not 64 MB.
  limits: { maxFileBytes: 2 * 1024 * 1024, maxArchiveDepth: 3 },
  // The demo wants a few seconds, not minutes, for retries to settle.
  scan: { retry: { baseMs: 300, maxMs: 3000 } },
  stability: { quietMs: 400 },
  // A demo-sized waterline budget so the meter actually moves.
  ui: { waterlineBudgetBytes: 8 * 1024 * 1024 },
});

const service = new Service(cfg, { log });
await service.init();
// --seed-only leaves the files for a separately started `npm start`; anything
// else starts the real watcher and pipeline right away.
if (!seedOnly) await service.start();

const written = [];
async function drop(name, data, { delayMs = 0 } = {}) {
  const p = path.join(cfg.watchDir, name);
  await fs.mkdir(path.dirname(p), { recursive: true });
  if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
  await fs.writeFile(p, data);
  written.push(name);
}

// --- fixtures ---------------------------------------------------------------

// 1. Normal attachments that should reach the parse queue.
await drop(
  "客户名单-2026Q4.txt",
  [
    "客户编号,客户名称,联系人",
    "C-1001,远山贸易,王敏",
    "C-1002,海纳物流,李强",
    "C-1003,星河科技,周洁",
  ].join("\n") + "\n",
);
await drop(
  "orders-2026-11.csv",
  "order_id,customer,amount,currency\n" +
    "SO-8801,C-1001,12800.00,CNY\n" +
    "SO-8802,C-1002,4200.50,CNY\n" +
    "SO-8803,C-1003,980.00,CNY\n",
);
await drop(
  "contract-meta.json",
  JSON.stringify(
    {
      contract: "HT-2026-0912",
      parties: ["远山贸易", "星河科技"],
      signedAt: "2026-11-02",
      clauses: 14,
      attachments: 3,
    },
    null,
    2,
  ),
);

// 2. Temp file: the name says "still uploading", so it is dismissed, not
//    parsed. (The demo's temp grace window is the default 30 s.)
await drop("付款单.xlsx.part", "partial upload bytes");

// 3. Oversized file: exceeds the demo's 2 MB per-file limit. The hash is still
//    recorded so the file can be identified later.
await drop("影像归档-扫描件.bin", crypto.randomBytes(2 * 1024 * 1024 + 4096));

// 4. Nested archive, depth 2 (within the cap): accepted and queued for the
//    archive-manifest parser.
await drop(
  "项目资料.zip",
  makeZip([
    {
      name: "inner/materials.zip",
      data: makeZip([{ name: "readme.txt", data: "嵌套压缩包中的说明文件\n" }]),
    },
    { name: "manifest.txt", data: "项目资料清单\n" },
  ]),
);

// 5. Nested too deep (5 levels, cap is 3) -> quarantine.
let deep = makeZip([{ name: "leaf.txt", data: "bottom\n" }]);
for (let i = 0; i < 5; i++) deep = makeZip([{ name: `level-${i}.zip`, data: deep }]);
await drop("层层嵌套.zip", deep);

// 6. Path traversal in a member name -> quarantine, never extracted.
await drop("恶意路径.zip", makeZip([{ name: "../../etc/escape.txt", data: "x" }]));

// 7. Duplicate content: the second delivery hashes the same and is parked as
//    duplicate_content instead of being parsed twice. Wait for the first one to
//    be admitted so the dedupe check has something to find.
const dupBody = "同一份附件被重复投递\n";
await drop("重复投递-1.txt", dupBody);
await waitForProduct("重复投递-1.txt", ["queued", "quarantined"]);
await drop("重复投递-2.txt", dupBody);

// 8. Same-name replacement: wait until the first version has been picked up,
//    then overwrite it with a different payload. The old row keeps its own
//    state; the new file gets a new row and a "replaced" event.
await drop("replaced.csv", "id,value\n1,old\n");
await waitForProduct("replaced.csv", ["queued", "quarantined"]);
await drop("replaced.csv", "id,value\n1,new-version\n2,another-row\n");

// 9. Simulated virus: find content the deterministic mock classifies as
//    infected so the demo is repeatable. The mock's rule is
//    sha256(sha256(content))[0..4]/2^32 < infectedRate.
const infectedRate = cfg.scan.mock.infectedRate;
const infectedBody = findContentForRoll(infectedRate, "demo-virus-sample");
if (infectedBody) {
  await drop("发票扫描件.pdf", infectedBody);
} else {
  console.warn("未能构造出会被判定为感染的样例（请降低 SCAN_MOCK_INFECTED_RATE）");
}

console.log(`\n已投递 ${written.length} 个演示文件到 ${cfg.watchDir}`);
if (seedOnly) {
  console.log("（--seed-only：未启动服务；用 INBOX_DATA_DIR=data-demo npm start 处理这些文件）");
  await service.stop();
  process.exit(0);
}

// --- wait for the pipeline to settle ---------------------------------------

const deadline = Date.now() + 25_000;
let settled = false;
while (Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 500));
  const rows = service.repo.listProducts({ limit: 500 }).rows;
  const busy = rows.some(
    (p) => p.state === "checking" || (p.state === "queued" && p.parse_status !== "ready"),
  );
  if (!busy && rows.length >= written.length - 2) {
    settled = true;
    break;
  }
}
if (!settled) console.log("提示：部分文件仍在处理，面板会继续更新。");

// --- waterline demo ---------------------------------------------------------
// Pause intake and leave a batch in the inbox so the meter shows a real level.
// The operator can press "暂停接收" on the page to resume and watch it drain.
if (!args.has("--no-waterline")) {
  service.setMaintenance(true);
  for (let i = 1; i <= 6; i++) {
    await drop(`待处理影像-${String(i).padStart(2, "0")}.bin`, crypto.randomBytes(1024 * 1024));
  }
  await service.sampleWaterline();
  const w = service.metrics.waterline;
  const pct = ((w.bytes / (w.budgetBytes || 1)) * 100).toFixed(0);
  console.log(
    `\n已在维护模式下投放 6 个待处理文件；目录水位 ${pct}%（预算 ${formatBytes(
      w.budgetBytes,
    )}）。在页面上点「暂停接收」即可继续处理。`,
  );
}

// --- serve ------------------------------------------------------------------

const server = createServer(service);
await new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve));
const url = `http://${cfg.host}:${server.address().port}`;

printSummary(service);
console.log(`\n仪表盘：${url}   （Ctrl-C 停止）\n`);

let stopping = false;
async function shutdown() {
  if (stopping) return;
  stopping = true;
  await new Promise((r) => server.close(r));
  await service.stop();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function printSummary(svc) {
  const rows = svc.repo.listProducts({ limit: 500, sort: "oldest" }).rows;
  const width = Math.max(...rows.map((p) => displayWidth(p.original_name)), 12);
  console.log("\n处理结果：");
  console.log(
    `${"文件".padEnd(width)}  ${"状态".padEnd(11)} ${"原因".padEnd(18)} 解析`,
  );
  for (const p of rows) {
    console.log(
      `${p.original_name.padEnd(width)}  ${String(p.state).padEnd(11)} ${String(
        p.reason_code ?? "-",
      ).padEnd(18)} ${p.parse_status ?? "-"}  ${formatBytes(p.size_bytes)}`,
    );
  }
  const counts = svc.repo.countsByState();
  const summary = Object.entries(counts)
    .map(([k, v]) => `${k}=${v}`)
    .join("  ");
  console.log(`\n状态汇总：${summary || "(空)"}`);
  console.log(`解析报告目录：${cfg.outDir}`);
}

function displayWidth(s) {
  // Good enough for the demo table: CJK counts as 2 columns.
  let w = 0;
  for (const ch of String(s)) w += /[　-鿿＀-￯]/.test(ch) ? 2 : 1;
  return w;
}

/** Wait until the first product for `name` reaches one of `states`. */
async function waitForProduct(name, states, timeoutMs = 20_000) {
  if (seedOnly) {
    // Nothing is consuming the inbox in this mode; a short pause is enough to
    // keep the write order sane (e.g. replacement needs the old file first).
    await new Promise((r) => setTimeout(r, 300));
    return;
  }
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { rows } = service.repo.listProducts({ search: name, limit: 20 });
    if (rows.some((p) => p.original_name === name && states.includes(p.state))) return;
    await new Promise((r) => setTimeout(r, 150));
  }
  console.warn(`等待 ${name} 进入 ${states.join("/")} 超时，继续投递后续样例`);
}

/** Brute-force a payload whose mock verdict lands in the requested bucket. */
function findContentForRoll(rate, label) {
  for (let i = 0; i < 5000; i++) {
    const body = Buffer.from(`${label} #${i}\n`);
    const inner = crypto.createHash("sha256").update(body).digest("hex");
    const h = crypto.createHash("sha256").update(inner).digest();
    if (h.readUInt32BE(0) / 0x100000000 < rate) return body;
  }
  return null;
}
