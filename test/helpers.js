// Test helpers: a throwaway service, file builders and a minimal ZIP writer.

import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import zlib from "node:zlib";
import { Service } from "../src/service.js";
import { loadConfig } from "../src/config.js";
import { silentLogger } from "../src/log.js";

export async function tempRoot(prefix = "ig-test-") {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

/** Config tuned for fast tests. */
export function testConfig(root, overrides = {}) {
  return loadConfig({
    dataDir: root,
    port: 0,
    stability: { quietMs: 200, maxWaitMs: 2500, pollMs: 40 },
    limits: {
      maxFileBytes: 512 * 1024,
      maxArchiveDepth: 2,
      maxArchiveMembers: 8,
      maxArchiveUncompressedBytes: 64 * 1024,
      maxRatio: 8,
      eventDebounceMs: 0,
      sweepIntervalMs: 3600_000,
      tempGraceMs: 0,
      hashSampleBytes: 1024,
    },
    scan: {
      mode: "mock",
      mock: { latencyMs: 2, infectedRate: 0, suspiciousRate: 0, unavailable: false, failTimes: 0 },
      external: { command: "", args: [], timeoutMs: 2000 },
      retry: { maxAttempts: 4, baseMs: 60, maxMs: 240, circuitOpenMs: 400, circuitFailThreshold: 2 },
      scannerId: "mock-test/1",
      infectedSeverities: ["high", "critical"],
    },
    parse: { concurrency: 2, pollMs: 40, maxParseAttempts: 3, baseMs: 60, maxMs: 240, leaseMs: 5000 },
    ui: {
      pageSize: 50,
      refreshMs: 3600_000,
      waterlineBudgetBytes: 4 * 1024 * 1024,
      warningPct: 70,
      criticalPct: 90,
      recentEvents: 200,
    },
    ...overrides,
  });
}

export async function startService(overrides = {}) {
  const root = await tempRoot();
  const cfg = testConfig(root, overrides);
  const service = new Service(cfg, { log: silentLogger() });
  await service.init();
  await service.start();
  return { root, cfg, service };
}

export async function stopService(service) {
  await service.stop();
}

export async function writeInbox(cfg, name, data) {
  const p = path.join(cfg.watchDir, name);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, data);
  return p;
}

export function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Poll until `fn(result)` is truthy or the deadline passes. */
export async function until(fn, { timeoutMs = 8000, intervalMs = 50, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last;
  for (;;) {
    last = await fn();
    if (last) return last;
    if (Date.now() > deadline) {
      throw new Error(`等待超时：${label}（最后结果：${JSON.stringify(last)}）`);
    }
    await wait(intervalMs);
  }
}

export async function productByName(service, name, { state } = {}) {
  return until(
    async () => {
      const { rows } = service.repo.listProducts({ search: name, limit: 20 });
      const hit = rows.filter((p) => p.original_name === name);
      const match = state ? hit.find((p) => p.state === state) : hit[0];
      return match ?? null;
    },
    { label: `product ${name}${state ? ` in ${state}` : ""}` },
  );
}

/** Minimal ZIP writer with raw deflate, enough to exercise our reader. */
export function makeZip(entries, { stored = false } = {}) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const { name, data, symlink = false, encrypt = false } of entries) {
    const body = Buffer.isBuffer(data) ? data : Buffer.from(data ?? "");
    const compressed = stored ? body : zlib.deflateRawSync(body);
    const nameBuf = Buffer.from(name, "utf8");
    const flags = encrypt ? 0x1 : 0;
    const method = stored ? 0 : 8;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(Buffer.concat([local, nameBuf, compressed]));

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(flags, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt32LE(compressed.length, 20);
    cd.writeUInt32LE(body.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    const mode = symlink ? 0o120777 : 0o100644;
    cd.writeUInt32LE((mode << 16) >>> 0, 38);
    cd.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cd, nameBuf]));

    offset += 30 + nameBuf.length + compressed.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cdBuf, eocd]);
}

/** TAR writer (ustar) for nested-archive tests. */
export function makeTar(entries) {
  const blocks = [];
  for (const { name, data } of entries) {
    const body = Buffer.isBuffer(data) ? data : Buffer.from(data ?? "");
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, "latin1");
    header.write("0000644\0", 100, 8, "latin1");
    header.write("0000000\0", 108, 8, "latin1");
    header.write("0000000\0", 116, 8, "latin1");
    header.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124, 12, "latin1");
    header.write("00000000000\0", 136, 12, "latin1");
    header.write("        ", 148, 8, "latin1");
    header.write("0", 156, 1, "latin1");
    header.write("ustar\0", 257, 6, "latin1");
    header.write("00", 263, 2, "latin1");
    let sum = 0;
    for (const b of header) sum += b;
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "latin1");
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** Force the next scanner call(s) to fail as if the service were down. */
export function forceScannerOutage(service, callCount = 999) {
  const engine = service.engine;
  const original = engine.scan.bind(engine);
  let remaining = callCount;
  engine.scan = async (input) => {
    if (remaining-- > 0) {
      const err = new Error("测试：扫描服务不可用");
      err.name = "ScannerUnavailableError";
      err.code = "scanner_unavailable";
      err.retryable = true;
      throw err;
    }
    return original(input);
  };
  return () => {
    engine.scan = original;
  };
}
