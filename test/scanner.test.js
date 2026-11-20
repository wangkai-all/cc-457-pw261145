// Scanner service: deterministic mock verdicts, the availability gate and the
// external command adapter.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import {
  MockScanner,
  ExternalScanner,
  ScannerService,
  ScannerUnavailableError,
  buildEngine,
} from "../src/scanner.js";
import { testConfig, tempRoot } from "./helpers.js";

function repoStub() {
  let state = { available: 1, consecutive_failures: 0, opened_at: null, last_error: null };
  return {
    getScannerState: () => state,
    setScannerState: (s) => {
      state = {
        available: s.available ? 1 : 0,
        consecutive_failures: s.consecutiveFailures,
        opened_at: s.openedAt,
        last_error: s.lastError,
      };
    },
  };
}

function cfgFor(scannerOverrides = {}) {
  const cfg = testConfig("/tmp/ig-scanner-cfg");
  return {
    ...cfg,
    scan: {
      ...cfg.scan,
      retry: { maxAttempts: 3, baseMs: 10, maxMs: 50, circuitOpenMs: 120, circuitFailThreshold: 2 },
      ...scannerOverrides,
    },
  };
}

test("MockScanner：同一内容判定稳定，感染率 0 时永远干净", async () => {
  const s = new MockScanner({ infectedRate: 0, suspiciousRate: 0, latencyMs: 0 });
  const a = await s.scan({ sha256: "a".repeat(64), name: "x", size: 1 });
  const b = await s.scan({ sha256: "a".repeat(64), name: "x", size: 1 });
  assert.equal(a.verdict, "clean");
  assert.equal(a.verdict, b.verdict);
  assert.equal(a.signature, b.signature);
});

test("MockScanner：感染率 1 时一律判定感染", async () => {
  const s = new MockScanner({ infectedRate: 1, suspiciousRate: 0, latencyMs: 0 });
  const v = await s.scan({ sha256: "b".repeat(64), name: "x", size: 1 });
  assert.equal(v.verdict, "infected");
  assert.ok(v.signature);
  assert.ok(["high", "critical"].includes(v.severity));
});

test("ScannerService：连续失败触发熔断，冷却后半开探测恢复", async () => {
  const cfg = cfgFor();
  const engine = new MockScanner({ latencyMs: 0, infectedRate: 0 });
  engine.setUnavailable(true);
  const svc = new ScannerService({ engine, repo: repoStub(), cfg });
  for (let i = 0; i < 2; i++) {
    await assert.rejects(
      () => svc.scan({ sha256: "c".repeat(64), name: "x", size: 1 }),
      (err) => err instanceof ScannerUnavailableError,
    );
  }
  const snap = svc.snapshot();
  assert.equal(snap.available, false);
  assert.ok(snap.openedAt);
  // While open, calls fail fast without touching the engine.
  const calls = engine.calls;
  await assert.rejects(
    () => svc.scan({ sha256: "d".repeat(64), name: "x", size: 1 }),
    /熔断/,
  );
  assert.equal(engine.calls, calls, "熔断期间不应再调用引擎");

  await new Promise((r) => setTimeout(r, 160));
  engine.setUnavailable(false);
  assert.equal(await svc.probe(), true);
  const ok = await svc.scan({ sha256: "e".repeat(64), name: "x", size: 1 });
  assert.equal(ok.verdict, "clean");
  assert.equal(svc.snapshot().available, true);
  assert.equal(svc.snapshot().consecutiveFailures, 0);
});

test("ScannerService：高危判定映射为 infected", async () => {
  const cfg = cfgFor();
  const engine = {
    id: "stub",
    scan: async () => ({ verdict: "suspicious", severity: "critical", engine: "stub" }),
    probe: async () => ({ ok: true }),
  };
  const svc = new ScannerService({ engine, repo: repoStub(), cfg });
  const r = await svc.scan({ sha256: "f".repeat(64), name: "x", size: 1 });
  assert.equal(r.infected, true);
});

test("ExternalScanner：解析 stdout JSON，退出码 75 视为不可用", async () => {
  const dir = await tempRoot("ig-ext-");
  const good = path.join(dir, "good.js");
  await fs.writeFile(
    good,
    `process.stdout.write(JSON.stringify({ verdict: "clean", engine: "ext/1" }));`,
  );
  const scanner = new ExternalScanner({ command: process.execPath, args: [good], timeoutMs: 5000 });
  const v = await scanner.scan({ path: "/tmp/x", sha256: "0".repeat(64), name: "x", size: 1 });
  assert.equal(v.verdict, "clean");
  assert.equal(v.engine, "ext/1");

  const down = path.join(dir, "down.js");
  await fs.writeFile(down, `process.exit(75);`);
  const broken = new ExternalScanner({ command: process.execPath, args: [down], timeoutMs: 5000 });
  await assert.rejects(
    () => broken.scan({ path: "/tmp/x", sha256: "0".repeat(64), name: "x", size: 1 }),
    (err) => err.code === "scanner_unavailable",
  );

  const garbage = path.join(dir, "garbage.js");
  await fs.writeFile(garbage, `process.stdout.write("not json");`);
  const bad = new ExternalScanner({ command: process.execPath, args: [garbage], timeoutMs: 5000 });
  await assert.rejects(
    () => bad.scan({ path: "/tmp/x", sha256: "0".repeat(64), name: "x", size: 1 }),
    (err) => err.code === "scanner_unavailable",
  );
});

test("外部扫描示例脚本：真实子进程输出可解析的判定", async () => {
  const script = path.resolve("scripts/mock-scanner.js");
  const dir = await tempRoot("ig-ext-demo-");
  const file = path.join(dir, "sample.txt");
  await fs.writeFile(file, "sample payload");
  const cfg = cfgFor({
    mode: "external",
    external: { command: process.execPath, args: [script, "{path}"], timeoutMs: 5000 },
  });
  const engine = buildEngine(cfg);
  assert.ok(engine instanceof ExternalScanner);
  const svc = new ScannerService({ engine, repo: repoStub(), cfg });
  const v = await svc.scan({ path: file, sha256: "0".repeat(64), name: "sample.txt", size: 14 });
  assert.ok(["clean", "suspicious", "infected"].includes(v.verdict));
  assert.equal(svc.snapshot().available, true);
});

test("buildEngine：auto 模式无外部命令时使用 mock", () => {
  const cfg = cfgFor({ mode: "auto", external: { command: "", args: [], timeoutMs: 1000 } });
  assert.ok(buildEngine(cfg) instanceof MockScanner);
});
