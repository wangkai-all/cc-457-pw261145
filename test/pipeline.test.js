// End-to-end pipeline tests: temp files, replacement, nesting, oversize,
// virus, unavailability, retries, release/delete, restart and duplicate events.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import zlib from "node:zlib";
import {
  startService,
  stopService,
  writeInbox,
  productByName,
  until,
  wait,
  makeZip,
  forceScannerOutage,
} from "./helpers.js";

/** Start a service, run the body, always stop. */
async function withService(fn, overrides = {}) {
  const ctx = await startService(overrides);
  try {
    return await fn(ctx);
  } finally {
    await stopService(ctx.service);
  }
}

async function productsFor(service, name) {
  return (await service.repo.listProducts({ search: name, limit: 50 })).rows;
}

test("临时文件被忽略，不产生处理记录", async () => {
  // tempGraceMs > 0 keeps temp-named files "in flight"; the sweeper skips them.
  await withService(async ({ cfg, service }) => {
    await writeInbox(cfg, ".in-progress.pdf.a1b2", "partial");
    await writeInbox(cfg, "real.pdf.tmp", "partial");
    await wait(600);
    const ignored = service.repo.recentEvents(50).filter((e) => e.kind === "ignored");
    assert.ok(ignored.length >= 2, "应记录两条忽略事件");
    assert.ok(ignored.every((e) => e.reason_code === "temp_file"));
    // Neither file became a product.
    assert.equal((await productsFor(service, "in-progress")).length, 0);
    assert.equal((await productsFor(service, "real.pdf")).length, 0);
    // And they stay in the inbox for the producer to finish.
    const left = await fs.readdir(cfg.watchDir);
    assert.ok(left.includes(".in-progress.pdf.a1b2"));
  }, { limits: { tempGraceMs: 60_000 } });
});

test("正常的稳定文件进入解析队列并生成报告", async () => {
  await withService(async ({ cfg, service }) => {
    await writeInbox(cfg, "orders.csv", "id,name\n1,alpha\n2,beta\n");
    const p = await productByName(service, "orders.csv", { state: "queued" });
    assert.ok(p.sha256, "入队文件必须有完整哈希");
    assert.equal(p.parse_status, "ready");
    const result = service.repo.getParseResult(p.id);
    assert.equal(result.kind, "csv");
    assert.ok(result.payload.columns.length >= 2);
    // Report file written next to nothing else.
    const reports = await fs.readdir(cfg.outDir);
    assert.equal(reports.filter((f) => f.endsWith(".report.json")).length, 1);
    assert.equal(await statExists(path.join(cfg.queueDir, path.basename(p.storage_path))), true);
  });
});

test("超大文件被隔离，保留哈希与原因", async () => {
  await withService(
    async ({ cfg, service }) => {
      const big = Buffer.alloc(700 * 1024, 0x42);
      await writeInbox(cfg, "huge.bin", big);
      const p = await productByName(service, "huge.bin", { state: "quarantined" });
      assert.equal(p.reason_code, "too_large");
      assert.equal(p.sha256.length, 64);
      assert.equal(p.reason_detail.limit, 512 * 1024);
      assert.equal(p.storage_kind, "quarantine");
      assert.equal(p.scan_verdict, null, "超限文件不应浪费时间扫描");
      assert.ok(await statExists(p.storage_path));
    },
    { limits: { maxFileBytes: 512 * 1024 } },
  );
});

test("病毒扫描判定恶意时隔离，并记录签名", async () => {
  await withService(async ({ cfg, service }) => {
    const engine = service.engine;
    const original = engine.scan.bind(engine);
    engine.scan = async (input) =>
      input.name === "infected.txt"
        ? {
            verdict: "infected",
            severity: "critical",
            engine: "mock-test/1",
            signature: "EICAR-Test-File",
            checkedAt: new Date().toISOString(),
          }
        : original(input);

    await writeInbox(cfg, "infected.txt", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR");
    const p = await productByName(service, "infected.txt", { state: "quarantined" });
    assert.equal(p.reason_code, "virus_detected");
    assert.equal(p.scan_verdict, "infected");
    assert.equal(p.scan_signature, "EICAR-Test-File");
    assert.equal(p.reason_detail.severity, "critical");
    assert.equal(p.reason_detail.retryable, false, "病毒判定不应自动重试");
    // Never queued.
    assert.equal(await statExists(path.join(cfg.queueDir, path.basename(p.storage_path))), false);
  });
});

test("嵌套压缩包：正常放行，过深/穿越隔离", async () => {
  await withService(async ({ cfg, service }) => {
    const inner = makeZip([{ name: "a.txt", data: "inner" }]);
    const middle = makeZip([{ name: "inner.zip", data: inner }]);
    const deep = makeZip([{ name: "middle.zip", data: middle }]);
    const ok = makeZip([{ name: "notes.txt", data: "fine" }, { name: "nested.zip", data: inner }]);
    const evil = makeZip([{ name: "../../etc/passwd", data: "x" }]);

    await writeInbox(cfg, "ok.zip", ok);
    await writeInbox(cfg, "deep.zip", deep);
    await writeInbox(cfg, "evil.zip", evil);

    const okP = await productByName(service, "ok.zip", { state: "queued" });
    assert.equal(okP.archive_kind, "zip");
    assert.ok(okP.archive_members >= 2);

    const deepP = await productByName(service, "deep.zip", { state: "quarantined" });
    assert.equal(deepP.reason_code, "archive_too_deep");

    const evilP = await productByName(service, "evil.zip", { state: "quarantined" });
    assert.equal(evilP.reason_code, "archive_path_traversal");
    assert.ok(evilP.reason_detail.findings.some((f) => f.code === "archive_path_traversal"));
  });
});

test("压缩炸弹与成员过多分别隔离", async () => {
  await withService(async ({ cfg, service }) => {
    const bomb = makeZip([{ name: "zero.bin", data: Buffer.alloc(3 * 1024 * 1024) }]);
    const many = makeZip(
      Array.from({ length: 20 }, (_, i) => ({ name: `f${i}.txt`, data: "x" })),
    );
    await writeInbox(cfg, "bomb.zip", bomb);
    await writeInbox(cfg, "many.zip", many);
    const b = await productByName(service, "bomb.zip", { state: "quarantined" });
    assert.ok(
      ["archive_expansion_limit", "archive_ratio_high"].includes(b.reason_code) ||
        b.reason_detail.findings?.some((f) => f.code === "archive_ratio_high"),
      `unexpected reason ${b.reason_code}`,
    );
    const m = await productByName(service, "many.zip", { state: "quarantined" });
    assert.equal(m.reason_code, "archive_too_many_members");
  });
});

test("同名替换：旧版本被标记，新内容单独记录", async () => {
  await withService(async ({ cfg, service }) => {
    await writeInbox(cfg, "report.txt", "version one");
    const first = await productByName(service, "report.txt", { state: "queued" });
    await wait(250);
    await writeInbox(cfg, "report.txt", "version two is different");
    const second = await until(
      async () => (await productsFor(service, "report.txt")).find((p) => p.id !== first.id && p.state === "queued"),
      { label: "second version queued" },
    );
    assert.notEqual(first.sha256, second.sha256);
    const replaced = service.repo.recentEvents(100).filter((e) => e.kind === "replaced");
    assert.ok(replaced.length >= 1, "应记录同名替换事件");
    // Both hashes retained in the journal.
    const all = await productsFor(service, "report.txt");
    const hashes = new Set(all.map((p) => p.sha256).filter(Boolean));
    assert.ok(hashes.size >= 2);
  });
});

test("扫描服务不可用时隔离为可重试，服务恢复后自动入队", async () => {
  await withService(async ({ cfg, service }) => {
    const restore = forceScannerOutage(service, 999);
    await writeInbox(cfg, "during-outage.txt", "payload");
    const p = await productByName(service, "during-outage.txt", { state: "quarantined" });
    assert.ok(
      ["scanner_unavailable", "scanner_error"].includes(p.reason_code),
      `unexpected ${p.reason_code}`,
    );
    assert.equal(p.reason_detail.retryable, true);
    assert.equal(p.scan_verdict, "error");
    assert.ok(p.sha256, "失败文件也必须保留哈希");

    // Bring the scanner back and let the retry loop pick it up.
    restore();
    service.scanner.state.available = true;
    service.scanner.state.consecutiveFailures = 0;
    service.scanner.state.openedAt = null;
    const queued = await until(
      async () => {
        const row = (await productsFor(service, "during-outage.txt")).find((x) => x.state === "queued");
        return row ?? null;
      },
      { timeoutMs: 12_000, label: "auto retry to queued" },
    );
    assert.equal(queued.scan_verdict, "clean");
  });
});

test("熔断后不再逐个打挂扫描服务，并记录可用性状态", async () => {
  await withService(async ({ cfg, service }) => {
    const restore = forceScannerOutage(service, 999);
    await writeInbox(cfg, "a1.txt", "one");
    await writeInbox(cfg, "a2.txt", "two");
    await writeInbox(cfg, "a3.txt", "three");
    await until(
      async () => (await productsFor(service, "a3.txt"))[0]?.state === "quarantined",
      { timeoutMs: 15_000, label: "all three quarantined" },
    );
    const snap = service.scanner.snapshot();
    assert.equal(snap.available, false);
    assert.ok(snap.consecutiveFailures >= 2);
    restore();
  });
});

test("显式重试：隔离文件重新检查后入队", async () => {
  await withService(async ({ cfg, service }) => {
    const engine = service.engine;
    const original = engine.scan.bind(engine);
    let fail = true;
    engine.scan = async (input) => {
      if (fail) {
        const err = new Error("temporary");
        err.code = "scanner_unavailable";
        err.retryable = true;
        throw err;
      }
      return original(input);
    };
    await writeInbox(cfg, "retry-me.txt", "retry payload");
    const p = await productByName(service, "retry-me.txt", { state: "quarantined" });
    fail = false;
    service.scanner.state.available = true;
    service.scanner.state.consecutiveFailures = 0;
    service.scanner.state.openedAt = null;
    const updated = await service.pipeline.retryProduct(p.id, { manual: true });
    assert.equal(updated.state, "checking");
    const queued = await until(
      async () => {
        const row = service.repo.getProduct(p.id);
        return row.state === "queued" ? row : null;
      },
      { timeoutMs: 10_000, label: "manual retry queued" },
    );
    assert.equal(queued.sha256, p.sha256, "重试不应改变内容哈希");
  });
});

test("释放与删除：文件位移、记录保留、不可重复操作", async () => {
  await withService(async ({ cfg, service }) => {
    const engine = service.engine;
    const original = engine.scan.bind(engine);
    engine.scan = async (input) =>
      input.name === "bad.txt"
        ? {
            verdict: "infected",
            severity: "critical",
            engine: "mock-test/1",
            signature: "Mock.Virus",
            checkedAt: new Date().toISOString(),
          }
        : original(input);
    await writeInbox(cfg, "bad.txt", "nasty");
    const p = await productByName(service, "bad.txt", { state: "quarantined" });

    const target = path.join(cfg.dataDir, "released");
    const released = await service.pipeline.release(p.id, { targetDir: target, note: "已确认安全" });
    assert.equal(released.state, "released");
    assert.equal(released.release_target, path.join(target, "bad.txt"));
    assert.ok(await statExists(released.release_target));
    assert.equal(await statExists(p.storage_path), false, "原隔离副本应已移走");
    await assert.rejects(() => service.pipeline.release(p.id), /不支持释放|不存在/);

    /**********************************************************************
     * 删除路径
     **********************************************************************/
    const engine2 = service.engine;
    const orig2 = engine2.scan.bind(engine2);
    engine2.scan = async (input) =>
      input.name === "junk.txt"
        ? {
            verdict: "infected",
            severity: "high",
            engine: "mock-test/1",
            signature: "Mock.Virus",
            checkedAt: new Date().toISOString(),
          }
        : orig2(input);
    await writeInbox(cfg, "junk.txt", "junk");
    const j = await productByName(service, "junk.txt", { state: "quarantined" });
    const deleted = await service.pipeline.remove(j.id, { note: "确认删除", hard: true });
    assert.equal(deleted.state, "deleted");
    assert.equal(deleted.sha256, j.sha256, "删除后仍保留哈希用于审计");
    assert.equal(deleted.reason_code, j.reason_code);
    assert.equal(await statExists(j.storage_path), false);
    assert.equal(
      await statExists(path.join(cfg.trashDir, path.basename(j.storage_path))),
      false,
      "hard 删除应同时移除回收区副本",
    );
    assert.equal(service.repo.getSeen(j.sha256), null, "hard 删除应清除去重记录");
    // Deleting again is a no-op, not an error.
    assert.equal((await service.pipeline.remove(j.id)).state, "deleted");
  });
});

test("重复事件：同一路径的多次事件只产生一个产品", async () => {
  await withService(async ({ cfg, service }) => {
    const p = path.join(cfg.watchDir, "burst.txt");
    await fs.writeFile(p, "initial");
    // Hammer the path with events while it is still being processed.
    for (let i = 0; i < 12; i++) {
      await wait(15);
      await service.watcher.react(p).catch(() => {});
      service.watcher.scheduleReact(p);
    }
    await wait(400);

    const rows = await productsFor(service, "burst.txt");
    const live = rows.filter((r) => r.state !== "lost");
    assert.equal(live.length, 1, `expected exactly one product, got ${live.length}`);
    const queued = await productByName(service, "burst.txt", { state: "queued" });
    const content = await fs.readFile(queued.storage_path, "utf8");
    assert.equal(content, "initial", "入队副本内容应完整");

    // The original was moved out of the inbox, so a producer writing the name
    // again creates a new file: one replacement product with the new content.
    await fs.writeFile(p, "initial more");
    service.watcher.scheduleReact(p);
    const second = await until(
      async () => (await productsFor(service, "burst.txt")).find((r) => r.id !== queued.id && r.state === "queued"),
      { label: "replacement queued" },
    );
    const content2 = await fs.readFile(second.storage_path, "utf8");
    assert.equal(content2, "initial more", "替换后的副本应完整");
  });
});

test("监控重启：暂存中的文件恢复检查，队列文件不重复入队", async () => {
  const ctx = await startService();
  const { cfg, service } = ctx;
  try {
    await writeInbox(cfg, "persist.txt", "persist me");
    const before = await productByName(service, "persist.txt", { state: "queued" });
    const sha = before.sha256;

    // Simulate a crash: stop without letting the parser touch the row again.
    await stopService(service);
    const again = await startService({ dataDir: cfg.dataDir });
    try {
      const rows = await productsFor(again.service, "persist.txt");
      const queued = rows.find((r) => r.sha256 === sha);
      assert.ok(queued, "重启后记录仍在");
      assert.equal(queued.state, "queued");
      const results = await fs.readdir(again.cfg.queueDir);
      assert.equal(results.length, 1, "队列目录不应出现重复副本");
      // The parse result survives — same product id.
      assert.equal(queued.id, before.id);
    } finally {
      await stopService(again.service);
    }
  } catch (err) {
    await stopService(service).catch(() => {});
    throw err;
  }
});

test("监控重启：检查中的文件在重启后继续检查", async () => {
  const ctx = await startService();
  const { cfg, service } = ctx;
  try {
    // Create a product row + staged file directly, mimicking a crash mid-check.
    const staged = path.join(cfg.stagingDir, "pd_aaaaaaaaaaaa.txt");
    await fs.writeFile(staged, "orphan-staged");
    service.repo.insertProduct({
      id: "pd_aaaaaaaaaaaa",
      sha256: null,
      original_name: "orphan.txt",
      extension: ".txt",
      size_bytes: 13,
      mtime_ms: Date.now(),
      state: "checking",
      storage_path: staged,
      storage_kind: "staging",
    });
    await stopService(service);

    const again = await startService({ dataDir: cfg.dataDir });
    try {
      const row = await until(
        async () => {
          const p = again.service.repo.getProduct("pd_aaaaaaaaaaaa");
          return p && p.state === "queued" ? p : null;
        },
        { timeoutMs: 8000, label: "recovered check finishes" },
      );
      assert.equal(row.state, "queued");
      assert.ok(row.sha256);
    } finally {
      await stopService(again.service);
    }
  } catch (err) {
    await stopService(service).catch(() => {});
    throw err;
  }
});

test("重启清扫：磁盘上无主文件被接管，缺失副本标记 lost", async () => {
  const ctx = await startService();
  const { cfg, service } = ctx;
  try {
    const orphan = path.join(cfg.quarantineDir, "pd_bbbbbbbbbbbb.bin");
    await fs.writeFile(orphan, "orphan");
    service.repo.insertProduct({
      id: "pd_cccccccccccc",
      sha256: "d".repeat(64),
      original_name: "ghost.txt",
      extension: ".txt",
      size_bytes: 10,
      state: "quarantined",
      reason_code: "too_large",
      storage_path: path.join(cfg.quarantineDir, "pd_cccccccccccc.txt"),
      storage_kind: "quarantine",
      reason_detail: { severity: "medium", retryable: false },
    });
    await stopService(service);

    const again = await startService({ dataDir: cfg.dataDir });
    try {
      const adopted = again.service.repo.getProduct("pd_bbbbbbbbbbbb");
      assert.ok(adopted, "无主文件应被接管");
      assert.equal(adopted.state, "quarantined");
      const ghost = again.service.repo.getProduct("pd_cccccccccccc");
      assert.equal(ghost.state, "lost");
      assert.equal(ghost.reason_code, "file_missing");
      assert.equal(ghost.sha256, "d".repeat(64), "丢失文件仍保留哈希");
    } finally {
      await stopService(again.service);
    }
  } catch (err) {
    await stopService(service).catch(() => {});
    throw err;
  }
});

test("去重：相同内容再次投递被隔离为 duplicate", async () => {
  await withService(async ({ cfg, service }) => {
    const payload = "same bytes every time";
    await writeInbox(cfg, "one.txt", payload);
    const first = await productByName(service, "one.txt", { state: "queued" });
    await writeInbox(cfg, "two.txt", payload);
    const dup = await productByName(service, "two.txt", { state: "quarantined" });
    assert.equal(dup.reason_code, "duplicate_content");
    assert.equal(dup.reason_detail.firstProductId, first.id);
    assert.equal(dup.sha256, first.sha256);
  });
});

test("暂停接收：维护模式下新文件留在目录中", async () => {
  await withService(async ({ cfg, service }) => {
    service.setMaintenance(true);
    await writeInbox(cfg, "held.txt", "held");
    await wait(600);
    assert.equal(await statExists(path.join(cfg.watchDir, "held.txt")), true);
    assert.equal((await productsFor(service, "held.txt")).length, 0);
    service.setMaintenance(false);
    await service.watcher.sweep("test");
    // A clean scan is what admits it; the mock is deterministic per content.
    const p = await until(
      async () => {
        const row = (await productsFor(service, "held.txt"))[0];
        return row && row.state !== "checking" ? row : null;
      },
      { label: "held file decided" },
    );
    assert.equal(p.state, "queued");
    assert.equal(p.reason_code, null);
  });
});

test("水位采样反映收件目录占用", async () => {
  await withService(async ({ cfg, service }) => {
    service.setMaintenance(true); // keep files in the inbox
    await writeInbox(cfg, "a.bin", Buffer.alloc(1000, 1));
    await writeInbox(cfg, "b.bin", Buffer.alloc(2000, 2));
    await service.sampleWaterline();
    const d = await service.dashboard();
    assert.equal(d.waterline.files, 2);
    assert.equal(d.waterline.bytes, 3000);
    assert.ok(d.waterline.percent > 0);
    service.setMaintenance(false);
  });
});

async function statExists(p) {
  if (!p) return false;
  try {
    await fs.stat(p);
    return true;
  } catch {
    return false;
  }
}
