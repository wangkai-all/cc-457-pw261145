// HTTP API tests: dashboard shape, paging, filters, actions and error paths.

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import {
  startService,
  stopService,
  writeInbox,
  productByName,
  makeZip,
  wait,
  until,
} from "./helpers.js";
import { createServer } from "../src/http.js";

async function withServer(fn) {
  const { cfg, service } = await startService();
  const server = createServer(service);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    return await fn({ base, service, cfg });
  } finally {
    await new Promise((r) => server.close(r));
    await stopService(service);
  }
}

async function get(base, p) {
  const res = await fetch(base + p);
  return { status: res.status, body: await res.json() };
}

async function post(base, p, body) {
  const res = await fetch(base + p, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { status: res.status, body: await res.json() };
}

test("GET /api/dashboard 返回完整面板结构", async () => {
  await withServer(async ({ base, cfg }) => {
    await writeInbox(cfg, "a.txt", "one");
    await productByNameFor(base, "a.txt");
    const { status, body } = await get(base, "/api/dashboard");
    assert.equal(status, 200);
    for (const key of ["scanner", "watcher", "parseQueue", "waterline", "counts", "quarantine", "parse", "events", "health", "limits"]) {
      assert.ok(key in body, `dashboard missing ${key}`);
    }
    assert.equal(typeof body.waterline.percent, "number");
    assert.ok(["good", "warning", "critical"].includes(body.waterline.level));
    assert.ok(["ok", "degraded", "down"].includes(body.health.status));
    assert.equal(body.health.checks.length, 4);
  });
});

test("GET /api/products 支持状态筛选、搜索、分页与排序", async () => {
  await withServer(async ({ base, cfg, service }) => {
    const engine = service.engine;
    const original = engine.scan.bind(engine);
    engine.scan = async (input) =>
      input.name.startsWith("bad-")
        ? { verdict: "infected", severity: "critical", engine: "t", signature: "Mock", checkedAt: new Date().toISOString() }
        : original(input);
    await writeInbox(cfg, "good.txt", "good");
    await writeInbox(cfg, "bad-1.txt", "bad1");
    await writeInbox(cfg, "bad-2.txt", "bad2");
    await productByName(service, "good.txt", { state: "queued" });
    await productByName(service, "bad-1.txt", { state: "quarantined" });
    await productByName(service, "bad-2.txt", { state: "quarantined" });

    const q = await get(base, "/api/products?state=quarantined");
    assert.equal(q.body.total, 2);
    assert.ok(q.body.items.every((p) => p.state === "quarantined"));
    assert.ok(q.body.items.every((p) => p.reason_code === "virus_detected"));

    const s = await get(base, "/api/products?q=bad-1");
    assert.equal(s.body.total, 1);
    assert.equal(s.body.items[0].original_name, "bad-1.txt");

    const paged = await get(base, "/api/products?limit=1&offset=1&sort=oldest");
    assert.equal(paged.body.items.length, 1);
    assert.equal(paged.body.total, 3);

    const bad = await get(base, "/api/products?state=../../etc&limit=99999");
    assert.equal(bad.status, 200, "非法状态值被忽略而不是报错");
  });
});

test("GET /api/products/:id 返回事件轨迹与解析结果", async () => {
  await withServer(async ({ base, cfg, service }) => {
    await writeInbox(cfg, "detail.txt", "line one\nline two\n");
    const p = await productByName(service, "detail.txt", { state: "queued" });
    await until(
      async () => service.repo.getProduct(p.id)?.parse_status === "ready",
      { label: "parse ready" },
    );
    const { status, body } = await get(base, `/api/products/${p.id}`);
    assert.equal(status, 200);
    assert.equal(body.product.id, p.id);
    assert.ok(body.events.length >= 3);
    assert.equal(body.parseResult.kind, "txt");
    assert.equal(body.product.retryable, false);

    const missing = await get(base, "/api/products/pd_zzzzzzzzzzzz");
    assert.equal(missing.status, 404);
  });
});

test("POST 重试 / 释放 / 删除 与错误路径", async () => {
  await withServer(async ({ base, cfg, service }) => {
    const engine = service.engine;
    const original = engine.scan.bind(engine);
    engine.scan = async (input) =>
      input.name === "infected.txt"
        ? { verdict: "infected", severity: "high", engine: "t", signature: "Mock", checkedAt: new Date().toISOString() }
        : original(input);
    await writeInbox(cfg, "infected.txt", "bad");
    const p = await productByName(service, "infected.txt", { state: "quarantined" });

    // Virus verdicts are not retryable.
    const retry = await post(base, `/api/products/${p.id}/retry`);
    assert.equal(retry.status, 409);

    // Release to an explicit absolute directory.
    const target = path.join(cfg.dataDir, "manual");
    const rel = await post(base, `/api/products/${p.id}/release`, {
      targetDir: target,
      confirmOutsideDataDir: true,
      note: "测试放行",
    });
    assert.equal(rel.status, 200);
    assert.equal(rel.body.product.state, "released");

    // Missing operations on an unknown id are 404.
    const nf = await post(base, `/api/products/pd_zzzzzzzzzzzz/delete`, { confirm: true });
    assert.equal(nf.status, 404);

    // Delete requires explicit confirmation.
    await writeInbox(cfg, "temp-delete.txt", "delete me");
    const d = await productByName(service, "temp-delete.txt", { state: "queued" });
    const noConfirm = await post(base, `/api/products/${d.id}/delete`, {});
    assert.equal(noConfirm.status, 400);
    const del = await post(base, `/api/products/${d.id}/delete`, { confirm: true });
    assert.equal(del.status, 200);
    assert.equal(del.body.product.state, "deleted");
    assert.equal(del.body.product.sha256, d.sha256);
  });
});

test("扫描服务模拟开关与健康检查", async () => {
  await withServer(async ({ base, service }) => {
    const down = await post(base, "/api/scanner/simulate-unavailable");
    assert.equal(down.status, 200);
    assert.equal(down.body.scanner.available, false);
    const health = await get(base, "/api/health");
    assert.equal(health.body.status, "degraded");
    const up = await post(base, "/api/scanner/simulate-recover");
    assert.equal(up.status, 200);
    assert.equal(up.body.scanner.available, true);
    const probe = await post(base, "/api/scanner/probe");
    assert.deepEqual(probe.body.probe, { available: true });
    assert.ok(service.repo.recentEvents(10).some((e) => e.kind === "scanner_simulated"));
  });
});

test("维护模式切换", async () => {
  await withServer(async ({ base }) => {
    const on = await post(base, "/api/maintenance", { enabled: true });
    assert.equal(on.body.maintenance, true);
    const d = await get(base, "/api/dashboard");
    assert.equal(d.body.maintenance, true);
    const off = await post(base, "/api/maintenance", { enabled: false });
    assert.equal(off.body.maintenance, false);
  });
});

test("静态资源与未知路由", async () => {
  await withServer(async ({ base }) => {
    const index = await fetch(base + "/");
    assert.equal(index.status, 200);
    assert.match(index.headers.get("content-type"), /text\/html/);
    const missing = await fetch(base + "/nope.js");
    assert.equal(missing.status, 404);
    const traversal = await fetch(base + "/../src/config.js");
    assert.equal(traversal.status, 404);
  });
});

test("POST 非法 JSON 返回 400", async () => {
  await withServer(async ({ base }) => {
    const res = await fetch(base + "/api/maintenance", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    assert.equal(res.status, 400);
  });
});

/** Wait for the queued row via the API surface (same predicate the UI uses). */
async function productByNameFor(base, name) {
  return until(
    async () => {
      const { body } = await get(base, `/api/products?q=${encodeURIComponent(name)}`);
      return body.items.find((p) => p.original_name === name && p.state !== "checking") ?? null;
    },
    { label: `api product ${name}` },
  );
}

test("并发重复请求不会造成重复产品", async () => {
  await withServer(async ({ base, cfg }) => {
    const name = "concurrent.txt";
    await writeInbox(cfg, name, "payload for concurrency");
    const results = await Promise.all(
      Array.from({ length: 6 }, () => get(base, `/api/products?q=${encodeURIComponent(name)}`)),
    );
    assert.ok(results.every((r) => r.status === 200));
    await wait(300);
    const { body } = await get(base, `/api/products?q=${encodeURIComponent(name)}`);
    assert.ok(body.total <= 2, `unexpected products: ${body.total}`);
  });
});

test("压缩包经 API 呈现检查结论", async () => {
  await withServer(async ({ base, cfg, service }) => {
    const evil = makeZip([{ name: "../escape.txt", data: "x" }]);
    await writeInbox(cfg, "container.zip", evil);
    const p = await productByName(service, "container.zip", { state: "quarantined" });
    const { body } = await get(base, `/api/products/${p.id}`);
    assert.equal(body.product.reason_code, "archive_path_traversal");
    assert.equal(body.product.archive_kind, "zip");
    assert.ok(body.product.retryable === false);
    assert.ok(body.events.some((e) => e.kind === "archive_inspected"));
  });
});
