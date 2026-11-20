// HTTP layer: JSON API + the static dashboard. No framework.
//
// Route table lives at the bottom; everything is plain node:http.

import http from "node:http";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { NotFoundError, ConflictError } from "./pipeline.js";
import { formatBytes } from "./util.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(HERE, "..", "public");

const MAX_BODY = 256 * 1024;
const ALLOWED_STATES = new Set([
  "checking",
  "quarantined",
  "queued",
  "released",
  "deleted",
  "lost",
  "duplicate",
]);

class HttpError extends Error {
  constructor(status, message, detail) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
    "cache-control": "no-store",
  });
  res.end(data);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, "请求体过大");
    chunks.push(chunk);
  }
  if (!size) return {};
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      throw new Error("not an object");
    }
    return v;
  } catch {
    throw new HttpError(400, "请求体不是合法 JSON 对象");
  }
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
  ".ico": "image/x-icon",
};

export function createServer(service) {
  const { repo, pipeline, cfg } = service;

  const productView = (p) => ({
    ...p,
    reason_detail: p.reason_detail ?? null,
    sizeLabel: formatBytes(p.size_bytes),
    retryable: Boolean(p.reason_detail?.retryable),
  });

  const routes = [
    {
      method: "GET",
      pattern: /^\/api\/health$/,
      handler: async () => {
        const h = service.health();
        return { status: h.status, checks: h.checks, serverTime: new Date().toISOString() };
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/dashboard$/,
      handler: async (req, url) => {
        const since = url.searchParams.get("eventsSinceId");
        return service.dashboard({ eventsSinceId: since ? Number(since) : null });
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/products$/,
      handler: async (req, url) => {
        const states = (url.searchParams.get("state") ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter((s) => ALLOWED_STATES.has(s));
        const sort = url.searchParams.get("sort") ?? "newest";
        const search = (url.searchParams.get("q") ?? "").slice(0, 120);
        const limit = clampInt(url.searchParams.get("limit"), 50, 1, 500);
        const offset = clampInt(url.searchParams.get("offset"), 0, 0, 1_000_000);
        const res = repo.listProducts({ states, search, sort, limit, offset });
        return { total: res.total, limit, offset, items: res.rows.map(productView) };
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/products\/([^/]+)$/,
      handler: async (req, url, [id]) => {
        const p = repo.getProduct(id);
        if (!p) throw new NotFoundError("文件不存在");
        const events = repo.eventsForProduct(id, 100);
        const parseResult = repo.getParseResult(id);
        return { product: productView(p), events, parseResult };
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/products\/([^/]+)\/retry$/,
      handler: async (req, url, [id]) => {
        const body = await readJson(req);
        const p = await pipeline.retryProduct(id, { manual: true, note: body.note });
        return { ok: true, product: productView(p) };
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/products\/([^/]+)\/release$/,
      handler: async (req, url, [id]) => {
        const body = await readJson(req);
        const targetDir = typeof body.targetDir === "string" ? body.targetDir.slice(0, 500) : null;
        if (targetDir && (!path.isAbsolute(targetDir) || targetDir.includes("\0"))) {
          throw new HttpError(400, "释放目录必须是绝对路径");
        }
        if (targetDir && !targetDir.startsWith(cfg.dataDir)) {
          // Releasing outside the service's data dir is a deliberate operator
          // action; allow it but require the caller to be explicit.
          if (body.confirmOutsideDataDir !== true) {
            throw new HttpError(400, "释放到数据目录之外需要 confirmOutsideDataDir=true");
          }
        }
        const p = await pipeline.release(id, {
          targetDir,
          actor: typeof body.actor === "string" ? body.actor.slice(0, 80) : "operator",
          note: typeof body.note === "string" ? body.note.slice(0, 500) : "",
        });
        return { ok: true, product: productView(p) };
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/products\/([^/]+)\/delete$/,
      handler: async (req, url, [id]) => {
        const body = await readJson(req);
        if (body.confirm !== true) throw new HttpError(400, "删除操作需要 confirm=true");
        const p = await pipeline.remove(id, {
          actor: typeof body.actor === "string" ? body.actor.slice(0, 80) : "operator",
          note: typeof body.note === "string" ? body.note.slice(0, 500) : "",
          hard: body.hard === true,
        });
        return { ok: true, product: productView(p) };
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/maintenance$/,
      handler: async (req) => {
        const body = await readJson(req);
        const on = service.setMaintenance(body.enabled === true);
        return { ok: true, maintenance: on };
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/scanner\/(simulate-unavailable|simulate-recover|simulate-failures)$/,
      handler: async (req, url, [action]) => {
        // Test hook for the in-process mock only. External scanners are not
        // controllable from the UI - that would be a remote-control surface.
        const engine = service.engine;
        if (typeof engine.setUnavailable !== "function" || typeof engine.failNext !== "function") {
          throw new HttpError(409, "当前扫描引擎不支持从界面模拟故障");
        }
        if (action === "simulate-unavailable") {
          engine.setUnavailable?.(true);
          service.scanner.setAvailable(false, "已模拟扫描服务不可用");
          repo.logEvent({ kind: "scanner_simulated", summary: "已模拟扫描服务不可用" });
        } else if (action === "simulate-recover") {
          engine.setUnavailable?.(false);
          service.scanner.setAvailable(true);
          repo.logEvent({ kind: "scanner_simulated", summary: "已解除扫描服务故障模拟" });
        } else {
          const body = await readJson(req);
          const n = clampInt(String(body.count ?? 1), 1, 0, 50);
          engine.failNext?.(n);
          repo.logEvent({ kind: "scanner_simulated", summary: `已模拟 ${n} 次扫描失败` });
        }
        return { ok: true, scanner: service.scanner.snapshot() };
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/scanner$/,
      handler: async () => ({ scanner: service.scanner.snapshot() }),
    },
    {
      method: "POST",
      pattern: /^\/api\/scanner\/probe$/,
      handler: async () => ({ scanner: service.scanner.snapshot(), probe: await service.checkScannerHealth() }),
    },
    {
      method: "GET",
      pattern: /^\/api\/events$/,
      handler: async (req, url) => {
        const limit = clampInt(url.searchParams.get("limit"), 50, 1, 500);
        const since = url.searchParams.get("sinceId");
        return { events: repo.recentEvents(limit, since ? Number(since) : null) };
      },
    },
  ];

  async function serveStatic(req, res, urlPath) {
    const rel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
    const full = path.resolve(PUBLIC_DIR, rel);
    // Directory traversal guard.
    if (!full.startsWith(PUBLIC_DIR + path.sep) && full !== PUBLIC_DIR) {
      throw new HttpError(403, "禁止访问");
    }
    let data;
    try {
      data = await fsp.readFile(full);
    } catch (err) {
      if (err.code === "ENOENT") throw new HttpError(404, "页面不存在");
      throw err;
    }
    res.writeHead(200, {
      "content-type": MIME[path.extname(full)] ?? "application/octet-stream",
      "content-length": data.length,
      "cache-control": "no-cache",
    });
    res.end(data);
  }

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);
    try {
      for (const route of routes) {
        if (route.method !== req.method) continue;
        const m = route.pattern.exec(url.pathname);
        if (!m) continue;
        const body = await route.handler(req, url, m.slice(1));
        json(res, 200, body);
        return;
      }
      if (req.method === "GET" || req.method === "HEAD") {
        await serveStatic(req, res, url.pathname);
        return;
      }
      throw new HttpError(404, "接口不存在");
    } catch (err) {
      const status = err.status ?? (err instanceof NotFoundError ? 404 : err instanceof ConflictError ? 409 : 500);
      if (status >= 500) {
        service.log.error(
          { method: req.method, path: url.pathname, err: err.message, stack: err.stack },
          "请求处理失败",
        );
      }
      json(res, status, {
        error: err.message,
        detail: err.detail ?? null,
        ...(status >= 500 ? { code: err.code ?? "internal" } : {}),
      });
    } finally {
      if (url.pathname.startsWith("/api/")) {
        service.log.debug(
          { method: req.method, path: url.pathname, ms: Date.now() - started },
          "api",
        );
      }
    }
  });

  server.on("clientError", (err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  });

  return server;
}

function clampInt(raw, fallback, min, max) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}
