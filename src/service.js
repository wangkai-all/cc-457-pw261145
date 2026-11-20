// Service wiring: owns the database, scanner, pipeline, watcher and parse queue,
// plus the periodic maintenance jobs (retries, scanner health, waterline
// sampling, retention).

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

import { loadConfig } from "./config.js";
import { openDatabase, ensureDirs } from "./db.js";
import { buildEngine, ScannerService } from "./scanner.js";
import { Pipeline } from "./pipeline.js";
import { InboxWatcher } from "./watcher.js";
import { ParseQueue } from "./parsequeue.js";
import { parseFile } from "./parser.js";
import { createLogger } from "./log.js";
import { nowIso } from "./util.js";
import { reasonInfo } from "./reasons.js";

export class Service {
  constructor(config = loadConfig(), { log } = {}) {
    this.cfg = config;
    this.log = log ?? createLogger();
    this.repo = null;
    this.startedAt = nowIso();
    this.maintenance = false; // operator "pause intake" switch
    this.metrics = {
      waterline: {
        samples: [],
        bytes: 0,
        files: 0,
        sampledAt: null,
        budgetBytes: config.ui.waterlineBudgetBytes,
      },
      ingest: { discovered: 0, admitted: 0, quarantined: 0, dismissed: 0 },
    };
    this.timers = [];
    this.running = false;
  }

  async init() {
    await ensureDirs([
      this.cfg.dataDir,
      this.cfg.watchDir,
      this.cfg.stagingDir,
      this.cfg.quarantineDir,
      this.cfg.queueDir,
      this.cfg.outDir,
      this.cfg.trashDir,
    ]);
    this.repo = openDatabase(this.cfg.dbPath);
    const engine = buildEngine(this.cfg);
    this.engine = engine;
    this.scanner = new ScannerService({
      engine,
      repo: this.repo,
      cfg: this.cfg,
      log: this.log,
    });
    this.pipeline = new Pipeline({
      repo: this.repo,
      cfg: this.cfg,
      scanner: this.scanner,
      parse: parseFile,
      log: this.log,
      paused: () => this.maintenance,
    });
    this.pipeline.onAdmitted = () => (this.metrics.ingest.admitted += 1);
    this.pipeline.onQuarantined = () => (this.metrics.ingest.quarantined += 1);
    this.pipeline.onQueued = () => this.parseQueue?.wakeUp();

    this.parseQueue = new ParseQueue({
      repo: this.repo,
      cfg: this.cfg,
      parse: parseFile,
      log: this.log,
      paused: () => this.maintenance,
    });
    this.watcher = new InboxWatcher({
      repo: this.repo,
      cfg: this.cfg,
      pipeline: this.pipeline,
      log: this.log,
    });
    return this;
  }

  async start() {
    if (this.running) return;
    this.running = true;
    await this.pipeline.init();
    await this.watcher.start();
    await this.parseQueue.start();
    this.log.info(
      { watchDir: this.cfg.watchDir, scanMode: this.cfg.scan.mode, scanner: this.scanner.engineId },
      "监控服务已启动",
    );
    this.#startTimers();
    await this.sampleWaterline();
    this.repo.logEvent({
      kind: "service_started",
      summary: "监控服务启动",
      detail: {
        watchDir: this.cfg.watchDir,
        scanMode: this.cfg.scan.mode,
        scanner: this.scanner.engineId,
      },
    });
  }

  #startTimers() {
    const every = (ms, name, fn, immediate = false) => {
      const t = setInterval(() => {
        fn().catch((err) => this.log.error({ job: name, err: err.message }, "维护任务失败"));
      }, ms);
      t.unref?.();
      this.timers.push(t);
      if (immediate) fn().catch(() => {});
    };
    // Retries run often - they are cheap and latency matters after a blip.
    every(1000, "retries", () => this.pipeline.processDueRetries());
    // Scanner health: probe while the breaker is open, and periodically when
    // healthy so an outage is noticed before the first file hits it.
    every(Math.min(this.cfg.scan.retry.circuitOpenMs, 10_000), "scanner-health", () =>
      this.checkScannerHealth(),
    );
    every(this.cfg.ui.refreshMs, "waterline", () => this.sampleWaterline());
    every(3600_000, "retention", () => this.prune());
  }

  async checkScannerHealth() {
    const snap = this.scanner.snapshot();
    if (snap.available) return { available: true };
    const ok = await this.scanner.probe();
    if (ok) {
      this.repo.logEvent({
        kind: "scanner_recovered",
        summary: "扫描服务恢复可用，重试队列将继续处理",
      });
    }
    return { available: ok };
  }

  /** Occupancy of the inbox (the "waterline") plus quarantine/queue sizes. */
  async sampleWaterline() {
    let files = 0;
    let bytes = 0;
    let entries;
    try {
      entries = await fsp.readdir(this.cfg.watchDir, { withFileTypes: true });
    } catch {
      entries = [];
    }
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      try {
        const st = await fsp.stat(path.join(this.cfg.watchDir, ent.name));
        files += 1;
        bytes += st.size;
      } catch {
        /* vanished mid-scan */
      }
    }
    const w = this.metrics.waterline;
    w.files = files;
    w.bytes = bytes;
    w.sampledAt = nowIso();
    w.samples.push({ at: w.sampledAt, files, bytes });
    if (w.samples.length > 120) w.samples.shift();
    return w;
  }

  async prune() {
    const cutoff = new Date(Date.now() - this.cfg.limits.eventRetentionMs).toISOString();
    const removed = this.repo.pruneEvents(cutoff);
    // Reconcile trash: files older than the event window are unrecoverable.
    let swept = 0;
    try {
      const names = await fsp.readdir(this.cfg.trashDir);
      for (const name of names) {
        const full = path.join(this.cfg.trashDir, name);
        const st = await fsp.stat(full).catch(() => null);
        if (st && Date.now() - st.mtimeMs > this.cfg.limits.eventRetentionMs) {
          await fsp.unlink(full).catch(() => {});
          swept += 1;
        }
      }
    } catch {
      /* trash dir may not exist yet */
    }
    if (removed || swept) {
      this.repo.logEvent({
        kind: "retention",
        summary: `清理 ${removed} 条事件、${swept} 个回收文件`,
      });
    }
  }

  /** Dashboard payload - one round trip for the whole first paint. */
  async dashboard({ eventsSinceId = null } = {}) {
    const counts = this.repo.countsByState();
    const storage = this.repo.bytesByStorage();
    const inStates = (...s) => s.reduce((n, k) => n + (counts[k] ?? 0), 0);

    const quarantined = this.repo.listProducts({
      states: ["quarantined"],
      sort: "newest",
      limit: 200,
      offset: 0,
    });
    const reasonBuckets = new Map();
    for (const p of quarantined.rows) {
      const code = p.reason_code ?? "unknown";
      const info = reasonInfo(code);
      const b = reasonBuckets.get(code) ?? {
        code,
        label: info.label,
        group: info.group,
        severity: info.severity,
        retryable: info.retryable,
        count: 0,
        bytes: 0,
      };
      b.count += 1;
      b.bytes += p.size_bytes;
      reasonBuckets.set(code, b);
    }

    const queue = this.repo.listProducts({ states: ["queued"], sort: "oldest", limit: 200 });
    const parseStats = { pending: 0, running: 0, ready: 0, failed: 0 };
    for (const p of queue.rows) if (p.parse_status in parseStats) parseStats[p.parse_status] += 1;

    const w = this.metrics.waterline;
    const budget = w.budgetBytes || 1;
    const pct = Math.min(100, (w.bytes / budget) * 100);
    const level =
      pct >= this.cfg.ui.criticalPct ? "critical" : pct >= this.cfg.ui.warningPct ? "warning" : "good";

    const scanner = this.scanner.snapshot();
    const watcher = this.watcher.snapshot();
    const counts2 = {
      quarantined: inStates("quarantined"),
      queued: inStates("queued", "released"),
      checking: inStates("checking"),
      deleted: inStates("deleted"),
      lost: inStates("lost"),
    };

    const recent = this.repo.recentEvents(this.cfg.ui.recentEvents, eventsSinceId);
    const health = this.health();

    return {
      serverTime: nowIso(),
      uptimeMs: Date.now() - Date.parse(this.startedAt),
      maintenance: this.maintenance,
      scanner,
      watcher,
      parseQueue: this.parseQueue.snapshot(),
      waterline: {
        ...w,
        percent: Number(pct.toFixed(1)),
        level,
        warningPct: this.cfg.ui.warningPct,
        criticalPct: this.cfg.ui.criticalPct,
        budgetBytes: budget,
      },
      counts: {
        ...counts2,
        totalSeen: Object.values(counts).reduce((a, b) => a + b, 0),
        byState: counts,
      },
      storage,
      quarantine: {
        total: counts2.quarantined,
        reasons: [...reasonBuckets.values()].sort((a, b) => b.count - a.count),
        retryable: quarantined.rows.filter((p) => p.reason_detail?.retryable).length,
      },
      parse: parseStats,
      events: recent,
      health,
      limits: {
        maxFileBytes: this.cfg.limits.maxFileBytes,
        maxArchiveDepth: this.cfg.limits.maxArchiveDepth,
        maxArchiveMembers: this.cfg.limits.maxArchiveMembers,
        maxArchiveUncompressedBytes: this.cfg.limits.maxArchiveUncompressedBytes,
        maxRatio: this.cfg.limits.maxRatio,
      },
    };
  }

  /** Health is derived, not just "process is up". */
  health() {
    const scanner = this.scanner.snapshot();
    const watcher = this.watcher.snapshot();
    const w = this.metrics.waterline;
    const pct = (w.bytes / (w.budgetBytes || 1)) * 100;
    const checks = [
      {
        id: "watcher",
        label: "目录监控",
        status: watcher.running ? "ok" : watcher.ready ? "degraded" : "down",
        detail: watcher.mode,
      },
      {
        id: "scanner",
        label: "病毒扫描",
        status: scanner.available ? "ok" : "degraded",
        detail: scanner.available
          ? `${scanner.engine} 正常`
          : `熔断至 ${scanner.openUntil ?? "—"}（${scanner.lastError ?? "无详情"}）`,
      },
      {
        id: "parser",
        label: "解析队列",
        status: this.parseQueue.running ? "ok" : "down",
        detail: `并发 ${this.parseQueue.active}/${this.cfg.parse.concurrency}`,
      },
      {
        id: "waterline",
        label: "目录水位",
        status: pct >= this.cfg.ui.criticalPct ? "degraded" : "ok",
        detail: `${pct.toFixed(1)}%`,
      },
    ];
    const worst = checks.some((c) => c.status === "down")
      ? "down"
      : checks.some((c) => c.status === "degraded")
        ? "degraded"
        : "ok";
    return { status: worst, checks };
  }

  setMaintenance(on) {
    const changed = this.maintenance !== Boolean(on);
    this.maintenance = Boolean(on);
    if (changed) {
      this.repo.logEvent({
        kind: "maintenance",
        summary: this.maintenance ? "进入维护模式：暂停接收与解析" : "退出维护模式",
      });
      this.log.info({ maintenance: this.maintenance }, "维护模式切换");
    }
    return this.maintenance;
  }

  async stop() {
    this.running = false;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    await this.watcher?.stop();
    await this.parseQueue?.stop();
    this.repo?.logEvent({ kind: "service_stopped", summary: "监控服务停止" });
    this.repo?.close();
  }
}
