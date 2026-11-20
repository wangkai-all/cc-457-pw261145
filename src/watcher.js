// Inbox monitoring: fs.watch for latency plus a periodic reconciliation sweep
// for correctness. fs.watch events are treated as hints only - every path is
// re-stat'ed and the pipeline itself is idempotent.
//
// Event storms (copying a tree, build tools) are coalesced per path.
// Files that vanish before we get to them are counted, not logged as errors.

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { classifyTempName } from "./stability.js";

const IGNORED_NAMES = new Set([".DS_Store", "Thumbs.db", "desktop.ini"]);

export class InboxWatcher {
  constructor({ cfg, repo, pipeline, log }) {
    this.cfg = cfg;
    this.repo = repo;
    this.pipeline = pipeline;
    this.log = log;
    this.watcher = null;
    this.pending = new Map(); // abs path -> timeout
    this.sweepTimer = null;
    this.running = false;
    this.stats = {
      eventsReceived: 0,
      eventsCoalesced: 0,
      eventsIgnored: 0,
      sweepsCompleted: 0,
      lastSweepAt: null,
      lastEventAt: null,
      watcherErrors: 0,
      droppedMissing: 0,
    };
    this.ready = false;
  }

  async start() {
    this.running = true;
    await fsp.mkdir(this.cfg.watchDir, { recursive: true });
    // 1. Reconcile first so a restart catches everything that arrived while down.
    await this.sweep("startup");
    this.ready = true;
    // 2. Watch for changes.
    this.startWatcher();
    // 3. Periodic sweep as a safety net.
    this.sweepTimer = setInterval(() => {
      this.sweep("interval").catch((err) =>
        this.log.error({ err: err.message }, "收件目录巡检失败"),
      );
    }, this.cfg.limits.sweepIntervalMs);
    this.sweepTimer.unref?.();
  }

  startWatcher() {
    try {
      this.watcher = fs.watch(this.cfg.watchDir, { persistent: true }, (eventType, filename) => {
        if (!filename) {
          // Some platforms drop the filename; fall back to a sweep.
          this.scheduleSweepSoon();
          return;
        }
        this.stats.eventsReceived += 1;
        this.stats.lastEventAt = new Date().toISOString();
        const name = filename.toString();
        if (name.includes(path.sep) || name.includes("/")) {
          // New subdirectory contents: watch() on the root may emit the parent;
          // let the sweep pick up files inside.
          this.scheduleSweepSoon();
          return;
        }
        if (IGNORED_NAMES.has(name) || name.startsWith(".~lock.")) {
          this.stats.eventsIgnored += 1;
          return;
        }
        this.scheduleReact(path.join(this.cfg.watchDir, name));
      });
      this.watcher.on("error", (err) => {
        this.stats.watcherErrors += 1;
        this.log.error({ err: err.message }, "目录监听器出错，将重建");
        this.recreateWatcher();
      });
    } catch (err) {
      this.stats.watcherErrors += 1;
      this.log.error({ err: err.message }, "无法监听收件目录，仅依赖巡检");
      // Retry after a delay; the sweep still makes progress meanwhile.
      setTimeout(() => this.running && this.startWatcher(), 2000).unref?.();
    }
  }

  recreateWatcher() {
    try {
      this.watcher?.close();
    } catch {
      /* already closed */
    }
    this.watcher = null;
    if (this.running) setTimeout(() => this.running && this.startWatcher(), 1000).unref?.();
  }

  /** Coalesce a burst of events for one path into a single intake call. */
  scheduleReact(absPath) {
    const existing = this.pending.get(absPath);
    if (existing) {
      this.stats.eventsCoalesced += 1;
      clearTimeout(existing);
    }
    const delay = Math.max(this.cfg.limits.eventDebounceMs, 200);
    const timer = setTimeout(() => {
      this.pending.delete(absPath);
      this.react(absPath).catch((err) =>
        this.log.error({ path: absPath, err: err.message }, "处理目录事件失败"),
      );
    }, delay);
    timer.unref?.();
    this.pending.set(absPath, timer);
  }

  scheduleSweepSoon() {
    if (this._soon) return;
    this._soon = setTimeout(() => {
      this._soon = null;
      this.sweep("event").catch(() => {});
    }, 500);
    this._soon.unref?.();
  }

  async react(absPath) {
    if (!this.running) return;
    let st;
    try {
      st = await fsp.stat(absPath);
    } catch (err) {
      if (err.code === "ENOENT") {
        this.stats.droppedMissing += 1;
        // If we were tracking this path, the file was removed before we took
        // it. Nothing to do - the sweep won't bring it back either.
        return;
      }
      throw err;
    }
    if (!st.isFile()) {
      this.stats.eventsIgnored += 1;
      return;
    }
    await this.pipeline.intake(absPath);
  }

  /** Walk the inbox and hand every regular file to the pipeline. */
  async sweep(reason = "interval") {
    let entries;
    try {
      entries = await fsp.readdir(this.cfg.watchDir, { withFileTypes: true });
    } catch (err) {
      this.log.warn({ err: err.message }, "无法读取收件目录");
      return { scanned: 0 };
    }
    let scanned = 0;
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      if (IGNORED_NAMES.has(ent.name)) continue;
      const tmp = classifyTempName(ent.name);
      if (tmp.temp && reason !== "startup") {
        // Temp files are handled by the event path (which waits for them to
        // age out of the grace window); don't churn the DB on every sweep.
        this.stats.eventsIgnored += 1;
        continue;
      }
      scanned += 1;
      await this.pipeline.intake(path.join(this.cfg.watchDir, ent.name));
    }
    this.stats.sweepsCompleted += 1;
    this.stats.lastSweepAt = new Date().toISOString();
    if (reason !== "startup") {
      // Log only sweeps that actually had work, to keep the journal readable.
      if (scanned > 0) {
        this.repo.logEvent({
          kind: "sweep",
          summary: `巡检收件目录：${scanned} 个待处理文件`,
          detail: { reason, scanned },
        });
      }
    }
    return { scanned };
  }

  /** Health info for the dashboard. */
  snapshot() {
    return {
      running: this.running && Boolean(this.watcher),
      mode: this.watcher ? "fs.watch + 巡检" : "仅巡检",
      ready: this.ready,
      watchDir: this.cfg.watchDir,
      stats: { ...this.stats },
    };
  }

  async stop() {
    this.running = false;
    clearInterval(this.sweepTimer);
    if (this._soon) clearTimeout(this._soon);
    for (const timer of this.pending.values()) clearTimeout(timer);
    this.pending.clear();
    try {
      this.watcher?.close();
    } catch {
      /* already closed */
    }
    this.watcher = null;
    // Let in-flight intakes finish their current move/DB step.
    await Promise.allSettled([...this.pipeline.inFlight.values()]);
  }
}
