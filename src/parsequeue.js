// Parse workers. A worker claims one queued product at a time (DB compare-and-
// set), parses the payload from the queue directory and writes a report file
// next to it. Failures are recorded with a reason and retried with backoff;
// non-retryable failures leave the file in the queue for an operator.

import fsp from "node:fs/promises";
import path from "node:path";
import { nowIso, backoffMs, formatBytes } from "./util.js";
import { reasonInfo } from "./reasons.js";
import { hashFile, statSample } from "./stability.js";
import { ParseUnsupportedError, ParseError } from "./parser.js";

export class ParseQueue {
  /**
   * @param {object} deps
   * @param {import('./db.js').Repo} deps.repo
   * @param {object} deps.cfg
   * @param {(filePath:string, name:string)=>Promise<object>} deps.parse
   */
  constructor({ repo, cfg, parse, log, paused = () => false }) {
    this.repo = repo;
    this.cfg = cfg;
    this.parse = parse;
    this.log = log;
    this.paused = paused;
    this.running = false;
    this.active = 0;
    this.timer = null;
    this.stats = { parsed: 0, failed: 0, unsupported: 0, lastRunAt: null };
  }

  async start() {
    this.running = true;
    this.repo.resetRunningParses();
    this.loop();
    this.log.info({ concurrency: this.cfg.parse.concurrency }, "解析队列已启动");
  }

  loop() {
    if (!this.running) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.tick(), this.cfg.parse.pollMs);
    this.timer.unref?.();
  }

  /** Called when something is admitted so we don't wait out the poll interval. */
  wakeUp() {
    if (!this.running) return;
    clearTimeout(this.timer);
    setImmediate(() => this.tick());
  }

  async tick() {
    if (!this.running) return;
    try {
      if (this.paused()) {
        this.loop();
        return;
      }
      await this.pump();
    } catch (err) {
      this.log.error({ err: err.message, stack: err.stack }, "解析队列循环出错");
    }
    this.loop();
  }

  /** Fill all free worker slots. */
  async pump() {
    while (this.running && this.active < this.cfg.parse.concurrency) {
      const next = this.repo.nextDueParse();
      if (!next) break;
      if (!this.repo.claimParse(next.id)) continue;
      this.active += 1;
      this.work(next.id)
        .catch((err) => this.log.error({ id: next.id, err: err.message }, "解析任务异常"))
        .finally(() => {
          this.active -= 1;
          this.onIdle?.();
        });
    }
  }

  async work(productId) {
    const product = this.repo.getProduct(productId);
    if (!product || !product.storage_path) {
      this.repo.setParse(productId, { status: "failed", lastError: "队列副本不存在" });
      this.repo.transition(productId, {
        to: "lost",
        reasonCode: "file_missing",
        reason: "队列副本路径缺失",
        reasonDetail: { stage: "parse" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      return;
    }
    const filePath = product.storage_path;
    const st = await statSample(filePath);
    if (!st) {
      this.repo.setParse(productId, { status: "failed", lastError: "队列副本不存在" });
      this.repo.transition(productId, {
        to: "lost",
        reasonCode: "file_missing",
        reason: "队列副本不存在",
        reasonDetail: { stage: "parse" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      this.repo.logEvent({
        productId,
        sha256: product.sha256,
        kind: "lost",
        reasonCode: "file_missing",
        summary: "解析前发现队列副本不存在",
        detail: { path: product.storage_path },
      });
      return;
    }

    // Verify the copy is still the one that passed the gate. The queue dir is
    // only written by us, so this is a belt-and-braces check.
    if (product.sha256) {
      try {
        const h = await hashFile(filePath, this.cfg.limits.hashSampleBytes);
        if (h.sha256 !== product.sha256) {
          this.repo.setParse(productId, { status: "failed", lastError: "队列副本哈希不一致" });
          this.repo.transition(productId, {
            to: "quarantined",
            reasonCode: "hash_mismatch",
            reason: "队列副本哈希不一致",
            reasonDetail: { expected: product.sha256, actual: h.sha256, stage: "parse" },
            storagePath: filePath,
            storageKind: "queue",
            decided: true,
          });
          this.repo.logEvent({
            productId,
            sha256: product.sha256,
            kind: "hash_mismatch",
            reasonCode: "hash_mismatch",
            summary: "解析前校验失败，文件已移出解析队列",
          });
          return;
        }
      } catch (err) {
        this.repo.setParse(productId, { status: "failed", lastError: err.message });
        return;
      }
    }

    const started = Date.now();
    this.repo.logEvent({
      productId,
      sha256: product.sha256,
      kind: "parse_started",
      summary: `开始解析 ${product.original_name}`,
    });

    try {
      const result = await this.parse(filePath, product.original_name, {
        readFile: async (p) => {
          const size = (await fsp.stat(p)).size;
          if (size > this.cfg.limits.maxFileBytes) {
            throw new ParseError(`解析输入超过上限（${formatBytes(size)}）`);
          }
          return fsp.readFile(p);
        },
      });
      this.repo.saveParseResult(productId, {
        sha256: product.sha256,
        kind: result.kind,
        summary: result.summary,
        payload: result.payload,
        bytesRead: result.bytesRead,
      });
      this.repo.setParse(productId, { status: "ready", lastError: null });
      await this.writeReport(product, result);
      this.stats.parsed += 1;
      this.stats.lastRunAt = nowIso();
      this.repo.logEvent({
        productId,
        sha256: product.sha256,
        kind: "parse_ready",
        summary: `解析完成：${result.summary}`,
        detail: { kind: result.kind, ms: Date.now() - started },
      });
    } catch (err) {
      const unsupported = err instanceof ParseUnsupportedError || err.code === "parse_unsupported";
      if (unsupported) {
        this.stats.unsupported += 1;
        this.repo.setParse(productId, { status: "ready", lastError: err.message });
        this.repo.logEvent({
          productId,
          sha256: product.sha256,
          kind: "parse_unsupported",
          reasonCode: "parse_unsupported",
          summary: `解析器不支持该格式，文件保留在队列中：${err.message}`,
        });
        return;
      }
      // claimParse already counted this attempt; the row we loaded predates it.
      const attempts = product.parse_attempts + 1;
      const max = this.cfg.parse.maxParseAttempts;
      this.stats.failed += 1;
      if (attempts < max) {
        const nextAt = new Date(
          Date.now() + backoffMs(attempts, this.cfg.parse.baseMs, this.cfg.parse.maxMs),
        ).toISOString();
        this.repo.setParse(productId, {
          status: "failed",
          nextRetryAt: nextAt,
          lastError: err.message,
        });
        this.repo.logEvent({
          productId,
          sha256: product.sha256,
          kind: "parse_retry_scheduled",
          reasonCode: "parse_failed",
          summary: `解析失败，将在 ${nextAt} 重试（${attempts}/${max}）：${err.message}`,
          detail: { error: err.message, nextAt },
        });
      } else {
        this.repo.setParse(productId, { status: "failed", lastError: err.message });
        this.repo.transition(productId, {
          to: "quarantined",
          reasonCode: "parse_failed",
          reason: reasonInfo("parse_failed").label,
          reasonDetail: { error: err.message, attempts, stage: "parse" },
          storagePath: filePath,
          storageKind: "queue",
          decided: true,
        });
        this.repo.logEvent({
          productId,
          sha256: product.sha256,
          kind: "parse_failed",
          reasonCode: "parse_failed",
          summary: `解析多次失败（${attempts}/${max}），文件保留在队列中：${err.message}`,
          detail: { error: err.message },
        });
      }
    }
  }

  async writeReport(product, result) {
    const reportPath = path.join(
      this.cfg.outDir,
      `${path.basename(product.storage_path, path.extname(product.storage_path))}.report.json`,
    );
    const report = {
      productId: product.id,
      sha256: product.sha256,
      name: product.original_name,
      sizeBytes: product.size_bytes,
      scannedAt: product.scan_checked_at,
      scan: {
        verdict: product.scan_verdict,
        engine: product.scan_engine,
        signature: product.scan_signature,
      },
      archive: {
        kind: product.archive_kind,
        depth: product.archive_depth,
        members: product.archive_members,
      },
      parse: { kind: result.kind, summary: result.summary },
      payload: result.payload,
      generatedAt: nowIso(),
    };
    const tmp = `${reportPath}.tmp`;
    await fsp.writeFile(tmp, JSON.stringify(report, null, 2));
    await fsp.rename(tmp, reportPath);
    return reportPath;
  }

  snapshot() {
    return {
      running: this.running,
      active: this.active,
      concurrency: this.cfg.parse.concurrency,
      ...this.stats,
    };
  }

  async stop() {
    this.running = false;
    clearTimeout(this.timer);
    // Let current parses finish; they are short and lease-free.
    const deadline = Date.now() + 5000;
    while (this.active > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
}
