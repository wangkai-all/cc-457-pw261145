// The gate: everything that decides whether a file may enter the parse queue.
//
// Stages (each one can park a product in quarantine with a reason code):
//   1. intake     - temp-name / disappearing files are dismissed, the rest are
//                   MOVED into staging so the inbox reflects what we own.
//   2. stability  - wait for a quiet window + no writer; replaced files restart.
//   3. size/hash  - over-limit files get a sampled hash and stop here.
//   4. archive    - nested archive inspection (bomb ratio, traversal, depth).
//   5. scan       - virus scan; unavailability is retryable, not a rejection.
//   6. admit      - move to queue/ and hand to the parser.
//
// Every rejection records the hash (when known) plus reason code and keeps the
// file on disk in quarantine so an operator can release or delete it.

import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

import { newProductId } from "./ids.js";
import { nowIso, backoffMs, sleep, formatBytes } from "./util.js";
import { REASONS, reasonInfo } from "./reasons.js";
import {
  statSample,
  hashFile,
  classifyTempName,
  waitForStable,
  moveNoClobber,
  fsyncDir,
} from "./stability.js";
import { inspectArchive, emptyReport, BLOCKING_ARCHIVE_CODES } from "./archive.js";
import { ScannerUnavailableError } from "./scanner.js";
import { storedName, parseStoredName, dirForKind } from "./db.js";

/** Reasons that are retried automatically after a backoff. */
const AUTO_RETRY_REASONS = new Set([
  "scanner_unavailable",
  "scanner_timeout",
  "scanner_error",
  "unstable_write",
  "archive_inspection_timeout",
]);

export class Pipeline {
  /**
   * @param {object} deps
   * @param {import('./db.js').Repo} deps.repo
   * @param {object} deps.cfg
   * @param {object} deps.scanner  ScannerService
   * @param {(filePath:string, originalName:string, opts:object)=>Promise<object>} deps.parser
   * @param {object} deps.log
   * @param {()=>boolean} [deps.paused]
   */
  constructor({ repo, cfg, scanner, parse, log, paused = () => false }) {
    this.repo = repo;
    this.cfg = cfg;
    this.scanner = scanner;
    this.parse = parse;
    this.log = log;
    this.paused = paused;
    this.inFlight = new Map(); // inbox path -> in-flight intake promise
    this.controllers = new Map(); // inbox path -> AbortController
    this.closed = false;
  }

  /** Pause decision used by the UI maintenance toggle. */
  get isPaused() {
    return this.paused();
  }

  async init() {
    await fsp.mkdir(this.cfg.watchDir, { recursive: true });
    await fsp.mkdir(this.cfg.stagingDir, { recursive: true });
    await fsp.mkdir(this.cfg.quarantineDir, { recursive: true });
    await fsp.mkdir(this.cfg.queueDir, { recursive: true });
    await fsp.mkdir(this.cfg.outDir, { recursive: true });
    await fsp.mkdir(this.cfg.trashDir, { recursive: true });
    await this.recover();
  }

  // -------------------------------------------------------------------------
  // Startup reconciliation
  // -------------------------------------------------------------------------

  /**
   * Recover after a crash/restart:
   *  - parse rows stuck in `running` go back to pending,
   *  - `checking` rows whose staging copy is gone are marked lost (or re-run
   *    from the inbox if the original is still there),
   *  - files in staging with no row are adopted for a fresh check,
   *  - files in quarantine/queue with no row are adopted from their filename.
   */
  async recover() {
    const reset = this.repo.resetRunningParses();
    if (reset) this.repo.logEvent({ kind: "recovered", summary: `${reset} 个解析任务从崩溃中恢复` });

    const checking = this.repo.productsInStates(["checking"]);
    for (const p of checking) {
      const onDisk = p.storage_path ? await statSample(p.storage_path) : null;
      if (!onDisk) {
        const inbox = p.discovered_path;
        if (inbox && (await statSample(inbox))) {
          // The inbox copy survived; re-check from the top.
          this.repo.transition(p.id, {
            to: "checking",
            reasonCode: null,
            reason: null,
            reasonDetail: null,
            storagePath: p.storage_path,
            storageKind: "staging",
            decided: false,
          });
          this.log.info({ id: p.id }, "重启恢复：原文件仍在收件目录，重新检查");
          continue;
        }
        this.repo.transition(p.id, {
          to: "lost",
          reasonCode: "file_missing",
          reason: REASONS.file_missing.label,
          reasonDetail: { stage: "recover" },
          storagePath: null,
          storageKind: null,
          decided: true,
        });
        this.repo.logEvent({
          productId: p.id,
          kind: "lost",
          reasonCode: "file_missing",
          summary: `重启后未找到 ${p.original_name} 的暂存副本`,
        });
        continue;
      }
      // Still on disk: resume the check on the recovered copy.
      this.resumeCheck(p).catch((err) =>
        this.log.error({ id: p.id, err: err.message }, "恢复检查失败"),
      );
    }

    await this.adoptOrphans();
  }

  async adoptOrphans() {
    const known = new Set(
      this.repo
        .productsInStates(["checking", "quarantined", "queued"])
        .map((p) => p.storage_path)
        .filter(Boolean),
    );
    const dirs = [
      ["staging", this.cfg.stagingDir],
      ["quarantine", this.cfg.quarantineDir],
      ["queue", this.cfg.queueDir],
    ];
    let adopted = 0;
    for (const [kind, dir] of dirs) {
      let names = [];
      try {
        names = await fsp.readdir(dir);
      } catch {
        continue;
      }
      for (const name of names) {
        const full = path.join(dir, name);
        if (known.has(full)) continue;
        const st = await statSample(full);
        if (!st || !st.isFile) continue;
        adopted += await this.adoptFile(full, kind);
      }
    }
    if (adopted) {
      this.repo.logEvent({ kind: "recovered", summary: `启动时接管 ${adopted} 个无主文件` });
      this.log.info({ adopted }, "接管无主文件");
    }
    // Products pointing at a storage file that no longer exists.
    for (const p of this.repo.productsInStates(["quarantined", "queued"])) {
      if (!p.storage_path) continue;
      // Only the directory we scanned for orphans can be judged here; a
      // released file legitimately lives outside it.
      const expectedDir = dirForKind(this.cfg, p.storage_kind);
      if (!expectedDir || path.dirname(p.storage_path) !== path.resolve(expectedDir)) continue;
      if (await statSample(p.storage_path)) continue;
      this.repo.transition(p.id, {
        to: "lost",
        reasonCode: "file_missing",
        reason: REASONS.file_missing.label,
        reasonDetail: { storage_path: p.storage_path, stage: "reconcile" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      this.repo.logEvent({
        productId: p.id,
        sha256: p.sha256,
        kind: "lost",
        reasonCode: "file_missing",
        summary: `隔离区/队列中的副本已不存在：${p.original_name}`,
      });
    }
  }

  /** Take ownership of a file found on disk with no database row. */
  async adoptFile(fullPath, kind) {
    const parsed = parseStoredName(path.basename(fullPath));
    if (!parsed || this.repo.getProduct(parsed.id)) return 0;
    const { id, extension } = parsed;
    const st = await statSample(fullPath);
    if (!st) return 0;
    this.repo.insertProduct({
      id,
      sha256: null,
      hash_scope: null,
      original_name: `恢复文件${extension}`,
      extension,
      size_bytes: st.size,
      mtime_ms: st.mtimeMs,
      state: kind === "queue" ? "queued" : kind === "quarantine" ? "quarantined" : "checking",
      parse_status: kind === "queue" ? "pending" : null,
      storage_path: fullPath,
      storage_kind: kind,
      discovered_path: null,
      reason_code: kind === "quarantine" ? "recovered_orphan" : null,
      reason: kind === "quarantine" ? "隔离区无主文件" : null,
      reason_detail: { recovered: true },
    });
    this.repo.logEvent({
      productId: id,
      kind: "adopted",
      summary: `${kind} 中发现无主文件，已接管`,
      detail: { path: fullPath },
    });
    if (kind === "staging") {
      const p = this.repo.getProduct(id);
      this.resumeCheck(p).catch(() => {});
    }
    return 1;
  }

  // -------------------------------------------------------------------------
  // Intake
  // -------------------------------------------------------------------------

  /**
   * Called for each inbox entry we think is ready. Idempotent: repeated fs
   * events for the same path share one in-flight job.
   */
  async intake(inboxPath) {
    if (this.closed) return;
    if (this.isPaused) {
      this.log.debug({ path: inboxPath }, "维护模式：跳过新文件");
      return;
    }
    const key = path.resolve(inboxPath);
    if (this.inFlight.has(key)) return this.inFlight.get(key);

    const ac = new AbortController();
    this.controllers.set(key, ac);
    const job = this.#runIntake(inboxPath, ac.signal)
      .catch((err) => {
        // Rethrow anything that is not an input problem as a loud log line, but
        // keep the service alive: one bad file must never stop the watcher.
        this.log.error({ path: inboxPath, err: err.message, stack: err.stack }, "接收流程异常");
        this.repo.logEvent({
          kind: "error",
          summary: `接收 ${path.basename(inboxPath)} 时发生内部错误`,
          detail: { error: err.message },
        });
      })
      .finally(() => {
        this.inFlight.delete(key);
        this.controllers.delete(key);
      });
    this.inFlight.set(key, job);
    return job;
  }

  async #runIntake(inboxPath, signal) {
    const name = path.basename(inboxPath);
    const first = await statSample(inboxPath);
    if (!first) {
      this.log.debug({ path: inboxPath }, "文件已消失，忽略本次事件");
      return;
    }
    if (!first.isFile) {
      this.repo.logEvent({
        kind: "ignored",
        reasonCode: "temp_file",
        summary: `忽略非普通文件：${name}`,
      });
      return;
    }

    // Re-delivery of a name we already own and are still working on.
    const prior = this.repo.latestByDiscovered(inboxPath);
    if (
      prior &&
      prior.state === "checking" &&
      prior.storage_path === null &&
      prior.size_bytes === first.size &&
      Math.abs((prior.mtime_ms ?? 0) - first.mtimeMs) < 1
    ) {
      // Claimed but not yet moved (crash window or repeated sweep): skip.
      this.log.debug({ id: prior.id, path: inboxPath }, "重复事件：文件已被认领");
      return;
    }
    if (
      prior &&
      ["checking", "quarantined", "queued"].includes(prior.state) &&
      prior.storage_path &&
      (await statSample(prior.storage_path))
    ) {
      // Same name, but is it the same content? Compare cheaply by size+mtime.
      if (prior.size_bytes === first.size && Math.abs((prior.mtime_ms ?? 0) - first.mtimeMs) < 1) {
        this.log.debug({ id: prior.id, path: inboxPath }, "重复事件：已在处理中的同一文件");
        return;
      }
      await this.supersede(prior, first);
    }

    // Temp-named entries that are still being written are ignored without a
    // product row. An old temp-named file is a finished upload with an
    // unfortunate name, so it goes through the normal checks.
    const temp = classifyTempName(name);
    if (temp.temp && Date.now() - first.mtimeMs < this.cfg.limits.tempGraceMs) {
      await this.recordDismissal(inboxPath, name, first, temp.reason);
      return;
    }

    const pid = newProductId();
    const ext = path.extname(name);
    const product = this.repo.insertProduct({
      id: pid,
      sha256: null,
      original_name: name,
      extension: ext,
      size_bytes: first.size,
      mtime_ms: first.mtimeMs,
      state: "checking",
      discovered_path: inboxPath,
      storage_path: null,
      storage_kind: "staging",
      reason_code: temp.temp ? temp.reason : null,
    });
    this.repo.logEvent({
      productId: pid,
      kind: "discovered",
      summary: `发现新文件 ${name}`,
      detail: { size: first.size, path: inboxPath, tempName: temp.temp },
    });

    // Move into staging first so a slow inbox (network share) isn't held open.
    const stagedName = storedName(product);
    const staged = path.join(this.cfg.stagingDir, stagedName);
    try {
      await moveNoClobber(inboxPath, this.cfg.stagingDir, stagedName);
      await fsyncDir(this.cfg.stagingDir);
    } catch (err) {
      if (err.code === "ENOENT" || err.code === "EEXIST") {
        // Gone (or already staged under the same name while we were slow): one
        // of the duplicate intake jobs for this path won. Nothing left to do.
        this.repo.transition(pid, {
          to: "lost",
          reasonCode: "file_missing",
          reason: "文件在接收阶段被移除或已被接管",
          reasonDetail: { stage: "move", error: err.code },
          storagePath: null,
          storageKind: null,
          decided: true,
        });
        this.repo.logEvent({
          productId: pid,
          kind: "lost",
          reasonCode: "file_missing",
          summary: `文件在接收前被移除：${name}`,
          detail: { code: err.code },
        });
        return;
      }
      this.repo.transition(pid, {
        to: "failed_move",
        reasonCode: "file_missing",
        reason: "文件无法移动到暂存区",
        reasonDetail: { stage: "move", error: err.code ?? null },
        storagePath: inboxPath,
        storageKind: "inbox",
        decided: false,
      });
      this.repo.logEvent({
        productId: pid,
        kind: "error",
        summary: `无法把 ${name} 移动到暂存区：${err.message}`,
        detail: { code: err.code ?? null },
      });
      return;
    }
    this.repo.updateLocation(pid, { storagePath: staged, storageKind: "staging" });
    await fsyncDir(this.cfg.watchDir);

    const fp = await statSample(staged);
    if (!fp) {
      this.repo.markLost(pid, "文件在暂存后消失");
      return;
    }
    if (first.ino !== fp.ino && (fp.mtimeMs !== first.mtimeMs || fp.size !== first.size)) {
      // The file changed while we were moving it (writer still active on the
      // original and we copied). The stability pass below will handle it.
      this.log.debug({ id: pid }, "移动后统计信息不同：仍在写入的文件");
    }

    await this.#check(product.id, staged, temp, signal);
  }

  /** A newer file reused the name of an older product still in the pipeline. */
  async supersede(prior, newStat) {
    // A same-size, same-mtime file under the same name is the same delivery;
    // only a genuinely different file counts as a replacement.
    if (prior.size_bytes === newStat.size && Math.abs((prior.mtime_ms ?? 0) - newStat.mtimeMs) < 1) {
      return;
    }
    const sameContent = prior.sha256 ? this.repo.productsBySha(prior.sha256) : [];
    this.repo.logEvent({
      productId: prior.id,
      sha256: prior.sha256,
      kind: "replaced",
      reasonCode: "name_reuse",
      summary: `同名文件被新版本替换：${prior.original_name}`,
      detail: {
        oldSize: prior.size_bytes,
        newSize: newStat.size,
        oldState: prior.state,
        sameContentCopies: sameContent.length,
      },
    });
    // The old copy keeps its own row and state; the new file gets a new row.
    // If the old copy was still being inspected, stop that work - the producer
    // no longer intends it to be processed under this name.
    if (prior.state === "checking" && prior.storage_path) {
      this.controllers.get(path.resolve(prior.discovered_path))?.abort();
    }
  }

  async recordDismissal(inboxPath, name, stat, reasonText) {
    // Sweeps revisit the same temp file every interval; only journal the first
    // sighting of a given (path, size, mtime) so the event feed stays useful.
    const key = `${inboxPath}\u0000${stat.size}\u0000${stat.mtimeMs}`;
    if (!this.dismissed) this.dismissed = new Map();
    if (this.dismissed.has(key)) return;
    if (this.dismissed.size > 2000) this.dismissed.clear();
    this.dismissed.set(key, Date.now());
    this.repo.logEvent({
      kind: "ignored",
      reasonCode: "temp_file",
      summary: `忽略临时文件 ${name}（${reasonText}）`,
      detail: { path: inboxPath, size: stat.size, mtimeMs: stat.mtimeMs },
    });
    this.log.debug({ path: inboxPath, reason: reasonText }, "忽略临时文件");
  }

  // -------------------------------------------------------------------------
  // Checks
  // -------------------------------------------------------------------------

  /** Continue checking a product whose file is already in staging. */
  async resumeCheck(product) {
    await this.#check(product.id, product.storage_path, { temp: false, reason: null }, null, {
      resumed: true,
    });
  }

  async #check(productId, stagedPath, tempInfo, signal, { resumed = false } = {}) {
    const product = this.repo.getProduct(productId);
    if (!product) return;
    const name = product.original_name;

    // 1. Stability ---------------------------------------------------------
    let stat = await statSample(stagedPath);
    if (!stat) {
      this.repo.transition(productId, {
        to: "lost",
        reasonCode: "file_missing",
        reason: REASONS.file_missing.label,
        reasonDetail: { stage: "stability" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      return;
    }
    const stable = await waitForStable(
      stagedPath,
      stat,
      {
        quietMs: resumed ? Math.min(this.cfg.stability.quietMs, 300) : this.cfg.stability.quietMs,
        maxWaitMs: this.cfg.stability.maxWaitMs,
        pollMs: this.cfg.stability.pollMs,
        checkOpenHandles: true,
      },
      signal,
    );

    if (stable.state === "aborted") {
      this.log.debug({ id: productId }, "检查被取消（同名文件已被替换）");
      return;
    }
    if (stable.state === "gone") {
      this.repo.transition(productId, {
        to: "lost",
        reasonCode: "file_missing",
        reason: REASONS.file_missing.label,
        reasonDetail: { stage: "stability" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      return;
    }

    if (stable.state === "replaced") {
      // Another writer replaced the staged copy's inode. Re-run on the new one.
      this.repo.logEvent({
        productId,
        kind: "replaced",
        reasonCode: "unstable_write",
        summary: `暂存副本被替换，重新检查：${name}`,
      });
      if ((await statSample(stagedPath))?.isFile) {
        return this.#check(productId, stagedPath, tempInfo, signal, { resumed: true });
      }
      return;
    }

    if (stable.state === "unstable") {
      return this.#quarantine(productId, stagedPath, "unstable_write", {
        waitedMs: stable.waitedMs,
        size: stable.stat?.size,
      });
    }

    stat = stable.stat ?? (await statSample(stagedPath));
    if (!stat) return;

    // If the producer wrote a temp-named file that has since settled, we still
    // treat it as an attachment - the name was the only suspicious thing.
    if (tempInfo.temp) {
      this.repo.logEvent({
        productId,
        kind: "stable",
        summary: `临时命名的文件已稳定，按正式附件检查：${name}`,
        detail: { tempReason: tempInfo.reason },
      });
    } else {
      this.repo.logEvent({
        productId,
        kind: "stable",
        summary: `文件已稳定（${formatBytes(stat.size)}）`,
        detail: { waitedMs: stable.waitedMs ?? 0 },
      });
    }

    // 2. Size and hash -----------------------------------------------------
    const overLimit = stat.size > this.cfg.limits.maxFileBytes;
    let hash;
    try {
      hash = await hashFile(stagedPath, this.cfg.limits.hashSampleBytes);
    } catch (err) {
      return this.#quarantine(productId, stagedPath, "file_missing", {
        error: err.message,
        stage: "hash",
      });
    }
    this.repo.recordHash(productId, {
      sha256: hash.sha256,
      scope: "full",
      sampleHash: hash.sampleHash,
      size: hash.bytes,
      mtimeMs: hash.mtimeMs,
    });
    const sha = hash.sha256;

    if (overLimit) {
      return this.#quarantine(productId, stagedPath, "too_large", {
        size: stat.size,
        limit: this.cfg.limits.maxFileBytes,
      });
    }

    // 3. Duplicate content -------------------------------------------------
    const seen = this.repo.getSeen(sha);
    if (seen && seen.product_id !== productId) {
      const prior = this.repo.getProduct(seen.product_id);
      // A redelivery of a file that is still being processed by us is a
      // duplicate, not a new task. But if the earlier one is in quarantine for
      // a retryable reason and we are in the retry path, allow this copy to
      // proceed (it may be the operator's second attempt).
      const isRetryCopy =
        prior && AUTO_RETRY_REASONS.has(prior.reason_code) && product.reason_code !== null;
      if (!isRetryCopy) {
        this.repo.noteSeen(sha, productId);
        return this.#quarantine(productId, stagedPath, "duplicate_content", {
          firstProductId: seen.product_id,
          hits: seen.hits + 1,
          firstSeen: seen.first_seen,
        }, { dedupeOf: seen.product_id });
      }
    }
    this.repo.noteSeen(sha, productId);

    // 4. Archive inspection -------------------------------------------------
    let archive = emptyReport();
    if (this.#looksArchival(name, stagedPath)) {
      try {
        archive = await inspectArchive(stagedPath, {
          maxDepth: this.cfg.limits.maxArchiveDepth,
          maxMembers: this.cfg.limits.maxArchiveMembers,
          maxUncompressedBytes: this.cfg.limits.maxArchiveUncompressedBytes,
          maxRatio: this.cfg.limits.maxRatio,
        });
      } catch (err) {
        archive.findings.push({
          code: "archive_unreadable",
          severity: "medium",
          message: err.message,
          detail: null,
        });
      }
      this.repo.recordArchive(productId, archive);
      if (archive.archive) {
        this.repo.logEvent({
          productId,
          sha256: sha,
          kind: "archive_inspected",
          summary: `压缩包检查：${archive.kind}，${archive.members} 个成员，嵌套 ${archive.nestedArchives} 个`,
          detail: {
            kind: archive.kind,
            depth: archive.nestingDepth,
            members: archive.members,
            totalUncompressed: archive.totalUncompressed,
            findings: archive.findings.map((f) => f.code),
          },
        });
      }
      const blocking = archive.findings.filter((f) => BLOCKING_ARCHIVE_CODES.has(f.code));
      if (blocking.length) {
        const primary = blocking[0];
        return this.#quarantine(
          productId,
          stagedPath,
          primary.code,
          { findings: blocking, archive: { kind: archive.kind, members: archive.members } },
          { extraReasons: blocking.slice(1).map((f) => f.code) },
        );
      }
    }

    // 5. Virus scan ---------------------------------------------------------
    await this.#scanAndAdmit(productId, stagedPath, sha, archive);
  }

  #looksArchival(name, stagedPath) {
    const ext = path.extname(name).toLowerCase();
    const archiveExts = new Set([
      ".zip", ".jar", ".war", ".ear", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub",
      ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar", ".cab", ".iso", ".dmg", ".zst",
    ]);
    if (archiveExts.has(ext)) return true;
    return false;
  }

  async #scanAndAdmit(productId, stagedPath, sha, archive) {
    const product = this.repo.getProduct(productId);
    if (!product) return;

    let verdict;
    try {
      verdict = await this.scanner.scan({
        path: stagedPath,
        sha256: sha,
        name: product.original_name,
        size: product.size_bytes,
      });
    } catch (err) {
      if (
        err instanceof ScannerUnavailableError ||
        err.code === "scanner_timeout" ||
        err.code === "scanner_unavailable" ||
        err.retryable === true
      ) {
        this.repo.recordScan(productId, {
          verdict: "error",
          severity: "unknown",
          engine: this.scanner.engineId,
          error: err.message,
        });
        const code =
          err.code === "scanner_timeout" || err.code === "scanner_unavailable"
            ? err.code
            : "scanner_unavailable";
        return this.#quarantine(productId, stagedPath, code, {
          error: err.message,
          engine: this.scanner.engineId,
          detail: err.detail ?? null,
        });
      }
      this.repo.recordScan(productId, {
        verdict: "error",
        severity: "unknown",
        engine: this.scanner.engineId,
        error: err.message,
      });
      return this.#quarantine(productId, stagedPath, "scanner_error", { error: err.message });
    }

    this.repo.recordScan(productId, {
      verdict: verdict.verdict,
      severity: verdict.severity,
      engine: verdict.engine,
      signature: verdict.signature,
      checkedAt: verdict.checkedAt,
    });
    this.repo.logEvent({
      productId,
      sha256: sha,
      kind: verdict.infected ? "scan_infected" : verdict.verdict === "suspicious" ? "scan_suspicious" : "scan_clean",
      summary:
        verdict.verdict === "clean"
          ? `扫描通过（${verdict.engine}）`
          : `扫描判定 ${verdict.verdict}${verdict.signature ? `：${verdict.signature}` : ""}`,
      detail: {
        engine: verdict.engine,
        severity: verdict.severity,
        signature: verdict.signature,
      },
    });

    if (verdict.verdict === "infected") {
      return this.#quarantine(productId, stagedPath, "virus_detected", {
        signature: verdict.signature,
        severity: verdict.severity,
        engine: verdict.engine,
      });
    }
    if (verdict.verdict === "suspicious") {
      return this.#quarantine(productId, stagedPath, "scan_suspicious", {
        signature: verdict.signature,
        severity: verdict.severity,
        engine: verdict.engine,
      });
    }

    // 6. Admit to the parse queue ------------------------------------------
    await this.#admit(productId, stagedPath, sha);
  }

  async #admit(productId, stagedPath, sha) {
    const product = this.repo.getProduct(productId);
    if (!product) return;
    // Verify the staging copy hasn't been swapped since it was hashed. This is
    // cheap relative to parsing and closes the TOCTOU window on the queue.
    let recheck;
    try {
      recheck = await hashFile(stagedPath, this.cfg.limits.hashSampleBytes);
    } catch {
      recheck = null;
    }
    if (!recheck || recheck.sha256 !== sha) {
      return this.#quarantine(productId, stagedPath, "hash_mismatch", {
        expected: sha,
        actual: recheck?.sha256 ?? null,
      });
    }

    const finalName = path.basename(stagedPath);
    const queuedPath = path.join(this.cfg.queueDir, finalName);
    try {
      await moveNoClobber(stagedPath, this.cfg.queueDir, finalName);
      await fsyncDir(this.cfg.queueDir);
    } catch (err) {
      if (err.code === "EEXIST") {
        // Already queued under the same content name (possible after a crash
        // between move and DB write). Adopt the existing file.
        this.repo.updateLocation(productId, { storagePath: queuedPath, storageKind: "queue" });
      } else {
        throw err;
      }
    }
    this.repo.transition(productId, {
      to: "queued",
      reasonCode: null,
      reason: null,
      reasonDetail: null,
      storagePath: queuedPath,
      storageKind: "queue",
      decided: true,
    });
    this.repo.setParse(productId, { status: "pending" });
    this.repo.logEvent({
      productId,
      sha256: sha,
      kind: "queued",
      summary: `已完成稳定性与安全检查，进入解析队列：${product.original_name}`,
      detail: { path: queuedPath },
    });
    this.log.info({ id: productId, sha }, "进入解析队列");
    this.onAdmitted?.(productId);
    this.onQueued?.();
  }


  // -------------------------------------------------------------------------
  // Quarantine
  // -------------------------------------------------------------------------

  /**
   * Park a file in quarantine with a reason. The file is moved, not copied, so
   * there is exactly one copy; the hash (if computed) is kept on the row. When
   * the file is already gone, the row is still recorded.
   */
  async #quarantine(productId, currentPath, code, detail = {}, { extraReasons = [], dedupeOf = null } = {}) {
    const info = reasonInfo(code);
    const product = this.repo.getProduct(productId);
    if (!product) return;
    const sha = product.sha256 ?? null;
    let storagePath = currentPath;
    let storageKind = "staging";

    if (currentPath && (await statSample(currentPath))) {
      const baseName = path.basename(currentPath);
      try {
        storagePath = path.join(this.cfg.quarantineDir, baseName);
        await moveNoClobber(currentPath, this.cfg.quarantineDir, baseName);
        await fsyncDir(this.cfg.quarantineDir);
        storageKind = "quarantine";
      } catch (err) {
        if (err.code === "EEXIST") {
          storagePath = path.join(this.cfg.quarantineDir, baseName);
          storageKind = "quarantine";
          // The staged copy is now redundant; drop it.
          await fsp.unlink(currentPath).catch(() => {});
        } else {
          this.log.error({ id: productId, err: err.message }, "隔离移动失败");
        }
      }
    } else {
      storagePath = null;
      storageKind = null;
    }

    this.repo.transition(productId, {
      to: "quarantined",
      reasonCode: code,
      reason: info.label,
      reasonDetail: {
        ...detail,
        retryable: info.retryable,
        severity: info.severity,
        extraReasons,
        quarantinedAt: nowIso(),
      },
      storagePath,
      storageKind,
      decided: true,
    });
    this.repo.logEvent({
      productId,
      sha256: sha,
      kind: "quarantined",
      reasonCode: code,
      summary: `已隔离：${info.label}`,
      detail: { ...detail, extraReasons },
    });
    this.log.warn({ id: productId, code, reason: info.label }, "文件被隔离");

    if (AUTO_RETRY_REASONS.has(code) && info.retryable) {
      this.scheduleRetry(productId, "gate", code);
    }
    this.onQuarantined?.(productId, code);
  }

  /** Record a retry slot so a transient failure is re-attempted after backoff. */
  scheduleRetry(productId, stage, reasonCode) {
    const product = this.repo.getProduct(productId);
    if (!product) return;
    const key = `${stage}:${productId}`;
    const prior = this.repo.getRetry(key);
    const attempts = (prior?.attempts ?? 0) + 1;
    const max = stage === "gate" ? this.cfg.scan.retry.maxAttempts : this.cfg.parse.maxParseAttempts;
    const base = stage === "gate" ? this.cfg.scan.retry.baseMs : this.cfg.parse.baseMs;
    const cap = stage === "gate" ? this.cfg.scan.retry.maxMs : this.cfg.parse.maxMs;
    const nextAt = new Date(Date.now() + backoffMs(attempts, base, cap)).toISOString();
    this.repo.putRetry({
      key,
      stage,
      sha256: product.sha256 ?? "",
      productId,
      attempts,
      maxAttempts: max,
      nextAt,
      lastError: reasonCode,
    });
    this.repo.logEvent({
      productId,
      sha256: product.sha256,
      kind: "retry_scheduled",
      reasonCode,
      summary:
        attempts > max
          ? `自动重试已达上限（${max} 次），等待人工处理`
          : `将在 ${nextAt} 自动重试（第 ${attempts}/${max} 次）`,
      detail: { attempts, max, nextAt, stage },
    });
  }

  /** Re-run the gate for a quarantined product that is retryable. */
  async retryProduct(productId, { manual = false } = {}) {
    const product = this.repo.getProduct(productId);
    if (!product) throw new NotFoundError("文件不存在");
    if (product.state !== "quarantined") {
      throw new ConflictError(
        product.state === "queued" ? "文件已在解析队列中" : "只有隔离中的文件可以重试",
      );
    }
    if (!product.reason_detail?.retryable) {
      // Re-running a deterministic rejection (virus, oversize, traversal) only
      // burns resources and cannot change the outcome.
      throw new ConflictError(`该原因（${reasonInfo(product.reason_code).label}）不支持重试`);
    }
    if (!product.storage_path) throw new ConflictError("隔离副本已不存在，无法重试");
    if (!(await statSample(product.storage_path))) {
      this.repo.transition(productId, {
        to: "lost",
        reasonCode: "file_missing",
        reason: REASONS.file_missing.label,
        reasonDetail: { stage: "retry" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      throw new ConflictError("隔离副本已不存在");
    }
    // Move it back to staging and re-run from the stability step.
    const base = path.basename(product.storage_path);
    let staged;
    try {
      staged = path.join(this.cfg.stagingDir, base);
      await moveNoClobber(product.storage_path, this.cfg.stagingDir, base);
    } catch (err) {
      if (err.code === "EEXIST") {
        staged = path.join(this.cfg.stagingDir, base);
        await fsp.unlink(product.storage_path).catch(() => {});
      } else {
        throw err;
      }
    }
    this.repo.transition(productId, {
      to: "checking",
      reasonCode: null,
      reason: null,
      reasonDetail: null,
      storagePath: staged,
      storageKind: "staging",
      decided: false,
    });
    this.repo.clearRetry(`gate:${productId}`);
    this.repo.logEvent({
      productId,
      sha256: product.sha256,
      kind: "retry_started",
      summary: manual ? "人工触发重试，重新执行稳定性与安全检查" : "自动重试，重新执行稳定性与安全检查",
      detail: { previousReason: product.reason_code },
    });
    this.resumeCheck(this.repo.getProduct(productId)).catch((err) =>
      this.log.error({ id: productId, err: err.message }, "重试失败"),
    );
    return this.repo.getProduct(productId);
  }

  /** Process due retry rows. Called by the scheduler. */
  async processDueRetries() {
    if (this.isPaused) return;
    const due = this.repo.dueRetries(10);
    for (const r of due) {
      const product = this.repo.getProduct(r.product_id);
      if (!product) {
        this.repo.clearRetry(r.key);
        continue;
      }
      if (product.state !== "quarantined") {
        // The product moved on for another reason; drop the stale retry.
        this.repo.clearRetry(r.key);
        continue;
      }
      if (r.stage !== "gate") continue;
      if (r.attempts > r.max_attempts) {
        // Out of attempts: leave it quarantined, stop rescheduling.
        this.repo.clearRetry(r.key);
        this.repo.logEvent({
          productId: product.id,
          sha256: product.sha256,
          kind: "retry_exhausted",
          reasonCode: product.reason_code,
          summary: `自动重试已用尽（${r.attempts - 1}/${r.max_attempts}），保留在隔离区等待人工处理`,
        });
        continue;
      }
      // For scanner failures, don't beat on a service that is still down.
      if (
        ["scanner_unavailable", "scanner_timeout"].includes(product.reason_code) &&
        !this.scanner.snapshot().available
      ) {
        // Push the retry out instead of consuming an attempt.
        this.repo.putRetry({
          ...r,
          key: r.key,
          stage: r.stage,
          sha256: r.sha256,
          productId: r.product_id,
          attempts: r.attempts - 1,
          maxAttempts: r.max_attempts,
          nextAt: new Date(Date.now() + this.cfg.scan.retry.circuitOpenMs).toISOString(),
          lastError: r.last_error,
        });
        continue;
      }
      try {
        await this.retryProduct(product.id);
      } catch (err) {
        this.log.warn({ id: product.id, err: err.message }, "自动重试未能启动");
      }
    }
  }

  // -------------------------------------------------------------------------
  // Operator actions
  // -------------------------------------------------------------------------

  /**
   * Release a quarantined product. The operator supplies a destination
   * directory (or the default release dir); the file is moved there and the
   * row records who/where. Never overwrites.
   */
  async release(productId, { targetDir, actor = "operator", note = "" } = {}) {
    const product = this.repo.getProduct(productId);
    if (!product) throw new NotFoundError("文件不存在");
    if (product.state !== "quarantined" && product.state !== "queued") {
      throw new ConflictError(`当前状态（${product.state}）不支持释放`);
    }
    if (!product.storage_path) throw new ConflictError("磁盘上的副本已不存在");
    const st = await statSample(product.storage_path);
    if (!st) {
      this.repo.transition(productId, {
        to: "lost",
        reasonCode: "file_missing",
        reason: REASONS.file_missing.label,
        reasonDetail: { stage: "release" },
        storagePath: null,
        storageKind: null,
        decided: true,
      });
      throw new ConflictError("磁盘上的副本已不存在");
    }
    // Never release a copy whose bytes don't match what we checked.
    if (product.sha256) {
      const h = await hashFile(product.storage_path, this.cfg.limits.hashSampleBytes);
      if (h.sha256 !== product.sha256) {
        this.repo.transition(productId, {
          to: "quarantined",
          reasonCode: "hash_mismatch",
          reason: REASONS.hash_mismatch.label,
          reasonDetail: {
            expected: product.sha256,
            actual: h.sha256,
            stage: "release",
            retryable: REASONS.hash_mismatch.retryable,
            severity: REASONS.hash_mismatch.severity,
            quarantinedAt: nowIso(),
          },
          storagePath: product.storage_path,
          storageKind: product.storage_kind,
          decided: true,
        });
        this.repo.logEvent({
          productId,
          sha256: product.sha256,
          kind: "hash_mismatch",
          reasonCode: "hash_mismatch",
          summary: "释放前校验失败：副本内容与记录不一致",
          detail: { expected: product.sha256, actual: h.sha256 },
        });
        throw new ConflictError("副本内容校验失败，已重新隔离");
      }
    }

    const dir = targetDir ? path.resolve(targetDir) : path.join(this.cfg.dataDir, "released");
    await fsp.mkdir(dir, { recursive: true });
    const destName = uniqueName(dir, product.original_name);
    let dest;
    try {
      dest = await moveNoClobber(product.storage_path, dir, destName);
    } catch (err) {
      if (err.code === "EEXIST") throw new ConflictError("目标目录存在同名文件");
      throw err;
    }
    this.repo.transition(productId, {
      to: "released",
      reasonCode: null,
      reason: "人工放行",
      reasonDetail: {
        releasedBy: actor,
        note,
        previousReason: product.reason_code,
        releasedAt: nowIso(),
      },
      storagePath: dest,
      storageKind: "released",
      decided: true,
    });
    this.repo.setReleaseTarget(productId, dest);
    this.repo.clearRetry(`gate:${productId}`);
    this.repo.logEvent({
      productId,
      sha256: product.sha256,
      kind: "released",
      summary: `人工放行到 ${dest}`,
      detail: { actor, note, previousReason: product.reason_code, dest },
    });
    return this.repo.getProduct(productId);
  }

  /**
   * Delete a product's on-disk copy. The row always survives (state=deleted)
   * with its hash and reason, so the audit trail is intact either way.
   * - default: move the copy into trash/, where retention can recover it;
   * - hard: also unlink the trashed copy and clear the dedupe marker, so a
   *   later redelivery of the same bytes is processed as a new file.
   */
  async remove(productId, { actor = "operator", note = "", hard = false } = {}) {
    const product = this.repo.getProduct(productId);
    if (!product) throw new NotFoundError("文件不存在");
    if (product.state === "deleted") return product;
    if (product.state === "checking") throw new ConflictError("文件正在检查中，请稍后再删除");

    let trashed = null;
    if (product.storage_path) {
      const exists = await statSample(product.storage_path);
      if (exists) {
        const base = path.basename(product.storage_path);
        try {
          trashed = await moveNoClobber(product.storage_path, this.cfg.trashDir, base);
        } catch (err) {
          if (err.code === "EEXIST") {
            await fsp.unlink(product.storage_path).catch(() => {});
          } else {
            throw err;
          }
        }
      }
    }
    if (hard) {
      if (trashed) await fsp.unlink(trashed).catch(() => {});
      // Remove the dedupe marker so a fresh delivery is processed again.
      if (product.sha256) this.repo.clearSeen(product.sha256);
    }
    this.repo.markDeleted(productId);
    this.repo.clearRetry(`gate:${productId}`);
    this.repo.clearRetriesForProduct(productId);
    this.repo.logEvent({
      productId,
      sha256: product.sha256,
      kind: "deleted",
      summary: hard ? "已彻底删除（含去重记录）" : "已删除，副本移入回收区",
      detail: { actor, note, previousState: product.state, trashed, hard },
    });
    return this.repo.getProduct(productId);
  }
}

export function uniqueName(dir, wanted) {
  const ext = path.extname(wanted);
  const stem = path.basename(wanted, ext);
  // Path separators in a producer-supplied name must not escape the directory.
  const safeStem = stem.replace(/[/\\\0]/g, "_").slice(0, 180) || "file";
  return `${safeStem}${ext.toLowerCase()}`;
}

export class NotFoundError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "NotFoundError";
    this.status = 404;
  }
}

export class ConflictError extends Error {
  constructor(msg) {
    super(msg);
    this.name = "ConflictError";
    this.status = 409;
  }
}
