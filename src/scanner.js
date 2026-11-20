// Virus-scan abstraction with availability tracking.
//
// Two engines ship:
//   mock      - deterministic by content hash; can be told to fail/unavailable.
//   external  - runs a command that prints a JSON verdict.
// Both are wrapped in an availability gate (circuit breaker) so a dead scanner
// puts scans into a bounded retry path instead of quarantining good files.

import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { nowIso } from "./util.js";

export class ScannerUnavailableError extends Error {
  constructor(message, detail) {
    super(message);
    this.name = "ScannerUnavailableError";
    this.code = "scanner_unavailable";
    this.detail = detail ?? null;
    this.retryable = true;
  }
}

export class ScannerTimeoutError extends Error {
  constructor(message) {
    super(message);
    this.name = "ScannerTimeoutError";
    this.code = "scanner_timeout";
    this.retryable = true;
  }
}

const MOCK_SIGNATURES = [
  "EICAR-Test-File",
  "Win.Test.Mock.Dropper",
  "Trojan.Mock.Agent",
  "Script.Mock.Macro",
  "PUA.Mock.Adware",
];

/**
 * Deterministic mock engine. The verdict is a pure function of the file hash and
 * the configured infected rate, so repeated scans of the same content agree -
 * which is what makes the retry path testable.
 */
export class MockScanner {
  constructor(opts = {}) {
    this.id = opts.id ?? "mock-scanner/1.0";
    this.latencyMs = opts.latencyMs ?? 40;
    this.infectedRate = opts.infectedRate ?? 0.08;
    this.suspiciousRate = opts.suspiciousRate ?? 0.04;
    this.unavailable = opts.unavailable ?? false;
    this.failTimes = opts.failTimes ?? 0;
    this.calls = 0;
    this.failuresLeft = 0;
  }

  setUnavailable(flag) {
    this.unavailable = Boolean(flag);
    this.failuresLeft = 0;
  }

  /** Make the next N scans throw (transient outage simulation). */
  failNext(n) {
    this.failuresLeft = Math.max(0, n);
  }

  async probe() {
    if (this.unavailable) {
      throw new ScannerUnavailableError("扫描服务不可用（模拟）", { engine: this.id });
    }
    return { ok: true };
  }

  async scan({ sha256, name, size }) {
    this.calls += 1;
    if (this.latencyMs) await new Promise((r) => setTimeout(r, this.latencyMs));
    if (this.unavailable) {
      throw new ScannerUnavailableError("扫描服务不可用（模拟）", { engine: this.id });
    }
    if (this.failuresLeft > 0) {
      this.failuresLeft -= 1;
      throw new ScannerUnavailableError("扫描服务暂时无响应（模拟故障）", {
        engine: this.id,
        remaining: this.failuresLeft,
      });
    }
    const h = crypto.createHash("sha256").update(sha256).digest();
    const roll = h.readUInt32BE(0) / 0x100000000;
    const infected = roll < this.infectedRate;
    // Stable per content, and only ever a fraction of the clean population.
    const suspicious = !infected && h[4] / 256 < this.suspiciousRate;
    const severity = infected ? (h[5] % 2 ? "high" : "critical") : suspicious ? "medium" : "none";
    const signature = infected
      ? `${MOCK_SIGNATURES[h[6] % MOCK_SIGNATURES.length]}.${(h[7] % 90) + 10}`
      : suspicious
        ? "Heuristic.Mock.Suspicious"
        : null;
    return {
      verdict: infected ? "infected" : suspicious ? "suspicious" : "clean",
      severity,
      engine: this.id,
      signature,
      checkedAt: nowIso(),
      raw: { name, size, roll: Number(roll.toFixed(6)), simulated: true },
    };
  }
}

/** Runs an external command; expects one JSON object on stdout. */
export class ExternalScanner {
  constructor({ command, args = [], timeoutMs = 60_000, id = "external-scanner" }) {
    this.id = id;
    this.command = command;
    this.args = args;
    this.timeoutMs = timeoutMs;
  }

  async probe() {
    // A real probe would be a version/health command; we treat "command exists"
    // as healthy and let the scan call report failures.
    if (!this.command) throw new ScannerUnavailableError("未配置扫描命令");
    return { ok: true };
  }

  scan({ path, sha256, name, size }) {
    const argv = this.args.map((a) =>
      a.replaceAll("{path}", path).replaceAll("{sha256}", sha256).replaceAll("{name}", name),
    );
    return new Promise((resolve, reject) => {
      const child = spawn(this.command, argv, { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new ScannerTimeoutError(`扫描超时（${this.timeoutMs} ms）`));
      }, this.timeoutMs);
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(
          new ScannerUnavailableError(`无法启动扫描程序：${e.message}`, { engine: this.id }),
        );
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code === 75) {
          reject(new ScannerUnavailableError(`扫描服务不可用（exit 75）`, { engine: this.id, stderr: err }));
          return;
        }
        if (code !== 0) {
          reject(
            new ScannerUnavailableError(`扫描程序退出码 ${code}`, {
              engine: this.id,
              stderr: err.slice(0, 500),
            }),
          );
          return;
        }
        let parsed;
        try {
          parsed = JSON.parse(out);
        } catch {
          reject(
            new ScannerUnavailableError("扫描程序输出不是合法 JSON", {
              engine: this.id,
              stdout: out.slice(0, 500),
            }),
          );
          return;
        }
        resolve(normalizeVerdict(parsed, this.id, { path, sha256, name, size }));
      });
    });
  }
}

export function normalizeVerdict(v, engineId, ctx) {
  const verdictRaw = String(v.verdict ?? v.status ?? "").toLowerCase();
  const verdict =
    verdictRaw === "infected" || verdictRaw === "malicious" || verdictRaw === "virus"
      ? "infected"
      : verdictRaw === "suspicious" || verdictRaw === "heuristic"
        ? "suspicious"
        : verdictRaw === "clean" || verdictRaw === "ok"
          ? "clean"
          : null;
  if (!verdict) {
    throw new ScannerUnavailableError(`扫描结果无法识别：${verdictRaw || "(空)"}`, {
      engine: engineId,
      raw: v,
    });
  }
  return {
    verdict,
    severity: String(v.severity ?? (verdict === "infected" ? "high" : "none")).toLowerCase(),
    engine: String(v.engine ?? engineId),
    signature: v.signature ?? v.threat ?? null,
    checkedAt: v.checkedAt ?? nowIso(),
    raw: v,
  };
}

/**
 * Availability gate around any engine.
 *
 * - consecutive failures trip a breaker; while open, scans fail fast with a
 *   retryable ScannerUnavailableError instead of waiting on a dead service.
 -  a successful scan closes it again.
 */
export class ScannerService {
  constructor({ engine, repo, cfg, log }) {
    this.engine = engine;
    this.repo = repo;
    this.cfg = cfg;
    this.log = log;
    this.state = {
      available: true,
      consecutiveFailures: 0,
      openedAt: null,
      lastError: null,
      lastOkAt: null,
      lastCheckAt: null,
    };
    const persisted = repo?.getScannerState();
    if (persisted && !persisted.available) {
      this.state.available = false;
      this.state.consecutiveFailures = persisted.consecutive_failures ?? 1;
      this.state.openedAt = persisted.opened_at;
      this.state.lastError = persisted.last_error;
      this.state.lastOkAt = persisted.last_ok_at;
      this.state.lastCheckAt = persisted.last_check_at;
    }
  }

  get engineId() {
    return this.engine.id ?? this.cfg.scan.scannerId;
  }

  snapshot() {
    return {
      ...this.state,
      engine: this.engineId,
      mode: this.cfg.scan.mode,
      openUntil: this.state.openedAt
        ? new Date(Date.parse(this.state.openedAt) + this.cfg.scan.retry.circuitOpenMs).toISOString()
        : null,
    };
  }

  #persist() {
    this.repo?.setScannerState(this.state);
  }

  /** True when the breaker should let a call through. */
  #circuitAllows() {
    if (this.state.available) return true;
    if (!this.state.openedAt) return true;
    const elapsed = Date.now() - Date.parse(this.state.openedAt);
    // Half-open: allow a probe once the cool-down has passed.
    return elapsed >= this.cfg.scan.retry.circuitOpenMs;
  }

  #recordFailure(err) {
    this.state.consecutiveFailures += 1;
    this.state.lastError = err.message;
    this.state.lastCheckAt = nowIso();
    if (this.state.consecutiveFailures >= this.cfg.scan.retry.circuitFailThreshold) {
      if (this.state.available) {
        this.state.available = false;
        this.state.openedAt = nowIso();
        this.log?.warn(
          { err: err.message, failures: this.state.consecutiveFailures },
          "扫描服务熔断：后续扫描进入重试队列",
        );
      }
    }
    this.#persist();
  }

  #recordSuccess() {
    const wasDown = !this.state.available;
    this.state.available = true;
    this.state.consecutiveFailures = 0;
    this.state.openedAt = null;
    this.state.lastError = null;
    this.state.lastOkAt = nowIso();
    this.state.lastCheckAt = nowIso();
    this.#persist();
    if (wasDown) this.log?.info("扫描服务已恢复");
  }

  /**
   * Scan a staged file. Throws only retryable errors; a bad verdict is a
   * successful call.
   */
  async scan(input) {
    if (!this.#circuitAllows()) {
      throw new ScannerUnavailableError(
        `扫描服务熔断中（自 ${this.state.openedAt}）`,
        { engine: this.engineId, lastError: this.state.lastError },
      );
    }
    try {
      const res = await this.engine.scan(input);
      const severity = res.severity ?? "none";
      const infected =
        res.verdict === "infected" ||
        (res.verdict !== "clean" && this.cfg.scan.infectedSeverities.includes(severity));
      this.#recordSuccess();
      return { ...res, infected };
    } catch (err) {
      const retryable =
        err instanceof ScannerUnavailableError ||
        err instanceof ScannerTimeoutError ||
        err.retryable === true;
      if (!retryable) throw err;
      this.#recordFailure(err);
      throw err;
    }
  }

  /** Operator/test override: force the breaker open or closed. */
  setAvailable(available, reason = null) {
    if (available) {
      this.#recordSuccess();
    } else {
      const wasAvailable = this.state.available;
      this.state.available = false;
      this.state.openedAt = this.state.openedAt ?? nowIso();
      this.state.lastError = reason ?? this.state.lastError ?? "手动标记为不可用";
      this.state.lastCheckAt = nowIso();
      if (wasAvailable) this.state.consecutiveFailures = Math.max(1, this.state.consecutiveFailures);
      this.#persist();
      this.log?.warn({ reason }, "扫描服务被标记为不可用");
    }
    return this.snapshot();
  }

  /** Half-open probe used by the health loop while the breaker is open. */
  async probe() {
    if (!this.#circuitAllows()) return false;
    try {
      await this.engine.probe();
      this.#recordSuccess();
      return true;
    } catch (err) {
      this.#recordFailure(err);
      return false;
    }
  }
}

export function buildEngine(cfg) {
  const mode =
    cfg.scan.mode === "auto" ? (cfg.scan.external.command ? "external" : "mock") : cfg.scan.mode;
  if (mode === "external") {
    return new ExternalScanner({
      command: cfg.scan.external.command,
      args: cfg.scan.external.args,
      timeoutMs: cfg.scan.external.timeoutMs,
      id: cfg.scan.scannerId,
    });
  }
  return new MockScanner({
    id: cfg.scan.scannerId,
    latencyMs: cfg.scan.mock.latencyMs,
    infectedRate: cfg.scan.mock.infectedRate,
    suspiciousRate: cfg.scan.mock.suspiciousRate,
    unavailable: cfg.scan.mock.unavailable,
    failTimes: cfg.scan.mock.failTimes,
  });
}
