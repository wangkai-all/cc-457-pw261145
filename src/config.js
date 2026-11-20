// Configuration. Every value can be overridden with an environment variable so
// the service can be re-tuned per deployment without code changes.

import path from "node:path";

function envStr(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function envInt(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < min || n > max) {
    throw new Error(`环境变量 ${name}=${raw} 无效，应为 ${min}..${max} 之间的整数`);
  }
  return n;
}

function envBool(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return ["1", "true", "yes", "on"].includes(raw.toLowerCase());
}

export function loadConfig(overrides = {}) {
  const ov = overrides && typeof overrides === "object" ? overrides : {};
  const dataDir = path.resolve(
    ov.dataDir ?? envStr("INBOX_DATA_DIR", path.join(process.cwd(), "data")),
  );
  const scanMode = ov.scan?.mode ?? envStr("SCAN_MODE", "auto"); // auto | mock | external
  // Derived directories follow dataDir unless explicitly overridden.
  const dir = (overrideKey, envKey, name) =>
    path.resolve(ov[overrideKey] ?? envStr(envKey, path.join(dataDir, name)));
  const cfg = {
    port: envInt("PORT", 4173, { min: 0, max: 65535 }),
    host: envStr("HOST", "127.0.0.1"),
    dataDir,

    watchDir: dir("watchDir", "WATCH_DIR", "inbox"),
    // In-flight copies and hashing; never read by the parser.
    stagingDir: dir("stagingDir", "STAGING_DIR", "staging"),
    // Depending on stability + scan verdict a file lands in one of these.
    quarantineDir: dir("quarantineDir", "QUARANTINE_DIR", "quarantine"),
    // Only the parse queue reads from here; nothing else writes to it.
    queueDir: dir("queueDir", "QUEUE_DIR", "queue"),
    // Outcomes are written as report files for downstream consumers.
    outDir: dir("outDir", "OUT_DIR", "out"),
    // Trash holds files removed from the queue/staging by an operator action, so
    // it is recoverable until retention sweeps it.
    trashDir: dir("trashDir", "TRASH_DIR", "trash"),
    dbPath: dir("dbPath", "DB_PATH", "inbox-guard.sqlite3"),

    stability: {
      // A file must be quiet (size+mtime unchanged) this long before we look.
      quietMs: envInt("STABILITY_QUIET_MS", 1500, { min: 100 }),
      // Absolute budget; a file that never settles is quarantined as unstable.
      maxWaitMs: envInt("STABILITY_MAX_WAIT_MS", 10 * 60_000, { min: 1000 }),
      pollMs: envInt("STABILITY_POLL_MS", 250, { min: 25 }),
    },

    limits: {
      maxFileBytes: envInt("MAX_FILE_BYTES", 64 * 1024 * 1024, { min: 1 }),
      maxArchiveDepth: envInt("MAX_ARCHIVE_DEPTH", 3, { min: 0 }),
      maxArchiveMembers: envInt("MAX_ARCHIVE_MEMBERS", 2000, { min: 1 }),
      maxArchiveUncompressedBytes: envInt(
        "MAX_ARCHIVE_UNCOMPRESSED_BYTES",
        512 * 1024 * 1024,
        { min: 1 },
      ),
      maxRatio: envInt("MAX_ARCHIVE_RATIO", 120, { min: 1 }),
      // Housekeeping: drop activity rows older than this.
      eventRetentionMs: envInt("EVENT_RETENTION_MS", 30 * 24 * 3600_000, { min: 60_000 }),
      // Debounce window for repeated fs events on the same path.
      eventDebounceMs: envInt("EVENT_DEBOUNCE_MS", 120, { min: 0 }),
      // Files whose name says "still being written" but didn't change for this
      // long are given one stability pass before being dismissed as temp.
      tempGraceMs: envInt("TEMP_GRACE_MS", 30_000, { min: 0 }),
      // Reconciliation sweep of the inbox, independent of fs events.
      sweepIntervalMs: envInt("SWEEP_INTERVAL_MS", 15_000, { min: 1000 }),
      // Head/tail bytes used for the cheap "same content?" digest.
      hashSampleBytes: envInt("HASH_SAMPLE_BYTES", 64 * 1024, { min: 1024 }),
    },

    scan: {
      mode: scanMode,
      // Mock scanner knobs - also usable as the fallback when a real scanner is down.
      mock: {
        latencyMs: envInt("SCAN_MOCK_LATENCY_MS", 60, { min: 0 }),
        // Probability a file is reported infected (deterministic by hash seed if 0/1).
        infectedRate: Number(envStr("SCAN_MOCK_INFECTED_RATE", "0.08")),
        // Probability of a "suspicious" (heuristic) verdict for clean files.
        suspiciousRate: Number(envStr("SCAN_MOCK_SUSPICIOUS_RATE", "0.04")),
        unavailable: envBool("SCAN_MOCK_UNAVAILABLE", false),
        // Consecutive failures after which the mock "recovers" (undefined = stays down).
        failTimes: envInt("SCAN_MOCK_FAIL_TIMES", 0, { min: 0 }),
      },
      external: {
        // Optional real scanner: a command that prints a JSON verdict to stdout.
        // `{path}` is substituted with the staged copy's path.
        command: envStr("SCAN_CMD", ""),
        args: envStr("SCAN_ARGS", "").split(" ").filter(Boolean),
        timeoutMs: envInt("SCAN_TIMEOUT_MS", 60_000, { min: 100 }),
      },
      retry: {
        maxAttempts: envInt("SCAN_MAX_ATTEMPTS", 3, { min: 1 }),
        baseMs: envInt("SCAN_RETRY_BASE_MS", 1000, { min: 10 }),
        maxMs: envInt("SCAN_RETRY_MAX_MS", 30_000, { min: 100 }),
        circuitOpenMs: envInt("SCAN_CIRCUIT_OPEN_MS", 30_000, { min: 100 }),
        circuitFailThreshold: envInt("SCAN_CIRCUIT_FAILS", 2, { min: 1 }),
      },
      scannerId: envStr("SCAN_ID", "mock-scanner/1.0"),
      // Verdicts at or above this severity are treated as infected.
      infectedSeverities: (envStr("SCAN_INFECTED_SEVERITIES", "high,critical") || "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    },

    parse: {
      concurrency: envInt("PARSE_CONCURRENCY", 2, { min: 1 }),
      // Failures of this kind mean "try again later", not "reject".
      retryableKinds: ["scanner_unavailable", "scanner_timeout", "parser_busy", "internal"],
      maxParseAttempts: envInt("PARSE_MAX_ATTEMPTS", 3, { min: 1 }),
      baseMs: envInt("PARSE_RETRY_BASE_MS", 1000, { min: 10 }),
      maxMs: envInt("PARSE_RETRY_MAX_MS", 60_000, { min: 100 }),
      pollMs: envInt("PARSE_POLL_MS", 700, { min: 50 }),
      leaseMs: envInt("PARSE_LEASE_MS", 120_000, { min: 1000 }),
    },

    ui: {
      pageSize: envInt("UI_PAGE_SIZE", 50, { min: 5, max: 500 }),
      refreshMs: envInt("UI_REFRESH_MS", 5000, { min: 1000 }),
      // Directory occupancy thresholds, as a fraction of the max watch-dir budget.
      waterlineBudgetBytes: envInt("WATERLINE_BUDGET_BYTES", 2 * 1024 * 1024 * 1024, { min: 1 }),
      warningPct: Number(envStr("WATERLINE_WARNING_PCT", "70")),
      criticalPct: Number(envStr("WATERLINE_CRITICAL_PCT", "90")),
      recentEvents: envInt("UI_RECENT_EVENTS", 40, { min: 1, max: 500 }),
    },
  };

  if (!["auto", "mock", "external"].includes(cfg.scan.mode)) {
    throw new Error(`SCAN_MODE=${cfg.scan.mode} 无效（auto|mock|external）`);
  }
  if (cfg.scan.mode === "external" && !cfg.scan.external.command) {
    throw new Error("SCAN_MODE=external 需要配置 SCAN_CMD");
  }
  return deepMerge(cfg, overrides);
}

/** Merge nested plain objects; everything else (arrays, scalars) replaces. */
function deepMerge(base, patch) {
  if (!isPlainObject(patch)) return base;
  const out = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    out[k] = isPlainObject(v) && isPlainObject(base[k]) ? deepMerge(base[k], v) : v;
  }
  return out;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
