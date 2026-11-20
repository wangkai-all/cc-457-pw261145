// Schema + thin data-access layer over node:sqlite.
//
// The database is the source of truth for file state. Directory moves happen
// first and are then recorded, so a crash is always reconcilable by re-walking
// the staging directory and re-running the checks for `checking` rows.

import { DatabaseSync } from "node:sqlite";
import fsp from "node:fs/promises";
import path from "node:path";
import { nowIso } from "./util.js";

const SCHEMA_VERSION = 1;

const DDL = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- One row per observed product (a file as it entered the pipeline).
CREATE TABLE IF NOT EXISTS products (
  id                TEXT PRIMARY KEY,
  sha256            TEXT,                 -- NULL until the staged copy is hashed
  hash_scope        TEXT,                 -- full|sampled (oversize files)
  sample_hash       TEXT,
  original_name     TEXT NOT NULL,
  extension         TEXT,
  size_bytes        INTEGER NOT NULL,
  mtime_ms          REAL,
  state             TEXT NOT NULL,        -- checking|quarantined|queued|released|deleted|duplicate|lost
  reason_code       TEXT,
  reason            TEXT,
  reason_detail     TEXT,                 -- JSON
  discovered_path   TEXT,                 -- where it was found in the inbox
  storage_path      TEXT,                 -- current on-disk path (or null if deleted)
  storage_kind      TEXT,                 -- inbox|staging|quarantine|queue|trash|null
  release_target    TEXT,                 -- where an operator released it to
  archive_kind      TEXT,
  archive_depth     INTEGER,
  archive_members   INTEGER,
  scan_verdict      TEXT,                 -- clean|infected|suspicious|error
  scan_severity     TEXT,
  scan_engine       TEXT,
  scan_signature    TEXT,
  scan_checked_at   TEXT,
  parse_status      TEXT,                 -- pending|running|ready|failed
  parse_attempts    INTEGER NOT NULL DEFAULT 0,
  next_retry_at     TEXT,
  last_error        TEXT,
  first_seen_at     TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  decided_at        TEXT,
  deleted_at        TEXT,
  dedupe_of         TEXT,                 -- id of the earlier product with the same content
  superseded_by     TEXT                  -- id of the later product that reused this name
);
CREATE INDEX IF NOT EXISTS idx_products_state ON products(state);
CREATE INDEX IF NOT EXISTS idx_products_sha ON products(sha256);
CREATE INDEX IF NOT EXISTS idx_products_discovered ON products(discovered_path);
CREATE INDEX IF NOT EXISTS idx_products_updated ON products(updated_at);
CREATE INDEX IF NOT EXISTS idx_products_storage ON products(storage_path);

-- Append-only journal of everything the monitor decided.
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  at          TEXT NOT NULL,
  product_id  TEXT,
  sha256      TEXT,
  kind        TEXT NOT NULL,             -- discovered|stable|duplicate|replaced|rejected|queued|...
  reason_code TEXT,
  summary     TEXT NOT NULL,
  detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_at ON events(at);
CREATE INDEX IF NOT EXISTS idx_events_product ON events(product_id);

-- Dedupe state across restarts: one row per content hash.
CREATE TABLE IF NOT EXISTS seen (
  sha256      TEXT PRIMARY KEY,
  product_id  TEXT NOT NULL,
  hits        INTEGER NOT NULL DEFAULT 1,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL
);

-- Retry bookkeeping keyed by stage + content so failures survive restarts.
CREATE TABLE IF NOT EXISTS retries (
  key           TEXT PRIMARY KEY,
  stage         TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  product_id    TEXT NOT NULL,
  attempts      INTEGER NOT NULL,
  max_attempts  INTEGER NOT NULL,
  next_at       TEXT NOT NULL,
  last_error    TEXT,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_retries_next ON retries(next_at);

-- Parsed payload, one row per product.
CREATE TABLE IF NOT EXISTS parse_results (
  product_id  TEXT PRIMARY KEY,
  sha256      TEXT NOT NULL,
  kind        TEXT NOT NULL,
  summary     TEXT NOT NULL,
  payload     TEXT,
  bytes_read  INTEGER,
  parsed_at   TEXT NOT NULL
);

-- Scanner availability state, so a restart doesn't hammer a dead service.
CREATE TABLE IF NOT EXISTS scanner_state (
  id                     INTEGER PRIMARY KEY CHECK (id = 1),
  available              INTEGER NOT NULL DEFAULT 1,
  consecutive_failures   INTEGER NOT NULL DEFAULT 0,
  opened_at              TEXT,
  last_error             TEXT,
  last_ok_at             TEXT,
  last_check_at          TEXT
);

INSERT OR IGNORE INTO scanner_state (id) VALUES (1);
`;

const PRODUCT_COLUMNS = [
  "id", "sha256", "hash_scope", "sample_hash", "original_name", "extension", "size_bytes", "mtime_ms",
  "state", "reason_code", "reason", "reason_detail", "discovered_path", "storage_path",
  "storage_kind", "release_target", "archive_kind", "archive_depth", "archive_members",
  "scan_verdict", "scan_severity", "scan_engine", "scan_signature", "scan_checked_at",
  "parse_status", "parse_attempts", "next_retry_at", "last_error", "first_seen_at",
  "updated_at", "decided_at", "deleted_at", "dedupe_of", "superseded_by",
];

const SORTS = {
  newest: "first_seen_at DESC",
  oldest: "first_seen_at ASC",
  size: "size_bytes DESC",
  updated: "updated_at DESC",
};

export function openDatabase(dbPath) {
  const db = new DatabaseSync(dbPath);
  db.exec(DDL);
  const row = db.prepare("SELECT value FROM meta WHERE key='schema_version'").get();
  if (!row) {
    db.prepare("INSERT INTO meta (key, value) VALUES (?, ?)").run(
      "schema_version",
      String(SCHEMA_VERSION),
    );
  } else if (Number(row.value) !== SCHEMA_VERSION) {
    throw new Error(`数据库 schema 版本 ${row.value} 与服务版本 ${SCHEMA_VERSION} 不一致`);
  }
  return new Repo(db);
}

export class Repo {
  constructor(db) {
    this.db = db;
    this.stmt = {
      insertProduct: db.prepare(`
        INSERT INTO products (
          id, sha256, hash_scope, sample_hash, original_name, extension, size_bytes, mtime_ms,
          state, reason_code, reason, reason_detail, discovered_path, storage_path, storage_kind,
          parse_status, first_seen_at, updated_at
        ) VALUES (
          :id, :sha256, :hash_scope, :sample_hash, :original_name, :extension, :size_bytes, :mtime_ms,
          :state, :reason_code, :reason, :reason_detail, :discovered_path, :storage_path, :storage_kind,
          :parse_status, :first_seen_at, :updated_at
        )`),
      getProduct: db.prepare("SELECT * FROM products WHERE id = ?"),
      bySha: db.prepare("SELECT * FROM products WHERE sha256 = ? ORDER BY first_seen_at ASC"),
      latestBySha: db.prepare(
        "SELECT * FROM products WHERE sha256 = ? ORDER BY first_seen_at DESC LIMIT 1",
      ),
      byDiscovered: db.prepare(
        "SELECT * FROM products WHERE discovered_path = ? ORDER BY first_seen_at DESC LIMIT 1",
      ),
      byStorage: db.prepare(
        "SELECT * FROM products WHERE storage_path = ? ORDER BY first_seen_at DESC LIMIT 1",
      ),
      byState: db.prepare("SELECT * FROM products WHERE state = ?"),
      onDisk: db.prepare(
        "SELECT * FROM products WHERE storage_kind = ? AND state IN ('checking','quarantined','queued')",
      ),
      setState: db.prepare(`
        UPDATE products SET
          state=:state, reason_code=:reason_code, reason=:reason, reason_detail=:reason_detail,
          storage_path=:storage_path, storage_kind=:storage_kind,
          updated_at=:updated_at, decided_at=:decided_at
        WHERE id=:id`),
      updateLocation: db.prepare(
        "UPDATE products SET storage_path=:storage_path, storage_kind=:storage_kind, updated_at=:updated_at WHERE id=:id",
      ),
      setHash: db.prepare(`
        UPDATE products SET sha256=:sha256, hash_scope=:scope, sample_hash=:sample_hash,
          size_bytes=:size, mtime_ms=:mtime, updated_at=:updated_at
        WHERE id=:id`),
      setSuperseded: db.prepare(
        "UPDATE products SET superseded_by=:by, updated_at=:at WHERE id=:id",
      ),
      setScan: db.prepare(`
        UPDATE products SET scan_verdict=:verdict, scan_severity=:severity, scan_engine=:engine,
          scan_signature=:signature, scan_checked_at=:checked_at,
          last_error=:last_error, updated_at=:updated_at
        WHERE id=:id`),
      setArchive: db.prepare(`
        UPDATE products SET archive_kind=:kind, archive_depth=:depth, archive_members=:members,
          updated_at=:updated_at WHERE id=:id`),
      setParse: db.prepare(`
        UPDATE products SET parse_status=:status, next_retry_at=:next, last_error=:last_error,
          updated_at=:updated_at WHERE id=:id`),
      claimParse: db.prepare(`
        UPDATE products SET parse_status='running', parse_attempts=parse_attempts+1,
          updated_at=:updated_at
        WHERE id=:id AND state='queued' AND parse_status IN ('pending','failed')`),
      dueParse: db.prepare(`
        SELECT * FROM products
        WHERE state='queued' AND parse_status IN ('pending','failed')
          AND (next_retry_at IS NULL OR next_retry_at <= :now)
        ORDER BY first_seen_at ASC LIMIT 1`),
      resetRunning: db.prepare(
        "UPDATE products SET parse_status='pending', updated_at=:at WHERE parse_status='running'",
      ),
      setReleased: db.prepare(
        "UPDATE products SET release_target=:target, updated_at=:updated_at WHERE id=:id",
      ),
      markDeleted: db.prepare(
        "UPDATE products SET state='deleted', deleted_at=:at, updated_at=:at, storage_path=NULL, storage_kind=NULL WHERE id=:id",
      ),

      insertEvent: db.prepare(`
        INSERT INTO events (at, product_id, sha256, kind, reason_code, summary, detail)
        VALUES (:at, :product_id, :sha256, :kind, :reason_code, :summary, :detail)`),
      recentEvents: db.prepare("SELECT * FROM events ORDER BY id DESC LIMIT ?"),
      recentEventsSince: db.prepare("SELECT * FROM events WHERE id > ? ORDER BY id DESC LIMIT ?"),
      eventsForProduct: db.prepare(
        "SELECT * FROM events WHERE product_id = ? ORDER BY id DESC LIMIT ?",
      ),
      pruneEvents: db.prepare("DELETE FROM events WHERE at < ?"),

      upsertSeen: db.prepare(`
        INSERT INTO seen (sha256, product_id, hits, first_seen, last_seen)
        VALUES (:sha256, :product_id, 1, :at, :at)
        ON CONFLICT(sha256) DO UPDATE SET hits = hits + 1, last_seen = excluded.last_seen`),
      getSeen: db.prepare("SELECT * FROM seen WHERE sha256 = ?"),

      getRetry: db.prepare("SELECT * FROM retries WHERE key = ?"),
      dueRetries: db.prepare(
        "SELECT * FROM retries WHERE next_at <= :now ORDER BY next_at ASC LIMIT :limit",
      ),
      retriesForProduct: db.prepare("SELECT * FROM retries WHERE product_id = ?"),
      upsertRetry: db.prepare(`
        INSERT INTO retries (key, stage, sha256, product_id, attempts, max_attempts, next_at, last_error, updated_at)
        VALUES (:key, :stage, :sha256, :product_id, :attempts, :max_attempts, :next_at, :last_error, :updated_at)
        ON CONFLICT(key) DO UPDATE SET
          attempts=excluded.attempts, next_at=excluded.next_at,
          last_error=excluded.last_error, updated_at=excluded.updated_at`),
      clearRetry: db.prepare("DELETE FROM retries WHERE key = ?"),
      clearSeen: db.prepare("DELETE FROM seen WHERE sha256 = ?"),
      clearRetriesForProduct: db.prepare("DELETE FROM retries WHERE product_id = ?"),

      getScanner: db.prepare("SELECT * FROM scanner_state WHERE id = 1"),
      setScanner: db.prepare(`
        UPDATE scanner_state SET available=:available, consecutive_failures=:fails,
          opened_at=:opened_at, last_error=:last_error, last_ok_at=:last_ok_at,
          last_check_at=:last_check_at WHERE id = 1`),

      upsertParseResult: db.prepare(`
        INSERT INTO parse_results (product_id, sha256, kind, summary, payload, bytes_read, parsed_at)
        VALUES (:product_id, :sha256, :kind, :summary, :payload, :bytes_read, :parsed_at)
        ON CONFLICT(product_id) DO UPDATE SET
          kind=excluded.kind, summary=excluded.summary, payload=excluded.payload,
          bytes_read=excluded.bytes_read, parsed_at=excluded.parsed_at`),
      getParseResult: db.prepare("SELECT * FROM parse_results WHERE product_id = ?"),

      countsByState: db.prepare("SELECT state, COUNT(*) AS n FROM products GROUP BY state"),
      sumByStorage: db.prepare(`
        SELECT storage_kind, COUNT(*) AS files, COALESCE(SUM(size_bytes),0) AS bytes
        FROM products
        WHERE storage_kind IS NOT NULL AND state != 'deleted'
        GROUP BY storage_kind`),
    };
  }

  close() {
    try {
      this.db.close();
    } catch {
      /* already closed */
    }
  }

  // -- products -------------------------------------------------------------

  insertProduct(p) {
    const at = p.first_seen_at ?? nowIso();
    this.stmt.insertProduct.run({
      id: p.id,
      sha256: p.sha256 ?? null,
      hash_scope: p.hash_scope ?? null,
      sample_hash: p.sample_hash ?? null,
      original_name: p.original_name,
      extension: p.extension ?? null,
      size_bytes: p.size_bytes,
      mtime_ms: p.mtime_ms ?? null,
      state: p.state,
      reason_code: p.reason_code ?? null,
      reason: p.reason ?? null,
      reason_detail: p.reason_detail ? JSON.stringify(p.reason_detail) : null,
      discovered_path: p.discovered_path ?? null,
      storage_path: p.storage_path ?? null,
      storage_kind: p.storage_kind ?? null,
      parse_status: p.parse_status ?? null,
      first_seen_at: at,
      updated_at: at,
    });
    return this.getProduct(p.id);
  }

  getProduct(id) {
    const row = this.stmt.getProduct.get(id);
    return row ? parseProduct(row) : null;
  }

  productsBySha(sha256) {
    return this.stmt.bySha.all(sha256);
  }

  latestBySha(sha256) {
    return this.stmt.latestBySha.get(sha256) ?? null;
  }

  latestByDiscovered(discoveredPath) {
    return this.stmt.byDiscovered.get(discoveredPath) ?? null;
  }

  byStoragePath(storagePath) {
    return this.stmt.byStorage.get(storagePath) ?? null;
  }

  productsInStates(states) {
    return states.flatMap((s) => this.stmt.byState.all(s));
  }

  /**
   * Move a product to a new state (and optionally a new storage location).
   * Returns false when the row disappeared (e.g. deleted concurrently).
   */
  transition(
    id,
    { to, reasonCode = null, reason = null, reasonDetail = null, storagePath, storageKind, decided = false },
  ) {
    const cur = this.getProduct(id);
    if (!cur) return false;
    const res = this.stmt.setState.run({
      id,
      state: to,
      reason_code: reasonCode,
      reason,
      reason_detail: reasonDetail ? JSON.stringify(reasonDetail) : null,
      storage_path: storagePath === undefined ? cur.storage_path : storagePath,
      storage_kind: storageKind === undefined ? cur.storage_kind : storageKind,
      updated_at: nowIso(),
      decided_at: decided ? nowIso() : cur.decided_at,
    });
    return res.changes > 0;
  }

  recordHash(id, { sha256, scope, sampleHash = null, size, mtimeMs = null }) {
    return (
      this.stmt.setHash.run({
        id,
        sha256,
        scope,
        sample_hash: sampleHash,
        size,
        mtime: mtimeMs,
        updated_at: nowIso(),
      }).changes > 0
    );
  }

  markSuperseded(id, by) {
    this.stmt.setSuperseded.run({ id, by, at: nowIso() });
  }

  updateLocation(id, { storagePath, storageKind }) {
    return (
      this.stmt.updateLocation.run({
        id,
        storage_path: storagePath,
        storage_kind: storageKind,
        updated_at: nowIso(),
      }).changes > 0
    );
  }

  recordScan(id, scan) {
    this.stmt.setScan.run({
      id,
      verdict: scan.verdict ?? null,
      severity: scan.severity ?? null,
      engine: scan.engine ?? null,
      signature: scan.signature ?? null,
      checked_at: scan.checkedAt ?? nowIso(),
      last_error: scan.error ?? null,
      updated_at: nowIso(),
    });
  }

  recordArchive(id, report) {
    this.stmt.setArchive.run({
      id,
      kind: report.kind ?? null,
      depth: report.nestingDepth ?? null,
      members: report.members ?? null,
      updated_at: nowIso(),
    });
  }

  setParse(id, { status, nextRetryAt = null, lastError = null }) {
    this.stmt.setParse.run({
      id,
      status,
      next: nextRetryAt,
      last_error: lastError,
      updated_at: nowIso(),
    });
  }

  claimParse(id) {
    return this.stmt.claimParse.run({ id, updated_at: nowIso() }).changes > 0;
  }

  nextDueParse() {
    return this.stmt.dueParse.get({ now: nowIso() }) ?? null;
  }

  resetRunningParses() {
    return this.stmt.resetRunning.run({ at: nowIso() }).changes;
  }

  setReleaseTarget(id, target) {
    this.stmt.setReleased.run({ id, target, updated_at: nowIso() });
  }

  markDeleted(id) {
    this.stmt.markDeleted.run({ id, at: nowIso() });
  }

  /** Record that a file vanished before it could be processed. */
  markLost(id, reason, detail = null) {
    return this.transition(id, {
      to: "lost",
      reasonCode: "file_missing",
      reason,
      reasonDetail: detail,
      storagePath: null,
      storageKind: null,
      decided: true,
    });
  }

  /** Paged product list with optional state/reason filters and search. */
  listProducts({ states = [], search = "", sort = "newest", limit = 50, offset = 0 } = {}) {
    const where = [];
    const params = {};
    if (states.length) {
      where.push(`state IN (${states.map((_, i) => `:s${i}`).join(",")})`);
      states.forEach((s, i) => (params[`s${i}`] = s));
    }
    if (search) {
      where.push("(original_name LIKE :q OR sha256 LIKE :q OR reason_code LIKE :q OR id LIKE :q)");
      params.q = `%${search}%`;
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const orderSql = SORTS[sort] ?? SORTS.newest;
    const total = this.db
      .prepare(`SELECT COUNT(*) AS n FROM products ${whereSql}`)
      .get(params).n;
    const rows = this.db
      .prepare(
        `SELECT ${PRODUCT_COLUMNS.join(",")} FROM products ${whereSql} ORDER BY ${orderSql} LIMIT :lim OFFSET :off`,
      )
      .all({ ...params, lim: limit, off: offset });
    return { total, rows: rows.map(parseProduct) };
  }

  // -- events ---------------------------------------------------------------

  logEvent({ productId = null, sha256 = null, kind, reasonCode = null, summary, detail = null }) {
    this.stmt.insertEvent.run({
      at: nowIso(),
      product_id: productId,
      sha256,
      kind,
      reason_code: reasonCode,
      summary,
      detail: detail ? JSON.stringify(detail) : null,
    });
  }

  recentEvents(limit = 40, sinceId = null) {
    const rows = sinceId
      ? this.stmt.recentEventsSince.all(sinceId, limit)
      : this.stmt.recentEvents.all(limit);
    return rows.map(parseEvent);
  }

  eventsForProduct(productId, limit = 50) {
    return this.stmt.eventsForProduct.all(productId, limit).map(parseEvent);
  }

  pruneEvents(beforeIso) {
    return this.stmt.pruneEvents.run(beforeIso).changes;
  }

  // -- dedupe ---------------------------------------------------------------

  noteSeen(sha256, productId) {
    const at = nowIso();
    this.stmt.upsertSeen.run({ sha256, product_id: productId, at });
    return this.stmt.getSeen.get(sha256);
  }

  getSeen(sha256) {
    return this.stmt.getSeen.get(sha256) ?? null;
  }

  // -- retries --------------------------------------------------------------

  getRetry(key) {
    return this.stmt.getRetry.get(key) ?? null;
  }

  dueRetries(limit = 20) {
    return this.stmt.dueRetries.all({ now: nowIso(), limit });
  }

  retriesForProduct(productId) {
    return this.stmt.retriesForProduct.all(productId);
  }

  putRetry({ key, stage, sha256, productId, attempts, maxAttempts, nextAt, lastError }) {
    this.stmt.upsertRetry.run({
      key,
      stage,
      sha256,
      product_id: productId,
      attempts,
      max_attempts: maxAttempts,
      next_at: nextAt,
      last_error: lastError ?? null,
      updated_at: nowIso(),
    });
  }

  clearRetry(key) {
    this.stmt.clearRetry.run(key);
  }

  clearSeen(sha256) {
    this.stmt.clearSeen.run(sha256);
  }

  clearRetriesForProduct(productId) {
    this.stmt.clearRetriesForProduct.run(productId);
  }

  // -- parse results --------------------------------------------------------

  saveParseResult(id, { sha256, kind, summary, payload, bytesRead }) {
    this.stmt.upsertParseResult.run({
      product_id: id,
      sha256,
      kind,
      summary,
      payload: payload == null ? null : JSON.stringify(payload),
      bytes_read: bytesRead ?? null,
      parsed_at: nowIso(),
    });
  }

  getParseResult(id) {
    const row = this.stmt.getParseResult.get(id);
    if (!row) return null;
    let payload = null;
    if (row.payload) {
      try {
        payload = JSON.parse(row.payload);
      } catch {
        payload = null;
      }
    }
    return { ...row, payload };
  }

  // -- scanner health -------------------------------------------------------

  getScannerState() {
    return this.stmt.getScanner.get();
  }

  setScannerState(s) {
    this.stmt.setScanner.run({
      available: s.available ? 1 : 0,
      fails: s.consecutiveFailures ?? 0,
      opened_at: s.openedAt ?? null,
      last_error: s.lastError ?? null,
      last_ok_at: s.lastOkAt ?? null,
      last_check_at: s.lastCheckAt ?? nowIso(),
    });
  }

  // -- aggregates -----------------------------------------------------------

  countsByState() {
    const out = {};
    for (const r of this.stmt.countsByState.all()) out[r.state] = r.n;
    return out;
  }

  bytesByStorage() {
    const out = {};
    for (const r of this.stmt.sumByStorage.all()) {
      out[r.storage_kind] = { files: r.files, bytes: r.bytes };
    }
    return out;
  }
}

function parseProduct(row) {
  let detail = null;
  if (row.reason_detail) {
    try {
      detail = JSON.parse(row.reason_detail);
    } catch {
      detail = { raw: row.reason_detail };
    }
  }
  return { ...row, reason_detail: detail };
}

function parseEvent(row) {
  let detail = null;
  if (row.detail) {
    try {
      detail = JSON.parse(row.detail);
    } catch {
      detail = { raw: row.detail };
    }
  }
  return { ...row, detail };
}

export async function ensureDirs(paths) {
  for (const p of paths) await fsp.mkdir(p, { recursive: true });
}

export function dirForKind(cfg, kind) {
  switch (kind) {
    case "inbox":
      return cfg.watchDir;
    case "staging":
      return cfg.stagingDir;
    case "quarantine":
      return cfg.quarantineDir;
    case "queue":
      return cfg.queueDir;
    case "trash":
      return cfg.trashDir;
    default:
      return null;
  }
}

/** The on-disk name a product gets once it leaves the inbox. */
export function storedName(product) {
  const ext = product.extension ?? path.extname(product.original_name) ?? "";
  const safeExt = /^\.[A-Za-z0-9]{1,12}$/.test(ext) ? ext.toLowerCase() : "";
  return `${product.id}${safeExt}`;
}

/** Parse a stored filename back into its product id and extension. */
export function parseStoredName(base) {
  const m = /^(pd_[0-9a-z]{12})(\.[A-Za-z0-9]{1,12})?$/.exec(base);
  if (!m) return null;
  return { id: m[1], extension: m[2] ?? "" };
}
