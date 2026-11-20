// Small shared helpers: time, ids, backoff, size formatting.

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function nowIso() {
  return new Date().toISOString();
}

let seq = 0;
/** Sortable, collision-resistant id without external deps. */
export function newId(prefix) {
  seq = (seq + 1) % 0x10000;
  return `${prefix}_${Date.now().toString(36)}${seq.toString(36).padStart(3, "0")}${Math.random()
    .toString(36)
    .slice(2, 6)}`;
}

/** Exponential backoff with jitter, clamped to a ceiling. */
export function backoffMs(attempt, baseMs, maxMs = 60_000) {
  const raw = baseMs * 2 ** Math.max(0, attempt - 1);
  const jitter = 0.85 + Math.random() * 0.3;
  return Math.min(maxMs, Math.round(raw * jitter));
}

export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return `${v.toFixed(digits)} ${units[i]}`;
}

export function formatDuration(ms) {
  if (ms == null || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

export function truncateMiddle(s, max = 48) {
  if (typeof s !== "string" || s.length <= max) return s;
  const keepStart = Math.ceil((max - 1) * 0.55);
  const keepEnd = max - 1 - keepStart;
  return `${s.slice(0, keepStart)}…${s.slice(-keepEnd)}`;
}

export function sumBy(list, fn) {
  let t = 0;
  for (const item of list) t += fn(item) || 0;
  return t;
}

/** Percentile on an already-sorted numeric array. */
export function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}
