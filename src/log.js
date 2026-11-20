// Very small structured logger: one JSON object per line, plus a readable
// message. Level from LOG_LEVEL (debug|info|warn|error), default info.

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

export function createLogger({ level = process.env.LOG_LEVEL || "info", sink = process.stdout } = {}) {
  const threshold = LEVELS[level] ?? LEVELS.info;

  function emit(lvl, fields, msg) {
    if (LEVELS[lvl] < threshold) return;
    const rec = { at: new Date().toISOString(), level: lvl, msg, ...fields };
    let line;
    try {
      line = JSON.stringify(rec);
    } catch {
      line = JSON.stringify({ at: rec.at, level: lvl, msg });
    }
    sink.write(`${line}\n`);
  }

  return {
    debug: (fields, msg) => emit("debug", fields, msg),
    info: (fields, msg) => emit("info", fields, msg),
    warn: (fields, msg) => emit("warn", fields, msg),
    error: (fields, msg) => emit("error", fields, msg),
    child(bindings) {
      return createLogger({ level, sink, bindings });
    },
  };
}

/** Quiet logger for tests. */
export function silentLogger() {
  const noop = () => {};
  return { debug: noop, info: noop, warn: noop, error: noop, child: () => silentLogger() };
}
