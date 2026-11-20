// Hashing and stability checks.
//
// A file "settles" when its size, mtime and inode stay unchanged for a quiet
// window, and (on POSIX) no process still holds it open for writing. Files that
// settle get hashed; the hash is what every downstream decision is keyed on.

import fs from "node:fs";
import fsp from "node:fs/promises";
import crypto from "node:crypto";
import { sleep } from "./util.js";

/**
 * Sample a stat record for the fields stability cares about.
 * Returns null when the file vanished between listing and stat.
 */
export async function statSample(filePath) {
  try {
    const st = await fsp.stat(filePath, { bigint: false });
    return {
      exists: true,
      size: st.size,
      mtimeMs: st.mtimeMs,
      ctimeMs: st.ctimeMs,
      ino: st.ino,
      dev: st.dev,
      isFile: st.isFile(),
      isSymbolicLink: st.isSymbolicLink(),
      nlink: st.nlink,
    };
  } catch (err) {
    if (err.code === "ENOENT" || err.code === "ENOTDIR") return null;
    throw err;
  }
}

export function sameStat(a, b) {
  if (!a || !b) return false;
  return a.size === b.size && a.mtimeMs === b.mtimeMs && a.ino === b.ino && a.dev === b.dev;
}

/** Temp / partial-write naming conventions seen from upload tools and editors. */
const TEMP_PATTERNS = [
  /^~/,
  /^\.~lock\./, // LibreOffice lock files
  /^~\$/, // Office owner files
  /\.tmp$/i,
  /\.temp$/i,
  /\.part$/i,
  /\.partial$/i,
  /\.crdownload$/i,
  /\.download$/i,
  /\.filepart$/i,
  /\.swp$/i,
  /\.swx$/i,
  /\.bak$/i,
  /(^|\/)\.DS_Store$/i,
  /(^|\/)Thumbs\.db$/i,
  /(^|\/)desktop\.ini$/i,
];

export function classifyTempName(name, { inFlight = false } = {}) {
  const base = name.split("/").pop() || name;
  if (inFlight) return { temp: true, reason: "写入中" };
  if (base.startsWith(".") && base !== ".keep") return { temp: true, reason: "隐藏/临时文件" };
  for (const re of TEMP_PATTERNS) {
    if (re.test(base)) return { temp: true, reason: "临时/未完成文件后缀" };
  }
  return { temp: false, reason: null };
}

/**
 * Whether another process still has the file open for writing. Linux-only
 * (reads /proc/*\/fd); elsewhere we rely on the quiet window alone.
 */
export async function heldOpenForWriting(filePath) {
  if (process.platform !== "linux") return false;
  let target;
  try {
    target = await fsp.realpath(filePath);
  } catch {
    return false;
  }
  let pids;
  try {
    pids = await fsp.readdir("/proc", { withFileTypes: true });
  } catch {
    return false;
  }
  for (const ent of pids) {
    if (!ent.isDirectory() || !/^\d+$/.test(ent.name)) continue;
    const fdDir = `/proc/${ent.name}/fd`;
    let fds;
    try {
      fds = await fsp.readdir(fdDir);
    } catch {
      continue;
    }
    for (const fd of fds) {
      let link;
      try {
        link = await fsp.readlink(`${fdDir}/${fd}`);
      } catch {
        continue;
      }
      if (link !== target) continue;
      // Only count descriptors that can write.
      try {
        const info = await fsp.readFile(`/proc/${ent.name}/fdinfo/${fd}`, "utf8");
        const flags = /flags:\s*([0-7]+)/.exec(info);
        if (flags && (parseInt(flags[1], 8) & 0o3) !== 0) return true;
      } catch {
        return true;
      }
    }
  }
  return false;
}

/**
 * Wait until a path settles, disappears, or is replaced under the same name.
 * Returns one of:
 *   { state: "stable", stat, waitedMs }
 *   { state: "gone" }
 *   { state: "replaced", stat }   (inode changed - a new file took the name)
 *   { state: "unstable", stat }   (never quiet within maxWaitMs)
 *   { state: "aborted" }
 */
export async function waitForStable(filePath, initial, opts, signal) {
  const { quietMs, maxWaitMs, pollMs, checkOpenHandles = true } = opts;
  const started = Date.now();
  let last = initial;
  let quietSince = initial ? Date.now() : null;

  for (;;) {
    await sleep(pollMs);
    if (signal?.aborted) return { state: "aborted" };

    const cur = await statSample(filePath);
    if (!cur) return { state: "gone" };

    if (last && cur.ino !== last.ino) return { state: "replaced", stat: cur };
    if (!sameStat(cur, last)) {
      last = cur;
      quietSince = Date.now();
      continue;
    }

    if (quietSince !== null && Date.now() - quietSince >= quietMs) {
      if (!checkOpenHandles || !(await heldOpenForWriting(filePath))) {
        return { state: "stable", stat: cur, waitedMs: Date.now() - started };
      }
      // Somebody still has it open for writing: keep the original quiet start so
      // a file held open forever still hits maxWaitMs and is quarantined.
      quietSince = Math.max(quietSince, Date.now() - quietMs);
    }

    if (Date.now() - started > maxWaitMs) {
      return { state: "unstable", stat: cur, waitedMs: Date.now() - started };
    }
  }
}

/**
 * Full-content SHA-256 plus a cheap head/tail sample hash. The sample hash lets
 * the service recognise a redelivery without re-reading large files.
 */
export async function hashFile(filePath, sampleBytes = 64 * 1024) {
  const full = crypto.createHash("sha256");
  const sample = crypto.createHash("sha256");
  const fh = await fsp.open(filePath, "r");
  try {
    const st = await fh.stat();
    const size = st.size;
    const headLen = Math.min(sampleBytes, size);
    const head = Buffer.alloc(headLen);
    await fh.read(head, 0, headLen, 0);
    sample.update(head);
    let pos = 0;
    const buf = Buffer.allocUnsafe(1024 * 1024);
    while (pos < size) {
      const { bytesRead } = await fh.read(buf, 0, Math.min(buf.length, size - pos), pos);
      if (bytesRead === 0) break;
      full.update(buf.subarray(0, bytesRead));
      pos += bytesRead;
    }
    if (size > sampleBytes) {
      const tailLen = Math.min(sampleBytes, size);
      const tail = Buffer.alloc(tailLen);
      await fh.read(tail, 0, tailLen, size - tailLen);
      sample.update(tail);
    }
    sample.update(String(size));
    return {
      sha256: full.digest("hex"),
      sampleHash: sample.digest("hex"),
      bytes: pos,
      mtimeMs: st.mtimeMs,
    };
  } finally {
    await fh.close();
  }
}

/** Atomically move a file, never overwriting the destination. */
export async function moveNoClobber(src, dstDir, dstName) {
  await fsp.mkdir(dstDir, { recursive: true });
  const dst = `${dstDir}/${dstName}`;
  try {
    await fsp.link(src, dst);
    await fsp.unlink(src);
    return dst;
  } catch (err) {
    if (err.code === "EEXIST") {
      throw Object.assign(new Error("目标文件已存在"), { code: "EEXIST" });
    }
    if (err.code === "EXDEV" || err.code === "EPERM" || err.code === "ENOTSUP" || err.code === "EACCES") {
      // Different filesystem or no hardlinks: copy without overwriting, then unlink.
      await fsp.copyFile(src, dst, fs.constants.COPYFILE_EXCL);
      await fsp.unlink(src);
      return dst;
    }
    throw err;
  }
}

/** Best-effort durable fsync of a directory entry after a move. */
export async function fsyncDir(dir) {
  try {
    const fh = await fsp.open(dir, "r");
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch {
    /* not all platforms allow opening a directory */
  }
}
