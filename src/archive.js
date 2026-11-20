// Archive inspection: nested archives, bomb ratios, unsafe member names and
// encryption. Nothing here trusts the archive's own claims; expansion is capped
// by declared size and by output length while inflating.
//
// Findings are advisory: the caller decides which codes reject a file.

import fsp from "node:fs/promises";
import path from "node:path";
import zlib from "node:zlib";

const SIG = {
  zipLocal: 0x04034b50,
  zipCentral: 0x02014b50,
  zipEnd: 0x06054b50,
  zip64End: 0x06064b50,
  zip64Locator: 0x07064b50,
};

// Extension -> canonical kind.
const EXT_KIND = new Map([
  [".zip", "zip"], [".jar", "zip"], [".war", "zip"], [".ear", "zip"], [".apk", "zip"],
  [".epub", "zip"], [".docx", "zip"], [".xlsx", "zip"], [".pptx", "zip"], [".odt", "zip"],
  [".ods", "zip"], [".odp", "zip"],
  [".tar", "tar"], [".tgz", "gzip"], [".gz", "gzip"],
  [".bz2", "bz2"], [".tbz2", "bz2"], [".xz", "xz"], [".txz", "xz"],
  [".7z", "7z"], [".rar", "rar"], [".cab", "cab"], [".iso", "iso"], [".dmg", "dmg"],
  [".lz", "lz"], [".zst", "zst"],
]);

const INSPECT_MAX_MEMBER_BYTES = 8 * 1024 * 1024;

export class ArchiveError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.code = code;
    this.detail = detail;
  }
}

/** Canonical archive kind from the filename, or null. */
export function archiveKindOfName(name) {
  const lower = name.toLowerCase();
  if (lower.endsWith(".tar.gz")) return "gzip";
  return EXT_KIND.get(path.extname(lower)) ?? null;
}

/** Magic-number check so a renamed archive is still spotted. */
export function sniffArchive(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 3 || buf[2] === 5 || buf[2] === 7)) {
    return "zip";
  }
  if (buf[0] === 0x1f && buf[1] === 0x8b) return "gzip";
  if (buf.length >= 262 && buf.toString("latin1", 257, 262) === "ustar") return "tar";
  if (buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf) return "7z";
  if (buf.toString("latin1", 0, 7) === "Rar!\x1a\x07") return "rar";
  if (buf[0] === 0x42 && buf[1] === 0x5a && buf[2] === 0x68) return "bz2";
  if (buf[0] === 0xfd && buf[1] === 0x37 && buf[2] === 0x7a) return "xz";
  return null;
}

function finding(code, severity, message, detail) {
  return { code, severity, message, detail: detail ?? null };
}

/** Findings that mean "do not hand this to the parser". */
export const BLOCKING_ARCHIVE_CODES = new Set([
  "archive_path_traversal",
  "archive_absolute_path",
  "archive_symlink",
  "archive_encrypted",
  "archive_too_deep",
  "archive_too_many_members",
  "archive_expansion_limit",
  "archive_unreadable",
  "archive_duplicate_member",
]);

export function emptyReport() {
  return {
    archive: false,
    kind: null,
    nestingDepth: 0,
    members: 0,
    totalUncompressed: 0,
    nestedArchives: 0,
    findings: [],
  };
}

/**
 * Inspect a staged file. Never throws for hostile input; problems come back as
 * findings so the caller can record a reason.
 */
export async function inspectArchive(filePath, opts = {}) {
  const {
    maxDepth = 3,
    maxMembers = 2000,
    maxUncompressedBytes = 512 * 1024 * 1024,
    maxRatio = 120,
    timeBudgetMs = 20_000,
  } = opts;

  const report = emptyReport();
  let buf;
  try {
    buf = await fsp.readFile(filePath);
  } catch (err) {
    report.findings.push(finding("archive_unreadable", "medium", `无法读取文件：${err.message}`));
    return report;
  }
  const kind = sniffArchive(buf) ?? archiveKindOfName(filePath);
  if (!kind) return report;

  report.archive = true;
  report.kind = kind;
  const ctx = {
    report,
    maxMembers,
    maxUncompressedBytes,
    maxRatio,
    deadline: Date.now() + timeBudgetMs,
    memberPaths: new Set(),
  };

  try {
    if (kind === "zip") await walkZip(buf, 1, maxDepth, ctx);
    else if (kind === "gzip") await walkGzip(buf, 1, maxDepth, ctx);
    else if (kind === "tar") walkTar(buf, 1, maxDepth, ctx);
    else {
      report.nestingDepth = 1;
      report.findings.push(
        finding("archive_unsupported_format", "low", `暂不支持展开 ${kind} 格式，仅做整体扫描`, {
          kind,
        }),
      );
    }
  } catch (err) {
    if (err instanceof ArchiveError) {
      report.findings.push(finding(err.code, "high", err.message, err.detail));
    } else {
      report.findings.push(
        finding("archive_unreadable", "medium", `压缩包无法解析：${err.message}`),
      );
    }
  }
  report.nestingDepth = Math.max(report.nestingDepth, report.archive ? 1 : 0);
  return report;
}

function checkBudget(ctx, member) {
  if (Date.now() > ctx.deadline) {
    throw new ArchiveError("archive_inspection_timeout", "压缩包展开超时，已停止");
  }
  if (ctx.report.members + 1 > ctx.maxMembers) {
    throw new ArchiveError(
      "archive_too_many_members",
      `压缩包内文件数超过上限 ${ctx.maxMembers}`,
      { members: ctx.report.members + 1 },
    );
  }
  ctx.report.members += 1;
  if (member && !member.isDirectory) {
    if (ctx.report.totalUncompressed + (member.uncompressed || 0) > ctx.maxUncompressedBytes) {
      throw new ArchiveError(
        "archive_expansion_limit",
        `压缩包解压总量超过上限 ${ctx.maxUncompressedBytes} 字节`,
        { total: ctx.report.totalUncompressed + member.uncompressed, member: member.name },
      );
    }
    ctx.report.totalUncompressed += member.uncompressed || 0;
  }
}

function checkMember(member, ctx, depth) {
  const name = member.name;
  const normalized = name.replace(/\\/g, "/");
  if (normalized.startsWith("/") || /^[a-zA-Z]:\//.test(normalized)) {
    ctx.report.findings.push(
      finding("archive_absolute_path", "high", "成员路径为绝对路径，解压时可能越界写入", {
        member: name,
        depth,
      }),
    );
  }
  if (normalized.split("/").some((seg) => seg === "..")) {
    ctx.report.findings.push(
      finding("archive_path_traversal", "high", "成员路径包含 ..，存在路径穿越风险", {
        member: name,
        depth,
      }),
    );
  }
  if (member.isSymlink) {
    ctx.report.findings.push(
      finding("archive_symlink", "medium", "成员为符号链接，解压时可能指向包外文件", {
        member: name,
        depth,
      }),
    );
  }
  if (member.encrypted) {
    ctx.report.findings.push(
      finding("archive_encrypted", "high", "成员已加密，无法完成内容检查", { member: name, depth }),
    );
  }
  if (member.ratio > ctx.maxRatio && member.uncompressed > 1024 * 1024) {
    ctx.report.findings.push(
      finding("archive_ratio_high", "medium", `成员压缩比 ${Math.round(member.ratio)}:1 超过阈值`, {
        member: name,
        ratio: Math.round(member.ratio),
        depth,
      }),
    );
  }
  const key = normalized.toLowerCase();
  if (ctx.memberPaths.has(key)) {
    ctx.report.findings.push(
      finding("archive_duplicate_member", "high", "压缩包内存在重复的成员名", {
        member: name,
        depth,
      }),
    );
  }
  ctx.memberPaths.add(key);
}

async function descend(data, name, depth, maxDepth, ctx) {
  const innerKind = sniffArchive(data.subarray(0, 512)) ?? archiveKindOfName(name);
  if (!innerKind) return;
  ctx.report.nestedArchives += 1;
  ctx.report.nestingDepth = Math.max(ctx.report.nestingDepth, depth + 1);
  if (depth + 1 > maxDepth) {
    throw new ArchiveError(
      "archive_too_deep",
      `压缩包嵌套超过 ${maxDepth} 层，已停止展开`,
      { depth: depth + 1, member: name },
    );
  }
  if (innerKind === "zip") await walkZip(data, depth + 1, maxDepth, ctx);
  else if (innerKind === "tar") walkTar(data, depth + 1, maxDepth, ctx);
  else if (innerKind === "gzip") await walkGzip(data, depth + 1, maxDepth, ctx);
  else {
    ctx.report.findings.push(
      finding("nested_unsupported_format", "low", `嵌套的 ${innerKind} 压缩包暂不能展开`, {
        member: name,
        kind: innerKind,
        depth: depth + 1,
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

async function walkZip(buf, depth, maxDepth, ctx) {
  const members = listZip(buf, ctx);
  for (const m of members) {
    checkBudget(ctx, m);
    if (m.isDirectory) continue;
    checkMember(m, ctx, depth);
    if (m.encrypted || m.uncompressed > INSPECT_MAX_MEMBER_BYTES) continue;
    let data;
    try {
      data = m.read();
    } catch (err) {
      ctx.report.findings.push(
        finding("archive_member_unreadable", "medium", `成员无法解压：${err.message}`, {
          member: m.name,
          depth,
        }),
      );
      continue;
    }
    if (!data) continue;
    // A nested archive keeps its declared size in the totals; its contents are
    // counted as they are walked.
    await descend(data, m.name, depth, maxDepth, ctx);
  }
}

function listZip(buf, ctx) {
  const eocd = findEocd(buf);
  if (!eocd) throw new ArchiveError("archive_unreadable", "找不到 ZIP 中央目录（文件可能被截断）");
  let totalEntries = eocd.entries;
  let cdOffset = eocd.cdOffset;
  let cdSize = eocd.cdSize;

  if (totalEntries === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) {
    const z64 = readZip64End(buf, eocd.eocdPos);
    if (z64) {
      totalEntries = z64.entries;
      cdOffset = z64.cdOffset;
      cdSize = z64.cdSize;
    }
  }
  if (totalEntries > ctx.maxMembers) {
    throw new ArchiveError(
      "archive_too_many_members",
      `ZIP 中央目录声明 ${totalEntries} 个成员，超过上限 ${ctx.maxMembers}`,
      { declared: totalEntries },
    );
  }
  if (cdOffset + cdSize > buf.length) {
    throw new ArchiveError("archive_unreadable", "ZIP 中央目录超出文件范围（文件可能被截断）");
  }

  const members = [];
  let p = cdOffset;
  const end = cdOffset + cdSize;
  let count = 0;
  while (p + 46 <= end && count < totalEntries) {
    if (buf.readUInt32LE(p) !== SIG.zipCentral) {
      throw new ArchiveError("archive_unreadable", "ZIP 中央目录损坏");
    }
    count += 1;
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const extAttr = buf.readUInt32LE(p + 38);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    const extra = buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);

    let realComp = compSize;
    let realUncomp = uncompSize;
    let realOffset = localOffset;
    if (
      compSize === 0xffffffff ||
      uncompSize === 0xffffffff ||
      localOffset === 0xffffffff
    ) {
      const z = readZip64Extra(extra);
      if (z.uncompressed !== undefined) realUncomp = z.uncompressed;
      if (z.compressed !== undefined) realComp = z.compressed;
      if (z.localOffset !== undefined) realOffset = z.localOffset;
    }

    const mode = (extAttr >>> 16) & 0xffff;
    const isSymlink = (mode & 0o170000) === 0o120000;
    const isDirectory = name.endsWith("/") || (mode & 0o170000) === 0o040000;
    const encrypted = (flags & 0x1) === 1;
    const ratio = realComp > 0 ? realUncomp / realComp : realUncomp > 0 ? Infinity : 0;
    const member = {
      name,
      compressed: realComp,
      uncompressed: realUncomp,
      ratio: Number.isFinite(ratio) ? ratio : 10_000,
      encrypted,
      isSymlink,
      isDirectory,
      read: isDirectory || realOffset === 0xffffffff || encrypted
        ? null
        : () => readZipEntry(buf, realOffset, realComp, method, realUncomp),
    };
    members.push(member);
    p += 46 + nameLen + extraLen + commentLen;
  }
  return members;
}

function findEocd(buf) {
  const minPos = Math.max(0, buf.length - 65_557);
  for (let i = buf.length - 22; i >= minPos; i--) {
    if (buf.readUInt32LE(i) !== SIG.zipEnd) continue;
    const entries = buf.readUInt16LE(i + 10);
    const cdSize = buf.readUInt32LE(i + 12);
    const cdOffset = buf.readUInt32LE(i + 16);
    // Reject a signature inside the trailing comment: the directory must land
    // before the record itself.
    if (cdOffset + cdSize > i) continue;
    return { entries, cdSize, cdOffset, eocdPos: i };
  }
  return null;
}

function readZip64End(buf, eocdPos) {
  const locatorPos = eocdPos - 20;
  if (locatorPos < 0 || buf.readUInt32LE(locatorPos) !== SIG.zip64Locator) return null;
  const z64Pos = Number(buf.readBigUInt64LE(locatorPos + 8));
  if (!Number.isSafeInteger(z64Pos) || z64Pos < 0 || z64Pos + 56 > buf.length) return null;
  if (buf.readUInt32LE(z64Pos) !== SIG.zip64End) return null;
  return {
    entries: Number(buf.readBigUInt64LE(z64Pos + 32)),
    cdSize: Number(buf.readBigUInt64LE(z64Pos + 40)),
    cdOffset: Number(buf.readBigUInt64LE(z64Pos + 48)),
  };
}

function readZip64Extra(extra) {
  let p = 0;
  while (p + 4 <= extra.length) {
    const id = extra.readUInt16LE(p);
    const size = extra.readUInt16LE(p + 2);
    if (id === 0x0001) {
      let q = p + 4;
      const end = Math.min(extra.length, q + size);
      const out = {};
      if (q + 8 <= end) {
        out.uncompressed = Number(extra.readBigUInt64LE(q));
        q += 8;
      }
      if (q + 8 <= end) {
        out.compressed = Number(extra.readBigUInt64LE(q));
        q += 8;
      }
      if (q + 8 <= end) out.localOffset = Number(extra.readBigUInt64LE(q));
      return out;
    }
    p += 4 + size;
  }
  return {};
}

function readZipEntry(buf, localOffset, compSize, method, uncompressedSize) {
  if (localOffset + 30 > buf.length) throw new Error("本地文件头越界");
  if (buf.readUInt32LE(localOffset) !== SIG.zipLocal) throw new Error("本地文件头损坏");
  const nameLen = buf.readUInt16LE(localOffset + 26);
  const extraLen = buf.readUInt16LE(localOffset + 28);
  const start = localOffset + 30 + nameLen + extraLen;
  const data = buf.subarray(start, start + compSize);
  if (data.length < compSize) throw new Error("成员数据被截断");
  if (method === 0) return data;
  if (method === 8) {
    return zlib.inflateRawSync(data, {
      maxOutputLength: Math.max(1, Math.min(uncompressedSize + 1024, INSPECT_MAX_MEMBER_BYTES)),
    });
  }
  throw new Error(`不支持的压缩方法 ${method}`);
}

// ---------------------------------------------------------------------------
// gzip / tar
// ---------------------------------------------------------------------------

async function walkGzip(buf, depth, maxDepth, ctx) {
  let inner;
  try {
    inner = zlib.gunzipSync(buf, { maxOutputLength: ctx.maxUncompressedBytes });
  } catch {
    throw new ArchiveError("archive_expansion_limit", "gzip 解压超过上限或数据损坏");
  }
  checkBudget(ctx, { uncompressed: inner.length, isDirectory: false, name: "gzip 载荷" });
  const kind = sniffArchive(inner.subarray(0, 512));
  if (kind === "tar") {
    ctx.report.nestedArchives += 1;
    ctx.report.nestingDepth = Math.max(ctx.report.nestingDepth, depth + 1);
    if (depth + 1 > maxDepth) {
      throw new ArchiveError("archive_too_deep", `压缩包嵌套超过 ${maxDepth} 层，已停止展开`, {
        depth: depth + 1,
      });
    }
    walkTar(inner, depth + 1, maxDepth, ctx);
  }
}

function walkTar(buf, depth, maxDepth, ctx) {
  const members = listTar(buf);
  for (const m of members) {
    checkBudget(ctx, m);
    if (m.isDirectory) continue;
    checkMember(m, ctx, depth);
    if (!m.data) continue;
    descend(m.data, m.name, depth, maxDepth, ctx).catch((err) => {
      if (err instanceof ArchiveError) {
        ctx.report.findings.push(finding(err.code, "high", err.message, err.detail));
      }
    });
  }
}

function listTar(buf) {
  const members = [];
  let p = 0;
  let longName = null;
  let paxPath = null;
  for (;;) {
    if (p + 512 > buf.length) break;
    const header = buf.subarray(p, p + 512);
    if (header.every((b) => b === 0)) break;
    const type = header.toString("latin1", 156, 157);
    const sizeField = header.toString("latin1", 124, 136).replace(/\0.*$/, "").trim();
    const size = /^[0-7]+$/.test(sizeField) ? parseInt(sizeField, 8) : 0;
    const dataStart = p + 512;
    if (!Number.isFinite(size) || dataStart + size > buf.length) {
      throw new ArchiveError("archive_unreadable", "tar 成员被截断");
    }
    const data = buf.subarray(dataStart, dataStart + size);
    if (type === "L") {
      longName = data.toString("utf8").replace(/\0.*$/, "");
    } else if (type === "x") {
      const m = /(?:^|\n)\d+ path=([^\n]+)\n/.exec(data.toString("utf8"));
      paxPath = m ? m[1] : null;
    } else if (type !== "g") {
      const rawName = header.toString("latin1", 0, 100).replace(/\0.*$/, "");
      const prefix = header.toString("latin1", 345, 500).replace(/\0.*$/, "");
      const name = paxPath || longName || (prefix ? `${prefix}/${rawName}` : rawName);
      longName = null;
      paxPath = null;
      if (name) {
        const isDirectory = type === "5";
        members.push({
          name,
          data: isDirectory ? null : data,
          isDirectory,
          isSymlink: type === "1" || type === "2",
          encrypted: false,
          uncompressed: size,
          compressed: size,
          ratio: 1,
        });
      }
    }
    p = dataStart + Math.ceil(size / 512) * 512;
  }
  return members;
}
