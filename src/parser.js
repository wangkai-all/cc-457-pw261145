// Content extraction. The parser only ever sees admitted files (queue dir),
// never the inbox. Results are report files next to the payload so the queue is
// self-describing even if the database is rebuilt.
//
// Supported without dependencies: text/CSV/JSON/Markdown, XML, product-format
// ZIP containers (docx, xlsx, pptx, odt) via text extraction, and a manifest
// listing for other archives. Everything else is recorded as unsupported.

import path from "node:path";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { sniffArchive, archiveKindOfName } from "./archive.js";

const TEXT_EXTS = new Set([
  ".txt", ".log", ".csv", ".tsv", ".md", ".markdown", ".json", ".ndjson", ".xml", ".html",
  ".htm", ".yaml", ".yml", ".ini", ".conf", ".sql", ".js", ".ts", ".py", ".sh", ".css",
]);

const OOXML_PARTS = {
  docx: ["word/document.xml"],
  xlsx: ["xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"],
  pptx: ["ppt/slides/slide1.xml"],
  odt: ["content.xml"],
  ods: ["content.xml"],
  odp: ["content.xml"],
};

export class ParseUnsupportedError extends Error {
  constructor(message) {
    super(message);
    this.code = "parse_unsupported";
    this.retryable = false;
  }
}

export class ParseError extends Error {
  constructor(message, detail) {
    super(message);
    this.code = "parse_failed";
    this.retryable = true;
    this.detail = detail ?? null;
  }
}

export function detectFormat(filename, head) {
  const ext = path.extname(filename).toLowerCase();
  const sniff = sniffArchive(head);
  if (sniff === "zip") {
    const known = /\.(docx|xlsx|pptx|odt|ods|odp|epub)$/i.test(filename);
    return known ? ext.slice(1) : "zip";
  }
  if (sniff) return archiveKindOfName(filename) ?? sniff;
  if (TEXT_EXTS.has(ext)) return ext.slice(1);
  if (head && isProbablyText(head)) return "text";
  return "binary";
}

function isProbablyText(buf) {
  const n = Math.min(buf.length, 4096);
  if (n === 0) return true;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const b = buf[i];
    if (b === 0) return false;
    if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b < 0x7f)) printable += 1;
    else if (b >= 0x80) printable += 0.5;
  }
  return printable / n > 0.85;
}

/**
 * Parse one file. Returns { kind, summary, payload, bytesRead } or throws
 * ParseUnsupportedError / ParseError.
 */
export async function parseFile(filePath, originalName, { readFile }) {
  const buf = await readFile(filePath);
  const head = buf.subarray(0, 4096);
  const kind = detectFormat(originalName, head);

  if (kind === "zip" || kind === "gzip" || kind === "tar") {
    return manifestSummary(buf, kind, originalName);
  }
  if (OOXML_PARTS[kind]) {
    return ooxmlSummary(buf, kind, originalName);
  }
  if (kind === "binary") {
    throw new ParseUnsupportedError(
      `二进制格式（${path.extname(originalName) || "无扩展名"}）没有可用的文本解析器`,
    );
  }
  return textSummary(buf, kind, originalName);
}

function textSummary(buf, kind, originalName) {
  let text = buf.toString("utf8");
  // Strip a UTF-8 BOM so the first token isn't polluted.
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const lines = text.length ? text.split(/\r\n|\r|\n/) : [];
  const nonEmpty = lines.filter((l) => l.trim().length > 0);
  const decoded = kind === "json" ? jsonShape(text) : null;
  const words = (text.match(/[\p{L}\p{N}_'-]+/gu) ?? []).length;
  const payload = {
    format: kind,
    encoding: "utf-8",
    lineCount: lines.length,
    nonEmptyLines: nonEmpty.length,
    wordCount: words,
    charCount: text.length,
    preview: text.slice(0, 400),
    head: nonEmpty.slice(0, 5),
    json: decoded,
    columns: kind === "csv" || kind === "tsv" ? inferColumns(nonEmpty, kind === "tsv" ? "\t" : ",") : null,
  };
  const summary =
    kind === "json" && decoded
      ? `JSON ${decoded.type}${decoded.keys ? `（${decoded.keys} 个字段）` : ""}，${nonEmpty.length} 行`
      : `${kind.toUpperCase()}，${lines.length} 行 / ${words} 词`;
  return { kind, summary, payload, bytesRead: buf.length };
}

function jsonShape(text) {
  try {
    const v = JSON.parse(text);
    if (Array.isArray(v)) return { type: "array", length: v.length };
    if (v && typeof v === "object") {
      return { type: "object", keys: Object.keys(v).length, keyNames: Object.keys(v).slice(0, 12) };
    }
    return { type: typeof v };
  } catch {
    return { type: "invalid" };
  }
}

function inferColumns(nonEmpty, sep) {
  if (!nonEmpty.length) return [];
  const first = nonEmpty[0].split(sep).map((s) => s.trim().replace(/^"|"$/g, ""));
  if (first.length < 2) return [];
  return first.slice(0, 24).map((name, i) => ({ index: i, name: name || `列 ${i + 1}` }));
}

// Minimal ZIP reader for OOXML containers: we only need named entries.
function zipEntries(buf) {
  const SIG_EOCD = 0x06054b50;
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ParseError("ZIP 容器缺少中央目录");
  const entries = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out = new Map();
  for (let i = 0; i < entries; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) break;
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    out.set(name, { method, compSize, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

function readEntry(buf, entry) {
  const p = entry.localOffset;
  if (buf.readUInt32LE(p) !== 0x04034b50) throw new ParseError("ZIP 本地头损坏");
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const start = p + 30 + nameLen + extraLen;
  const data = buf.subarray(start, start + entry.compSize);
  if (entry.method === 0) return data;
  if (entry.method === 8) {
    return zlib.inflateRawSync(data, { maxOutputLength: 32 * 1024 * 1024 });
  }
  throw new ParseUnsupportedError(`不支持的压缩方法 ${entry.method}`);
}

function ooxmlSummary(buf, kind, originalName) {
  const entries = zipEntries(buf);
  const wanted = OOXML_PARTS[kind] ?? [];
  const texts = [];
  for (const part of wanted) {
    const e = entries.get(part);
    if (!e) continue;
    const xml = readEntry(buf, e).toString("utf8");
    texts.push(xmlToText(xml));
  }
  const text = texts.join("\n").trim();
  const payload = {
    format: kind,
    entries: entries.size,
    partsRead: wanted.filter((w) => entries.has(w)),
    charCount: text.length,
    preview: text.slice(0, 600),
  };
  const summary = text.length
    ? `${kind.toUpperCase()}，提取 ${text.length} 字符`
    : `${kind.toUpperCase()}，未提取到文本`;
  return { kind, summary, payload, bytesRead: buf.length };
}

function manifestSummary(buf, kind, originalName) {
  // Reuse the archive inspector's findings for the manifest? The inspector has
  // already run and its report is attached to the product; here we only need a
  // member listing for the parse result.
  const entries = kind === "zip" ? [...zipEntries(buf).keys()] : [];
  const payload = {
    format: kind,
    containerOnly: true,
    memberCount: entries.length,
    members: entries.slice(0, 100),
    truncated: entries.length > 100,
  };
  return {
    kind: kind === "gzip" ? "archive" : kind,
    summary:
      kind === "zip"
        ? `ZIP 清单，${entries.length} 个成员`
        : `${kind} 容器，已通过完整性检查`,
    payload,
    bytesRead: buf.length,
  };
}

function xmlToText(xml) {
  return xml
    .replace(/<w:p[ >]/g, "\n<w:p ")
    .replace(/<\/w:p>/g, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{2,}/g, "\n")
    .trim();
}

/** Stable content digest for parse reports. */
export function digestOf(...parts) {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(String(p));
  return h.digest("hex");
}
