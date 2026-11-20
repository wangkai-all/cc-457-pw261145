// Archive inspector unit tests: nesting, bombs, traversal, encryption, limits.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import zlib from "node:zlib";
import { inspectArchive, sniffArchive, archiveKindOfName } from "../src/archive.js";
import { makeZip, makeTar, tempRoot } from "./helpers.js";

async function staged(entries, opts) {
  const dir = await tempRoot("ig-arc-");
  const p = path.join(dir, "sample.zip");
  await fs.writeFile(p, makeZip(entries, opts));
  return { dir, p };
}

const LIMITS = {
  maxDepth: 2,
  maxMembers: 20,
  maxUncompressedBytes: 256 * 1024,
  maxRatio: 10,
};

test("sniffArchive 识别常见格式与伪装扩展名", () => {
  assert.equal(sniffArchive(makeZip([{ name: "a", data: "x" }])), "zip");
  assert.equal(sniffArchive(zlib.gzipSync("hello")), "gzip");
  assert.equal(sniffArchive(makeTar([{ name: "a.txt", data: "x" }])), "tar");
  assert.equal(sniffArchive(Buffer.from("plain text")), null);
  assert.equal(archiveKindOfName("report.tar.gz"), "gzip");
  assert.equal(archiveKindOfName("photo.png"), null);
});

test("普通 zip：列出成员、统计大小", async () => {
  const { p } = await staged([
    { name: "a.txt", data: "hello" },
    { name: "dir/b.txt", data: "world world" },
  ]);
  const r = await inspectArchive(p, LIMITS);
  assert.equal(r.archive, true);
  assert.equal(r.kind, "zip");
  assert.equal(r.members, 2);
  assert.equal(r.nestingDepth, 1);
  assert.equal(r.findings.length, 0);
  assert.ok(r.totalUncompressed > 0);
});

test("路径穿越与绝对路径被标记为高危", async () => {
  const { p } = await staged([
    { name: "../../etc/passwd", data: "x" },
    { name: "/abs/evil.sh", data: "y" },
    { name: "ok.txt", data: "z" },
  ]);
  const r = await inspectArchive(p, LIMITS);
  const codes = r.findings.map((f) => f.code);
  assert.ok(codes.includes("archive_path_traversal"));
  assert.ok(codes.includes("archive_absolute_path"));
  for (const f of r.findings) assert.equal(f.severity, "high");
});

test("符号链接与加密成员被识别", async () => {
  const { p } = await staged([
    { name: "link", data: "/etc/shadow", symlink: true },
    { name: "secret.txt", data: "ciphertext", encrypt: true },
  ]);
  const r = await inspectArchive(p, LIMITS);
  const codes = r.findings.map((f) => f.code);
  assert.ok(codes.includes("archive_symlink"));
  assert.ok(codes.includes("archive_encrypted"));
});

test("嵌套 zip 会被展开，超过层数上限则拒绝", async () => {
  const inner = makeZip([{ name: "deep.txt", data: "deeper" }]);
  const middle = makeZip([{ name: "inner.zip", data: inner }]);
  const outer = makeZip([{ name: "middle.zip", data: middle }]);
  const dir = await tempRoot("ig-nest-");
  const p = path.join(dir, "outer.zip");
  await fs.writeFile(p, outer);

  const shallow = await inspectArchive(p, { ...LIMITS, maxDepth: 1 });
  assert.ok(shallow.findings.some((f) => f.code === "archive_too_deep"));

  const deep = await inspectArchive(p, { ...LIMITS, maxDepth: 3 });
  assert.equal(deep.findings.filter((f) => f.code === "archive_too_deep").length, 0);
  assert.ok(deep.nestedArchives >= 2);
  assert.ok(deep.nestingDepth >= 3);
});

test("成员数量上限", async () => {
  const entries = Array.from({ length: 30 }, (_, i) => ({ name: `f${i}.txt`, data: "x" }));
  const { p } = await staged(entries);
  const r = await inspectArchive(p, { ...LIMITS, maxMembers: 10 });
  assert.ok(r.findings.some((f) => f.code === "archive_too_many_members"));
});

test("解压总量上限按声明体积判断（压缩炸弹）", async () => {
  const bomb = Buffer.alloc(2 * 1024 * 1024, 0x41); // compresses to ~2 KB
  const { p } = await staged([{ name: "bomb.txt", data: bomb }]);
  const r = await inspectArchive(p, { ...LIMITS, maxUncompressedBytes: 100 * 1024 });
  const codes = r.findings.map((f) => f.code);
  assert.ok(
    codes.includes("archive_expansion_limit") || codes.includes("archive_ratio_high"),
    `expected expansion guard, got ${codes.join(",")}`,
  );
});

test("重名成员被标记（覆盖攻击）", async () => {
  const { p } = await staged([
    { name: "same.txt", data: "first" },
    { name: "same.txt", data: "second" },
  ]);
  const r = await inspectArchive(p, LIMITS);
  assert.ok(r.findings.some((f) => f.code === "archive_duplicate_member"));
});

test("截断的 zip 不会抛异常，而是给出损坏原因", async () => {
  const good = makeZip([{ name: "a.txt", data: "hello" }]);
  const dir = await tempRoot("ig-trunc-");
  const p = path.join(dir, "broken.zip");
  await fs.writeFile(p, good.subarray(0, good.length - 40));
  const r = await inspectArchive(p, LIMITS);
  assert.equal(r.archive, true);
  assert.ok(r.findings.some((f) => f.code === "archive_unreadable"));
});

test("tar 与嵌套在 tar 里的 zip", async () => {
  const innerZip = makeZip([{ name: "x.txt", data: "inside" }]);
  const tar = makeTar([
    { name: "readme.txt", data: "hello" },
    { name: "payload.zip", data: innerZip },
  ]);
  const dir = await tempRoot("ig-tar-");
  const p = path.join(dir, "bundle.tar");
  await fs.writeFile(p, tar);
  const r = await inspectArchive(p, { ...LIMITS, maxDepth: 3 });
  assert.equal(r.kind, "tar");
  // members counts everything inspected, including the nested zip's entry.
  assert.ok(r.members >= 2);
  assert.ok(r.nestedArchives >= 1);
});
