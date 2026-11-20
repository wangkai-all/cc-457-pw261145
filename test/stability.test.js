// Stability helpers: temp naming, quiet-window detection, writer detection,
// hashing and no-clobber moves.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import {
  classifyTempName,
  waitForStable,
  statSample,
  hashFile,
  moveNoClobber,
  heldOpenForWriting,
} from "../src/stability.js";
import { tempRoot, wait } from "./helpers.js";

test("临时文件名识别", () => {
  const temp = [
    ".hidden",
    ".report.pdf.a1b2c3",
    "~$proposal.docx",
    ".~lock.report.odt#",
    "upload.part",
    "video.crdownload",
    "file.tmp",
    "notes.swp",
    ".DS_Store",
  ];
  for (const n of temp) assert.equal(classifyTempName(n).temp, true, n);

  const real = ["report.pdf", "data.csv", "archive.zip", "photo.png", "说明.docx"];
  for (const n of real) assert.equal(classifyTempName(n).temp, false, n);

  assert.equal(classifyTempName("upload.zip", { inFlight: true }).temp, true);
});

test("waitForStable：停止写入后判定稳定", async () => {
  const dir = await tempRoot("ig-stab-");
  const p = path.join(dir, "file.txt");
  await fs.writeFile(p, "a");
  const fh = await fs.open(p, "a");
  const writing = (async () => {
    for (let i = 0; i < 6; i++) {
      await fh.write("x");
      await wait(60);
    }
    await fh.close();
  })();
  const res = await waitForStable(
    p,
    await statSample(p),
    { quietMs: 150, maxWaitMs: 4000, pollMs: 30, checkOpenHandles: true },
  );
  await writing;
  assert.equal(res.state, "stable");
  const final = await statSample(p);
  assert.equal(res.stat.size, final.size);
});

test("waitForStable：持续写入触发 unstable", async () => {
  const dir = await tempRoot("ig-stab2-");
  const p = path.join(dir, "growing.bin");
  await fs.writeFile(p, "0");
  const fh = await fs.open(p, "a");
  let stop = false;
  const writer = (async () => {
    while (!stop) {
      await fh.write("z");
      await wait(40);
    }
  })();
  const res = await waitForStable(
    p,
    await statSample(p),
    { quietMs: 120, maxWaitMs: 700, pollMs: 25, checkOpenHandles: false },
  );
  stop = true;
  await writer;
  await fh.close();
  assert.equal(res.state, "unstable");
});

test("waitForStable：文件被新 inode 替换时报告 replaced", async () => {
  const dir = await tempRoot("ig-stab3-");
  const p = path.join(dir, "swap.txt");
  await fs.writeFile(p, "old");
  const initial = await statSample(p);
  const swap = async () => {
    await wait(80);
    const tmp = path.join(dir, "new.tmp");
    await fs.writeFile(tmp, "new content");
    await fs.rename(tmp, p); // atomic replace → new inode
  };
  swap();
  const res = await waitForStable(p, initial, {
    quietMs: 10_000,
    maxWaitMs: 5000,
    pollMs: 25,
    checkOpenHandles: false,
  });
  assert.equal(res.state, "replaced");
  assert.notEqual(res.stat.ino, initial.ino);
});

test("waitForStable：文件消失", async () => {
  const dir = await tempRoot("ig-stab4-");
  const p = path.join(dir, "gone.txt");
  await fs.writeFile(p, "x");
  const initial = await statSample(p);
  setTimeout(() => fs.unlink(p), 60);
  const res = await waitForStable(p, initial, { quietMs: 500, maxWaitMs: 3000, pollMs: 25 });
  assert.equal(res.state, "gone");
});

test("hashFile：内容相同哈希相同，尾部不同则不同", async () => {
  const dir = await tempRoot("ig-hash-");
  const a = path.join(dir, "a.bin");
  const b = path.join(dir, "b.bin");
  const c = path.join(dir, "c.bin");
  const head = Buffer.alloc(4096, 1);
  await fs.writeFile(a, Buffer.concat([head, Buffer.from("tail-1")]));
  await fs.writeFile(b, Buffer.concat([head, Buffer.from("tail-1")]));
  await fs.writeFile(c, Buffer.concat([head, Buffer.from("tail-2")]));
  const ha = await hashFile(a, 512);
  const hb = await hashFile(b, 512);
  const hc = await hashFile(c, 512);
  assert.equal(ha.sha256, hb.sha256);
  assert.notEqual(ha.sha256, hc.sha256);
  assert.notEqual(ha.sampleHash, hc.sampleHash, "采样哈希也要能区分尾部差异");
});

test("moveNoClobber：目标存在时抛 EEXIST 且不动源文件", async () => {
  const dir = await tempRoot("ig-move-");
  const src = path.join(dir, "src.txt");
  const dst = path.join(dir, "dst");
  await fs.mkdir(dst);
  await fs.writeFile(src, "src");
  await fs.writeFile(path.join(dst, "src.txt"), "existing");
  await assert.rejects(() => moveNoClobber(src, dst, "src.txt"), (err) => err.code === "EEXIST");
  assert.equal(await fs.readFile(src, "utf8"), "src");
  assert.equal(await fs.readFile(path.join(dst, "src.txt"), "utf8"), "existing");
});

test("heldOpenForWriting 能发现写入句柄（仅 linux）", async (t) => {
  if (process.platform !== "linux") {
    t.skip("仅 linux 支持 /proc 检查");
    return;
  }
  const dir = await tempRoot("ig-open-");
  const p = path.join(dir, "busy.txt");
  await fs.writeFile(p, "x");
  assert.equal(await heldOpenForWriting(p), false);
  const fh = await fs.open(p, "a");
  assert.equal(await heldOpenForWriting(p), true);
  await fh.close();
  assert.equal(await heldOpenForWriting(p), false);
});
