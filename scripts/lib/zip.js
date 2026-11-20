// Tiny ZIP writer used by the demo seeder (and only by it).
//
// Deliberately minimal: stored or deflated entries, no ZIP64, no encryption
// beyond setting the flag for fixtures that need an "encrypted" member.

import zlib from "node:zlib";

export function makeZip(entries, { stored = false } = {}) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const { name, data, symlink = false, encrypt = false } of entries) {
    const body = Buffer.isBuffer(data) ? data : Buffer.from(data ?? "");
    const compressed = stored ? body : zlib.deflateRawSync(body);
    const nameBuf = Buffer.from(name, "utf8");
    const flags = encrypt ? 0x1 : 0;
    const method = stored ? 0 : 8;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(body.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(Buffer.concat([local, nameBuf, compressed]));

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(flags, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt32LE(compressed.length, 20);
    cd.writeUInt32LE(body.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    const mode = symlink ? 0o120777 : 0o100644;
    cd.writeUInt32LE((mode << 16) >>> 0, 38);
    cd.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cd, nameBuf]));

    offset += 30 + nameBuf.length + compressed.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cdBuf, eocd]);
}
