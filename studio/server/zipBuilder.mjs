import { deflateRawSync } from "node:zlib";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, posix, relative } from "node:path";

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32(buffer) {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i++) {
    crc = CRC_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Create a standard PKZIP archive buffer from an array of { path, data } entries.
 * Uses DEFLATE (method 8) and UTF-8 filename flag (bit 11).
 */
export function buildZipBuffer(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const cleanPath = entry.path.replace(/\\/g, "/").replace(/^\/+/, "");
    const nameBytes = Buffer.from(cleanPath, "utf8");
    const rawData = Buffer.isBuffer(entry.data)
      ? entry.data
      : Buffer.from(String(entry.data), "utf8");
    const compressed = deflateRawSync(rawData, { level: 6 });
    const checksum = crc32(rawData);

    // Local file header (30 bytes + filename)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed (2.0)
    localHeader.writeUInt16LE(0x0800, 6); // UTF-8 flag
    localHeader.writeUInt16LE(8, 8); // compression method: deflate
    localHeader.writeUInt16LE(0x6000, 10); // mod time
    localHeader.writeUInt16LE(0x5d59, 12); // mod date
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(rawData.length, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra length

    localParts.push(localHeader, nameBytes, compressed);

    // Central directory header (46 bytes + filename)
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0x0800, 8); // UTF-8 flag
    centralHeader.writeUInt16LE(8, 10); // deflate
    centralHeader.writeUInt16LE(0x6000, 12);
    centralHeader.writeUInt16LE(0x5d59, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(rawData.length, 24);
    centralHeader.writeUInt16LE(nameBytes.length, 28);
    centralHeader.writeUInt16LE(0, 30); // extra
    centralHeader.writeUInt16LE(0, 32); // comment
    centralHeader.writeUInt16LE(0, 34); // disk start
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE(0, 38); // external attrs
    centralHeader.writeUInt32LE(offset, 42); // relative offset

    centralParts.push(centralHeader, nameBytes);
    offset += localHeader.length + nameBytes.length + compressed.length;
  }

  const centralBuffer = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuffer.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralBuffer, eocd]);
}

/**
 * Recursively pack a directory on disk into a ZIP buffer under an optional root prefix.
 */
export function zipDirectory(rootDir, prefix = "") {
  const entries = [];
  const walk = (currentDir) => {
    const names = readdirSync(currentDir).sort();
    for (const name of names) {
      const fullPath = join(currentDir, name);
      const st = statSync(fullPath);
      if (st.isDirectory()) {
        walk(fullPath);
      } else if (st.isFile()) {
        const rel = relative(rootDir, fullPath).split("\\").join("/");
        const zipPath = prefix ? posix.join(prefix, rel) : rel;
        entries.push({ path: zipPath, data: readFileSync(fullPath) });
      }
    }
  };
  walk(rootDir);
  return buildZipBuffer(entries);
}
