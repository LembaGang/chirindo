// A deterministic zip (B-439 spec §4: "equal inputs, equal bytes"). Members
// are STORED (method 0, no compression), in the order given, with one fixed
// DOS time, no extra fields and no comments, so the bytes depend only on the
// paths, the contents and that time. The reader takes only what the writer
// makes and refuses anything else; it is for checking a pack, not a general
// unzip.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export interface ZipMember {
  path: string;
  data: Buffer;
}

// A DOS date and time (2-second resolution, read as UTC). Zip cannot hold a
// year before 1980; such a time is refused.
function dosTime(d: Date): { time: number; date: number } {
  const y = d.getUTCFullYear();
  if (y < 1980 || y > 2107) throw new Error(`zip: a member time must lie in 1980 to 2107 (got ${d.toISOString()})`);
  return {
    time: (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2),
    date: ((y - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate(),
  };
}

const PATH_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

export function writeZip(members: ZipMember[], at: Date): Buffer {
  const { time, date } = dosTime(at);
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  const seen = new Set<string>();
  let offset = 0;
  for (const m of members) {
    if (!PATH_RE.test(m.path) || m.path.split("/").some((s) => s === "." || s === "..")) throw new Error(`zip: path not allowed: ${m.path}`);
    if (seen.has(m.path)) throw new Error(`zip: duplicate path ${m.path}`);
    seen.add(m.path);
    if (m.data.length > 0xfffffffe) throw new Error(`zip: member too large: ${m.path}`);
    const name = Buffer.from(m.path, "utf8");
    const crc = crc32(m.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(m.data.length, 18);
    local.writeUInt32LE(m.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, m.data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(m.data.length, 20);
    central.writeUInt32LE(m.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + m.data.length;
  }
  if (members.length > 0xffff) throw new Error("zip: too many members");
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(members.length, 8);
  end.writeUInt16LE(members.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

// Reads a zip this module wrote: stored members only, each local header
// agreeing with the central directory, each CRC matching. Throws otherwise.
export function readZip(buf: Buffer): Map<string, Buffer> {
  if (buf.length < 22) throw new Error("zip: too short");
  const endAt = buf.length - 22;
  if (buf.readUInt32LE(endAt) !== 0x06054b50) throw new Error("zip: no end record where this writer puts it (a comment or another writer?)");
  const count = buf.readUInt16LE(endAt + 10);
  const cdSize = buf.readUInt32LE(endAt + 12);
  const cdAt = buf.readUInt32LE(endAt + 16);
  if (cdAt + cdSize !== endAt) throw new Error("zip: central directory is not directly before the end record");
  const out = new Map<string, Buffer>();
  let p = cdAt;
  let expectLocal = 0;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("zip: bad central directory entry");
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localAt = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    if (method !== 0 || extraLen !== 0 || commentLen !== 0) throw new Error(`zip: ${name}: not a stored member without extras`);
    if (localAt !== expectLocal) throw new Error(`zip: ${name}: members are not contiguous`);
    if (buf.readUInt32LE(localAt) !== 0x04034b50) throw new Error(`zip: ${name}: bad local header`);
    const lNameLen = buf.readUInt16LE(localAt + 26);
    const lExtra = buf.readUInt16LE(localAt + 28);
    if (lNameLen !== nameLen || lExtra !== 0 || buf.subarray(localAt + 30, localAt + 30 + nameLen).toString("utf8") !== name) {
      throw new Error(`zip: ${name}: local header disagrees with the central directory`);
    }
    if (buf.readUInt32LE(localAt + 14) !== crc || buf.readUInt32LE(localAt + 18) !== size || buf.readUInt32LE(localAt + 22) !== size) {
      throw new Error(`zip: ${name}: local sizes or CRC disagree with the central directory`);
    }
    const dataAt = localAt + 30 + nameLen;
    const data = buf.subarray(dataAt, dataAt + size);
    if (data.length !== size || crc32(data) !== crc) throw new Error(`zip: ${name}: CRC mismatch`);
    if (out.has(name)) throw new Error(`zip: duplicate member ${name}`);
    out.set(name, Buffer.from(data));
    expectLocal = dataAt + size;
    p += 46 + nameLen;
  }
  if (expectLocal !== cdAt) throw new Error("zip: bytes between the last member and the central directory");
  return out;
}
