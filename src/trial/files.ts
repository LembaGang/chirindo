// The trial recorder's files under its data directory:
//
//   chains/<session_id>.jsonl                  the chain (appendReceipt's format)
//   chains/<session_id>.jsonl.witness.ndjson   its witness sidecar (unchanged format)
//   chains/<session_id>.lock                   the process id of the running recorder
//   args/<session_id>/<floor(count/1000)>/<count>-<32 hex>.json   retained arguments
//   gaps.ndjson                                one line per call that made no entry
//   witness-timing.ndjson                      one line per witness POST and awaitWitness
//
// Directories are created 0700 and files 0600 where the OS honours modes. No
// file name holds a colon: args_hash begins "sha256:", and on NTFS a colon in
// a file name names an alternate data stream.

import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  fstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;

export function chainsDir(dir: string): string {
  return join(dir, "chains");
}
export function chainPathOf(dir: string, sessionId: string): string {
  return join(dir, "chains", `${sessionId}.jsonl`);
}
export function lockPathOf(dir: string, sessionId: string): string {
  return join(dir, "chains", `${sessionId}.lock`);
}
export function gapsPathOf(dir: string): string {
  return join(dir, "gaps.ndjson");
}
export function timingPathOf(dir: string): string {
  return join(dir, "witness-timing.ndjson");
}

export function ensureDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: DIR_MODE });
}

// Create the file 0600 if absent, for writers that append without a mode.
export function ensureFile(path: string): void {
  closeSync(openSync(path, "a", FILE_MODE));
}

export function appendJsonLine(path: string, value: unknown): void {
  appendFileSync(path, JSON.stringify(value) + "\n", { encoding: "utf8", mode: FILE_MODE });
}

export function sha256Tagged(s: string): string {
  return "sha256:" + createHash("sha256").update(s, "utf8").digest("hex");
}

// Write one retained-arguments file; returns its path. Throws when it cannot,
// leaving no partial file behind.
export function writeRetained(
  dir: string,
  sessionId: string,
  count: number,
  argsHash: string,
  content: { args_hash: string; order_ref_sha256: string; call_seq: number | null; arguments: unknown },
): string {
  const bucket = join(dir, "args", sessionId, String(Math.floor(count / 1000)));
  ensureDir(bucket);
  const path = join(bucket, `${count}-${argsHash.slice("sha256:".length, "sha256:".length + 32)}.json`);
  try {
    // "w": a file left with this name by an earlier failed append is an orphan
    // that no entry names, so it may be replaced.
    writeFileSync(path, JSON.stringify(content), { encoding: "utf8", mode: FILE_MODE, flag: "w" });
  } catch (e) {
    rmSync(path, { force: true });
    throw e;
  }
  return path;
}

export function writeLock(dir: string, sessionId: string): void {
  writeFileSync(lockPathOf(dir, sessionId), String(process.pid), { encoding: "utf8", mode: FILE_MODE });
}

export function removeLock(dir: string, sessionId: string): void {
  try {
    rmSync(lockPathOf(dir, sessionId), { force: true });
  } catch {
    /* the directory may be gone; nothing to release */
  }
}

// Whether a lock names a running process. Unreadable or malformed counts as
// live (fail closed: such a chain is skipped, never touched).
export function lockIsLive(path: string): boolean {
  if (!existsSync(path)) return false;
  let pid: number;
  try {
    const t = readFileSync(path, "utf8").trim();
    if (!/^[1-9][0-9]{0,9}$/.test(t)) return true;
    pid = Number(t);
  } catch {
    return true;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM: it exists and belongs to someone else.
    return (e as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

const EDGE_BYTES = 65_536;

// The first line and the last complete line of a chain, read from its two
// ends only, so the cost does not grow with the chain. A torn last line (no
// newline after it) is ignored. null when either cannot be found.
export function chainEnds(path: string): { first: string; last: string } | null {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    const headLen = Math.min(size, EDGE_BYTES);
    const head = Buffer.alloc(headLen);
    readSync(fd, head, 0, headLen, 0);
    const firstEnd = head.indexOf(0x0a);
    if (firstEnd === -1) return null;
    const tailStart = Math.max(0, size - EDGE_BYTES);
    const tail = Buffer.alloc(size - tailStart);
    readSync(fd, tail, 0, tail.length, tailStart);
    const lastEnd = tail.lastIndexOf(0x0a);
    // A negative offset would count from the end of the buffer.
    if (lastEnd < 1) return null;
    const prev = tail.lastIndexOf(0x0a, lastEnd - 1);
    if (prev === -1 && tailStart !== 0) return null;
    return {
      first: head.subarray(0, firstEnd).toString("utf8").replace(/\r$/, ""),
      last: tail.subarray(prev + 1, lastEnd).toString("utf8").replace(/\r$/, ""),
    };
  } finally {
    closeSync(fd);
  }
}

// Earlier sessions' chains, newest first: [session_id, path, mtimeMs].
export function earlierChains(dir: string, ownSessionId: string): { sessionId: string; path: string; mtimeMs: number }[] {
  const out: { sessionId: string; path: string; mtimeMs: number }[] = [];
  for (const name of readdirSync(chainsDir(dir))) {
    const m = /^([0-9a-f]{32})\.jsonl$/.exec(name);
    if (m === null || m[1] === ownSessionId) continue;
    const path = join(chainsDir(dir), name);
    try {
      out.push({ sessionId: m[1]!, path, mtimeMs: statSync(path).mtimeMs });
    } catch {
      /* gone since the listing */
    }
  }
  return out.sort((a, b) => b.mtimeMs - a.mtimeMs);
}

// Remove every retained file for an args_hash, or for an order reference
// (matched by its SHA-256). Touches nothing outside <dir>/args. Returns the
// removed paths relative to <dir>, and how many files could not be read.
export function eraseRetained(
  dir: string,
  by: { argsHash: string } | { orderRefSha256: string },
): { removed: string[]; unreadable: number } {
  const removed: string[] = [];
  let unreadable = 0;
  const root = join(dir, "args");
  if (!existsSync(root)) return { removed, unreadable };
  const suffix = "argsHash" in by ? `-${by.argsHash.slice("sha256:".length, "sha256:".length + 32)}.json` : ".json";
  for (const sid of readdirSync(root)) {
    const sidDir = join(root, sid);
    if (!statSync(sidDir).isDirectory()) continue;
    for (const bucket of readdirSync(sidDir)) {
      const bucketDir = join(sidDir, bucket);
      if (!statSync(bucketDir).isDirectory()) continue;
      for (const name of readdirSync(bucketDir)) {
        if (!name.endsWith(suffix)) continue;
        const path = join(bucketDir, name);
        let j: Record<string, unknown>;
        try {
          j = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
        } catch {
          unreadable++;
          continue;
        }
        const match = "argsHash" in by ? j["args_hash"] === by.argsHash : j["order_ref_sha256"] === by.orderRefSha256;
        if (!match) continue;
        rmSync(path);
        removed.push(["args", sid, bucket, name].join("/"));
      }
    }
  }
  return { removed, unreadable };
}
