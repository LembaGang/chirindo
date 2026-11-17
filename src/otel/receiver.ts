// B-481 T2, N2: the local OpenTelemetry receiver (`chirindo otel-receiver`).
// SPEC_2026-11-13_B481_one-line-install_rev2.md section 3, with the T2
// handoff's rulings (rev 3):
//
//   - Listens on 127.0.0.1 always, and on ::1 too when the machine has it
//     (ruling L2 b): if the ::1 bind fails because the address family or the
//     address is not available (EAFNOSUPPORT, EADDRNOTAVAIL) it carries on
//     with 127.0.0.1 alone and prints one line; any other failure of either
//     bind (the port taken above all) closes what was bound and fails the
//     start with the address named, so it is never half bound. Port 4318 by
//     default.
//   - The Host header must be localhost, 127.0.0.1 or [::1] at the bound port
//     (DNS rebinding). A request that carries an Origin header, or a
//     Sec-Fetch-Site other than "none", comes from a web page and is refused
//     on every route (an OTLP SDK sends neither). The OTLP routes take only
//     application/x-protobuf or application/json, the records route only
//     application/json (media type compared without parameters); OPTIONS and
//     every other method are refused; no response carries an
//     Access-Control-* header. With a token, every request needs
//     "Authorization: Bearer <token>" (compared in constant time).
//   - POST /v1/traces: OTLP/HTTP protobuf or JSON, optional gzip (src/otlp);
//     every span becomes one signed tool_call record (decision observed,
//     decision_source n/a, gate null), appended synchronously in arrival order.
//   - POST /v1/metrics and /v1/logs: forwarded with a forward endpoint, else
//     counted and discarded without being kept or parsed; answered 200.
//   - POST /v1/chirindo/records: JSON records from the add-ons (T4); the
//     provisional schema of ruling L3.
//   - Bodies are counted while they stream (Node SDKs send chunked bodies with
//     no Content-Length, T0 F2) and refused past 16 MiB. The bytes held across
//     all requests are capped (MAX_BYTES_IN_FLIGHT) and so are the open
//     connections (MAX_CONNECTIONS); past either the answer is 503 with
//     Retry-After, which the OTLP specification lets an SDK retry, and a gap
//     line.
//   - Every connection has three deadlines (rev 3, N1): its request headers
//     complete within HEADERS_DEADLINE_MS of the connection opening (or of the
//     previous answer), its body within BODY_DEADLINE_MS of the headers, and no
//     gap of IDLE_DEADLINE_MS without a byte in the middle of a request. A
//     connection that misses one is closed. When every connection slot is
//     taken, a new connection takes the slot of a connection that is not doing
//     useful work: the oldest with no request headers yet or idle between
//     requests, else the slowest body arriving under 64 KiB/s; only when
//     there is none is it answered 503.
//   - Gap lines (gaps.ndjson, never the chain). A request refused before its
//     body is read (Host, Origin, method, token, content type, connection
//     limit, a closed idle connection, gRPC) is a refusal: the first one of a
//     reason on a route is written at once with count 1, and later ones are
//     counted and written as one line per reason and route per
//     GAP_INTERVAL_MS with the count and the first and last times (rev 3, N2).
//     A request whose body was read, or begun, and that gave no record (a
//     refused or cut-off batch, a broken chain, a failed append or forward)
//     is a record gap and always has its own line. A refused trace batch is
//     also printed.
//   - Retain: the canonical span (or the records route's arguments) is written
//     to the sidecar BEFORE its record is appended, so a record on disk always
//     has its sidecar line; a crash between the two leaves a sidecar line with
//     no record, which the next start finds and writes as a gap line
//     (retained-without-record). --no-retain writes no sidecar.
//   - With a forward endpoint, each OTLP request's bytes and headers go on
//     unchanged after the receiver has answered; a failure (an answer of 300
//     or more, an error, 10 s) is a gap line forward-failed. Headers are never
//     written anywhere.
//   - The first start creates the signing key in the data directory if none.
//   - One random session per process. No checkpoint and no witness call: T3.
//
// Files under <dir>/otel/:
//   chains/<session>.jsonl              the chain (`chirindo verify` reads it)
//   chains/<session>.retained.ndjson    {seq, args_hash, preimage[, result_hash, result_preimage]}
//   gaps.ndjson                         {ts, session_id, route, reason, ...}

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { appendFileSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, statSync } from "node:fs";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import type { AddressInfo, Socket } from "node:net";
import { join } from "node:path";
import { OTLP_MAX_BODY_BYTES, OtlpDecodeError, mapTraceBody } from "../otlp/index.js";
import { GATE_AGENT } from "../receipt.js";
import {
  IDENTITY_FILENAME,
  PRIVATE_KEY_FILENAME,
  argsHash,
  jcsBytes,
  loadFullIdentity,
  resultHash,
  runInit,
  strictJsonParse,
  type ToolCallEvent,
} from "../vendor/recorder/index.js";
import { openObservedWriter, type ObservedWriter } from "./append.js";

export const OTEL_RECEIVER_DEFAULT_PORT = 4318;
export const OTEL_ROUTES = ["/v1/traces", "/v1/metrics", "/v1/logs", "/v1/chirindo/records"] as const;
// Records route limits (ruling L3, provisional for T4).
export const RECORDS_MAX = 1000;
export const TOOL_NAME_MAX = 256;
// Sized for a machine with under 1 GB free (the T2 read's M2): at most 32 MiB
// of request bodies held at once (two full 16 MiB batches). Rev 3 (N7): 32 open
// connections, so an exporter sending 20 batches at once is not answered 503;
// the bytes limit, not the connection count, bounds memory.
export const MAX_BYTES_IN_FLIGHT = 32 * 1024 * 1024;
export const MAX_CONNECTIONS = 32;
export const RETRY_AFTER_S = 2;
// Rev 3 (N1): connection deadlines. A T0 SDK request (1,460 to 7,373 bytes)
// arrives in one or two writes within milliseconds; the largest legal body
// (16 MiB) took well under 1 s on loopback in the worker's container, under
// 40 s at 40 times slower. See the handoff for the measurements.
export const HEADERS_DEADLINE_MS = 10_000;
export const BODY_DEADLINE_MS = 60_000;
export const IDLE_DEADLINE_MS = 15_000;
// A body in progress may lose its slot to a new connection when it has
// averaged less than EVICT_MIN_RATE bytes a second, its age counted as at least
// EVICT_AGE_FLOOR_MS (so a body is never judged on its first instant: under
// 3.2 KiB in its first 50 ms). A T0 request arrives whole in one read, so it
// is never a body in progress when a new connection is accepted.
export const EVICT_AGE_FLOOR_MS = 50;
export const EVICT_MIN_RATE = 64 * 1024;
// Rev 3 (N2): refusals are written as one line per reason and route per interval.
export const GAP_INTERVAL_MS = 60_000;
// The refusal reasons that are coalesced; every other gap line stands alone.
export const COALESCED_REASONS = ["host-not-allowed", "cross-origin", "method-not-allowed", "unauthorized", "unsupported_content_type", "too-many-connections", "evicted", "deadline-headers", "grpc-not-served"] as const;
const OTLP_TYPES = ["application/x-protobuf", "application/json"];
const RECORDS_TYPES = ["application/json"];

export interface OtelReceiverOptions {
  dir: string;
  port: number;
  token?: string;
  forward?: string;
  retain: boolean;
  log: (line: string) => void;
  now?: () => string;
  maxBytesInFlight?: number;
  maxConnections?: number;
  // Rev 3 seams for the tests; the defaults are the exported constants.
  headersDeadlineMs?: number;
  bodyDeadlineMs?: number;
  idleDeadlineMs?: number;
  gapIntervalMs?: number;
  // The ::1 bind; a seam for the tests (the default binds ::1 at the port).
  listen6?: (server: Server, port: number) => Promise<void>;
}

export interface OtelReceiverStats {
  connections: number;
  nonLoopbackConnections: number;
  refusedConnections: number;
  evictedConnections: number;
  deadlineCloses: number;
  refusals: number;
  records: number;
  gaps: number;
  bytesInFlight: number;
}

export interface OtelListening {
  port: number;
  url: string;
  addresses: string[];
  // "bound", or "unavailable (<code>)" when ::1 could not be bound for want of IPv6.
  ipv6: string;
}

export interface OtelReceiver {
  readonly sessionId: string;
  readonly chainPath: string;
  readonly retainedPath: string;
  readonly gapsPath: string;
  readonly identityPath: string;
  readonly keyCreated: boolean;
  listen(): Promise<OtelListening>;
  // Resolves when every forward started so far has finished.
  settled(): Promise<void>;
  stats(): OtelReceiverStats;
  close(): Promise<void>;
}

export function otelPaths(dir: string, sessionId: string) {
  return {
    chainsDir: join(dir, "otel", "chains"),
    chainPath: join(dir, "otel", "chains", `${sessionId}.jsonl`),
    retainedPath: join(dir, "otel", "chains", `${sessionId}.retained.ndjson`),
    gapsPath: join(dir, "otel", "gaps.ndjson"),
  };
}

// A loopback peer address as Node reports it.
export function isLoopbackAddress(a: string | undefined): boolean {
  if (a === undefined) return false;
  return a === "::1" || /^127\.\d+\.\d+\.\d+$/.test(a) || /^::ffff:127\.\d+\.\d+\.\d+$/i.test(a);
}

// The Host values accepted at the bound port (SPEC s3: localhost, 127.0.0.1 or
// [::1] at that port). Compared in lower case.
export function allowedHosts(port: number): string[] {
  return [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`];
}

// Ruling L2 b: which ::1 bind failures mean "this machine has no ::1" (carry on
// with 127.0.0.1 alone); every other failure stops the start.
export function ipv6Unavailable(code: string | undefined): boolean {
  return code === "EAFNOSUPPORT" || code === "EADDRNOTAVAIL";
}

// A request a web page made: it carries Origin, or a Sec-Fetch-Site other than
// "none" (a user typing the URL). OTLP SDKs send neither.
export function fromWebPage(headers: IncomingMessage["headers"]): string | undefined {
  if (headers.origin !== undefined) return "origin";
  const s = headers["sec-fetch-site"];
  if (s !== undefined && String(s).toLowerCase() !== "none") return "sec-fetch-site";
  return undefined;
}

// The media type of a Content-Type header: parameters removed, lower case.
export function mediaType(v: string | string[] | undefined): string {
  return String(v ?? "").split(";")[0]!.trim().toLowerCase();
}

// google.rpc.Status as protobuf: field 1 code (varint), field 2 message (string).
function statusProtobuf(code: number, message: string): Buffer {
  const msg = Buffer.from(message, "utf8");
  const varint = (n: number): number[] => {
    const out: number[] = [];
    do {
      let b = n & 0x7f;
      n = Math.floor(n / 128);
      if (n) b |= 0x80;
      out.push(b);
    } while (n);
    return out;
  };
  return Buffer.from([0x08, ...varint(code), 0x12, ...varint(msg.length), ...msg]);
}

const HOP_BY_HOP = new Set(["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-connection", "host", "content-length"]);
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest();

// The last complete line of a file, read from its end (a torn last line is
// skipped); undefined for an empty or missing file.
function lastLine(path: string): string | undefined {
  if (!existsSync(path)) return undefined;
  const fd = openSync(path, "r");
  try {
    let pos = fstatSync(fd).size;
    let acc = Buffer.alloc(0);
    while (pos > 0) {
      const n = Math.min(65536, pos);
      pos -= n;
      const b = Buffer.alloc(n);
      readSync(fd, b, 0, n, pos);
      acc = Buffer.concat([b, acc]);
      const lastNl = acc.lastIndexOf(0x0a);
      if (lastNl === -1) continue;
      const prevNl = acc.subarray(0, lastNl).lastIndexOf(0x0a);
      if (prevNl !== -1 || pos === 0) return acc.subarray(prevNl + 1, lastNl).toString("utf8");
    }
    return undefined;
  } finally {
    closeSync(fd);
  }
}

const defaultListen6 = (server: Server, port: number) =>
  new Promise<void>((done, fail) => {
    server.once("error", fail);
    server.listen(port, "::1", () => {
      server.off("error", fail);
      done();
    });
  });

export function createOtelReceiver(o: OtelReceiverOptions): OtelReceiver {
  const now = () => {
    try {
      const t = o.now?.();
      if (typeof t === "string") return t;
    } catch {
      /* fall back to the clock */
    }
    return new Date().toISOString();
  };
  const log = (line: string) => {
    try {
      o.log(line);
    } catch {
      /* the caller's logger failed */
    }
  };
  const maxBytes = o.maxBytesInFlight ?? MAX_BYTES_IN_FLIGHT;
  const maxConns = o.maxConnections ?? MAX_CONNECTIONS;
  const headersDeadline = o.headersDeadlineMs ?? HEADERS_DEADLINE_MS;
  const bodyDeadline = o.bodyDeadlineMs ?? BODY_DEADLINE_MS;
  const idleDeadline = o.idleDeadlineMs ?? IDLE_DEADLINE_MS;
  const gapInterval = o.gapIntervalMs ?? GAP_INTERVAL_MS;

  // The key: created on the first start if absent (SPEC s3), then loaded.
  mkdirSync(o.dir, { recursive: true, mode: 0o700 });
  const init = runInit({ dir: o.dir });
  const identityPath = join(o.dir, IDENTITY_FILENAME);
  const identity = loadFullIdentity(identityPath, join(o.dir, PRIVATE_KEY_FILENAME));
  const sessionId = randomBytes(16).toString("hex");
  const paths = otelPaths(o.dir, sessionId);
  mkdirSync(paths.chainsDir, { recursive: true, mode: 0o700 });
  const writer: ObservedWriter = openObservedWriter({
    chainPath: paths.chainPath,
    sessionId,
    agent: GATE_AGENT,
    kid: identity.kid,
    privateKey: identity.privateKey,
    publicKey: identity.publicKey,
  });

  let forwardBase: URL | undefined;
  if (o.forward !== undefined) {
    forwardBase = new URL(o.forward);
    if (forwardBase.protocol !== "http:" && forwardBase.protocol !== "https:") throw new Error("forward endpoint must be an http:// or https:// URL");
  }
  const tokenDigest = o.token !== undefined ? sha(o.token) : undefined;
  let port = o.port;
  let chainBroken = false;
  let inFlight = 0;
  const stats = { connections: 0, nonLoopbackConnections: 0, refusedConnections: 0, evictedConnections: 0, deadlineCloses: 0, refusals: 0, records: 0, gaps: 0 };
  const pending = new Set<Promise<void>>();
  const said = new Set<string>();
  const once = (key: string, line: string) => {
    if (!said.has(key)) {
      said.add(key);
      log(line);
    }
  };

  const writeGap = (line: Record<string, unknown>) => {
    stats.gaps += 1;
    try {
      appendFileSync(paths.gapsPath, JSON.stringify(line) + "\n", { encoding: "utf8", mode: 0o600 });
    } catch (e) {
      log(`[chirindo] otel-receiver: gap line not written (${(e as NodeJS.ErrnoException).code ?? "error"})`);
    }
  };
  // A record gap: always its own line.
  const gap = (route: string, reason: string, extra: Record<string, unknown> = {}) => {
    writeGap({ ts: now(), session_id: sessionId, route, reason, ...extra });
  };
  // A refusal (rev 3, N2): the first of a reason on a route is written at once
  // with count 1; later ones are counted, and each GAP_INTERVAL_MS the count
  // since the last line is written with the first and last times. A bucket
  // with nothing counted in an interval is dropped, so the next refusal of
  // that reason is again written at once. close() writes what is counted.
  type Bucket = { route: string; reason: string; opened: number; count: number; first?: string; last?: string };
  const buckets = new Map<string, Bucket>();
  const refuse = (route: string, reason: string, extra: Record<string, unknown> = {}) => {
    stats.refusals += 1;
    const key = `${route} ${reason}`;
    const b = buckets.get(key);
    const ts = now();
    if (b === undefined) {
      buckets.set(key, { route, reason, opened: Date.now(), count: 0 });
      writeGap({ ts, session_id: sessionId, route, reason, count: 1, first: ts, last: ts, ...extra });
      return;
    }
    b.count += 1;
    b.first ??= ts;
    b.last = ts;
  };
  const flushRefusals = (all: boolean) => {
    const t = Date.now();
    for (const [key, b] of buckets) {
      if (!all && t - b.opened < gapInterval) continue;
      if (b.count > 0) writeGap({ ts: now(), session_id: sessionId, route: b.route, reason: b.reason, count: b.count, first: b.first, last: b.last, coalesced: true });
      if (b.count === 0 || all) buckets.delete(key);
      else {
        b.opened = t;
        b.count = 0;
        delete b.first;
        delete b.last;
      }
    }
  };

  // A crash between a sidecar line and its record (M3) leaves a sidecar line
  // with no record. Found at start in every earlier session of this folder and
  // written once as a gap line.
  const checkLeftovers = () => {
    let names: string[] = [];
    try {
      names = readdirSync(paths.chainsDir).filter((n) => n.endsWith(".retained.ndjson"));
    } catch {
      return;
    }
    let reported = "";
    try {
      reported = readFileSync(paths.gapsPath, "utf8");
    } catch {
      /* no gap file yet */
    }
    for (const n of names) {
      const old = n.slice(0, -".retained.ndjson".length);
      if (old === sessionId) continue;
      try {
        const kept = lastLine(join(paths.chainsDir, n));
        if (kept === undefined) continue;
        const keptSeq = (JSON.parse(kept) as { seq: number }).seq;
        const cp = join(paths.chainsDir, `${old}.jsonl`);
        const rec = existsSync(cp) && statSync(cp).isFile() ? lastLine(cp) : undefined;
        const records = rec === undefined ? 0 : (JSON.parse(rec) as { seq: number }).seq + 1;
        if (keptSeq < records) continue;
        if (reported.includes(`"reason":"retained-without-record","old_session":"${old}"`)) continue;
        gap("start", "retained-without-record", { old_session: old, seq_from: records, seq_to: keptSeq });
        log(`[chirindo] otel-receiver: session ${old} has sidecar lines for seq ${records} to ${keptSeq} with no record (it stopped between the two writes); gap line written`);
      } catch {
        /* an unreadable earlier file is not this session's business */
      }
    }
  };
  checkLeftovers();

  const retainedLine = (seq: number, args_hash: string, preimage: unknown, canonical: Buffer | undefined, result?: { hash: string; preimage: unknown }) => {
    // A reader re-checks args_hash = sha256(JCS(preimage)); when the parsed
    // value does not give back the exact canonical bytes, the canonical text
    // is kept instead (preimage_jcs).
    const pre = canonical === undefined || jcsBytes(preimage).equals(canonical) ? { preimage } : { preimage_jcs: canonical.toString("utf8") };
    return JSON.stringify({ seq, args_hash, ...pre, ...(result !== undefined ? { result_hash: result.hash, result_preimage: result.preimage } : {}) }) + "\n";
  };

  // Append events in order: the sidecar line first, then the record. Returns
  // how many records were written before a failure; any failure ends
  // appending for this process (chain-broken).
  type Pending = { event: ToolCallEvent; preimage: unknown; canonical?: Buffer; result?: { hash: string; preimage: unknown } };
  let failedAt = "";
  const appendAll = (events: Pending[]): number => {
    let n = 0;
    for (const e of events) {
      if (chainBroken) break;
      const seq = writer.count;
      if (o.retain) {
        try {
          appendFileSync(paths.retainedPath, retainedLine(seq, e.event.args_hash, e.preimage, e.canonical, e.result), { encoding: "utf8", mode: 0o600 });
        } catch (err) {
          chainBroken = true;
          failedAt = "retained line";
          log(`[chirindo] otel-receiver: sidecar line for seq ${seq} not written (${(err as NodeJS.ErrnoException).code ?? (err as Error).message}); no further records are written by this process`);
          break;
        }
      }
      try {
        writer.append(e.event, now());
        stats.records += 1;
        n += 1;
      } catch (err) {
        chainBroken = true;
        failedAt = "chain line";
        log(`[chirindo] otel-receiver: append failed (${(err as NodeJS.ErrnoException).code ?? (err as Error).message}); no further records are written by this process`);
      }
    }
    return n;
  };

  const isJson = (req: IncomingMessage) => mediaType(req.headers["content-type"]) === "application/json";
  const sendOtlp = (req: IncomingMessage, res: ServerResponse, status: number, rpcCode: number, message: string, extra: Record<string, string> = {}) => {
    const json = isJson(req);
    const body = status === 200 ? (json ? Buffer.from("{}") : Buffer.alloc(0)) : json ? Buffer.from(JSON.stringify({ code: rpcCode, message })) : statusProtobuf(rpcCode, message);
    res.writeHead(status, { "content-type": json ? "application/json" : "application/x-protobuf", "content-length": String(body.length), "cache-control": "no-store", ...extra });
    res.end(body);
  };
  const sendJson = (res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) => {
    const text = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json", "content-length": String(Buffer.byteLength(text)), "cache-control": "no-store", ...extra });
    res.end(text);
  };

  const authorized = (req: IncomingMessage): boolean => {
    if (tokenDigest === undefined) return true;
    const h = req.headers["authorization"];
    if (typeof h !== "string" || !/^bearer /i.test(h)) return false;
    return timingSafeEqual(sha(h.slice("Bearer ".length)), tokenDigest);
  };

  // Connections and their deadlines (rev 3, N1). waiting: no request headers
  // yet; idle: between requests; body: headers in, body arriving; responding:
  // body in, the answer being made.
  type Conn = { s: Socket; state: "waiting" | "idle" | "body" | "responding" | "closed"; since: number; bodyStart: number; lastByte: number; bytes: number; cause?: string };
  const conns = new Map<Socket, Conn>();
  const closeConn = (c: Conn, cause: string) => {
    c.cause = cause;
    // A connection closed before its request headers is a refusal; one closed
    // in the middle of a body is a record gap, written by the request
    // ("aborted", with this cause).
    if (c.state === "waiting" || c.state === "idle") refuse("connection", cause);
    c.s.destroy();
  };
  // The slot a new connection may take when all are in use: the oldest
  // connection with no request headers yet or idle between requests, else the
  // body with the lowest average rate if that is under EVICT_MIN_RATE.
  const victim = (t: number): Conn | undefined => {
    let best: Conn | undefined;
    for (const c of conns.values()) {
      if (c.state === "waiting" || c.state === "idle") {
        if (best === undefined || best.state === "body" || c.since < best.since) best = c;
      }
    }
    if (best !== undefined) return best;
    let slowest = EVICT_MIN_RATE;
    for (const c of conns.values()) {
      if (c.state !== "body") continue;
      const rate = (c.bytes * 1000) / Math.max(t - c.bodyStart, EVICT_AGE_FLOOR_MS);
      if (rate < slowest) {
        slowest = rate;
        best = c;
      }
    }
    return best;
  };
  const sweep = () => {
    const t = Date.now();
    for (const c of [...conns.values()]) {
      if ((c.state === "waiting" || c.state === "idle") && t - c.since > headersDeadline) {
        stats.deadlineCloses += 1;
        closeConn(c, "deadline-headers");
      } else if (c.state === "body" && t - c.bodyStart > bodyDeadline) {
        stats.deadlineCloses += 1;
        closeConn(c, "deadline-body");
      } else if (c.state === "body" && t - c.lastByte > idleDeadline) {
        stats.deadlineCloses += 1;
        closeConn(c, "deadline-idle");
      }
    }
    flushRefusals(false);
  };
  let sweeper: NodeJS.Timeout | undefined;

  // The body, counted as it streams. keep: hold the bytes (else count and
  // discard). Held bytes count against MAX_BYTES_IN_FLIGHT until release().
  type Body = { kind: "ok"; buf: Buffer } | { kind: "too_large" } | { kind: "busy" } | { kind: "aborted"; cause?: string };
  const readBody = (req: IncomingMessage, keep: boolean): Promise<{ body: Body; release: () => void }> =>
    new Promise((done) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let held = 0;
      let state: "ok" | "too_large" | "busy" = "ok";
      let finished = false;
      const release = () => {
        inFlight -= held;
        held = 0;
        chunks.length = 0;
      };
      const finish = (body: Body) => {
        if (finished) return;
        finished = true;
        if (conn !== undefined && conn.state === "body") conn.state = "responding";
        if (body.kind !== "ok") release();
        done({ body, release });
      };
      const conn = conns.get(req.socket);
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (conn !== undefined) {
          conn.bytes += c.length;
          conn.lastByte = Date.now();
        }
        if (state === "ok" && size > OTLP_MAX_BODY_BYTES) {
          state = "too_large";
          release();
        }
        if (state !== "ok" || !keep) return;
        if (inFlight + c.length > maxBytes) {
          state = "busy";
          release();
          return;
        }
        inFlight += c.length;
        held += c.length;
        chunks.push(c);
      });
      req.on("end", () => finish(state === "ok" ? { kind: "ok", buf: keep ? Buffer.concat(chunks) : Buffer.alloc(0) } : { kind: state }));
      // A body cut off by the client (or a socket closed for a timeout) ends
      // in "close" without "end"; an "error" event always comes with it.
      req.on("error", () => undefined);
      req.on("close", () => {
        if (!req.complete) finish(conn?.cause !== undefined ? { kind: "aborted", cause: conn.cause } : { kind: "aborted" });
      });
    });

  const forward = (req: IncomingMessage, route: string, body: Buffer) => {
    if (forwardBase === undefined) return;
    const target = new URL(forwardBase.toString());
    target.pathname = target.pathname.replace(/\/+$/, "") + route;
    // Headers named in Connection are hop-by-hop too (RFC 9110 s7.6.1).
    const named = new Set(
      String(req.headers.connection ?? "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    );
    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || HOP_BY_HOP.has(k) || named.has(k)) continue;
      if (k === "authorization" && tokenDigest !== undefined) continue; // the receiver's own token
      headers[k] = v;
    }
    headers["content-length"] = String(body.length);
    const p = new Promise<void>((done) => {
      const send = target.protocol === "https:" ? httpsRequest : httpRequest;
      const out = send(target, { method: "POST", headers, timeout: 10_000 }, (r) => {
        r.resume();
        r.on("end", () => {
          if ((r.statusCode ?? 0) >= 300) {
            gap(route, "forward-failed", { status: r.statusCode });
            once(`fwd-${r.statusCode}`, `[chirindo] otel-receiver: forward endpoint answered ${r.statusCode} for ${route}`);
          }
          done();
        });
        r.on("error", () => done());
      });
      out.on("timeout", () => out.destroy(new Error("timeout")));
      out.on("error", (e) => {
        gap(route, "forward-failed", { error: (e as NodeJS.ErrnoException).code ?? e.message });
        once(`fwd-err-${(e as NodeJS.ErrnoException).code ?? e.message}`, `[chirindo] otel-receiver: forward to ${target.origin} failed (${(e as NodeJS.ErrnoException).code ?? e.message})`);
        done();
      });
      out.end(body);
    });
    pending.add(p);
    void p.then(() => pending.delete(p));
  };

  const handleTraces = (req: IncomingMessage, res: ServerResponse, body: Buffer) => {
    let mapped;
    try {
      const enc = req.headers["content-encoding"];
      mapped = mapTraceBody(body, req.headers["content-type"], typeof enc === "string" ? enc : undefined);
    } catch (e) {
      if (!(e instanceof OtlpDecodeError)) throw e;
      const status = e.reason === "too_large" ? 413 : e.reason === "unsupported_content_type" || e.reason === "unsupported_content_encoding" ? 415 : 400;
      gap("/v1/traces", e.reason, { detail: e.detail });
      log(`[chirindo] otel-receiver: refused a /v1/traces batch: ${e.reason}: ${e.detail} (no record written; gap line in ${paths.gapsPath})`);
      return sendOtlp(req, res, status, status === 413 ? 8 : 3, e.reason);
    }
    if (mapped.request.unknownFields > 0) once("unknown", `[chirindo] otel-receiver: ${mapped.request.unknownFields} field(s) this version does not know were skipped (not part of the records)`);
    if (chainBroken) {
      gap("/v1/traces", "chain-broken", { spans: mapped.spans.length });
      return sendOtlp(req, res, 503, 14, "chain-broken");
    }
    const n = appendAll(mapped.spans.map((s) => ({ event: s.event, preimage: JSON.parse(s.canonical.toString("utf8")) as unknown, canonical: s.canonical })));
    if (n < mapped.spans.length) {
      gap("/v1/traces", "append-failed", { spans: mapped.spans.length, appended: n, failed: failedAt });
      return sendOtlp(req, res, 503, 14, "append-failed");
    }
    log(`[chirindo] otel-receiver: /v1/traces ${mapped.spans.length} span(s) -> ${n} record(s), chain length ${writer.count}`);
    return sendOtlp(req, res, 200, 0, "");
  };

  // Ruling L3 (provisional for T4): {"records":[{"tool_name","outcome","args"[,"result"]}]}.
  const handleRecords = (res: ServerResponse, body: Buffer) => {
    let parsed: unknown;
    try {
      parsed = strictJsonParse(body.toString("utf8"));
    } catch {
      gap("/v1/chirindo/records", "invalid-json");
      return sendJson(res, 400, { error: "invalid-json" });
    }
    const list = (parsed as { records?: unknown } | null)?.records;
    const bad = (why: string) => {
      gap("/v1/chirindo/records", "invalid-records", { detail: why });
      return sendJson(res, 400, { error: "invalid-records", detail: why });
    };
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed) || !Array.isArray(list)) return bad("expected {\"records\": [...]}");
    if (list.length === 0 || list.length > RECORDS_MAX) return bad(`records must hold 1 to ${RECORDS_MAX} items`);
    const events: Pending[] = [];
    for (const [i, r] of list.entries()) {
      if (typeof r !== "object" || r === null || Array.isArray(r)) return bad(`records[${i}] is not an object`);
      const x = r as Record<string, unknown>;
      for (const k of Object.keys(x)) if (k !== "tool_name" && k !== "outcome" && k !== "args" && k !== "result") return bad(`records[${i}].${k} is not a known member`);
      if (typeof x.tool_name !== "string" || x.tool_name === "" || x.tool_name.length > TOOL_NAME_MAX) return bad(`records[${i}].tool_name must be a string of 1 to ${TOOL_NAME_MAX} characters`);
      if (x.outcome !== "executed" && x.outcome !== "errored") return bad(`records[${i}].outcome must be executed or errored`);
      if (!("args" in x)) return bad(`records[${i}].args is required`);
      const event: ToolCallEvent = { type: "tool_call", outcome: x.outcome, tool_name: x.tool_name, args_hash: argsHash(x.args), decision: "observed", decision_source: "n/a" };
      let result: { hash: string; preimage: unknown } | undefined;
      if ("result" in x) {
        event.result_hash = resultHash(x.result);
        result = { hash: event.result_hash, preimage: x.result };
      }
      events.push({ event, preimage: x.args, ...(result !== undefined ? { result } : {}) });
    }
    if (chainBroken) {
      gap("/v1/chirindo/records", "chain-broken", { records: events.length });
      return sendJson(res, 503, { error: "chain-broken" });
    }
    const first = writer.count;
    const n = appendAll(events);
    if (n < events.length) {
      gap("/v1/chirindo/records", "append-failed", { records: events.length, appended: n, failed: failedAt });
      return sendJson(res, 503, { error: "append-failed", appended: n });
    }
    return sendJson(res, 200, { ok: true, appended: n, first_seq: first, session_id: sessionId });
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "/").split("?")[0]!;
    const route = (OTEL_ROUTES as readonly string[]).includes(path) ? path : undefined;
    const where = route ?? "other";
    const host = String(req.headers.host ?? "").toLowerCase();
    if (!allowedHosts(port).includes(host)) {
      refuse(where, "host-not-allowed");
      return sendJson(res, 403, { error: "host-not-allowed" }, { connection: "close" });
    }
    const web = fromWebPage(req.headers);
    if (web !== undefined) {
      refuse(where, "cross-origin", { header: web });
      return sendJson(res, 403, { error: "cross-origin" }, { connection: "close" });
    }
    if (route === undefined) return sendJson(res, 404, { error: "not-found" }, { connection: "close" });
    if (req.method !== "POST") {
      refuse(route, "method-not-allowed", { method: String(req.method).slice(0, 16) });
      return sendJson(res, 405, { error: "method-not-allowed" }, { allow: "POST", connection: "close" });
    }
    if (!authorized(req)) {
      refuse(route, "unauthorized");
      return sendJson(res, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer", connection: "close" });
    }
    const types = route === "/v1/chirindo/records" ? RECORDS_TYPES : OTLP_TYPES;
    if (!types.includes(mediaType(req.headers["content-type"]))) {
      refuse(route, "unsupported_content_type", { detail: `expected ${types.join(" or ")}` });
      res.on("finish", () => req.destroy());
      if (route === "/v1/chirindo/records") return sendJson(res, 415, { error: "unsupported_content_type" }, { connection: "close" });
      res.setHeader("connection", "close");
      return sendOtlp(req, res, 415, 3, "unsupported_content_type");
    }
    const keep = route === "/v1/traces" || route === "/v1/chirindo/records" || forwardBase !== undefined;
    const { body, release } = await readBody(req, keep);
    try {
      if (body.kind === "aborted") {
        gap(route, "aborted", body.cause !== undefined ? { cause: body.cause } : {});
        return;
      }
      if (body.kind === "too_large" || body.kind === "busy") {
        gap(route, body.kind);
        res.on("finish", () => req.destroy());
        const extra: Record<string, string> = { connection: "close", ...(body.kind === "busy" ? { "retry-after": String(RETRY_AFTER_S) } : {}) };
        const status = body.kind === "busy" ? 503 : 413;
        if (route === "/v1/chirindo/records") return sendJson(res, status, { error: body.kind }, extra);
        return sendOtlp(req, res, status, body.kind === "busy" ? 14 : 8, body.kind, extra);
      }
      if (route === "/v1/traces") handleTraces(req, res, body.buf);
      else if (route === "/v1/chirindo/records") handleRecords(res, body.buf);
      else sendOtlp(req, res, 200, 0, "");
      if (route !== "/v1/chirindo/records") forward(req, route, body.buf);
    } finally {
      release();
    }
  };

  // Both servers share the handler, the counters and the connection slots. A
  // connection past the limit, when no slot can be taken back, is kept only to
  // answer its first request 503 (Retry-After, Connection: close) without
  // reading the body.
  const refused = new WeakSet<Socket>();
  const setup = (server: Server) => {
    server.on("request", (req: IncomingMessage, res: ServerResponse) => {
      if (refused.has(req.socket)) {
        refuse("connection", "too-many-connections", { limit: maxConns });
        once("conns", `[chirindo] otel-receiver: more than ${maxConns} open connections; further requests are answered 503 (gap lines counted per minute)`);
        res.on("finish", () => req.destroy());
        return sendJson(res, 503, { error: "too-many-connections" }, { "retry-after": String(RETRY_AFTER_S), connection: "close" });
      }
      const c = conns.get(req.socket);
      if (c !== undefined) {
        const t = Date.now();
        c.state = "body";
        c.bodyStart = t;
        c.lastByte = t;
        c.bytes = 0;
        res.on("finish", () => {
          if (c.state !== "closed") {
            c.state = "idle";
            c.since = Date.now();
          }
        });
      }
      handle(req, res).catch((e) => {
        log(`[chirindo] otel-receiver: internal error (${(e as Error).message})`);
        if (!res.headersSent) sendJson(res, 500, { error: "internal" });
        else res.destroy();
      });
    });
    server.on("connection", (s: Socket) => {
      stats.connections += 1;
      if (!isLoopbackAddress(s.remoteAddress)) {
        stats.nonLoopbackConnections += 1;
        s.destroy();
        return;
      }
      if (conns.size >= maxConns) {
        const v = victim(Date.now());
        if (v === undefined) {
          stats.refusedConnections += 1;
          refused.add(s);
          return;
        }
        stats.evictedConnections += 1;
        closeConn(v, "evicted");
      }
      const t = Date.now();
      conns.set(s, { s, state: "waiting", since: t, bodyStart: 0, lastByte: t, bytes: 0 });
      s.on("close", () => {
        const c = conns.get(s);
        if (c !== undefined) c.state = "closed";
        conns.delete(s);
      });
    });
    // A client that speaks HTTP/2 here is an OTLP/gRPC exporter (T0 F2: Python's
    // default without OTEL_EXPORTER_OTLP_PROTOCOL). Ruling L5: one line naming
    // the setting, and a gap line.
    server.on("clientError", (err: NodeJS.ErrnoException & { rawPacket?: Buffer }, socket: Socket) => {
      const raw = err.rawPacket;
      if (err.code === "HPE_PAUSED_H2_UPGRADE" || (raw !== undefined && raw.subarray(0, 14).toString("latin1") === "PRI * HTTP/2.0")) {
        refuse("grpc", "grpc-not-served");
        once("grpc", "[chirindo] otel-receiver: an OTLP/gRPC exporter is sending to this port; this receiver serves OTLP/HTTP only: set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf");
      }
      socket.destroy();
    });
    // Node's own timers stay as a backstop behind the receiver's deadlines.
    server.headersTimeout = headersDeadline + 5_000;
    server.requestTimeout = headersDeadline + bodyDeadline + 5_000;
    server.keepAliveTimeout = 5_000;
  };
  const server4: Server = createServer();
  const server6: Server = createServer();
  setup(server4);
  setup(server6);
  const closeServer = (s: Server) =>
    new Promise<void>((done) => {
      if (!s.listening) return done();
      s.close(() => done());
      s.closeAllConnections();
    });

  return {
    sessionId,
    chainPath: paths.chainPath,
    retainedPath: paths.retainedPath,
    gapsPath: paths.gapsPath,
    identityPath,
    keyCreated: init.kind === "created",
    listen: async () => {
      await new Promise<void>((done, fail) => {
        server4.once("error", fail);
        server4.listen(o.port, "127.0.0.1", () => {
          server4.off("error", fail);
          done();
        });
      }).catch((e: NodeJS.ErrnoException) => {
        Object.assign(e, { address: `127.0.0.1:${o.port}` });
        throw e;
      });
      port = (server4.address() as AddressInfo).port;
      let ipv6 = "bound";
      try {
        await (o.listen6 ?? defaultListen6)(server6, port);
      } catch (err) {
        const e = err as NodeJS.ErrnoException;
        if (ipv6Unavailable(e.code)) {
          ipv6 = `unavailable (${e.code})`;
          log(`[chirindo] otel-receiver: ::1 is not available on this machine (${e.code}); listening on 127.0.0.1 only`);
        } else {
          await closeServer(server6);
          await closeServer(server4);
          Object.assign(e, { address: `[::1]:${port}` });
          throw e;
        }
      }
      const tick = Math.max(20, Math.min(500, Math.floor(Math.min(headersDeadline, idleDeadline, gapInterval) / 4)));
      sweeper = setInterval(sweep, tick);
      sweeper.unref();
      const addresses = [`127.0.0.1:${port}`, ...(ipv6 === "bound" ? [`[::1]:${port}`] : [])];
      return { port, url: `http://127.0.0.1:${port}`, addresses, ipv6 };
    },
    settled: async () => {
      while (pending.size > 0) await Promise.all([...pending]);
    },
    stats: () => ({ ...stats, bytesInFlight: inFlight }),
    close: async () => {
      if (sweeper !== undefined) clearInterval(sweeper);
      await Promise.all([closeServer(server4), closeServer(server6)]);
      flushRefusals(true);
    },
  };
}

// The preimage line's hash, for a reader re-checking a retained sidecar line:
// args_hash = "sha256:" + hex(sha256(JCS(preimage))).
export function retainedHash(preimage: unknown): string {
  return "sha256:" + createHash("sha256").update(jcsBytes(preimage)).digest("hex");
}
