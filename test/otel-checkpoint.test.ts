// B-481 T3: the receiver's checkpoints and their witness
// (src/otel/checkpointer.ts, wired into src/otel/receiver.ts and the command).
// Every witness here is the repository's stub (test/witness-stub.ts) on
// 127.0.0.1, behind a capturing front on 127.0.0.1 that keeps every request
// byte for byte. No test waits on the wall clock: the checkpointer's clock
// and timers are a FakeTime this file moves by hand, and each step waits for
// the POST it started (settled()), so the answers are the same on any
// machine. A guard installed below, before any test, refuses every socket to
// an address that is not loopback; the last test fails if any was tried
// other than the guard's own two controls. Account keys are made at run time.
// Rulings R1 to R10 are the Lead's of 18 Nov (the T3 handoff); each test
// names the ones it holds.

import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Socket, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { startCommandForTest, witnessChoice } from "./otel-command-guard.js";
import {
  INTERVAL_KEY_S,
  INTERVAL_NO_KEY_S,
  OTEL_WITNESS_PINNED_HEX,
  OTEL_WITNESS_DEFAULT_URL,
  SHUTDOWN_MS,
  STOP_CODES,
  nextUtcMidnight,
  resolveOtelWitness,
  witnessStatePath,
  type OtelTimers,
} from "../src/otel/checkpointer.js";
import { createOtelReceiver, type OtelReceiver, type OtelReceiverOptions } from "../src/otel/receiver.js";
import { DEFAULT_WITNESS_KEY_ID, DEFAULT_WITNESS_NAME, readSidecar, sidecarPathFor, verifyAgainstWitness, witnessCheckpoint, witnessPubFromRaw, type WitnessOutcome, type WitnessTarget } from "../src/witness.js";
import { buildCheckpointFromHead } from "../src/checkpoint.js";
import { loadFullIdentity, publicKeyFromPrivate, runInit, runVerify, type SignedCheckpoint } from "../src/vendor/recorder/index.js";
import { STUB_WITNESS_NAME, startStubWitness, type StubWitness, type StubWitnessOptions } from "./witness-stub.js";

// ---------------------------------------------------------------------------
// The loopback guard (installed at load, before any test runs)
// ---------------------------------------------------------------------------

const isLoop = (h: string) => h === "localhost" || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h) || /^::ffff:127\.\d+\.\d+\.\d+$/i.test(h);
const netLog: { host: string; refused: boolean }[] = [];
const realConnect = Socket.prototype.connect;
(Socket.prototype as unknown as { connect: (...a: unknown[]) => Socket }).connect = function (this: Socket, ...args: unknown[]) {
  let a = args[0];
  if (Array.isArray(a)) a = a[0];
  let host = "localhost";
  if (a !== null && typeof a === "object") {
    const o = a as { host?: string; path?: string };
    const o2 = a as { host?: string; path?: unknown; port?: unknown };
    host = typeof o2.path === "string" && o2.path !== "" && o2.port === undefined && o2.host === undefined ? `pipe:${o2.path}` : (o.host ?? "localhost");
  } else if (typeof args[1] === "string") host = args[1];
  if (!host.startsWith("pipe:") && !isLoop(host)) {
    netLog.push({ host, refused: true });
    process.nextTick(() => this.destroy(Object.assign(new Error(`test guard: a connection to ${host} was refused (loopback only)`), { code: "ETESTGUARD" })));
    return this;
  }
  netLog.push({ host, refused: false });
  return (realConnect as unknown as (...a: unknown[]) => Socket).apply(this, args);
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_ISO = "2031-01-01T12:00:00.000Z"; // 12 h before a 00:00 UTC
const tmp = () => mkdtempSync(join(tmpdir(), "b481-t3-cp-"));
const lines = (p: string): string[] => (existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean) : []);
const newAccountKey = () => "ho_live_" + randomBytes(32).toString("hex");
const S = 1000;

class FakeTime {
  t: number;
  private q: { id: number; at: number; fn: () => void }[] = [];
  private n = 0;
  constructor(iso = BASE_ISO) {
    this.t = Date.parse(iso);
  }
  now = () => this.t;
  timers: OtelTimers = {
    set: (fn, ms) => {
      const id = ++this.n;
      this.q.push({ id, at: this.t + Math.max(0, ms), fn });
      return id;
    },
    clear: (h) => {
      this.q = this.q.filter((x) => x.id !== h);
    },
  };
  // The delays of the timers set, from now, soonest first.
  pending(): number[] {
    return this.q.map((x) => x.at - this.t).sort((a, b) => a - b);
  }
  // Move to `at`, firing every timer due on the way in order; after each,
  // wait until no POST is open.
  async to(at: number, settle: () => Promise<void>): Promise<void> {
    for (;;) {
      const due = this.q.filter((x) => x.at <= at).sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (due === undefined) break;
      this.q = this.q.filter((x) => x !== due);
      this.t = Math.max(this.t, due.at);
      due.fn();
      await settle();
    }
    this.t = Math.max(this.t, at);
  }
}

interface Got {
  method: string;
  path: string;
  headerNames: string[];
  headers: Record<string, string>;
  body: Buffer;
}
type Mode = "forward" | "drop" | "hang" | "reply";
// A front on 127.0.0.1 that keeps every request whole and forwards it to the
// stub, or drops the connection, holds it open, or answers with `reply`.
async function front(stub: StubWitness) {
  const got: Got[] = [];
  const st: { mode: Mode; reply: { status: number; body: unknown; headers: Record<string, string> } } = { mode: "forward", reply: { status: 200, body: {}, headers: {} } };
  const held: ServerResponse[] = [];
  const s: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const headerNames: string[] = [];
      for (let i = 0; i < req.rawHeaders.length; i += 2) headerNames.push(req.rawHeaders[i]!.toLowerCase());
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = String(v);
      got.push({ method: req.method ?? "", path: req.url ?? "", headerNames, headers, body });
      if (st.mode === "drop") return req.socket.destroy();
      if (st.mode === "hang") return void held.push(res);
      if (st.mode === "reply") {
        res.writeHead(st.reply.status, { "content-type": "application/json", ...st.reply.headers });
        return void res.end(JSON.stringify(st.reply.body));
      }
      const h: Record<string, string> = {};
      if (req.headers["content-type"] !== undefined) h["content-type"] = String(req.headers["content-type"]);
      if (req.headers["authorization"] !== undefined) h["authorization"] = String(req.headers["authorization"]);
      fetch(stub.url + (req.url ?? "/"), { method: req.method ?? "GET", headers: h, ...(req.method === "POST" ? { body } : {}) })
        .then(async (r) => {
          const text = await r.text();
          const out: Record<string, string> = { "content-type": "application/json" };
          const ra = r.headers.get("retry-after");
          if (ra !== null) out["retry-after"] = ra;
          res.writeHead(r.status, out);
          res.end(text);
        })
        .catch(() => res.socket?.destroy());
    });
  });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
  return {
    url,
    got,
    st,
    posts: () => got.filter((g) => g.method === "POST"),
    close: () =>
      new Promise<void>((r) => {
        for (const x of held) x.socket?.destroy();
        s.closeAllConnections();
        s.close(() => r());
      }),
  };
}

function targetOf(stub: StubWitness, url: string, accountKey?: string): WitnessTarget {
  return {
    baseUrl: url,
    name: STUB_WITNESS_NAME,
    pinned: { pubObj: witnessPubFromRaw(Buffer.from(stub.publicKeyHex, "hex")), hex: stub.publicKeyHex, id: stub.keyId },
    ...(accountKey !== undefined ? { accountKey } : {}),
  };
}

const noV6: NonNullable<OtelReceiverOptions["listen6"]> = async () => {
  throw Object.assign(new Error("test: no ::1"), { code: "EAFNOSUPPORT" });
};

async function rig(o: { stub?: StubWitnessOptions; accountKey?: string; intervalS?: number; dir?: string; time?: FakeTime; post?: (cp: SignedCheckpoint, stop: AbortSignal) => Promise<WitnessOutcome> } = {}) {
  const stub = await startStubWitness(o.stub ?? {});
  const f = await front(stub);
  const time = o.time ?? new FakeTime();
  const dir = o.dir ?? join(tmp(), "gate");
  const log: string[] = [];
  const r = createOtelReceiver({
    dir,
    port: 0,
    retain: true,
    log: (l) => log.push(l),
    listen6: noV6,
    witness: {
      target: targetOf(stub, f.url, o.accountKey),
      intervalMs: (o.intervalS ?? (o.accountKey !== undefined ? INTERVAL_KEY_S : INTERVAL_NO_KEY_S)) * S,
      clock: time.now,
      timers: time.timers,
      ...(o.post !== undefined ? { post: o.post } : {}),
    },
  });
  const l = await r.listen();
  const cp = r.checkpointer!;
  const settle = () => cp.settled();
  const close = async () => {
    await r.close();
    await f.close();
    await stub.close();
  };
  return { stub, f, time, dir, log, r, cp, port: l.port, settle, close };
}

function post(port: number, path: string, body: Buffer | string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((done, fail) => {
    const buf = typeof body === "string" ? Buffer.from(body) : body;
    const req = request({ host: "127.0.0.1", port, path, method: "POST", headers: { host: `127.0.0.1:${port}`, "content-length": String(buf.length), ...headers }, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => done({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", fail);
    req.end(buf);
  });
}
const addRecords = (port: number, records: unknown[]) => post(port, "/v1/chirindo/records", JSON.stringify({ records }), { "content-type": "application/json" });
const one = (port: number, tag = "x") => addRecords(port, [{ tool_name: `tool-${tag}`, outcome: "executed", args: { tag } }]);
const FIX = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "otlp");
const T0_PB = readFileSync(join(FIX, "t0-shape.pb"));
// The times (from the fake clock's start, in s) of the checkpoints POSTed.
const postTimes = (f: { posts: () => Got[] }, t0: number) => f.posts().map((g) => (Date.parse((JSON.parse(g.body.toString("utf8")) as { checkpoint: { ts: string } }).checkpoint.ts) - t0) / S);

// ---------------------------------------------------------------------------

describe("otel-receiver checkpoints: the default witness and its start line (R1, R10)", () => {
  it("witness on by default: Headless Oracle, its key pinned; the start line says what leaves and how to stop it; --no-witness turns it off", () => {
    const r = resolveOtelWitness({ noWitness: false });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(OTEL_WITNESS_DEFAULT_URL).toBe("https://api.headlessoracle.com");
    expect(r.config.target?.baseUrl).toBe("https://api.headlessoracle.com");
    expect(r.config.target?.name).toBe(DEFAULT_WITNESS_NAME);
    expect(r.config.target?.pinned?.hex).toBe("03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178");
    expect(OTEL_WITNESS_PINNED_HEX).toBe(r.config.target?.pinned?.hex);
    expect(r.config.target?.pinned?.id).toBe(DEFAULT_WITNESS_KEY_ID);
    expect(r.config.target?.accountKey).toBeUndefined();
    const line = r.config.startLine;
    expect(line).toContain("witness on: https://api.headlessoracle.com");
    expect(line).toContain("the chain head hash, the record count, a timestamp and the session id");
    expect(line).toContain("never a record's content");
    expect(line).toContain("--no-witness turns this off");
    expect(line.split("\n").length).toBe(1);
    const off = resolveOtelWitness({ noWitness: true });
    expect(off.ok && off.config.target === undefined).toBe(true);
    expect(off.ok && off.config.startLine).toContain("witness off (--no-witness): no checkpoint leaves this machine");
    const both = resolveOtelWitness({ noWitness: true, witness: "http://127.0.0.1:1" });
    expect(both.ok).toBe(false);
  });

  it("the witness key is always pinned: --witness needs --witness-key; --witness-key or --witness-name alone is refused; a receipt under another key is not a receipt", async () => {
    expect(resolveOtelWitness({ noWitness: false, witness: "http://127.0.0.1:9" })).toEqual({ ok: false, why: "--witness needs --witness-key <hex|jwk-file>: the witness key is always pinned" });
    expect(resolveOtelWitness({ noWitness: false, witnessKey: "00".repeat(32) }).ok).toBe(false);
    expect(resolveOtelWitness({ noWitness: false, witnessName: "x" }).ok).toBe(false);
    expect(resolveOtelWitness({ noWitness: false, witness: "http://example.com", witnessKey: "00".repeat(32) }).ok).toBe(false); // http only for loopback
    // The stub signs with its key; the receiver pins another: recorded as an error, never a receipt.
    const other = witnessPubFromRaw(Buffer.alloc(32, 7));
    const stub = await startStubWitness();
    const f = await front(stub);
    const time = new FakeTime();
    const r = createOtelReceiver({ dir: join(tmp(), "gate"), port: 0, retain: true, log: () => undefined, listen6: noV6, witness: { target: { ...targetOf(stub, f.url), pinned: { pubObj: other, hex: "07".repeat(32), id: stub.keyId } }, intervalMs: INTERVAL_NO_KEY_S * S, clock: time.now, timers: time.timers } });
    const port = (await r.listen()).port;
    await one(port);
    await time.to(time.t + 10 * S, () => r.checkpointer!.settled());
    const side = readSidecar(sidecarPathFor(r.chainPath));
    expect(side.map((l) => [l.witness_receipt, l.witness_error])).toEqual([[null, "bad_witness_signature"]]);
    expect(stub.rows.length).toBe(1);
    await r.close();
    await f.close();
    await stub.close();
  });

  it("the command: on by default with the start line printed once; --no-witness prints the off line and sends nothing", async () => {
    const dir = tmp();
    const err: string[] = [];
    const calls: SignedCheckpoint[] = [];
    const time = new FakeTime();
    const seamPost = async (cp: SignedCheckpoint): Promise<WitnessOutcome> => {
      calls.push(cp);
      return { receipt: null, error: "witness_unreachable" };
    };
    const s = await startCommandForTest({ flags: new Map<string, string | true>([["dir", "gate"], ["port", "0"]]), positional: [], passthrough: [] }, { stdout: () => undefined, stderr: (l) => err.push(l), cwd: dir, witnessSeams: { clock: time.now, timers: time.timers, post: seamPost } });
    expect(s.code).toBe(0);
    expect(err.filter((l) => l.includes("witness on: https://api.headlessoracle.com")).length).toBe(1);
    expect(s.receiver!.checkpointer!.status().baseUrl).toBe("https://api.headlessoracle.com");
    expect(s.receiver!.checkpointer!.status().intervalMs).toBe(900 * S);
    await s.stop!();
    expect(calls.length).toBe(0); // nothing recorded, nothing sent
    const err2: string[] = [];
    const s2 = await startCommandForTest({ flags: new Map<string, string | true>([["dir", "gate2"], ["port", "0"], ["no-witness", true]]), positional: [], passthrough: [] }, { stdout: () => undefined, stderr: (l) => err2.push(l), cwd: dir });
    expect(s2.code).toBe(0);
    expect(s2.receiver!.checkpointer).toBeUndefined();
    expect(err2.filter((l) => l.includes("witness off (--no-witness)")).length).toBe(1);
    await s2.stop!();
    expect(existsSync(sidecarPathFor(s2.receiver!.chainPath))).toBe(false);
  });
});

describe("otel-receiver checkpoints: only a checkpoint leaves the machine (R1, the 14 Nov ruling)", () => {
  it("no request body sent to the witness carries any part of a record's content", async () => {
    const h = await rig();
    const marker = randomBytes(12).toString("hex");
    expect((await post(h.port, "/v1/traces", T0_PB, { "content-type": "application/x-protobuf" })).status).toBe(200);
    expect((await addRecords(h.port, [{ tool_name: `secret-tool-${marker}`, outcome: "executed", args: { card: `arg-${marker}`, n: 41 }, result: { ok: `res-${marker}` } }])).status).toBe(200);
    await h.time.to(h.time.t + 10 * S, h.settle); // the idle checkpoint
    await one(h.port, `late-${marker}`);
    await h.r.close(); // and the shutdown checkpoint (900 s interval ignored)
    const bodies = h.f.posts().map((g2) => g2.body.toString("utf8"));
    expect(bodies.length).toBe(2);
    // The body is exactly {checkpoint, public_key_jwk} with the checkpoint's eight members.
    for (const b of bodies) {
      const j = JSON.parse(b) as { checkpoint: Record<string, unknown>; public_key_jwk: Record<string, unknown> };
      expect(Object.keys(j).sort()).toEqual(["checkpoint", "public_key_jwk"]);
      expect(Object.keys(j.checkpoint).sort()).toEqual(["count", "kid", "last_entry_hash", "session_id", "sig", "ts", "type", "v"]);
      expect(Object.keys(j.public_key_jwk).sort()).toEqual(["crv", "kty", "x"]);
    }
    // Every string of 4 characters or more in every record and every retained
    // line is absent from every body, but for what a checkpoint carries by
    // design (the start line names them): the session id, the key id and
    // public key, the record version and the head hash.
    const leaves: string[] = [];
    const walk = (v: unknown, k = "") => {
      if (typeof v === "string") {
        if (v.length >= 4) leaves.push(v);
      } else if (Array.isArray(v)) v.forEach((x) => walk(x));
      else if (v !== null && typeof v === "object") for (const [kk, vv] of Object.entries(v)) walk(vv, kk);
    };
    const records = lines(h.r.chainPath).map((l) => JSON.parse(l));
    expect(records.length).toBe(9);
    records.forEach((x) => walk(x));
    lines(h.r.retainedPath).forEach((l) => walk(JSON.parse(l)));
    expect(leaves.length).toBeGreaterThan(100);
    expect(leaves.some((x) => x.includes(marker))).toBe(true);
    const byDesign = new Set<string>();
    for (const b of bodies) {
      const j = JSON.parse(b) as { checkpoint: Record<string, string>; public_key_jwk: Record<string, string> };
      for (const k of ["session_id", "kid", "v", "last_entry_hash"]) byDesign.add(String(j.checkpoint[k]));
      byDesign.add(j.public_key_jwk["x"]!);
    }
    const found = [...new Set(leaves.filter((x) => bodies.some((b) => b.includes(x))))];
    expect(found.filter((x) => !byDesign.has(x))).toEqual([]);
    expect(found.length).toBeGreaterThan(0); // the by-design values are found, so the search works
    for (const b of bodies) expect(b.includes(marker)).toBe(false);
    // Negative control: the same check finds a record's string when it is there.
    expect(leaves.filter((x) => (bodies[0]! + records[3].event.args_hash).includes(x)).length).toBeGreaterThan(0);
    await h.f.close();
    await h.stub.close();
  });
});

describe("otel-receiver checkpoints: pacing by time (R2, R3, R4)", () => {
  it("the interval: 120 s with an account key, --checkpoint-interval 40 to 900 with one, 900 s without; --checkpoint-interval without a key is refused", () => {
    const dir = tmp();
    const kf = join(dir, "acct");
    writeFileSync(kf, newAccountKey() + "\n");
    const ok = (x: ReturnType<typeof resolveOtelWitness>) => (x.ok ? x.config.intervalMs / S : x.why);
    expect(ok(resolveOtelWitness({ noWitness: false, accountKeyFile: kf }))).toBe(120);
    expect(ok(resolveOtelWitness({ noWitness: false, accountKeyFile: kf, checkpointInterval: "40" }))).toBe(40);
    expect(ok(resolveOtelWitness({ noWitness: false, accountKeyFile: kf, checkpointInterval: "900" }))).toBe(900);
    expect(ok(resolveOtelWitness({ noWitness: false }))).toBe(900);
    for (const bad of ["39", "901", "0", "4x", "040", "", "-40"]) expect(resolveOtelWitness({ noWitness: false, accountKeyFile: kf, checkpointInterval: bad }).ok, bad).toBe(false);
    expect(ok(resolveOtelWitness({ noWitness: false, checkpointInterval: "40" }))).toBe("--checkpoint-interval needs --account-key-file: without an account key the interval is 900 s");
  });

  it("busy with a key (120 s): one checkpoint 120 s after the head first moved, then one every 120 s while records keep coming", async () => {
    const key = newAccountKey();
    const g = await rig({ accountKey: key, stub: { accounts: { [key]: { status: "active", plan: "evidence" } } } });
    const t0 = g.time.t;
    for (let s = 0; s <= 400; s += 5) {
      await g.time.to(t0 + s * S, g.settle);
      await one(g.port, String(s));
    }
    await g.time.to(t0 + 400 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([120, 240, 360]);
    expect(g.stub.postAuth.every((a) => a === `Bearer ${key}`)).toBe(true);
    await g.close();
  });

  it("busy with no key: 900 s (15 min) after the head first moved since the last checkpoint", async () => {
    const g = await rig();
    const t0 = g.time.t;
    for (let s = 0; s <= 2000; s += 7) {
      await g.time.to(t0 + s * S, g.settle);
      await one(g.port, String(s));
    }
    // Records every 7 s: the head moves again at 903 s, so the next is at 1803 s.
    expect(postTimes(g.f, t0)).toEqual([900, 1803]);
    expect(g.stub.postAuth.every((a) => a === null)).toBe(true);
    await g.close();
  });

  it("--checkpoint-interval 40 with a key: 40 s after the head first moved since the last checkpoint", async () => {
    const key = newAccountKey();
    const g = await rig({ accountKey: key, intervalS: 40, stub: { accounts: { [key]: { status: "active", plan: "evidence" } } } });
    const t0 = g.time.t;
    for (let s = 0; s <= 130; s += 3) {
      await g.time.to(t0 + s * S, g.settle);
      await one(g.port, String(s));
    }
    // Records every 3 s: after the one at 40 s the head moves at 42 s and 84 s.
    expect(postTimes(g.f, t0)).toEqual([40, 82, 124]);
    await g.close();
  });

  it("idle (R4, Lead ruling of 18 Nov): 10 s after the last record, but never sooner than one interval after the previous checkpoint", async () => {
    const key = newAccountKey();
    const g = await rig({ accountKey: key, stub: { accounts: { [key]: { status: "active", plan: "evidence" } } } });
    const t0 = g.time.t;
    await one(g.port, "a"); // t0: the first record; quiet after it
    await g.time.to(t0 + 60 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10]); // 10 s after quiet (no earlier checkpoint)
    await g.time.to(t0 + 20 * S, g.settle);
    await one(g.port, "b"); // 10 s after the checkpoint; quiet after it
    await g.time.to(t0 + 100 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10]); // not at 30 s: the interval holds it
    await g.time.to(t0 + 200 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10, 130]); // at L + 120 s
    await g.time.to(t0 + 500 * S, g.settle);
    await one(g.port, "c"); // long after: 10 s after quiet again
    await g.time.to(t0 + 1000 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10, 130, 510]);
    expect(g.stub.rows.map((r) => r["count"])).toEqual(["1", "2", "3"]);
    // Nothing more is due once the head is witnessed.
    expect(g.cp.status().dueAt).toBeNull();
    expect(g.time.pending()).toEqual([]);
    await g.close();
  });

  it("no key: idle 10 s after quiet for the first checkpoint, then never sooner than 900 s after the last", async () => {
    const g = await rig();
    const t0 = g.time.t;
    await one(g.port);
    await g.time.to(t0 + 30 * S, g.settle);
    await one(g.port);
    await g.time.to(t0 + 2000 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10, 910]);
    await g.close();
  });
});

describe("otel-receiver checkpoints: failures (R5, R6)", () => {
  const cases: Array<{ code: (typeof STOP_CODES)[number]; status: number; stub: (key: string) => StubWitnessOptions; keyed: boolean }> = [
    { code: "invalid_key", status: 401, stub: () => ({ accounts: {} }), keyed: true },
    { code: "payment_required", status: 402, stub: (k) => ({ accounts: { [k]: { status: "inactive", plan: "evidence" } } }), keyed: true },
    { code: "witness_plan_required", status: 403, stub: (k) => ({ accounts: { [k]: { status: "active", plan: "free" } } }), keyed: true },
    { code: "quota_exceeded", status: 429, stub: (k) => ({ accounts: { [k]: { status: "active", plan: "evidence", quota: 1 } } }), keyed: true },
    { code: "witness_unavailable", status: 503, stub: () => ({ anonymousCap: 1 }), keyed: false },
  ];
  for (const c of cases) {
    it(`${c.status} ${c.code}: sending stops until 00:00 UTC (saved for a restart), the agent still gets 200, and sending resumes after midnight`, async () => {
      const key = newAccountKey();
      const g = await rig({ ...(c.keyed ? { accountKey: key } : {}), stub: c.stub(key) });
      const t0 = g.time.t;
      await one(g.port, "1");
      await g.time.to(t0 + 15 * S, g.settle);
      const quotaCase = c.code === "quota_exceeded" || c.code === "witness_unavailable";
      if (quotaCase) {
        // The first row fits the pool; the second is refused.
        expect(g.stub.rows.length).toBe(1);
        await g.time.to(t0 + 200 * S, g.settle);
        await one(g.port, "2");
        await g.time.to(t0 + 2000 * S, g.settle);
      }
      const replies = g.stub.postReplies.map((x) => x.status);
      expect(replies[replies.length - 1]).toBe(c.status);
      const midnight = nextUtcMidnight(g.time.t);
      expect(g.cp.status().stoppedUntil).toBe(midnight);
      expect(g.cp.status().stopReason).toBe(c.code);
      const saved = JSON.parse(readFileSync(witnessStatePath(g.dir), "utf8")) as { stopped_until: string; reason: string };
      expect(saved).toMatchObject({ stopped_until: new Date(midnight).toISOString(), reason: c.code });
      expect(g.log.some((l) => l.includes(`witness refused with ${c.code}`))).toBe(true);
      const n = g.f.posts().length;
      // Records keep coming and are answered 200; nothing is sent before midnight.
      for (let s = 2100; s < 40_000; s += 600) {
        await g.time.to(t0 + s * S, g.settle);
        expect((await one(g.port, String(s))).status).toBe(200);
      }
      await g.time.to(midnight - 1, g.settle);
      expect(g.f.posts().length).toBe(n);
      // A restart before midnight keeps the stop (R7).
      const dir2 = g.dir;
      const shut = g.log.length;
      await g.r.close();
      expect(g.log.slice(shut).join("\n")).toContain("witness at shutdown: not sent: the witness is stopped until");
      expect(g.f.posts().length).toBe(n);
      const r2 = createOtelReceiver({ dir: dir2, port: 0, retain: true, log: (l) => g.log.push(l), listen6: noV6, witness: { target: targetOf(g.stub, g.f.url, c.keyed ? key : undefined), intervalMs: 120 * S, clock: g.time.now, timers: g.time.timers } });
      const p2 = (await r2.listen()).port;
      expect(r2.checkpointer!.status().stoppedUntil).toBe(midnight);
      await one(p2, "after-restart");
      await g.time.to(midnight - 1, () => r2.checkpointer!.settled());
      expect(g.f.posts().length).toBe(n);
      // After 00:00 UTC it sends again (the stub still refuses; that is recorded).
      await g.time.to(midnight + 60 * S, () => r2.checkpointer!.settled());
      expect(g.f.posts().length).toBeGreaterThan(n);
      await r2.close();
      await g.f.close();
      await g.stub.close();
    });
  }

  it("402 is recorded and never answered: no payment header is ever built, and nothing more is sent that day", async () => {
    const g = await rig();
    // The front answers 402 with a payment challenge, as a paying witness would.
    g.f.st.mode = "reply";
    g.f.st.reply = { status: 402, body: { error: "payment_required", accepts: [{ scheme: "exact", network: "base", maxAmountRequired: "1000", payTo: "0x" + "11".repeat(20) }] }, headers: { "www-authenticate": 'X402 realm="witness"', "x-payment-required": "1" } };
    const t0 = g.time.t;
    await one(g.port);
    await g.time.to(t0 + 15 * S, g.settle);
    for (let s = 20; s < 5000; s += 100) {
      await g.time.to(t0 + s * S, g.settle);
      await one(g.port, String(s));
    }
    await g.r.close();
    expect(g.f.got.length).toBe(1); // one POST; no reply to the challenge, no retry
    const side = readSidecar(sidecarPathFor(g.r.chainPath));
    expect(side.map((l) => l.witness_error)).toEqual(["payment_required"]);
    const allowed = ["host", "connection", "content-type", "content-length", "accept", "accept-language", "accept-encoding", "sec-fetch-mode", "user-agent", "authorization"];
    for (const x of g.f.got) {
      expect(x.headerNames.filter((h) => !allowed.includes(h))).toEqual([]);
      expect(x.headerNames.filter((h) => /pay|x402|402/i.test(h))).toEqual([]);
      expect(Object.values(x.headers).filter((v) => /pay|x402/i.test(v))).toEqual([]);
      // On the parsed body (rev 4): no key names a payment and no value carries
      // the challenge back. Not a regular expression over the raw text, which a
      // random signature or key in the body can match by chance (it did, once).
      const keys: string[] = [];
      const vals: string[] = [];
      const walk = (v: unknown, k?: string): void => {
        if (k !== undefined) keys.push(k);
        if (typeof v === "string") vals.push(v);
        else if (v !== null && typeof v === "object") for (const [kk, vv] of Object.entries(v as Record<string, unknown>)) walk(vv, Array.isArray(v) ? undefined : kk);
      };
      walk(JSON.parse(x.body.toString("utf8")));
      expect(keys.length).toBeGreaterThan(0);
      expect(keys.filter((k) => /pay|x402|402/i.test(k))).toEqual([]);
      expect(vals.filter((v) => v.includes("0x" + "11".repeat(20)) || v.includes("payment_required") || v.includes("X402 realm"))).toEqual([]);
    }
    // The module that builds payments is not imported by the checkpointer.
    const src = readFileSync(join(fileURLToPath(new URL("..", import.meta.url)), "src", "otel", "checkpointer.ts"), "utf8");
    expect(src).not.toMatch(/from "\.\.\/payment\.js"|from "\.\.\/purchase/);
    await g.f.close();
    await g.stub.close();
  });

  it("429 RATE_LIMITED doubles the interval up to 900 s; a receipt puts it back", async () => {
    const key = newAccountKey();
    const opts: StubWitnessOptions = { accounts: { [key]: { status: "active", plan: "evidence" } }, rateLimited: true };
    const g = await rig({ accountKey: key, stub: opts });
    const t0 = g.time.t;
    const seen: number[] = [];
    for (let s = 0; s <= 3000; s += 5) {
      await g.time.to(t0 + s * S, g.settle);
      seen.push(g.cp.status().intervalMs / S);
      await one(g.port, String(s));
    }
    expect(postTimes(g.f, t0)).toEqual([120, 360, 840, 1740, 2640]);
    expect([...new Set(seen)]).toEqual([120, 240, 480, 900]);
    (opts as { rateLimited?: boolean }).rateLimited = false;
    await g.time.to(t0 + 3540 * S, g.settle);
    expect(g.stub.rows.length).toBe(1);
    expect(g.cp.status().intervalMs).toBe(120 * S);
    expect(g.cp.status().stoppedUntil).toBeNull();
    await g.close();
  });

  it("a network failure or a timeout is tried again at the next slot; the agent is answered 200 throughout", async () => {
    const key = newAccountKey();
    const g = await rig({ accountKey: key, stub: { accounts: { [key]: { status: "active", plan: "evidence" } } } });
    const t0 = g.time.t;
    g.f.st.mode = "drop";
    await one(g.port);
    await g.time.to(t0 + 15 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10]);
    await g.time.to(t0 + 129 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10]);
    g.f.st.mode = "forward";
    await g.time.to(t0 + 131 * S, g.settle);
    expect(postTimes(g.f, t0)).toEqual([10, 130]);
    const side = readSidecar(sidecarPathFor(g.r.chainPath));
    expect(side.map((l) => [l.witness_error, l.witness_receipt === null])).toEqual([["witness_unreachable", true], [null, false]]);
    expect(g.cp.status().stoppedUntil).toBeNull();
    await g.close();
  });

  it("never in the agent's way: while a witness POST hangs, trace batches are answered 200 and written at once (R6)", async () => {
    const g = await rig();
    g.f.st.mode = "hang";
    const t0 = g.time.t;
    await one(g.port);
    g.time.t = t0 + 10 * S;
    await g.time.to(t0 + 10 * S, async () => undefined); // starts the POST, does not wait for it
    expect(g.cp.status().inflight).toBe(true);
    for (let i = 0; i < 5; i++) expect((await post(g.port, "/v1/traces", T0_PB, { "content-type": "application/x-protobuf" })).status).toBe(200);
    expect(lines(g.r.chainPath).length).toBe(36);
    expect(g.f.posts().length).toBe(1);
    await g.f.close(); // the held POST fails; recorded
    await g.settle();
    await g.r.close();
    await g.stub.close();
  });
});

describe("otel-receiver checkpoints: what is kept, catch-up and shutdown (R7, R8)", () => {
  it("receipts are kept per session in <chain>.witness.ndjson, which verify --witness-file reads", async () => {
    const g = await rig();
    const t0 = g.time.t;
    await post(g.port, "/v1/traces", T0_PB, { "content-type": "application/x-protobuf" });
    await g.time.to(t0 + 20 * S, g.settle);
    await g.r.close();
    const side = sidecarPathFor(g.r.chainPath);
    expect(readSidecar(side).map((l) => [l.checkpoint.count, l.witness_error])).toEqual([[7, null]]);
    const v = runVerify({ chainPath: g.r.chainPath, identityPath: g.r.identityPath });
    expect(v.kind).toBe("valid");
    const w = await verifyAgainstWitness({ chainPath: g.r.chainPath, validText: "VALID", validExit: 0, witnessName: STUB_WITNESS_NAME, sidecarPath: side, pinned: targetOf(g.stub, g.f.url).pinned! });
    expect(w.code).toBe(0);
    expect(w.text).toContain("WITNESSED through count 7");
    expect(w.text).toContain("0 records after the last witnessed checkpoint are not witness-protected");
    await g.f.close();
    await g.stub.close();
  });

  it("catch-up at start: an earlier session whose head no receipt covers is sent first; a covered one is not", async () => {
    const time = new FakeTime();
    const a = await rig({ time });
    const dir = a.dir;
    a.f.st.mode = "drop";
    await post(a.port, "/v1/traces", T0_PB, { "content-type": "application/x-protobuf" });
    await a.r.close(); // the shutdown POST is dropped: session A is not witnessed
    const aChain = a.r.chainPath;
    expect(readSidecar(sidecarPathFor(aChain)).map((l) => l.witness_error)).toEqual(["witness_unreachable"]);
    a.f.st.mode = "forward";
    const log: string[] = [];
    const b = createOtelReceiver({ dir, port: 0, retain: true, log: (l) => log.push(l), listen6: noV6, witness: { target: targetOf(a.stub, a.f.url), intervalMs: 900 * S, clock: time.now, timers: time.timers } });
    await b.listen();
    await time.to(time.t, () => b.checkpointer!.settled());
    expect(log.some((l) => l.includes("1 earlier session(s) with an unwitnessed head"))).toBe(true);
    const sA = readSidecar(sidecarPathFor(aChain));
    expect(sA.map((l) => [l.witness_error, l.witness_receipt?.["count"] ?? null])).toEqual([["witness_unreachable", null], [null, "7"]]);
    expect(a.stub.rows.map((r) => r["session_id"])).toEqual([JSON.parse(lines(aChain)[0]!).session_id]);
    await b.close();
    // A third start finds A covered and B empty: nothing to send.
    const c = createOtelReceiver({ dir, port: 0, retain: true, log: () => undefined, listen6: noV6, witness: { target: targetOf(a.stub, a.f.url), intervalMs: 900 * S, clock: time.now, timers: time.timers } });
    await c.listen();
    await time.to(time.t + 1, () => c.checkpointer!.settled());
    expect(c.checkpointer!.status().posts).toBe(0);
    await c.close();
    await a.f.close();
    await a.stub.close();
  });

  it("shutdown: one last checkpoint outside the interval, 10 s at most for all of it, the outcome printed", async () => {
    expect(SHUTDOWN_MS).toBe(10_000);
    // Witnessed at shutdown.
    const g = await rig();
    await one(g.port);
    await g.r.close();
    expect(g.log.filter((l) => l.includes("witness at shutdown: count 1 witnessed, received_at")).length).toBe(1);
    await g.f.close();
    await g.stub.close();
    // Already witnessed: nothing sent.
    const h = await rig();
    await one(h.port);
    await h.time.to(h.time.t + 10 * S, h.settle);
    await h.r.close();
    expect(h.f.posts().length).toBe(1);
    expect(h.log.some((l) => l.includes("witness at shutdown: head already witnessed (count 1), nothing sent"))).toBe(true);
    await h.f.close();
    await h.stub.close();
    // A witness that never answers: the deadline is 10 s on the injected
    // timers; when it fires the POST is ended and the outcome printed.
    const k = await rig();
    k.f.st.mode = "hang";
    await one(k.port);
    const closing = k.r.close();
    for (let i = 0; i < 50 && k.f.posts().length === 0; i++) await new Promise((d) => setImmediate(d));
    expect(k.f.posts().length).toBe(1);
    expect(k.time.pending()).toEqual([10_000]);
    await k.time.to(k.time.t + 10_000, async () => undefined);
    await closing;
    expect(k.log.some((l) => l.includes("witness at shutdown: count 1 NOT witnessed (witness_timeout)"))).toBe(true);
    await k.f.close();
    await k.stub.close();
  });
});

describe("otel-receiver checkpoints: the account key (R9)", () => {
  it("is read from --account-key-file only: sent as the bearer on the POST, never written or printed; the environment variable is not read", async () => {
    const key = newAccountKey();
    const dir = tmp();
    const kf = join(dir, "acct-key");
    writeFileSync(kf, key + "\n");
    process.env["CHIRINDO_WITNESS_ACCOUNT_KEY"] = newAccountKey();
    try {
      const plain = resolveOtelWitness({ noWitness: false });
      expect(plain.ok && plain.config.target?.accountKey).toBeUndefined();
      expect(plain.ok && plain.config.keyed).toBe(false);
    } finally {
      delete process.env["CHIRINDO_WITNESS_ACCOUNT_KEY"];
    }
    expect(resolveOtelWitness({ noWitness: false, accountKeyFile: join(dir, `${key}`) }).ok).toBe(false);
    writeFileSync(join(dir, "bad-key"), "ho_live_XYZ\n");
    expect(resolveOtelWitness({ noWitness: false, accountKeyFile: join(dir, "bad-key") }).ok).toBe(false);
    expect(resolveOtelWitness({ noWitness: false, accountKeyFile: join(dir, "absent") }).ok).toBe(false);
    const stub = await startStubWitness({ accounts: { [key]: { status: "active", plan: "evidence" } } });
    const f = await front(stub);
    const err: string[] = [];
    const out: string[] = [];
    const time = new FakeTime();
    const s = await startCommandForTest(
      { flags: new Map<string, string | true>([["dir", "gate"], ["port", "0"], ["witness", f.url], ["witness-key", stub.publicKeyHex], ["witness-name", STUB_WITNESS_NAME], ["account-key-file", "acct-key"], ["checkpoint-interval", "40"]]), positional: [], passthrough: [] },
      { stdout: (l) => out.push(l), stderr: (l) => err.push(l), cwd: dir, witnessSeams: { clock: time.now, timers: time.timers } },
    );
    expect(s.code).toBe(0);
    expect(err.some((l) => l.includes("and the account key as the authorization header"))).toBe(true);
    const port = Number(new URL((JSON.parse(out[0]!) as { listening: string }).listening).port);
    await one(port);
    await time.to(time.t + 10 * S, () => s.receiver!.checkpointer!.settled());
    await s.stop!();
    expect(stub.postAuth).toEqual([`Bearer ${key}`]);
    expect(f.posts().every((g) => g.headers["authorization"] === `Bearer ${key}`)).toBe(true);
    expect(stub.rows.length).toBe(1);
    const written = [s.receiver!.chainPath, sidecarPathFor(s.receiver!.chainPath), s.receiver!.retainedPath, witnessStatePath(join(dir, "gate"))].filter(existsSync).map((p) => readFileSync(p, "utf8")).join("\n");
    expect(written.includes(key.slice(8, 24))).toBe(false);
    expect([...err, ...out].join("\n").includes(key.slice(8, 24))).toBe(false);
    // The other commands' flag and variable are not this command's.
    const e2: string[] = [];
    const s2 = await startCommandForTest({ flags: new Map<string, string | true>([["dir", "g2"], ["port", "0"], ["no-witness", true], ["witness-account-key-file", "acct-key"]]), positional: [], passthrough: [] }, { stdout: () => undefined, stderr: (l) => e2.push(l), cwd: dir });
    expect(s2.code).toBe(2);
    expect(e2.join("\n")).toContain("unknown flag --witness-account-key-file");
    await f.close();
    await stub.close();
  });
});

describe("otel-receiver checkpoints: no test starts the command with the live witness (rev 2)", () => {
  it("the test helper refuses a start with the witness left at its default (the live service), and allows --no-witness, a loopback --witness or an injected POST", async () => {
    const live = resolveOtelWitness({ noWitness: false });
    expect(live.ok && live.config.target?.baseUrl).toBe(OTEL_WITNESS_DEFAULT_URL);
    const args = (pairs: Array<[string, string | true]>) => ({ flags: new Map<string, string | true>(pairs), positional: [], passthrough: [] });
    const io = { stdout: () => undefined, stderr: () => undefined, cwd: tmp() };
    const before = netLog.length;
    await expect(startCommandForTest(args([["dir", "g"], ["port", "0"]]), io)).rejects.toThrow("test guard: the receiver command starts in a test only with");
    await expect(startCommandForTest(args([["dir", "g"], ["port", "0"], ["witness", "https://api.headlessoracle.com"], ["witness-key", OTEL_WITNESS_PINNED_HEX]]), io)).rejects.toThrow("test guard");
    expect(existsSync(join(io.cwd, "g"))).toBe(false); // refused before the command ran
    expect(netLog.length).toBe(before);
    expect(witnessChoice(args([["no-witness", true]]), io)).toBe("--no-witness");
    expect(witnessChoice(args([["witness", "http://127.0.0.1:9"]]), io)).toBe("a loopback --witness");
    expect(witnessChoice(args([["witness", "http://127.0.0.1.example.com:9"]]), io)).toBeNull();
    expect(witnessChoice(args([]), { ...io, witnessSeams: { post: async () => ({ receipt: null, error: "x" }) } })).toBe("an injected POST");
  });

  it("no test file calls the receiver command or spawns it but through the helper", () => {
    expect(resolveOtelWitness({ noWitness: true }).ok).toBe(true);
    const dir = fileURLToPath(new URL(".", import.meta.url));
    const direct = /\b(startOtelReceiverCommand|runOtelReceiverCli)\s*\(|spawn\w*\([^)]*otel-receiver/;
    const offenders = (name: string, text: string) => text.split("\n").map((l, i) => [i + 1, l] as const).filter(([, l]) => direct.test(l)).map(([n]) => `${name}:${n}`);
    const found: string[] = [];
    let files = 0;
    for (const n of readdirSync(dir).filter((x) => x.endsWith(".ts") && x !== "otel-command-guard.ts")) {
      files += 1;
      found.push(...offenders(n, readFileSync(join(dir, n), "utf8")));
    }
    expect(files).toBeGreaterThan(50);
    expect(found).toEqual([]);
    // Negative controls: the same search finds a direct call and a spawn.
    expect(offenders("x.ts", "const s = await startOtel" + "ReceiverCommand({ flags })")).toEqual(["x.ts:1"]);
    expect(offenders("y.ts", 'spawnSync(node, [cli, "otel-' + 'receiver"])')).toEqual(["y.ts:1"]);
  });
});

describe("otel-receiver checkpoints: the done line and the guard", () => {
  it("a stub witness holds the head after idle, and verify against it exits 0 with 0 unwitnessed", async () => {
    const g = await rig();
    const t0 = g.time.t;
    for (let i = 0; i < 3; i++) expect((await post(g.port, "/v1/traces", T0_PB, { "content-type": "application/x-protobuf" })).status).toBe(200);
    await g.time.to(t0 + 9 * S, g.settle);
    expect(g.stub.rows.length).toBe(0);
    await g.time.to(t0 + 10 * S, g.settle);
    expect(g.stub.rows.map((r) => r["count"])).toEqual(["21"]);
    await g.r.close();
    expect(g.f.posts().length).toBe(1);
    const v = runVerify({ chainPath: g.r.chainPath, identityPath: g.r.identityPath });
    expect(v.kind).toBe("valid");
    const w = await verifyAgainstWitness({ chainPath: g.r.chainPath, validText: "VALID", validExit: 0, witnessName: STUB_WITNESS_NAME, baseUrl: g.stub.url, pinned: targetOf(g.stub, g.f.url).pinned! });
    expect(w.code).toBe(0);
    expect(w.text).toContain("WITNESSED through count 21");
    expect(w.text).toContain("0 records after the last witnessed checkpoint are not witness-protected");
    await g.f.close();
    await g.stub.close();
  });

  it("the guard's controls: a socket to an address that is not loopback is refused and counted, by IP and by name; the default witness is such an address", async () => {
    const d = resolveOtelWitness({ noWitness: false });
    expect(d.ok && isLoop(new URL(d.config.target!.baseUrl).hostname)).toBe(false);
    const before = netLog.filter((x) => x.refused).length;
    await expect(fetch("http://192.0.2.1/")).rejects.toThrow();
    const dir = join(tmp(), "gate");
    runInit({ dir });
    const id = loadFullIdentity(join(dir, "identity.json"), join(dir, "private-key.pem"));
    const cp = buildCheckpointFromHead({ sessionId: "s".repeat(32), count: 1, lastEntryHash: "sha256:" + "0".repeat(64) }, id);
    const out = await witnessCheckpoint(cp, publicKeyFromPrivate(id.privateKey), { baseUrl: "https://witness.example.invalid", name: "x" });
    expect(out.error).toBe("witness_unreachable");
    expect(netLog.filter((x) => x.refused).slice(before).map((x) => x.host)).toEqual(["192.0.2.1", "witness.example.invalid"]);
  });

  it("no test in this file opened a socket to anything but loopback (the guard's two controls aside)", () => {
    expect(resolveOtelWitness({ noWitness: true }).ok).toBe(true);
    const refused = netLog.filter((x) => x.refused).map((x) => x.host);
    expect(refused).toEqual(["192.0.2.1", "witness.example.invalid"]);
    expect(netLog.filter((x) => !x.refused).every((x) => isLoop(x.host))).toBe(true);
    expect(netLog.filter((x) => !x.refused).length).toBeGreaterThan(50);
  });
});
