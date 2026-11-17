// B-481 T2: the local OpenTelemetry receiver (src/otel/receiver.ts and the
// command in src/otel/command.ts), run in this process on 127.0.0.1 with port
// 0 (a free port the system picks), called over loopback only. Every
// temporary folder is made under os.tmpdir() (the kit points TMPDIR, TMP and
// TEMP into its scratch folder) and is never removed. Expected values come
// from the T1 vectors (test/fixtures/otlp/vectors.json: the T0-shaped body
// maps to 7 records, lookup x7, one errored) and from the repository's own
// verifier, not from the code under test.

import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createServer, request, type IncomingHttpHeaders, type Server } from "node:http";
import { connect, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { OTLP_MAX_BODY_BYTES } from "../src/otlp/index.js";
import { startOtelReceiverCommand } from "../src/otel/command.js";
import { allowedHosts, createOtelReceiver, fromWebPage, ipv6Unavailable, isLoopbackAddress, mediaType, retainedHash, type OtelReceiver, type OtelReceiverOptions } from "../src/otel/receiver.js";
import { argsHash, jcsBytes, resultHash, runVerify } from "../src/vendor/recorder/index.js";

const FIX = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", "otlp");
const vec = (name: string): Buffer => readFileSync(join(FIX, name));
const VECTORS = JSON.parse(readFileSync(join(FIX, "vectors.json"), "utf8")) as { vectors: Array<{ file: string; records?: Array<{ tool_name: string; outcome: string; args_hash: string }> }> };
const T0 = VECTORS.vectors.find((v) => v.file === "t0-shape.pb")!.records!;
const PB = "application/x-protobuf";
const JSONT = "application/json";
const tmp = () => mkdtempSync(join(tmpdir(), "b481-t2-recv-"));
const lines = (p: string): string[] => (existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean) : []);
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

interface Res {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}
function post(port: number, path: string, body: Buffer | string, headers: Record<string, string> = {}, opts: { method?: string; chunked?: number } = {}): Promise<Res> {
  return new Promise((done, fail) => {
    const h: Record<string, string> = { host: `127.0.0.1:${port}`, ...headers };
    const buf = typeof body === "string" ? Buffer.from(body) : body;
    if (opts.chunked === undefined) h["content-length"] = String(buf.length);
    const req = request({ host: "127.0.0.1", port, path, method: opts.method ?? "POST", headers: h, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => done({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on("error", fail);
    });
    req.on("error", fail);
    if (opts.chunked !== undefined) {
      for (let i = 0; i < buf.length; i += opts.chunked) req.write(buf.subarray(i, i + opts.chunked));
      req.end();
    } else req.end(buf);
  });
}
// Bytes on a raw loopback socket; resolves with what came back when the peer closes.
function raw(port: number, bytes: string): Promise<string> {
  return new Promise((done) => {
    const s = connect(port, "127.0.0.1");
    const got: Buffer[] = [];
    s.on("data", (c: Buffer) => got.push(c));
    s.on("close", () => done(Buffer.concat(got).toString("latin1")));
    s.on("error", () => undefined);
    s.write(bytes);
    setTimeout(() => s.end(), 2000);
  });
}

// The tests bind 127.0.0.1 only: the ::1 bind is replaced by one that fails as
// on a machine without IPv6, except in the tests of the ::1 bind itself.
const noV6: NonNullable<OtelReceiverOptions["listen6"]> = async () => {
  throw Object.assign(new Error("test: no ::1"), { code: "EAFNOSUPPORT" });
};
type UpOpts = { token?: string; forward?: string; retain?: boolean; dir?: string; maxBytesInFlight?: number; maxConnections?: number; listen6?: OtelReceiverOptions["listen6"]; headersDeadlineMs?: number; bodyDeadlineMs?: number; idleDeadlineMs?: number; gapIntervalMs?: number };
async function up(o: UpOpts = {}) {
  const dir = o.dir ?? join(tmp(), "gate");
  const log: string[] = [];
  const r = createOtelReceiver({
    dir,
    port: 0,
    retain: o.retain ?? true,
    log: (l) => log.push(l),
    listen6: o.listen6 ?? noV6,
    ...(o.token !== undefined ? { token: o.token } : {}),
    ...(o.forward !== undefined ? { forward: o.forward } : {}),
    ...(o.maxBytesInFlight !== undefined ? { maxBytesInFlight: o.maxBytesInFlight } : {}),
    ...(o.maxConnections !== undefined ? { maxConnections: o.maxConnections } : {}),
    ...(o.headersDeadlineMs !== undefined ? { headersDeadlineMs: o.headersDeadlineMs } : {}),
    ...(o.bodyDeadlineMs !== undefined ? { bodyDeadlineMs: o.bodyDeadlineMs } : {}),
    ...(o.idleDeadlineMs !== undefined ? { idleDeadlineMs: o.idleDeadlineMs } : {}),
    ...(o.gapIntervalMs !== undefined ? { gapIntervalMs: o.gapIntervalMs } : {}),
  });
  const l = await r.listen();
  return { r, dir, port: l.port, url: l.url, log, listening: l };
}
const noAccessControl = (h: IncomingHttpHeaders) => Object.keys(h).filter((k) => k.startsWith("access-control-"));
const until = async (f: () => boolean, ms = 10_000) => {
  const t = Date.now();
  while (!f() && Date.now() - t < ms) await new Promise((d) => setTimeout(d, 20));
  return f();
};
const recs = (r: OtelReceiver) => lines(r.chainPath).map((l) => JSON.parse(l));
const gaps = (r: OtelReceiver) => lines(r.gapsPath).map((l) => JSON.parse(l));
const verify = (r: OtelReceiver) => runVerify({ chainPath: r.chainPath, identityPath: r.identityPath });
// Refusals are coalesced (rev 3, N2): the requests a reason stands for are the
// sum of the count fields of its lines (a line without count stands for one).
const tally = (r: OtelReceiver, reason: string) => gaps(r).filter((g) => g.reason === reason).reduce((n, g) => n + (typeof g.count === "number" ? g.count : 1), 0);

// A T0-shaped protobuf body of exactly n bytes: t0-shape.pb plus one unknown
// length-delimited field (number 99) of zero bytes (the T1 tests' padding).
function sized(n: number): Buffer {
  const base = vec("t0-shape.pb");
  const pad = n - base.length - 2 - 4;
  const len = Buffer.from([0x80 | (pad & 0x7f), 0x80 | ((pad >> 7) & 0x7f), 0x80 | ((pad >> 14) & 0x7f), (pad >> 21) & 0x7f]);
  return Buffer.concat([base, Buffer.from([0x9a, 0x06]), len, Buffer.alloc(pad)]);
}

async function stub(status = 200) {
  const got: Array<{ path: string; headers: IncomingHttpHeaders; body: Buffer }> = [];
  const s: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      got.push({ path: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(status);
      res.end();
    });
  });
  await new Promise<void>((d) => s.listen(0, "127.0.0.1", () => d()));
  return { got, port: (s.address() as AddressInfo).port, close: () => new Promise<void>((d) => s.close(() => d())) };
}

describe("otel-receiver: traces become records", { timeout: 120_000 }, () => {
  it("a T0-shaped protobuf batch becomes 7 records the repository's verifier accepts", async () => {
    const { r, port, url } = await up();
    expect(url).toBe(`http://127.0.0.1:${port}`);
    const res = await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe(PB);
    expect(res.body.length).toBe(0);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    const rs = recs(r);
    expect(rs.length).toBe(7);
    expect(rs.map((x) => [x.event.tool_name, x.event.outcome, x.event.args_hash])).toEqual(T0.map((x) => [x.tool_name, x.outcome, x.args_hash]));
    expect(rs.every((x) => x.gate === null && x.event.decision === "observed" && x.event.decision_source === "n/a" && x.event.type === "tool_call")).toBe(true);
    expect(rs.map((x) => x.seq)).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(rs.every((x) => x.session_id === r.sessionId)).toBe(true);
    const v = verify(r);
    expect(v.kind).toBe("valid");
    if (v.kind === "valid") expect(v.count).toBe(7);
    expect(gaps(r)).toEqual([]);
    await r.close();
  });

  it("the JSON and gzip forms of the same batch give the same 7 args_hash values, appended in arrival order", async () => {
    const { r, port } = await up();
    const j = await post(port, "/v1/traces", vec("t0-shape.json"), { "content-type": JSONT });
    expect(j.status).toBe(200);
    expect(j.headers["content-type"]).toBe(JSONT);
    expect(j.body.toString()).toBe("{}");
    const g = await post(port, "/v1/traces", vec("t0-shape.pb.gz"), { "content-type": PB, "content-encoding": "gzip" });
    expect(g.status).toBe(200);
    const rs = recs(r);
    expect(rs.length).toBe(14);
    expect(rs.slice(0, 7).map((x) => x.event.args_hash)).toEqual(T0.map((x) => x.args_hash));
    expect(rs.slice(7).map((x) => x.event.args_hash)).toEqual(T0.map((x) => x.args_hash));
    expect(rs.map((x) => x.seq)).toEqual([...Array(14).keys()]);
    const v = verify(r);
    expect(v.kind === "valid" && v.count).toBe(14);
    await r.close();
  });

  it("counts a chunked body (no Content-Length, as Node SDKs send) as it streams", async () => {
    const { r, port } = await up();
    const res = await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB }, { chunked: 100 });
    expect(res.status).toBe(200);
    expect(recs(r).length).toBe(7);
    await r.close();
  });

  it("keeps the canonical span beside the chain: sha256 of its JCS bytes is each record's args_hash", async () => {
    const { r, port } = await up();
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    const kept = lines(r.retainedPath).map((l) => JSON.parse(l));
    const rs = recs(r);
    expect(kept.map((k) => k.seq)).toEqual(rs.map((x) => x.seq));
    for (const [i, k] of kept.entries()) {
      expect(k.args_hash).toBe(rs[i].event.args_hash);
      expect("sha256:" + sha(jcsBytes(k.preimage))).toBe(rs[i].event.args_hash);
      expect(retainedHash(k.preimage)).toBe(rs[i].event.args_hash);
    }
    expect(r.retainedPath.endsWith(`${r.sessionId}.retained.ndjson`)).toBe(true);
    await r.close();
  });

  it("with retain off (--no-retain) keeps hashes only: no sidecar, the same records", async () => {
    const { r, port } = await up({ retain: false });
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(recs(r).map((x) => x.event.args_hash)).toEqual(T0.map((x) => x.args_hash));
    expect(existsSync(r.retainedPath)).toBe(false);
    expect(readdirSync(join(r.chainPath, "..")).length).toBe(1);
    await r.close();
  });

  it("an edited, removed or swapped record in its chain fails verification", async () => {
    const { r, port } = await up();
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    const ls = lines(r.chainPath);
    const dir = tmp();
    const edited = [...ls];
    edited[3] = edited[3]!.replace('"outcome":"errored"', '"outcome":"executed"');
    expect(edited[3]).not.toBe(ls[3]);
    const swapped = [...ls];
    [swapped[1], swapped[2]] = [swapped[2]!, swapped[1]!];
    for (const [name, body] of [["edited", edited], ["removed", ls.filter((_, i) => i !== 4)], ["swapped", swapped]] as const) {
      const q = join(dir, `${name}.jsonl`);
      writeFileSync(q, body.join("\n") + "\n");
      expect(runVerify({ chainPath: q, identityPath: r.identityPath }).kind, name).not.toBe("valid");
    }
    await r.close();
  });

  it("logs the count of fields it does not know, once", async () => {
    const { r, port, log } = await up();
    expect((await post(port, "/v1/traces", vec("unknown-fields.pb"), { "content-type": PB })).status).toBe(200);
    await post(port, "/v1/traces", vec("unknown-fields.pb"), { "content-type": PB });
    expect(log.filter((l) => l.includes("3 field(s) this version does not know were skipped")).length).toBe(1);
    expect(recs(r).length).toBe(2);
    await r.close();
  });
});

describe("otel-receiver: refusals are gap lines, never records", { timeout: 120_000 }, () => {
  it("a refused batch: 400 with an OTLP Status in the request's format, a gap line with the reason, and a printed line", async () => {
    const { r, port, log } = await up();
    const res = await post(port, "/v1/traces", vec("neg-trace-id-zero.pb"), { "content-type": PB });
    expect(res.status).toBe(400);
    expect(res.headers["content-type"]).toBe(PB);
    expect(res.body[0]).toBe(0x08);
    expect(res.body[1]).toBe(3);
    expect(res.body.subarray(4).toString()).toBe("trace_id_invalid");
    const j = await post(port, "/v1/traces", vec("neg-dup-member.json"), { "content-type": JSONT });
    expect(j.status).toBe(400);
    expect(JSON.parse(j.body.toString())).toEqual({ code: 3, message: "json_invalid" });
    expect(recs(r)).toEqual([]);
    const g = gaps(r);
    expect(g.map((x) => [x.route, x.reason])).toEqual([["/v1/traces", "trace_id_invalid"], ["/v1/traces", "json_invalid"]]);
    expect(g[0].session_id).toBe(r.sessionId);
    expect(typeof g[0].detail).toBe("string");
    expect(log.some((l) => l.includes("refused a /v1/traces batch: trace_id_invalid"))).toBe(true);
    await r.close();
  });

  it("415 for a content type or encoding it does not read", async () => {
    const { r, port } = await up();
    expect((await post(port, "/v1/traces", "x", { "content-type": "text/plain" })).status).toBe(415);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, "content-encoding": "br" })).status).toBe(415);
    expect(gaps(r).map((x) => x.reason)).toEqual(["unsupported_content_type", "unsupported_content_encoding"]);
    expect(recs(r)).toEqual([]);
    await r.close();
  });

  it("accepts a body of exactly 16 MiB and refuses 16 MiB + 1 with 413 and a gap line", async () => {
    const { r, port } = await up();
    const exact = sized(OTLP_MAX_BODY_BYTES);
    expect(exact.length).toBe(16 * 1024 * 1024);
    expect((await post(port, "/v1/traces", exact, { "content-type": PB }, { chunked: 1 << 20 })).status).toBe(200);
    expect(recs(r).length).toBe(7);
    const over = await post(port, "/v1/traces", sized(OTLP_MAX_BODY_BYTES + 1), { "content-type": PB }, { chunked: 1 << 20 });
    expect(over.status).toBe(413);
    expect(recs(r).length).toBe(7);
    expect(gaps(r).map((x) => [x.route, x.reason])).toEqual([["/v1/traces", "too_large"]]);
    await r.close();
  });

  it("refuses gzip that inflates past 16 MiB with 413 (the T1 bomb vector)", async () => {
    const { r, port, log } = await up();
    const res = await post(port, "/v1/traces", vec("bomb.pb.gz"), { "content-type": PB, "content-encoding": "gzip" });
    expect(res.status).toBe(413);
    expect(res.body.subarray(4).toString()).toBe("too_large");
    expect(recs(r)).toEqual([]);
    expect(gaps(r).map((x) => [x.route, x.reason])).toEqual([["/v1/traces", "too_large"]]);
    expect(log.some((l) => l.includes("refused a /v1/traces batch: too_large"))).toBe(true);
    await r.close();
  });

  it("refuses 16 MiB + 1 on /v1/metrics and /v1/chirindo/records too", async () => {
    const { r, port } = await up();
    const big = Buffer.alloc(OTLP_MAX_BODY_BYTES + 1);
    expect((await post(port, "/v1/metrics", big, { "content-type": PB })).status).toBe(413);
    expect((await post(port, "/v1/chirindo/records", big, { "content-type": JSONT })).status).toBe(413);
    expect(gaps(r).map((x) => [x.route, x.reason])).toEqual([["/v1/metrics", "too_large"], ["/v1/chirindo/records", "too_large"]]);
    await r.close();
  });

  it("answers /v1/metrics and /v1/logs 200 without reading them and writes nothing", async () => {
    const { r, port } = await up();
    const m = await post(port, "/v1/metrics", Buffer.from([0xff, 0x00, 0x13]), { "content-type": PB });
    expect(m.status).toBe(200);
    expect(m.body.length).toBe(0);
    const l = await post(port, "/v1/logs", "not json at all", { "content-type": JSONT });
    expect(l.status).toBe(200);
    expect(l.body.toString()).toBe("{}");
    expect(recs(r)).toEqual([]);
    expect(gaps(r)).toEqual([]);
    await r.close();
  });

  it("404 for another path and 405 for another method, with no record", async () => {
    const { r, port } = await up();
    expect((await post(port, "/v1/trace", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(404);
    expect((await post(port, "/", "", {})).status).toBe(404);
    const g = await post(port, "/v1/traces", "", {}, { method: "GET" });
    expect(g.status).toBe(405);
    expect(g.headers.allow).toBe("POST");
    expect((await post(port, "/v1/traces", "", {}, { method: "OPTIONS" })).headers["access-control-allow-origin"]).toBeUndefined();
    expect(recs(r)).toEqual([]);
    await r.close();
  });
});

describe("otel-receiver: Host and token", { timeout: 120_000 }, () => {
  it("accepts Host localhost, 127.0.0.1 and [::1] at the bound port, in any letter case", async () => {
    const { r, port } = await up();
    expect(allowedHosts(port)).toEqual([`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`]);
    for (const h of [`localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`, `LocalHost:${port}`]) {
      expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, host: h })).status, h).toBe(200);
    }
    expect(recs(r).length).toBe(28);
    await r.close();
  });

  it("refuses any other Host with 403 and a gap line, and writes no record", async () => {
    const { r, port } = await up();
    const bad = [`localhost:${port + 1}`, "localhost", "127.0.0.1", `evil.example:${port}`, `127.0.0.2:${port}`, `localhost.:${port}`, `[::2]:${port}`, `localhost:${port}.evil.example`, `0.0.0.0:${port}`, `127.0.0.1:0${port}`];
    for (const h of bad) {
      const res = await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, host: h });
      expect(res.status, h).toBe(403);
    }
    const none = await raw(port, "POST /v1/traces HTTP/1.0\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\n\r\n");
    expect(none.startsWith("HTTP/1.1 403")).toBe(true);
    expect(recs(r)).toEqual([]);
    expect(gaps(r).map((g) => [g.reason, g.count])).toEqual([["host-not-allowed", 1]]);
    await r.close();
    expect(tally(r, "host-not-allowed")).toBe(bad.length + 1);
    expect(new Set(gaps(r).map((x) => x.reason))).toEqual(new Set(["host-not-allowed"]));
    expect(gaps(r).length).toBe(2);
  });

  it("checks the Host on every route, before the path is looked up", async () => {
    const { r, port } = await up();
    for (const p of ["/v1/metrics", "/v1/logs", "/v1/chirindo/records", "/nothing"]) {
      expect((await post(port, p, "{}", { "content-type": JSONT, host: `evil.example:${port}` })).status, p).toBe(403);
    }
    await r.close();
  });

  it("with a token, refuses a request without it or with another, and accepts it in constant time", async () => {
    const { r, port } = await up({ token: "s3cret-token-b481" });
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(401);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, authorization: "Bearer s3cret-token-b48" })).status).toBe(401);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, authorization: "Basic s3cret-token-b481" })).status).toBe(401);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, authorization: "Digest s3cret-token-b481" })).status).toBe(401);
    expect(recs(r)).toEqual([]);
    expect(gaps(r).map((x) => [x.reason, x.count])).toEqual([["unauthorized", 1]]);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, authorization: "Bearer s3cret-token-b481" })).status).toBe(200);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, authorization: "bearer s3cret-token-b481" })).status).toBe(200);
    expect(recs(r).length).toBe(14);
    await r.close();
    expect(tally(r, "unauthorized")).toBe(4);
    for (const f of [r.chainPath, r.retainedPath, r.gapsPath]) expect(readFileSync(f, "utf8").includes("s3cret-token-b481")).toBe(false);
  });

  it("counts connections by peer address: every one in these tests is loopback", async () => {
    expect(["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"].map(isLoopbackAddress)).toEqual([true, true, true, true]);
    expect(["10.0.0.1", "0.0.0.0", "::", "::ffff:10.0.0.1", "128.0.0.1", "1127.0.0.1", undefined].map(isLoopbackAddress)).toEqual([false, false, false, false, false, false, false]);
    const { r, port } = await up();
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    await post(port, "/v1/metrics", "", { "content-type": PB });
    const s = r.stats();
    expect(s.connections).toBe(2);
    expect(s.nonLoopbackConnections).toBe(0);
    expect(s.records).toBe(7);
    await r.close();
  });
});

describe("otel-receiver: the records route (ruling L3, provisional)", { timeout: 120_000 }, () => {
  it("appends one observed tool_call record per item, args_hash and result_hash from the values sent", async () => {
    const { r, port } = await up();
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    const body = { records: [{ tool_name: "search", outcome: "executed", args: { q: "a", n: 2 }, result: { hits: [1, 2] } }, { tool_name: "fetch", outcome: "errored", args: ["x"] }] };
    const res = await post(port, "/v1/chirindo/records", JSON.stringify(body), { "content-type": JSONT });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.toString())).toEqual({ ok: true, appended: 2, first_seq: 7, session_id: r.sessionId });
    const rs = recs(r).slice(7);
    expect(rs.map((x) => x.event)).toEqual([
      { type: "tool_call", outcome: "executed", tool_name: "search", args_hash: argsHash({ q: "a", n: 2 }), decision: "observed", decision_source: "n/a", result_hash: resultHash({ hits: [1, 2] }) },
      { type: "tool_call", outcome: "errored", tool_name: "fetch", args_hash: argsHash(["x"]), decision: "observed", decision_source: "n/a" },
    ]);
    const kept = lines(r.retainedPath).map((l) => JSON.parse(l)).slice(7);
    expect(kept).toEqual([
      { seq: 7, args_hash: argsHash({ q: "a", n: 2 }), preimage: { q: "a", n: 2 }, result_hash: resultHash({ hits: [1, 2] }), result_preimage: { hits: [1, 2] } },
      { seq: 8, args_hash: argsHash(["x"]), preimage: ["x"] },
    ]);
    const v = verify(r);
    expect(v.kind === "valid" && v.count).toBe(9);
    await r.close();
  });

  it("refuses a malformed body whole, with 400 and a gap line, and appends nothing", async () => {
    const { r, port } = await up();
    const long = "t".repeat(257);
    const bad: unknown[] = [
      "{not json",
      { records: [] },
      [],
      { records: {} },
      { recs: [] },
      { records: [{ tool_name: "a", outcome: "executed" }] },
      { records: [{ tool_name: "", outcome: "executed", args: 1 }] },
      { records: [{ tool_name: long, outcome: "executed", args: 1 }] },
      { records: [{ tool_name: "a", outcome: "denied", args: 1 }] },
      { records: [{ tool_name: "a", outcome: "executed", args: 1, extra: 1 }] },
      { records: [{ tool_name: "a", outcome: "executed", args: 1 }, "x"] },
      { records: Array.from({ length: 1001 }, () => ({ tool_name: "a", outcome: "executed", args: 1 })) },
    ];
    for (const b of bad) {
      const res = await post(port, "/v1/chirindo/records", typeof b === "string" ? b : JSON.stringify(b), { "content-type": JSONT });
      expect(res.status, JSON.stringify(b).slice(0, 80)).toBe(400);
    }
    expect((await post(port, "/v1/chirindo/records", '{"records":[{"tool_name":"a","outcome":"executed","args":1,"args":2}]}', { "content-type": JSONT })).status).toBe(400);
    expect(recs(r)).toEqual([]);
    expect(gaps(r).length).toBe(bad.length + 1);
    expect(gaps(r).every((g) => g.route === "/v1/chirindo/records" && (g.reason === "invalid-json" || g.reason === "invalid-records"))).toBe(true);
    await r.close();
  });

  it("accepts the limits exactly: 1000 items, a tool_name of 256 characters", async () => {
    const { r, port } = await up();
    const many = { records: Array.from({ length: 1000 }, (_, i) => ({ tool_name: "t".repeat(i === 0 ? 256 : 1), outcome: "executed", args: i })) };
    const res = await post(port, "/v1/chirindo/records", JSON.stringify(many), { "content-type": JSONT });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.toString()).appended).toBe(1000);
    expect(recs(r).length).toBe(1000);
    expect(recs(r)[0].event.tool_name.length).toBe(256);
    await r.close();
  });
});

describe("otel-receiver: forwarding (ruling L4 a)", { timeout: 120_000 }, () => {
  it("sends each OTLP request's bytes and headers on unchanged, after answering, and writes no header to disk", async () => {
    const s = await stub();
    const { r, port, dir } = await up({ forward: `http://127.0.0.1:${s.port}/collector/` });
    const t = await post(port, "/v1/traces", vec("t0-shape.pb.gz"), { "content-type": PB, "content-encoding": "gzip", "x-vendor-key": "vk-b481-secret", "user-agent": "OTel-OTLP-Exporter-JavaScript/0.301.0" });
    expect(t.status).toBe(200);
    expect((await post(port, "/v1/metrics", Buffer.from([1, 2, 3]), { "content-type": PB, "x-vendor-key": "vk-b481-secret" })).status).toBe(200);
    expect((await post(port, "/v1/logs", "{}", { "content-type": JSONT, "x-vendor-key": "vk-b481-secret" })).status).toBe(200);
    await post(port, "/v1/chirindo/records", JSON.stringify({ records: [{ tool_name: "a", outcome: "executed", args: 1 }] }), { "content-type": JSONT });
    await r.settled();
    expect(s.got.map((g) => g.path)).toEqual(["/collector/v1/traces", "/collector/v1/metrics", "/collector/v1/logs"]);
    expect(s.got[0]!.body.equals(vec("t0-shape.pb.gz"))).toBe(true);
    expect(s.got[0]!.headers["x-vendor-key"]).toBe("vk-b481-secret");
    expect(s.got[0]!.headers["content-encoding"]).toBe("gzip");
    expect(s.got[0]!.headers["content-type"]).toBe(PB);
    expect(s.got[0]!.headers["user-agent"]).toBe("OTel-OTLP-Exporter-JavaScript/0.301.0");
    expect(s.got[0]!.headers.host).toBe(`127.0.0.1:${s.port}`);
    expect(s.got[1]!.body.equals(Buffer.from([1, 2, 3]))).toBe(true);
    expect(recs(r).length).toBe(8);
    const all = [r.chainPath, r.retainedPath, ...(existsSync(r.gapsPath) ? [r.gapsPath] : [])].map((f) => readFileSync(f, "utf8")).join("");
    expect(all.includes("vk-b481-secret")).toBe(false);
    expect(readdirSync(join(dir, "otel")).sort()).toEqual(["chains"]);
    await r.close();
    await s.close();
  });

  it("does not pass its own token on; passes the caller's other headers", async () => {
    const s = await stub();
    const { r, port } = await up({ token: "own-token-b481", forward: `http://127.0.0.1:${s.port}` });
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, authorization: "Bearer own-token-b481", "x-other": "1" });
    await r.settled();
    expect(s.got.length).toBe(1);
    expect(s.got[0]!.path).toBe("/v1/traces");
    expect(s.got[0]!.headers.authorization).toBeUndefined();
    expect(s.got[0]!.headers["x-other"]).toBe("1");
    await r.close();
    await s.close();
  });

  it("a backend that answers 500 or cannot be reached: the SDK still gets 200, and a forward-failed gap line", async () => {
    const s = await stub(500);
    const { r, port, log } = await up({ forward: `http://127.0.0.1:${s.port}` });
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    await r.settled();
    expect(recs(r).length).toBe(7);
    expect(gaps(r).map((g) => [g.route, g.reason, g.status])).toEqual([["/v1/traces", "forward-failed", 500]]);
    await r.close();
    await s.close();
    const gone = await up({ forward: `http://127.0.0.1:${s.port}` });
    expect((await post(gone.port, "/v1/metrics", "", { "content-type": PB })).status).toBe(200);
    await gone.r.settled();
    expect(gaps(gone.r).map((g) => [g.route, g.reason, g.error])).toEqual([["/v1/metrics", "forward-failed", "ECONNREFUSED"]]);
    expect(gone.log.some((l) => l.includes("forward to http://127.0.0.1:") && l.includes("ECONNREFUSED"))).toBe(true);
    expect(log.some((l) => l.includes("answered 500"))).toBe(true);
    await gone.r.close();
  });
});

describe("otel-receiver: start, key, sessions, gRPC, broken chain", { timeout: 120_000 }, () => {
  it("creates the key on first start, reuses it after, and gives each process its own session and chain", async () => {
    const dir = join(tmp(), "gate");
    const a = await up({ dir });
    expect(a.r.keyCreated).toBe(true);
    expect(existsSync(join(dir, "identity.json")) && existsSync(join(dir, "private-key.pem"))).toBe(true);
    await post(a.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    await a.r.close();
    const id = readFileSync(join(dir, "identity.json"), "utf8");
    const b = await up({ dir });
    expect(b.r.keyCreated).toBe(false);
    expect(readFileSync(join(dir, "identity.json"), "utf8")).toBe(id);
    expect(b.r.sessionId).not.toBe(a.r.sessionId);
    expect(b.r.sessionId).toMatch(/^[0-9a-f]{32}$/);
    await post(b.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(recs(b.r)[0].seq).toBe(0);
    expect(recs(a.r)[0].key_thumbprint).toBe(recs(b.r)[0].key_thumbprint);
    expect(verify(a.r).kind).toBe("valid");
    expect(verify(b.r).kind).toBe("valid");
    await b.r.close();
  });

  it("an OTLP/gRPC client (HTTP/2 preface) is closed, told the setting once, and leaves a gap line", async () => {
    const { r, port, log } = await up();
    await raw(port, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    await raw(port, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    expect(log.filter((l) => l.includes("OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf")).length).toBe(1);
    expect(gaps(r).map((g) => [g.route, g.reason, g.count])).toEqual([["grpc", "grpc-not-served", 1]]);
    expect(recs(r)).toEqual([]);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    await r.close();
    expect(tally(r, "grpc-not-served")).toBe(2);
  });

  it("when an append fails, answers 503, writes a gap line, and refuses every later batch (chain-broken)", async () => {
    const ok = await up();
    const br = await up();
    // The chain file's name now names a folder, so the first line write fails.
    mkdirSync(br.r.chainPath);
    const a = await post(br.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(a.status).toBe(503);
    const b = await post(br.port, "/v1/chirindo/records", JSON.stringify({ records: [{ tool_name: "a", outcome: "executed", args: 1 }] }), { "content-type": JSONT });
    expect(b.status).toBe(503);
    const c = await post(br.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(c.status).toBe(503);
    expect(gaps(br.r).map((g) => g.reason)).toEqual(["append-failed", "chain-broken", "chain-broken"]);
    expect(br.log.some((l) => l.includes("append failed"))).toBe(true);
    expect(br.r.stats().records).toBe(0);
    // Another receiver in the same process is not affected.
    expect((await post(ok.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(recs(ok.r).length).toBe(7);
    await br.r.close();
    await ok.r.close();
  });

  it("the command: prints its address, session and chain as one JSON line, and stops cleanly", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const dir = tmp();
    const s = await startOtelReceiverCommand({ flags: new Map<string, string | true>([["dir", "gate"], ["port", "0"], ["no-retain", true]]), positional: [], passthrough: [] }, { stdout: (l) => out.push(l), stderr: (l) => err.push(l), cwd: dir });
    expect(s.code).toBe(0);
    expect(out.length).toBe(1);
    const j = JSON.parse(out[0]!);
    expect(j.listening).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(j.session_id).toBe(s.receiver!.sessionId);
    expect(j.chain).toBe(join(dir, "gate", "otel", "chains", `${j.session_id}.jsonl`));
    expect(j.pid).toBe(process.pid);
    expect(j.addresses[0]).toBe(`127.0.0.1:${new URL(j.listening).port}`);
    expect(j.ipv6 === "bound" ? j.addresses.length === 2 : /^unavailable \((EAFNOSUPPORT|EADDRNOTAVAIL)\)$/.test(j.ipv6) && j.addresses.length === 1).toBe(true);
    expect(err.some((l) => l.includes("created one (identity.json, private-key.pem)"))).toBe(true);
    expect(err.some((l) => l.includes("retain=off") && l.includes("token=none"))).toBe(true);
    const port = Number(new URL(j.listening).port);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, host: `localhost:${port}` })).status).toBe(200);
    expect(lines(j.chain).length).toBe(7);
    expect(existsSync(s.receiver!.retainedPath)).toBe(false);
    await s.stop!();
    await expect(post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).rejects.toThrow();
  });

  it("the command: usage errors exit 2 before anything is written; a port in use exits 1", async () => {
    const dir = tmp();
    const run = async (flags: Array<[string, string | true]>, positional: string[] = []) => {
      const err: string[] = [];
      const s = await startOtelReceiverCommand({ flags: new Map(flags), positional, passthrough: [] }, { stdout: () => undefined, stderr: (l) => err.push(l), cwd: dir });
      return { code: s.code, err: err.join("\n"), s };
    };
    const g: Array<[string, string | true]> = [["dir", "g"]];
    expect((await run([...g, ["host", "0.0.0.0"]])).err).toContain("unknown flag --host");
    expect((await run([...g, ["port", "65536"]])).code).toBe(2);
    expect((await run([...g, ["port", "-1"]])).code).toBe(2);
    expect((await run([...g, ["port", "08"]])).code).toBe(2);
    expect((await run([...g, ["forward", "ftp://127.0.0.1/"]])).code).toBe(2);
    expect((await run([...g, ["forward", true]])).code).toBe(2);
    expect((await run([...g, ["no-retain", "yes"]])).code).toBe(2);
    expect((await run([...g, ["bind", "0.0.0.0"]])).err).toContain("unknown flag --bind");
    expect((await run(g, ["extra"])).code).toBe(2);
    writeFileSync(join(dir, "empty-token"), "\n");
    expect((await run([...g, ["token-file", "empty-token"]])).err).toContain("is empty");
    expect((await run([...g, ["token-file", "no-such-file"]])).code).toBe(2);
    expect(existsSync(join(dir, "g"))).toBe(false);
    const holder = createServer();
    await new Promise<void>((d) => holder.listen(0, "127.0.0.1", () => d()));
    const taken = (holder.address() as AddressInfo).port;
    const t = await run([...g, ["port", String(taken)]]);
    expect(t.code).toBe(1);
    expect(t.err).toContain(`cannot listen on 127.0.0.1:${taken} (EADDRINUSE)`);
    const ok = await run([...g, ["port", "65535"]]);
    expect([0, 1]).toContain(ok.code);
    if (ok.code === 0) await ok.s.stop!();
    await new Promise<void>((d) => holder.close(() => d()));
  });
});

describe("otel-receiver: web pages are refused (H1)", { timeout: 120_000 }, () => {
  const ORIGIN = "https://evil.example";
  const recBody = JSON.stringify({ records: [{ tool_name: "transfer_funds", outcome: "executed", args: { to: "x", amount: 1 } }] });
  it("a cross-site text/plain simple request (fetch no-cors) to the records route: 403, a gap line, no record", async () => {
    const { r, port } = await up();
    const res = await post(port, "/v1/chirindo/records", recBody, { "content-type": "text/plain;charset=UTF-8", origin: ORIGIN, "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors" });
    expect(res.status).toBe(403);
    expect(noAccessControl(res.headers)).toEqual([]);
    expect(recs(r)).toEqual([]);
    expect(gaps(r).map((g) => [g.route, g.reason, g.header])).toEqual([["/v1/chirindo/records", "cross-origin", "origin"]]);
    await r.close();
  });

  it("a form post (urlencoded and multipart) from a page: 403 on every route, no record", async () => {
    const { r, port } = await up();
    for (const p of ["/v1/chirindo/records", "/v1/traces", "/v1/metrics", "/v1/logs", "/elsewhere"]) {
      const a = await post(port, p, "records=1", { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN });
      const b = await post(port, p, "--b\r\n\r\nx\r\n--b--", { "content-type": "multipart/form-data; boundary=b", origin: ORIGIN });
      expect([a.status, b.status], p).toEqual([403, 403]);
      expect(noAccessControl(a.headers)).toEqual([]);
    }
    expect(recs(r)).toEqual([]);
    expect(gaps(r).length).toBe(5);
    await r.close();
    expect(tally(r, "cross-origin")).toBe(10);
    expect(new Set(gaps(r).map((g) => g.reason))).toEqual(new Set(["cross-origin"]));
  });

  it("a preflight (OPTIONS with Access-Control-Request-*) is refused and gets no Access-Control header", async () => {
    const { r, port } = await up();
    const res = await post(port, "/v1/chirindo/records", "", { origin: ORIGIN, "access-control-request-method": "POST", "access-control-request-headers": "content-type" }, { method: "OPTIONS" });
    expect(res.status).toBe(403);
    expect(noAccessControl(res.headers)).toEqual([]);
    const bare = await post(port, "/v1/chirindo/records", "", {}, { method: "OPTIONS" });
    expect(bare.status).toBe(405);
    expect(noAccessControl(bare.headers)).toEqual([]);
    expect(gaps(r).map((g) => g.reason)).toEqual(["cross-origin", "method-not-allowed"]);
    await r.close();
  });

  it("Origin: null (a sandboxed page or a file:// page) is refused like any other Origin", async () => {
    const { r, port } = await up();
    for (const [p, ct, body] of [["/v1/chirindo/records", "application/json", recBody], ["/v1/traces", PB, vec("t0-shape.pb")]] as const) {
      expect((await post(port, p, body, { "content-type": ct, origin: "null" })).status, p).toBe(403);
    }
    expect(recs(r)).toEqual([]);
    await r.close();
  });

  it("the same requests with a rebinding Host (a page's own name resolved to 127.0.0.1): 403, no record", async () => {
    const { r, port } = await up();
    const host = `attacker.example:${port}`;
    const sent = [
      await post(port, "/v1/chirindo/records", recBody, { host, "content-type": "text/plain", origin: `http://${host}` }),
      await post(port, "/v1/chirindo/records", recBody, { host, "content-type": "application/json" }),
      await post(port, "/v1/chirindo/records", "records=1", { host, "content-type": "application/x-www-form-urlencoded", origin: "null" }),
      await post(port, "/v1/chirindo/records", "", { host, origin: `http://${host}`, "access-control-request-method": "POST" }, { method: "OPTIONS" }),
    ];
    expect(sent.map((x) => x.status)).toEqual([403, 403, 403, 403]);
    expect(sent.flatMap((x) => noAccessControl(x.headers))).toEqual([]);
    expect(recs(r)).toEqual([]);
    expect(new Set(gaps(r).map((g) => g.reason))).toEqual(new Set(["host-not-allowed"]));
    await r.close();
  });

  it("Sec-Fetch-Site other than none is refused without an Origin; none is not", async () => {
    const { r, port } = await up();
    expect((await post(port, "/v1/chirindo/records", recBody, { "content-type": "application/json", "sec-fetch-site": "same-site" })).status).toBe(403);
    expect((await post(port, "/v1/chirindo/records", recBody, { "content-type": "application/json", "sec-fetch-site": "none" })).status).toBe(200);
    expect(fromWebPage({ origin: "null" })).toBe("origin");
    expect(fromWebPage({ "sec-fetch-site": "cross-site" })).toBe("sec-fetch-site");
    expect(fromWebPage({ "sec-fetch-site": "None" })).toBeUndefined();
    expect(fromWebPage({})).toBeUndefined();
    expect(recs(r).length).toBe(1);
    await r.close();
  });

  it("without an Origin: the records route takes only application/json and the OTLP routes only protobuf or JSON (parameters ignored)", async () => {
    const { r, port } = await up();
    expect((await post(port, "/v1/chirindo/records", recBody, { "content-type": "text/plain" })).status).toBe(415);
    expect((await post(port, "/v1/chirindo/records", recBody, { "content-type": "application/x-www-form-urlencoded" })).status).toBe(415);
    expect((await post(port, "/v1/chirindo/records", recBody, { "content-type": PB })).status).toBe(415);
    expect((await post(port, "/v1/chirindo/records", recBody, {})).status).toBe(415);
    expect((await post(port, "/v1/metrics", "x", { "content-type": "text/plain" })).status).toBe(415);
    expect((await post(port, "/v1/logs", "x", { "content-type": "multipart/form-data; boundary=b" })).status).toBe(415);
    expect(recs(r)).toEqual([]);
    expect(tally(r, "unsupported_content_type")).toBe(3);
    expect(new Set(gaps(r).map((g) => g.reason))).toEqual(new Set(["unsupported_content_type"]));
    expect((await post(port, "/v1/chirindo/records", recBody, { "content-type": "Application/JSON; charset=utf-8" })).status).toBe(200);
    expect((await post(port, "/v1/logs", "x", { "content-type": "application/x-protobuf; v=1" })).status).toBe(200);
    expect(mediaType(" Application/JSON ; charset=utf-8")).toBe("application/json");
    expect(recs(r).length).toBe(1);
    await r.close();
    expect(tally(r, "unsupported_content_type")).toBe(6);
  });

  it("an empty Origin header (Origin: with no value) is refused like any other (the closure read's N5)", async () => {
    const { r, port } = await up();
    const res = await raw(port, `POST /v1/chirindo/records HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: \r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(recBody)}\r\nConnection: close\r\n\r\n${recBody}`);
    expect(res.startsWith("HTTP/1.1 403")).toBe(true);
    const nul = await raw(port, `POST /v1/chirindo/records HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: null\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(recBody)}\r\nConnection: close\r\n\r\n${recBody}`);
    expect(nul.startsWith("HTTP/1.1 403")).toBe(true);
    expect(fromWebPage({ origin: "" })).toBe("origin");
    expect(recs(r)).toEqual([]);
    await r.close();
    expect(tally(r, "cross-origin")).toBe(2);
  });
});

describe("otel-receiver: bounded bytes and connections (M2)", { timeout: 120_000 }, () => {
  it("a body past the bytes-in-flight limit gets 503 with Retry-After and a gap line; the bytes are released", async () => {
    const { r, port } = await up({ maxBytesInFlight: 1 << 20 });
    const big = sized(3 << 19);
    const res = await post(port, "/v1/traces", big, { "content-type": PB }, { chunked: 1 << 16 });
    expect(res.status).toBe(503);
    expect(res.headers["retry-after"]).toBe("2");
    expect(gaps(r).map((g) => [g.route, g.reason])).toEqual([["/v1/traces", "busy"]]);
    expect(recs(r)).toEqual([]);
    expect(r.stats().bytesInFlight).toBe(0);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(r.stats().bytesInFlight).toBe(0);
    await r.close();
  });

  it("two bodies held at once share the limit: the second gets 503 busy, the first completes", async () => {
    const { r, port } = await up({ maxBytesInFlight: 1 << 20 });
    const half = sized(700_000);
    const first = new Promise<number>((done, fail) => {
      const q = request({ host: "127.0.0.1", port, path: "/v1/traces", method: "POST", agent: false, headers: { host: `127.0.0.1:${port}`, "content-type": PB } }, (res) => {
        res.resume();
        res.on("end", () => done(res.statusCode ?? 0));
      });
      q.on("error", fail);
      q.write(half.subarray(0, 650_000));
      void until(() => r.stats().bytesInFlight >= 650_000).then(async () => {
        const second = await post(port, "/v1/traces", sized(700_000), { "content-type": PB }, { chunked: 1 << 16 });
        expect(second.status).toBe(503);
        q.end(half.subarray(650_000));
      });
    });
    expect(await first).toBe(200);
    expect(recs(r).length).toBe(7);
    expect(gaps(r).map((g) => g.reason)).toEqual(["busy"]);
    await r.close();
  });

  it("metrics and logs without a forward endpoint are counted, not held: no limit applies", async () => {
    const { r, port } = await up({ maxBytesInFlight: 1 << 20 });
    expect((await post(port, "/v1/metrics", Buffer.alloc(3 << 20), { "content-type": PB }, { chunked: 1 << 16 })).status).toBe(200);
    expect(gaps(r)).toEqual([]);
    await r.close();
  });

  it("when no slot can be taken back (every connection has a body arriving faster than 64 KiB/s), a new connection is answered 503 with Retry-After", async () => {
    const { r, port } = await up({ maxConnections: 2 });
    const busy = [connect(port, "127.0.0.1"), connect(port, "127.0.0.1")];
    busy.forEach((s) => s.on("error", () => undefined));
    await Promise.all(busy.map((s) => new Promise((d) => s.on("connect", d))));
    const chunk = Buffer.alloc(64 * 1024, 0x78);
    for (const s of busy) s.write(`POST /v1/logs HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/x-protobuf\r\nContent-Length: ${OTLP_MAX_BODY_BYTES}\r\n\r\n`);
    const pump = setInterval(() => busy.forEach((s) => s.writable && s.write(chunk)), 10);
    await until(() => r.stats().connections >= 2, 2000);
    await until(() => false, 200);
    const res = await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(res.status).toBe(503);
    expect(res.headers["retry-after"]).toBe("2");
    const again = await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(again.status).toBe(503);
    expect(r.stats().refusedConnections).toBe(2);
    expect(r.stats().evictedConnections).toBe(0);
    expect(gaps(r).map((g) => [g.route, g.reason, g.limit, g.count])).toEqual([["connection", "too-many-connections", 2, 1]]);
    clearInterval(pump);
    for (const s of busy) s.destroy();
    await until(() => false, 200);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(recs(r).length).toBe(7);
    await r.close();
    expect(tally(r, "too-many-connections")).toBe(2);
    expect(tally(r, "aborted")).toBe(2);
  });

  it("a client that stops sending part way gets a gap line `aborted`, not `too_large`", async () => {
    const { r, port } = await up();
    const s = connect(port, "127.0.0.1");
    await new Promise((d) => s.on("connect", d));
    s.write(`POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/x-protobuf\r\nContent-Length: 1000\r\n\r\n0123456789`);
    await until(() => false, 100);
    s.destroy();
    expect(await until(() => gaps(r).length > 0)).toBe(true);
    expect(gaps(r).map((g) => g.reason)).toEqual(["aborted"]);
    expect(recs(r)).toEqual([]);
    await r.close();
  });
});

describe("otel-receiver: connection deadlines and slots (rev 3, N1)", { timeout: 120_000 }, () => {
  const hdr = (port: number, len = 100000) => `POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/x-protobuf\r\nContent-Length: ${len}\r\n\r\n`;
  const open = async (port: number) => {
    const s = connect(port, "127.0.0.1");
    s.on("error", () => undefined);
    await new Promise((d) => s.on("connect", d));
    return s;
  };
  const closedAfter = (s: ReturnType<typeof connect>, t0: number) => new Promise<number>((d) => s.on("close", () => d(Date.now() - t0)));

  it("a connection whose request headers do not complete in time is closed, with a refusal line", async () => {
    const { r, port } = await up({ headersDeadlineMs: 400 });
    const s = await open(port);
    const t0 = Date.now();
    const closed = closedAfter(s, t0);
    s.write("POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1:");
    const ms = await closed;
    expect(ms).toBeGreaterThanOrEqual(380);
    expect(ms).toBeLessThan(3000);
    expect(r.stats().deadlineCloses).toBe(1);
    await r.close();
    expect(tally(r, "deadline-headers")).toBe(1);
    expect(recs(r)).toEqual([]);
  });

  it("a body that does not complete within the body deadline is closed, and its request leaves an aborted line with the cause", async () => {
    const { r, port } = await up({ bodyDeadlineMs: 500, idleDeadlineMs: 5000 });
    const s = await open(port);
    const t0 = Date.now();
    const closed = closedAfter(s, t0);
    s.write(hdr(port));
    const drip = setInterval(() => s.writable && s.write("x"), 50);
    const ms = await closed;
    clearInterval(drip);
    expect(ms).toBeGreaterThanOrEqual(480);
    expect(ms).toBeLessThan(3000);
    expect(await until(() => gaps(r).some((g) => g.reason === "aborted"))).toBe(true);
    expect(gaps(r).filter((g) => g.reason === "aborted").map((g) => g.cause)).toEqual(["deadline-body"]);
    await r.close();
  });

  it("no byte for the idle deadline in the middle of a body closes the connection (aborted, cause deadline-idle)", async () => {
    const { r, port } = await up({ idleDeadlineMs: 300 });
    const s = await open(port);
    const closed = closedAfter(s, Date.now());
    s.write(hdr(port) + "xxxx");
    const ms = await closed;
    expect(ms).toBeGreaterThanOrEqual(280);
    expect(ms).toBeLessThan(3000);
    expect(await until(() => gaps(r).some((g) => g.reason === "aborted"))).toBe(true);
    expect(gaps(r).filter((g) => g.reason === "aborted").map((g) => g.cause)).toEqual(["deadline-idle"]);
    await r.close();
  });

  it("a body that keeps arriving, a byte every 100 ms, is not closed by a 300 ms idle deadline", async () => {
    const { r, port } = await up({ idleDeadlineMs: 300, bodyDeadlineMs: 10_000 });
    const body = JSON.stringify({ records: [{ tool_name: "t", outcome: "executed", args: {} }] });
    const s = await open(port);
    const got: Buffer[] = [];
    s.on("data", (c: Buffer) => got.push(c));
    s.write(`POST /v1/chirindo/records HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`);
    for (const ch of body) {
      s.write(ch);
      await until(() => false, 100);
    }
    expect(await until(() => Buffer.concat(got).toString("latin1").startsWith("HTTP/1.1 200"), 3000)).toBe(true);
    expect(recs(r).length).toBe(1);
    s.destroy();
    await r.close();
    expect(gaps(r)).toEqual([]);
  });

  it("a body just begun is judged as at least 50 ms old: 3,000 bytes sent 10 ms ago are slower than 64 KiB/s and give up their slot", async () => {
    const { r, port } = await up({ maxConnections: 1 });
    const s = await open(port);
    s.write(hdr(port) + "x".repeat(3000));
    await new Promise((d) => setTimeout(d, 10));
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(r.stats().evictedConnections).toBe(1);
    s.destroy();
    await r.close();
  });

  it("a keep-alive connection idle after its answer gives up its slot to a new connection", async () => {
    const { r, port } = await up({ maxConnections: 1 });
    const { Agent } = await import("node:http");
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    const body = vec("t0-shape.pb");
    const first = await new Promise<number>((d, f) => {
      const q = request({ host: "127.0.0.1", port, path: "/v1/traces", method: "POST", agent, headers: { host: `127.0.0.1:${port}`, "content-type": PB, "content-length": String(body.length) } }, (res) => {
        res.resume();
        res.on("end", () => d(res.statusCode ?? 0));
      });
      q.on("error", f);
      q.end(body);
    });
    expect(first).toBe(200);
    await until(() => false, 100);
    expect((await post(port, "/v1/traces", body, { "content-type": PB })).status).toBe(200);
    expect(r.stats().evictedConnections).toBe(1);
    expect(r.stats().refusedConnections).toBe(0);
    agent.destroy();
    expect(recs(r).length).toBe(14);
    await r.close();
  });

  it("idle connections that never send a request give up their slots to an SDK's connection at once", async () => {
    const { r, port } = await up({ maxConnections: 4 });
    const idle = await Promise.all([0, 1, 2, 3, 4, 5, 6, 7].map(() => open(port)));
    await until(() => r.stats().connections >= 8, 2000);
    for (let i = 0; i < 3; i++) expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(r.stats().evictedConnections).toBeGreaterThanOrEqual(3);
    expect(recs(r).length).toBe(21);
    for (const s of idle) s.destroy();
    await r.close();
    expect(tally(r, "evicted")).toBe(r.stats().evictedConnections);
  });

  it("sockets dribbling header bytes and reconnecting when closed (the closure read's attack) never keep an SDK post from a 200", async () => {
    const { r, port } = await up({ maxConnections: 4, headersDeadlineMs: 400 });
    let stop = false;
    const dribbler = async () => {
      while (!stop) {
        const s = await open(port);
        await new Promise<void>((d) => {
          const t = setInterval(() => (s.writable ? s.write("P") : undefined), 50);
          s.on("close", () => (clearInterval(t), d()));
          const end = setInterval(() => stop && (s.destroy(), clearInterval(end)), 20);
        });
      }
    };
    const runs = [0, 1, 2, 3, 4, 5].map(() => dribbler());
    await until(() => false, 600);
    const ms: number[] = [];
    for (let i = 0; i < 5; i++) {
      const t = Date.now();
      expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
      ms.push(Date.now() - t);
      await until(() => false, 150);
    }
    stop = true;
    await Promise.all(runs);
    expect(Math.max(...ms)).toBeLessThan(1000);
    expect(recs(r).length).toBe(35);
    await r.close();
  });

  it("a body arriving slower than 64 KiB/s gives up its slot when all are taken; it leaves an aborted line with the cause", async () => {
    const { r, port } = await up({ maxConnections: 1 });
    const s = await open(port);
    s.write(hdr(port) + "x".repeat(10));
    await until(() => false, 200);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(await until(() => gaps(r).some((g) => g.reason === "aborted"))).toBe(true);
    expect(gaps(r).filter((g) => g.reason === "aborted").map((g) => g.cause)).toEqual(["evicted"]);
    expect(r.stats().evictedConnections).toBe(1);
    s.destroy();
    await r.close();
  });

  it("an SDK's keep-alive connection between batches is not closed with a refusal line, and its batches all land", async () => {
    const { r, port } = await up({ headersDeadlineMs: 700, idleDeadlineMs: 250 });
    const { Agent } = await import("node:http");
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    const send = () =>
      new Promise<number>((d, f) => {
        const body = vec("t0-shape.pb");
        const q = request({ host: "127.0.0.1", port, path: "/v1/traces", method: "POST", agent, headers: { host: `127.0.0.1:${port}`, "content-type": PB, "content-length": String(body.length) } }, (res) => {
          res.resume();
          res.on("end", () => d(res.statusCode ?? 0));
        });
        q.on("error", f);
        q.end(body);
      });
    for (let i = 0; i < 4; i++) {
      expect(await send()).toBe(200);
      await until(() => false, 450);
    }
    agent.destroy();
    expect(r.stats().connections).toBe(1);
    expect(recs(r).length).toBe(28);
    await r.close();
    expect(gaps(r)).toEqual([]);
  });
});

describe("otel-receiver: refusals are counted, record gaps stand alone (rev 3, N2)", { timeout: 120_000 }, () => {
  const ORIGIN = "https://evil.example";
  it("a page's flood of refused requests writes one line at once and then one line per interval, with the count and the first and last times", async () => {
    const { r, port } = await up({ gapIntervalMs: 400 });
    const t0 = Date.now();
    let n = 0;
    while (Date.now() - t0 < 1500) {
      await Promise.all([0, 1, 2, 3].map(() => post(port, "/v1/chirindo/records", "x", { "content-type": "text/plain", origin: ORIGIN })));
      n += 4;
    }
    const before = gaps(r);
    expect(before[0]).toMatchObject({ route: "/v1/chirindo/records", reason: "cross-origin", count: 1, header: "origin" });
    expect(before.length).toBeLessThanOrEqual(1 + Math.ceil((Date.now() - t0) / 400) + 1);
    const later = before.slice(1);
    expect(later.length).toBeGreaterThanOrEqual(2);
    for (const g of later) {
      expect(g.coalesced).toBe(true);
      expect(g.count).toBeGreaterThan(0);
      expect(Date.parse(g.first)).toBeLessThanOrEqual(Date.parse(g.last));
    }
    await r.close();
    expect(tally(r, "cross-origin")).toBe(n);
    expect(r.stats().refusals).toBe(n);
    expect(recs(r)).toEqual([]);
  });

  it("each reason and route has its own count", async () => {
    const { r, port } = await up({ gapIntervalMs: 60_000 });
    for (let i = 0; i < 3; i++) {
      await post(port, "/v1/traces", "x", { "content-type": PB, origin: ORIGIN });
      await post(port, "/v1/logs", "x", { "content-type": PB, origin: ORIGIN });
      await post(port, "/v1/traces", "x", { "content-type": PB, host: "evil.example" });
    }
    expect(gaps(r).map((g) => [g.route, g.reason, g.count])).toEqual([
      ["/v1/traces", "cross-origin", 1],
      ["/v1/logs", "cross-origin", 1],
      ["/v1/traces", "host-not-allowed", 1],
    ]);
    await r.close();
    expect(gaps(r).slice(3).map((g) => [g.route, g.reason, g.count])).toEqual([
      ["/v1/traces", "cross-origin", 2],
      ["/v1/logs", "cross-origin", 2],
      ["/v1/traces", "host-not-allowed", 2],
    ]);
  });

  it("after an interval with no refusal, the next refusal is written at once again", async () => {
    const { r, port } = await up({ gapIntervalMs: 200 });
    await post(port, "/v1/traces", "x", { "content-type": PB, origin: ORIGIN });
    await until(() => false, 700);
    expect(gaps(r).length).toBe(1);
    await post(port, "/v1/traces", "x", { "content-type": PB, origin: ORIGIN });
    expect(gaps(r).map((g) => g.count)).toEqual([1, 1]);
    await r.close();
    expect(gaps(r).length).toBe(2);
  });

  it("record gaps are never counted together: every refused batch, invalid body and cut-off body has its own line", async () => {
    const { r, port } = await up({ gapIntervalMs: 60_000 });
    for (let i = 0; i < 3; i++) expect((await post(port, "/v1/traces", Buffer.from([0xff, 0xff, 0xff]), { "content-type": PB })).status).toBe(400);
    for (let i = 0; i < 3; i++) expect((await post(port, "/v1/chirindo/records", "{not json", { "content-type": JSONT })).status).toBe(400);
    for (let i = 0; i < 3; i++) {
      const s = connect(port, "127.0.0.1");
      s.on("error", () => undefined);
      await new Promise((d) => s.on("connect", d));
      s.write(`POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/x-protobuf\r\nContent-Length: 1000\r\n\r\n0123`);
      await until(() => false, 50);
      s.destroy();
    }
    expect(await until(() => gaps(r).filter((g) => g.reason === "aborted").length === 3)).toBe(true);
    const rs = gaps(r).map((g) => g.reason);
    expect(rs.filter((x) => x === "invalid-json").length).toBe(3);
    expect(rs.length).toBe(9);
    for (const g of gaps(r)) expect(g.count).toBeUndefined();
    await r.close();
    expect(gaps(r).length).toBe(9);
  });
});

describe("otel-receiver: the sidecar line is written before its record (M3)", { timeout: 120_000 }, () => {
  it("a record never exists without its sidecar line; a sidecar line left without a record is found at the next start, once", async () => {
    const dir = join(tmp(), "gate");
    const a = await up({ dir });
    expect((await post(a.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    await a.r.close();
    const b = await up({ dir });
    // The chain file's name now names a folder: the sidecar line is written, the record is not.
    mkdirSync(b.r.chainPath);
    expect((await post(b.port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(503);
    expect(lines(b.r.retainedPath).map((l) => JSON.parse(l).seq)).toEqual([0]);
    expect(gaps(b.r).filter((g) => g.session_id === b.r.sessionId).map((g) => [g.reason, g.failed])).toEqual([["append-failed", "chain line"]]);
    await b.r.close();
    const c = await up({ dir });
    const found = gaps(c.r).filter((g) => g.reason === "retained-without-record");
    expect(found.map((g) => [g.route, g.old_session, g.seq_from, g.seq_to])).toEqual([["start", b.r.sessionId, 0, 0]]);
    expect(c.log.some((l) => l.includes(`session ${b.r.sessionId} has sidecar lines for seq 0 to 0 with no record`))).toBe(true);
    await c.r.close();
    const d = await up({ dir });
    expect(gaps(d.r).filter((g) => g.reason === "retained-without-record").length).toBe(1);
    expect(d.log.some((l) => l.includes("no record"))).toBe(false);
    expect(verify(a.r).kind).toBe("valid");
    await d.r.close();
  });

  it("when the sidecar line cannot be written, no record is written either (503, chain-broken)", async () => {
    const { r, port } = await up();
    mkdirSync(r.retainedPath);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(503);
    expect(existsSync(r.chainPath)).toBe(false);
    expect(gaps(r).map((g) => [g.reason, g.failed])).toEqual([["append-failed", "retained line"]]);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(503);
    await r.close();
  });

  it("every record of a batch has its sidecar line, seq for seq", async () => {
    const { r, port } = await up();
    for (let i = 0; i < 3; i++) await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB });
    expect(lines(r.retainedPath).map((l) => JSON.parse(l).seq)).toEqual(recs(r).map((x) => x.seq));
    await r.close();
  });
});

describe("otel-receiver: 127.0.0.1 always, ::1 when the machine has it (ruling L2 b)", { timeout: 120_000 }, () => {
  it("only a missing address family or address counts as no ::1", () => {
    expect(["EAFNOSUPPORT", "EADDRNOTAVAIL"].map(ipv6Unavailable)).toEqual([true, true]);
    expect(["EADDRINUSE", "EACCES", "EINVAL", undefined].map(ipv6Unavailable)).toEqual([false, false, false, false]);
  });

  it("no ::1: carries on with 127.0.0.1 alone and prints one line", async () => {
    for (const code of ["EAFNOSUPPORT", "EADDRNOTAVAIL"]) {
      const { r, port, log, listening } = await up({ listen6: async () => { throw Object.assign(new Error("x"), { code }); } });
      expect(listening.addresses).toEqual([`127.0.0.1:${port}`]);
      expect(listening.ipv6).toBe(`unavailable (${code})`);
      expect(log.filter((l) => l.includes(`::1 is not available on this machine (${code}); listening on 127.0.0.1 only`)).length).toBe(1);
      expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
      await r.close();
    }
  });

  it("any other ::1 failure (the port taken) stops the start and leaves nothing bound", async () => {
    for (const code of ["EADDRINUSE", "EACCES"]) {
      let seen = 0;
      const r = createOtelReceiver({ dir: join(tmp(), "gate"), port: 0, retain: true, log: () => undefined, listen6: async (_s, p) => { seen = p; throw Object.assign(new Error("x"), { code }); } });
      const err = await r.listen().then(() => undefined, (e: NodeJS.ErrnoException & { address?: string }) => e);
      expect(err?.code).toBe(code);
      expect(err?.address).toBe(`[::1]:${seen}`);
      const refused = await new Promise<string>((d) => {
        const s = connect(seen, "127.0.0.1");
        s.on("connect", () => (s.destroy(), d("connected")));
        s.on("error", (e: NodeJS.ErrnoException) => d(e.code ?? "error"));
      });
      expect(refused, code).toBe("ECONNREFUSED");
    }
  });

  it("with ::1 bound, both addresses write to the one chain (a stand-in server on 127.0.0.1 plays ::1)", async () => {
    let v6port = 0;
    const { r, port, listening } = await up({
      listen6: (s, _p) =>
        new Promise<void>((d) => s.listen(0, "127.0.0.1", () => ((v6port = (s.address() as AddressInfo).port), d()))),
    });
    expect(listening.ipv6).toBe("bound");
    expect(listening.addresses).toEqual([`127.0.0.1:${port}`, `[::1]:${port}`]);
    expect((await post(v6port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, host: `[::1]:${port}` })).status).toBe(200);
    expect((await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB })).status).toBe(200);
    expect(recs(r).length).toBe(14);
    expect(verify(r).kind).toBe("valid");
    await r.close();
    const closed = await new Promise<string>((d) => {
      const s = connect(v6port, "127.0.0.1");
      s.on("connect", () => (s.destroy(), d("connected")));
      s.on("error", (e: NodeJS.ErrnoException) => d(e.code ?? "error"));
    });
    expect(closed).toBe("ECONNREFUSED");
  });

  it("the real ::1 bind: bound and recording, or reported unavailable", async () => {
    const dir = join(tmp(), "gate");
    const log: string[] = [];
    const r = createOtelReceiver({ dir, port: 0, retain: true, log: (l) => log.push(l) });
    const l = await r.listen();
    if (l.ipv6 === "bound") {
      const res = await new Promise<number>((done, fail) => {
        const q = request({ host: "::1", port: l.port, path: "/v1/traces", method: "POST", agent: false, headers: { host: `[::1]:${l.port}`, "content-type": PB } }, (x) => {
          x.resume();
          x.on("end", () => done(x.statusCode ?? 0));
        });
        q.on("error", fail);
        q.end(vec("t0-shape.pb"));
      });
      expect(res).toBe(200);
      expect(recs(r).length).toBe(7);
    } else {
      expect(l.ipv6).toMatch(/^unavailable \((EAFNOSUPPORT|EADDRNOTAVAIL)\)$/);
      expect(l.addresses).toEqual([`127.0.0.1:${l.port}`]);
    }
    await r.close();
  });
});

describe("otel-receiver: forwarding details and the token file (T2 read L1, L3, L4)", { timeout: 120_000 }, () => {
  it("headers named in Connection are not forwarded; a 307 is a forward failure and is not followed", async () => {
    const s = await stub(307);
    const { r, port } = await up({ forward: `http://127.0.0.1:${s.port}` });
    await post(port, "/v1/traces", vec("t0-shape.pb"), { "content-type": PB, connection: "keep-alive, x-secret-hop", "x-secret-hop": "hop", "x-kept": "1" });
    await r.settled();
    expect(s.got.length).toBe(1);
    expect(s.got[0]!.headers["x-secret-hop"]).toBeUndefined();
    expect(s.got[0]!.headers["x-kept"]).toBe("1");
    expect(gaps(r).map((g) => [g.reason, g.status])).toEqual([["forward-failed", 307]]);
    expect(recs(r).length).toBe(7);
    await r.close();
    await s.close();
  });

  it("warns when the token file can be read by other users (POSIX modes)", async () => {
    const dir = tmp();
    writeFileSync(join(dir, "open-token"), "tok-b481\n");
    writeFileSync(join(dir, "closed-token"), "tok-b481\n");
    chmodSync(join(dir, "open-token"), 0o644);
    chmodSync(join(dir, "closed-token"), 0o600);
    for (const [f, warn] of [["open-token", true], ["closed-token", false]] as const) {
      const err: string[] = [];
      const st = await startOtelReceiverCommand({ flags: new Map<string, string | true>([["dir", "g-" + f], ["port", "0"], ["token-file", f]]), positional: [], passthrough: [] }, { stdout: () => undefined, stderr: (l) => err.push(l), cwd: dir });
      expect(st.code).toBe(0);
      const warned = err.some((l) => l.includes("can be read by other users"));
      expect(warned, f).toBe(process.platform === "win32" ? false : warn);
      expect(err.join("\n").includes("tok-b481")).toBe(false);
      await st.stop!();
    }
  });
});
