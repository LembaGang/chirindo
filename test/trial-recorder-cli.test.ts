// D3(h) the loopback endpoint (`chirindo trial-recorder`) and D3(i) erasure
// (`chirindo trial-erase`), each run as the CLI in a child process.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createTrialRecorder } from "../src/trial/index.js";
import { cleanupTmpDir, runCli } from "./helpers.js";
import { startStubWitness, STUB_WITNESS_NAME, type StubWitness } from "./witness-stub.js";
import {
  closedPortUrl,
  httpCall,
  listeningUrl,
  newDataDir,
  sampleInput,
  sampleOrder,
  startCli,
  walkFiles,
  type CliChild,
  type HttpReply,
} from "./trial-helpers.js";

const children: CliChild[] = [];
const stubs: StubWitness[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const c of children.splice(0)) {
    c.child.kill();
    await c.exited;
  }
  for (const s of stubs.splice(0)) await s.close();
  for (const d of dirs.splice(0)) cleanupTmpDir(d);
});
function cli(args: string[]): CliChild {
  const c = startCli(args);
  children.push(c);
  return c;
}
function data() {
  const d = newDataDir();
  dirs.push(d.dir);
  return d;
}
function noCors(r: HttpReply): void {
  expect(Object.keys(r.headers).filter((h) => h.toLowerCase().startsWith("access-control-"))).toEqual([]);
}

describe("chirindo trial-recorder (loopback endpoint)", () => {
  it("(h) round-trips record, await and gap on 127.0.0.1, and refuses what R10 refuses", async () => {
    const stub = await startStubWitness();
    stubs.push(stub);
    const { dir } = data();
    const c = cli([
      "trial-recorder", "--dir", dir, "--server-label", "shop", "--port", "0",
      "--witness", stub.url, "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ]);
    const url = await listeningUrl(c);
    expect(url, c.stderr()).not.toBeNull();
    if (url === null) return;
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    const host = new URL(url).host;
    const json = { "content-type": "application/json", host };
    const replies: HttpReply[] = [];
    const call = async (o: Parameters<typeof httpCall>[1]) => {
      const r = await httpCall(url, o);
      replies.push(r);
      return r;
    };

    const rec = await call({ path: "/record", headers: json, body: JSON.stringify(sampleInput("H-1", 1)) });
    expect(rec.status).toBe(200);
    const recBody = JSON.parse(rec.body) as { ok: boolean; entry_hash: string; count: number };
    expect(recBody).toMatchObject({ ok: true, count: 1 });
    const aw = await call({ path: "/await", headers: json, body: JSON.stringify({ entry_hash: recBody.entry_hash, max_ms: 3_000 }) });
    expect(aw.status).toBe(200);
    expect(JSON.parse(aw.body)).toMatchObject({ ok: true, covering_count: 1 });
    const gap = await call({ path: "/gap", headers: json, body: JSON.stringify({ order_ref: "H-2", call_seq: 2, reason: "caller-timeout" }) });
    expect(gap.status).toBe(200);
    expect(JSON.parse(gap.body)).toEqual({ ok: true });
    const health = await call({ method: "GET", path: "/health", headers: { host } });
    expect(health.status).toBe(200);

    // A refused record is a 4xx with the result, never a 200.
    const refused = await call({ path: "/record", headers: json, body: JSON.stringify({ ...sampleInput("H-3"), email: "x" }) });
    expect(refused.status).toBe(422);
    expect(JSON.parse(refused.body)).toMatchObject({ ok: false, reason: "refused-field", paths: ["/email"] });

    const wrongHost = await call({ path: "/record", headers: { ...json, host: `localhost:${new URL(url).port}` }, body: JSON.stringify(sampleInput("H-4")) });
    expect(wrongHost.status).toBe(403);
    const textPlain = await call({ path: "/record", headers: { "content-type": "text/plain", host }, body: JSON.stringify(sampleInput("H-5")) });
    expect(textPlain.status).toBe(415);
    const dup = await call({ path: "/record", headers: json, body: '{"order_ref":"ZZ-ECHO-1","order_ref":"ZZ-ECHO-2","order":{}}' });
    expect(dup.status).toBe(400);
    expect(dup.body).not.toContain("ZZ-ECHO");
    const big = await call({ path: "/record", headers: json, body: JSON.stringify({ ...sampleInput("H-6"), pad: "p".repeat(270_000) }) });
    expect(big.status).toBe(413);
    const unknown = await call({ path: "/nope", headers: json, body: "{}" });
    expect(unknown.status).toBe(404);
    for (const r of replies) noCors(r);

    // Only the first record and the gap reached the data directory.
    const chains = walkFiles(join(dir, "chains")).filter((f) => f.endsWith(".jsonl"));
    expect(chains).toHaveLength(1);
    expect(readFileSync(chains[0]!, "utf8").trim().split("\n")).toHaveLength(1);
  }, 60_000);

  it("(h) --host accepts only 127.0.0.1 and ::1: 0.0.0.0 exits non-zero before listening", async () => {
    const { dir } = data();
    for (const h of ["0.0.0.0", "localhost"]) {
      const c = cli(["trial-recorder", "--dir", dir, "--server-label", "shop", "--port", "0", "--host", h]);
      const code = await c.exited;
      expect(code, h).not.toBe(0);
      expect(code, h).not.toBeNull();
      expect(c.stdout(), h).not.toContain("listening");
      expect(c.stderr(), h).toContain("--host must be 127.0.0.1 or ::1");
    }
  }, 60_000);

  it("(h) with --token-file a missing or wrong bearer token is refused, the right one accepted", async () => {
    const { dir } = data();
    const tokenFile = join(dir, "token");
    writeFileSync(tokenFile, "ZZ-token-" + createHash("sha256").update(dir).digest("hex") + "\n");
    const token = readFileSync(tokenFile, "utf8").trim();
    const c = cli(["trial-recorder", "--dir", dir, "--server-label", "shop", "--port", "0", "--token-file", tokenFile]);
    const url = await listeningUrl(c);
    expect(url, c.stderr()).not.toBeNull();
    if (url === null) return;
    const host = new URL(url).host;
    const body = JSON.stringify(sampleInput("T-1"));
    const missing = await httpCall(url, { path: "/record", headers: { "content-type": "application/json", host }, body });
    expect(missing.status).toBe(401);
    const wrong = await httpCall(url, { path: "/record", headers: { "content-type": "application/json", host, authorization: "Bearer nope" }, body });
    expect(wrong.status).toBe(401);
    expect(wrong.body).not.toContain(token);
    const right = await httpCall(url, { path: "/record", headers: { "content-type": "application/json", host, authorization: `Bearer ${token}` }, body });
    expect(right.status).toBe(200);
    noCors(missing);
    noCors(right);
  }, 60_000);
});

describe("chirindo trial-erase", () => {
  it("(i) by --args-hash and by --order-ref removes every matching retained file and leaves chains and sidecars byte-identical", async () => {
    const { dir } = data();
    const rec = createTrialRecorder({ dir, serverLabel: "shop", witness: { baseUrl: await closedPortUrl(), name: STUB_WITNESS_NAME }, logger: () => {} });
    const same = rec.record(sampleInput("I-A", 1));
    const again = rec.record(sampleInput("I-A", 2));
    const other = rec.record({ order_ref: "I-A", order: { ...sampleOrder("I-A"), total_minor: "4900", items: [{ sku: "X", quantity: 1, unit_price_minor: "4900" }] } });
    const b = rec.record(sampleInput("I-B", 3));
    await new Promise((r) => setTimeout(r, 300));
    await rec.close(1_000);
    expect([same, again, other, b].every((r) => r.ok)).toBe(true);
    if (!same.ok || !again.ok || !other.ok || !b.ok) return;
    expect(again.args_hash).toBe(same.args_hash);

    const kept = walkFiles(join(dir, "chains")).filter((f) => !f.endsWith(".lock"));
    expect(kept.some((f) => f.endsWith(".witness.ndjson"))).toBe(true);
    const snapshot = () => kept.map((f) => createHash("sha256").update(readFileSync(f)).digest("hex"));
    const before = snapshot();
    const retained = () => walkFiles(join(dir, "args")).map((f) => JSON.parse(readFileSync(f, "utf8")) as { args_hash: string });
    expect(retained()).toHaveLength(4);

    const byHash = runCli(["trial-erase", "--dir", dir, "--args-hash", same.args_hash]);
    expect(byHash.status, byHash.stderr).toBe(0);
    const out1 = byHash.stdout.trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(out1.filter((l) => "removed" in l)).toHaveLength(2);
    expect(out1.at(-1)).toEqual({ removed_count: 2 });
    expect(retained().map((r) => r.args_hash).sort()).toEqual([other.args_hash, b.args_hash].sort());

    const byRef = runCli(["trial-erase", "--dir", dir, "--order-ref", "I-A"]);
    expect(byRef.status, byRef.stderr).toBe(0);
    expect(byRef.stdout.trim().split("\n").at(-1)).toBe('{"removed_count":1}');
    expect(retained().map((r) => r.args_hash)).toEqual([b.args_hash]);
    expect(byRef.stdout).not.toContain("I-A");

    expect(snapshot()).toEqual(before);
    for (const f of walkFiles(join(dir, "args"))) expect(basename(f)).not.toContain(":");

    expect(runCli(["trial-erase", "--dir", dir]).status).toBe(2);
    expect(runCli(["trial-erase", "--dir", dir, "--args-hash", b.args_hash, "--order-ref", "I-B"]).status).toBe(2);
    expect(runCli(["trial-erase", "--dir", dir, "--args-hash", "sha256:nothex"]).status).toBe(2);
  }, 60_000);
});
