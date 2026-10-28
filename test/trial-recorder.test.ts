// The trial recorder (src/trial/): records, refusals, retained arguments, gap
// lines, the witness driver, awaitWitness, close and the restart catch-up.
// The endpoint and erasure are in trial-recorder-cli.test.ts, the order-rule
// parity in trial-order-parity.test.ts, the cost at length in
// trial-recorder-perf.test.ts.

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { basename, join } from "node:path";
import { performance } from "node:perf_hooks";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createTrialRecorder, type RecordInput, type TrialRecorder } from "../src/trial/index.js";
import { appendReceipt } from "../src/receipt.js";
import { buildCheckpoint } from "../src/checkpoint.js";
import { readSidecar } from "../src/witness.js";
import { argsHash, contentOf, entryHashOfCanonical, jcsBytes, readChainFile } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir, runCli } from "./helpers.js";
import { startStubWitness, STUB_WITNESS_NAME, type StubWitness } from "./witness-stub.js";
import {
  closedPortUrl,
  newDataDir,
  readNdjson,
  ROOT,
  sampleInput,
  sampleOrder,
  sha256Tagged,
  waitFor,
  walkFiles,
} from "./trial-helpers.js";
// @ts-expect-error -- plain .mjs without declarations; the texts are compared verbatim
import { LIMIT_TEXTS } from "../examples/evidence-bundle/lib/limits.mjs";

const quiet = () => {};
const chainOf = (dir: string, sid: string) => join(dir, "chains", `${sid}.jsonl`);
const gapsOf = (dir: string) => join(dir, "gaps.ndjson");
const timingOf = (dir: string) => join(dir, "witness-timing.ndjson");

const open: TrialRecorder[] = [];
const stubs: StubWitness[] = [];
const dirs: string[] = [];
function track<T extends TrialRecorder>(r: T): T {
  open.push(r);
  return r;
}
function data(): ReturnType<typeof newDataDir> {
  const d = newDataDir();
  dirs.push(d.dir);
  return d;
}
async function stubOf(o: Parameters<typeof startStubWitness>[0] = {}): Promise<StubWitness> {
  const s = await startStubWitness(o);
  stubs.push(s);
  return s;
}

afterEach(async () => {
  for (const r of open.splice(0)) await r.close(500);
  for (const s of stubs.splice(0)) await s.close();
  for (const d of dirs.splice(0)) cleanupTmpDir(d);
});

function witnessOf(stub: StubWitness) {
  return { baseUrl: stub.url, name: STUB_WITNESS_NAME, pinnedKey: stub.publicKeyHex };
}

function resourceCounts(): Record<string, number> {
  const out: Record<string, number> = {};
  for (const n of process.getActiveResourcesInfo()) out[n] = (out[n] ?? 0) + 1;
  return out;
}

describe("trial recorder: witnessing", () => {
  it("(b) after 20 records every entry is covered by a sidecar receipt, and awaitWitness(last) is ok", async () => {
    const stub = await stubOf({ delayMs: 20 });
    const { dir, identity } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    const hashes: string[] = [];
    for (let burst = 0; burst < 4; burst++) {
      for (let i = 0; i < 5; i++) {
        const r = rec.record(sampleInput(`B-${burst * 5 + i}`, burst * 5 + i));
        expect(r.ok).toBe(true);
        if (r.ok) hashes.push(r.entry_hash);
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(hashes).toHaveLength(20);
    const w = await rec.awaitWitness(hashes[19]!, 3_500);
    expect(w.ok).toBe(true);
    if (w.ok) expect(w.covering_count).toBeGreaterThanOrEqual(20);
    await rec.close(2_000);

    // Coalesced: never one POST per record.
    expect(stub.posts).toBeGreaterThanOrEqual(1);
    expect(stub.posts).toBeLessThan(20);

    const chainPath = chainOf(dir, rec.session_id);
    const lines = readSidecar(chainPath + ".witness.ndjson");
    const covered = lines.filter((l) => l.witness_receipt !== null).map((l) => l.checkpoint.count);
    for (let count = 1; count <= 20; count++) {
      expect(covered.some((c) => c >= count), `entry ${count} covered`).toBe(true);
    }
    // Each checkpoint is byte-equal to buildCheckpoint over the same head and ts.
    const { records } = readChainFile(chainPath);
    expect(records).toHaveLength(20);
    for (const l of lines) {
      expect(JSON.stringify(l.checkpoint)).toBe(
        JSON.stringify(buildCheckpoint(records.slice(0, l.checkpoint.count), identity, l.checkpoint.ts)),
      );
    }
    // The timing file: one line per POST, plus the await line; no key or signature.
    const timing = readNdjson(timingOf(dir));
    const posts = timing.filter((t) => t["await"] !== true);
    expect(posts).toHaveLength(stub.posts);
    for (const t of posts) {
      expect(Object.keys(t).sort()).toEqual(["count", "last_entry_hash", "outcome", "replied_at", "sent_at", "session_id"]);
      expect(t["outcome"]).toBe("ok");
    }
    const awaits = timing.filter((t) => t["await"] === true);
    expect(awaits).toHaveLength(1);
    expect(awaits[0]).toMatchObject({ session_id: rec.session_id, outcome: "ok", await: true });
    expect(readFileSync(timingOf(dir), "utf8")).not.toMatch(/"sig"|signature|ho_live_/);

    const v = runCli([
      "verify", chainPath, "--key", join(dir, "identity.json"),
      "--witness-file", chainPath + ".witness.ndjson", "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ]);
    expect(v.stdout + v.stderr).toContain("WITNESSED through count 20");
    expect(v.status).toBe(0);
  }, 60_000);

  it("(c) with the witness hanging, awaitWitness(entry, 500) times out; close(1000) resolves and leaves no open handle", async () => {
    const before = resourceCounts();
    const stub = await stubOf({ hangPosts: true });
    const { dir } = data();
    const rec = createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet });
    const r = rec.record(sampleInput("C-1", 1));
    expect(r.ok).toBe(true);
    const t0 = performance.now();
    const w = await rec.awaitWitness(r.ok ? r.entry_hash : "", 500);
    const waited = performance.now() - t0;
    expect(w).toEqual({ ok: false, reason: "timeout" });
    expect(waited).toBeGreaterThanOrEqual(450);
    expect(waited).toBeLessThan(2_000);

    const c0 = performance.now();
    await rec.close(1_000);
    expect(performance.now() - c0).toBeLessThan(3_000);
    const side = readSidecar(chainOf(dir, rec.session_id) + ".witness.ndjson");
    expect(side.at(-1)?.witness_error).toBe("witness_timeout");
    expect(await rec.awaitWitness(r.ok ? r.entry_hash : "", 100)).toEqual({ ok: false, reason: "closed" });

    await stub.close();
    stubs.splice(stubs.indexOf(stub), 1);
    const settled = await waitFor(() => {
      const a = resourceCounts();
      return (a["Timeout"] ?? 0) <= (before["Timeout"] ?? 0) && (a["TCPSocketWrap"] ?? 0) <= (before["TCPSocketWrap"] ?? 0);
    }, 3_000);
    expect(settled, JSON.stringify({ before, after: resourceCounts() })).toBe(true);
  }, 30_000);

  it("awaitWitness: no-witness without a target, unknown-entry for a hash this process did not write", async () => {
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
    const r = rec.record(sampleInput("A-1"));
    expect(r.ok).toBe(true);
    expect(await rec.awaitWitness(r.ok ? r.entry_hash : "", 100)).toEqual({ ok: false, reason: "no-witness" });

    const stub = await stubOf();
    const { dir: dir2 } = data();
    const rec2 = track(createTrialRecorder({ dir: dir2, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    expect(await rec2.awaitWitness("sha256:" + "0".repeat(64), 100)).toEqual({ ok: false, reason: "unknown-entry" });
  }, 30_000);

  it("R7: invalid_key stops sending until the next UTC day; awaitWitness reads stopped; one log line", async () => {
    const stub = await stubOf();
    const { dir } = data();
    const keyFile = join(dir, "witness.key");
    writeFileSync(keyFile, "ho_live_" + randomBytes(32).toString("hex") + "\n");
    const log: string[] = [];
    const rec = track(
      createTrialRecorder({ dir, serverLabel: "shop", witness: { ...witnessOf(stub), accountKeyFile: keyFile }, logger: (l) => log.push(l) }),
    );
    const r1 = rec.record(sampleInput("S-1"));
    expect(r1.ok).toBe(true);
    expect(await rec.awaitWitness(r1.ok ? r1.entry_hash : "", 3_000)).toEqual({ ok: false, reason: "stopped" });
    expect(stub.posts).toBe(1);
    const r2 = rec.record(sampleInput("S-2"));
    expect(r2.ok).toBe(true);
    await new Promise((r) => setTimeout(r, 200));
    expect(stub.posts).toBe(1);
    expect(log.filter((l) => l.includes("invalid_key"))).toHaveLength(1);
    expect(log.join("\n")).not.toContain("ho_live_");
  }, 30_000);
});

describe("trial recorder: refusals and gap lines", () => {
  it("(d) each refusal reason returns its result and writes one gap line; no refused value reaches any file", async () => {
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
    const order = sampleOrder("D-1");
    const item = order.items[0]!;
    const cases: { name: string; input: unknown; reason: string; paths: string[] }[] = [
      { name: "not an object", input: "ZZ-NOT-AN-OBJECT", reason: "invalid-input", paths: [] },
      { name: "over 256 KB", input: { order_ref: "D-big", order, call_seq: 1, junk: "x".repeat(270_000) }, reason: "invalid-input", paths: [] },
      { name: "order_ref empty", input: { order_ref: "", order, call_seq: 2 }, reason: "invalid-input", paths: ["/order_ref"] },
      { name: "call_seq negative", input: { order_ref: "D-3", order, call_seq: -1 }, reason: "invalid-input", paths: ["/call_seq"] },
      { name: "channel unknown", input: { order_ref: "D-4", order, call_seq: 4, agent_context: { channel: "ZZ-CHANNEL-SECRET" } }, reason: "invalid-input", paths: ["/agent_context/channel"] },
      { name: "currency bad", input: { order_ref: "D-5", order, call_seq: 5, agent_context: { payment_token_limits: { currency: "usd", max_amount_minor: "100" } } }, reason: "invalid-input", paths: ["/agent_context/payment_token_limits/currency"] },
      // Format failures are decided after the allow-list and the screening.
      { name: "bad channel + unknown field", input: { order_ref: "D-6", order, call_seq: 6, agent_context: { channel: "nope" }, ZZTOPFIELD: "ZZ-TOP-SECRET-0" }, reason: "refused-field", paths: ["/ZZTOPFIELD"] },
      { name: "bad channel + card in name", input: { order_ref: "D-7", call_seq: 7, agent_context: { channel: "nope" }, order: { ...order, items: [{ ...item, name: "card 5555555555554444" }] } }, reason: "refused-value", paths: ["/order/items/0/name"] },
      { name: "field: top level", input: { order_ref: "D-10", order, call_seq: 10, email: "ZZ-TOP-SECRET-1" }, reason: "refused-field", paths: ["/email"] },
      { name: "field: agent_context", input: { order_ref: "D-11", order, call_seq: 11, agent_context: { ip: "ZZ-AC-SECRET-2" } }, reason: "refused-field", paths: ["/agent_context/ip"] },
      { name: "field: order", input: { order_ref: "D-12", call_seq: 12, order: { ...order, customer_email: "ZZ-ORDER-SECRET-3" } }, reason: "refused-field", paths: ["/order/customer_email"] },
      { name: "field: item", input: { order_ref: "D-13", call_seq: 13, order: { ...order, items: [{ ...item, buyer: "ZZ-ITEM-SECRET-4" }] } }, reason: "refused-field", paths: ["/order/items/0/buyer"] },
      { name: "field: platform_signature", input: { order_ref: "D-14", order, call_seq: 14, agent_context: { platform_signature: { header_name: "Sig", value: "v", raw_body: "ZZ-PS-SECRET-5" } } }, reason: "refused-field", paths: ["/agent_context/platform_signature/raw_body"] },
      { name: "field: payment_token_limits", input: { order_ref: "D-15", order, call_seq: 15, agent_context: { payment_token_limits: { currency: "USD", max_amount_minor: "100", pan: "ZZ-PTL-SECRET-6" } } }, reason: "refused-field", paths: ["/agent_context/payment_token_limits/pan"] },
      { name: "field: mandate", input: { order_ref: "D-16", order, call_seq: 16, agent_context: { mandate: { format: "ap2", value: "m", holder: "ZZ-MANDATE-SECRET-7" } } }, reason: "refused-field", paths: ["/agent_context/mandate/holder"] },
      { name: "field: key outside the pointer alphabet", input: { order_ref: "D-17", order, call_seq: 17, "ZZKEYNAMESECRET9 x": "ZZ-KEY-SECRET-8" }, reason: "refused-field", paths: ["/~invalid-key"] },
      { name: "value: 16-digit card in item name", input: { order_ref: "D-20", call_seq: 20, order: { ...order, items: [{ ...item, name: "Gift 4111111111111111 for Ann" }] } }, reason: "refused-value", paths: ["/order/items/0/name"] },
      { name: "value: spaced card in item name", input: { order_ref: "D-21", call_seq: 21, order: { ...order, items: [{ ...item, name: "4111 1111 1111 1111" }] } }, reason: "refused-value", paths: ["/order/items/0/name"] },
      { name: "value: 4-6-5 card in item location", input: { order_ref: "D-22", call_seq: 22, order: { ...order, items: [{ ...item, location: "3782-822463-10005" }] } }, reason: "refused-value", paths: ["/order/items/0/location"] },
      { name: "value: e-mail in item name", input: { order_ref: "D-23", call_seq: 23, order: { ...order, items: [{ ...item, name: "for ZZbuyer.secret@example.com" }] } }, reason: "refused-value", paths: ["/order/items/0/name"] },
      { name: "value: e-mail in item category", input: { order_ref: "D-24", call_seq: 24, order: { ...order, items: [{ ...item, category: "ZZcat.secret@example.org" }] } }, reason: "refused-value", paths: ["/order/items/0/category"] },
      { name: "value: card in agent_name", input: { order_ref: "D-25", order, call_seq: 25, agent_context: { agent_name: "agent 6011111111111117" } }, reason: "refused-value", paths: ["/agent_context/agent_name"] },
      { name: "order: total_minor", input: { order_ref: "D-30", call_seq: 30, order: { ...order, total_minor: "04800" } }, reason: "invalid-order", paths: ["/order/total_minor"] },
      {
        name: "internal: a getter that throws",
        input: Object.defineProperty({ order_ref: "D-31", call_seq: 31 }, "order", { enumerable: true, get: () => { throw new Error("ZZ-GETTER-SECRET"); } }),
        reason: "internal",
        paths: [],
      },
    ];
    for (const c of cases) {
      const before = readNdjson(gapsOf(dir)).length;
      let r: ReturnType<TrialRecorder["record"]> | undefined;
      expect(() => (r = rec.record(c.input as RecordInput)), c.name).not.toThrow();
      expect(r, c.name).toEqual({ ok: false, reason: c.reason, paths: c.paths, session_id: rec.session_id });
      const gaps = readNdjson(gapsOf(dir));
      expect(gaps.length, c.name).toBe(before + 1);
      const g = gaps.at(-1)!;
      expect(Object.keys(g).sort(), c.name).toEqual(["call_seq", "order_ref_sha256", "paths", "reason", "session_id", "ts"]);
      expect(g, c.name).toMatchObject({ session_id: rec.session_id, reason: c.reason, paths: c.paths });
      const inp = c.input as Record<string, unknown>;
      const ref = typeof c.input === "object" ? inp["order_ref"] : undefined;
      expect(g["order_ref_sha256"], c.name).toBe(typeof ref === "string" ? sha256Tagged(ref) : null);
      const seq = typeof c.input === "object" ? inp["call_seq"] : undefined;
      expect(g["call_seq"], c.name).toBe(typeof seq === "number" && seq >= 0 ? seq : null);
    }

    // The screening accepts the merchant's own reference formats (D3(d)).
    const ok = rec.record({
      order_ref: "1730112345005",
      call_seq: 40,
      order: {
        merchant_id: "hotel.example",
        merchant_order_id: "1730112345005",
        checkout_ref: "20261028120008",
        currency: "EUR",
        total_minor: "28000",
        items: [{ sku: "4006381330060", quantity: 2, unit_price_minor: "14000", name: "Room 2026-11-10 2026-11-12", service_from: "2026-11-10", service_until: "2026-11-12" }],
      },
      agent_context: { channel: "acp", agent_name: "shopper-agent@openai.example" },
    });
    expect(ok.ok).toBe(true);
    expect(readNdjson(gapsOf(dir))).toHaveLength(cases.length);

    const secrets = [
      "ZZ-NOT-AN-OBJECT", "ZZ-CHANNEL-SECRET", "ZZ-TOP-SECRET-0", "ZZ-TOP-SECRET-1", "ZZ-AC-SECRET-2", "ZZ-ORDER-SECRET-3",
      "ZZ-ITEM-SECRET-4", "ZZ-PS-SECRET-5", "ZZ-PTL-SECRET-6", "ZZ-MANDATE-SECRET-7", "ZZ-KEY-SECRET-8", "ZZKEYNAMESECRET9",
      "4111111111111111", "4111 1111 1111 1111", "3782-822463-10005", "5555555555554444", "6011111111111117",
      "ZZbuyer.secret@example.com", "ZZcat.secret@example.org", "ZZ-GETTER-SECRET",
    ];
    const files = walkFiles(dir);
    expect(files.length).toBeGreaterThan(3);
    for (const f of files) {
      const bytes = readFileSync(f);
      for (const s of secrets) expect(bytes.includes(Buffer.from(s, "utf8")), `${s} in ${f}`).toBe(false);
    }
  }, 60_000);

  it("(e) with <dir>/chains or <dir>/args replaced by a file, record() returns write-failed with a gap line, leaves no retained file and throws nothing", async () => {
    for (const which of ["chains", "args"]) {
      const { dir } = data();
      const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
      expect(rec.record(sampleInput("E-1", 1)).ok, which).toBe(true);
      rmSync(join(dir, which), { recursive: true, force: true });
      writeFileSync(join(dir, which), "not a directory");
      let r: ReturnType<TrialRecorder["record"]> | undefined;
      expect(() => (r = rec.record(sampleInput("E-2", 2))), which).not.toThrow();
      expect(r, which).toMatchObject({ ok: false, reason: "write-failed" });
      expect(readNdjson(gapsOf(dir)).at(-1), which).toMatchObject({ reason: "write-failed", call_seq: 2, order_ref_sha256: sha256Tagged("E-2") });
      expect(walkFiles(join(dir, "args")).filter((f) => basename(f).startsWith("2-")), which).toEqual([]);
      await expect(rec.close(500)).resolves.toBeUndefined();
    }
  }, 30_000);

  it("(j) reportGap writes its line; a bad reason or reference writes nothing; an unwritable gap file still returns, with one stderr line", async () => {
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
    expect(rec.reportGap({ order_ref: "J-1", call_seq: 7, reason: "caller-timeout" })).toEqual({ ok: true });
    expect(rec.reportGap({ order_ref: "J-2", reason: "unreachable" })).toEqual({ ok: true });
    const gaps = readNdjson(gapsOf(dir));
    expect(gaps).toHaveLength(2);
    expect(gaps[0]).toMatchObject({ session_id: rec.session_id, order_ref_sha256: sha256Tagged("J-1"), call_seq: 7, reason: "caller-timeout", paths: [] });
    expect(gaps[1]).toMatchObject({ order_ref_sha256: sha256Tagged("J-2"), call_seq: null, reason: "unreachable" });
    expect(rec.reportGap({ order_ref: "J-3", reason: "maybe" as never })).toEqual({ ok: false, reason: "invalid-input" });
    expect(rec.reportGap({ order_ref: "", reason: "other" })).toEqual({ ok: false, reason: "invalid-input" });
    expect(readNdjson(gapsOf(dir))).toHaveLength(2);

    rmSync(gapsOf(dir));
    mkdirSync(gapsOf(dir));
    const spy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      let g: ReturnType<TrialRecorder["reportGap"]> | undefined;
      expect(() => (g = rec.reportGap({ order_ref: "ZZ-GAP-REF", reason: "other" }))).not.toThrow();
      expect(g).toEqual({ ok: false, reason: "write-failed" });
      const r = rec.record({ order_ref: "ZZ-GAP-REF-2", order: sampleOrder(), email: "x" } as never);
      expect(r).toMatchObject({ ok: false, reason: "refused-field" });
      const lines = spy.mock.calls.map((c) => String(c[0]));
      expect(lines).toHaveLength(2);
      for (const l of lines) {
        expect(l).toMatch(/gap line not written/);
        expect(l).not.toContain("ZZ-GAP-REF");
      }
    } finally {
      spy.mockRestore();
    }
  }, 30_000);
});

describe("trial recorder: entries and retained arguments", () => {
  it("(f) retained arguments hash to args_hash; record_agent_cart with jwks_uri; verify exits 0; equal to appendReceipt but for the signature", async () => {
    const { dir, identity } = data();
    const JWKS = "https://shop.example/.well-known/jwks.json";
    const TS = "2026-10-28T12:00:00.000Z";
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", jwksUri: JWKS, now: () => TS, logger: quiet }));
    const in1: RecordInput = { order_ref: "F-1", order: sampleOrder("F-1"), agent_context: { channel: "mcp", agent_name: "agent-x" }, call_seq: 3 };
    const in2: RecordInput = sampleInput("F-2");
    const r1 = rec.record(in1);
    const r2 = rec.record(in2);
    expect(r1.ok && r2.ok).toBe(true);
    if (!r1.ok || !r2.ok) return;
    expect(r1.count).toBe(1);
    expect(r2.count).toBe(2);
    expect(r1.session_id).toBe(rec.session_id);

    const chainPath = chainOf(dir, rec.session_id);
    const { records } = readChainFile(chainPath);
    expect(records).toHaveLength(2);
    const retained = walkFiles(join(dir, "args")).map((f) => ({ f, j: JSON.parse(readFileSync(f, "utf8")) as Record<string, unknown> }));
    expect(retained).toHaveLength(2);
    const wantArgs = [{ order: in1.order, agent_context: in1.agent_context }, { order: in2.order }];
    for (const [i, r] of [r1, r2].entries()) {
      const e = records[i]!;
      const ev = e.event as { args_hash: string };
      const file = retained.find((x) => x.j["args_hash"] === r.args_hash)!;
      expect(file, `retained ${i}`).toBeDefined();
      expect(Object.keys(file.j).sort()).toEqual(["args_hash", "arguments", "call_seq", "order_ref_sha256"]);
      expect(file.j["arguments"]).toEqual(wantArgs[i]);
      expect(argsHash(file.j["arguments"])).toBe(ev.args_hash);
      expect(ev.args_hash).toBe(r.args_hash);
      expect(file.j["order_ref_sha256"]).toBe(sha256Tagged(i === 0 ? "F-1" : "F-2"));
      expect(file.j["call_seq"]).toBe(i === 0 ? 3 : null);
      expect(e.event.type).toBe("mcp_call");
      expect((e.event as { tool_name: string }).tool_name).toBe("record_agent_cart");
      expect((e.event as { server: string }).server).toBe("shop");
      expect((e.event as { decision?: string }).decision).toBe("allow");
      expect(e.jwks_uri).toBe(JWKS);
      expect(entryHashOfCanonical(jcsBytes(contentOf(e)))).toBe(r.entry_hash);
    }
    expect("agent_context" in (retained.find((x) => x.j["args_hash"] === r2.args_hash)!.j["arguments"] as object)).toBe(false);

    const v = runCli(["verify", chainPath, "--key", join(dir, "identity.json")]);
    expect(v.stdout).toContain("VALID");
    expect(v.status).toBe(0);

    // The same inputs through appendReceipt: equal in every member but sig.
    const refChain = join(dir, "reference.jsonl");
    const ref = wantArgs.map((toolArgs) =>
      appendReceipt({ chainPath: refChain, sessionId: rec.session_id, identity, server: "shop", toolName: "record_agent_cart", toolArgs, decision: { kind: "allow" }, jwksUri: JWKS, ts: TS }),
    );
    const strip = (r: object) => {
      const { sig: _s, ...rest } = r as Record<string, unknown>;
      return JSON.stringify(rest);
    };
    for (let i = 0; i < 2; i++) expect(strip(records[i]!), `entry ${i}`).toBe(strip(ref[i]!));

    // (m) No retained file name holds a colon; the layout is <sid>/<floor(count/1000)>/<count>-<32 hex>.json.
    for (const { f, j } of retained) {
      expect(basename(f)).not.toContain(":");
      expect(f).not.toMatch(/[^\\/]:[^\\/]*$/);
      const count = Number(basename(f).split("-")[0]);
      expect(basename(f)).toBe(`${count}-${String(j["args_hash"]).slice("sha256:".length, "sha256:".length + 32)}.json`);
      expect(f).toBe(join(dir, "args", rec.session_id, String(Math.floor(count / 1000)), basename(f)));
    }
  }, 60_000);

  it.skipIf(process.platform === "win32")("R2: directories 0700, files 0600", async () => {
    const stub = await stubOf();
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    const r = rec.record(sampleInput("M-1"));
    rec.record({ order_ref: "M-2", order: sampleOrder(), x: 1 } as never);
    await rec.awaitWitness(r.ok ? r.entry_hash : "", 3_000);
    await rec.close(1_000);
    const created = walkFiles(dir).filter((f) => !/identity\.json$|private-key\.pem$/.test(f));
    expect(created.length).toBeGreaterThanOrEqual(5);
    for (const f of created) expect((statSync(f).mode & 0o777).toString(8), f).toBe("600");
    for (const d of [join(dir, "chains"), join(dir, "args"), join(dir, "args", rec.session_id)]) {
      expect((statSync(d).mode & 0o777).toString(8), d).toBe("700");
    }
  }, 30_000);
});

describe("trial recorder: restart catch-up", () => {
  it("(k) a new recorder witnesses an earlier session's unwitnessed head once, and skips live-locked, recent and foreign chains", async () => {
    const dead = await closedPortUrl();
    const { dir } = data();
    const past = new Date(Date.now() - 11 * 60_000);
    const unreachable = { baseUrl: dead, name: STUB_WITNESS_NAME };

    // A: closed, its head unwitnessed, its lock left behind naming a dead process.
    const a = createTrialRecorder({ dir, serverLabel: "shop", witness: unreachable, logger: quiet });
    for (let i = 0; i < 3; i++) expect(a.record(sampleInput(`K-A-${i}`)).ok).toBe(true);
    await a.close(1_000);
    const deadPid = spawnSync(process.execPath, ["-e", ""]).pid;
    writeFileSync(join(dir, "chains", `${a.session_id}.lock`), String(deadPid));
    utimesSync(chainOf(dir, a.session_id), past, past);

    // B: still open in this process (a live pid in its lock), aged.
    const b = track(createTrialRecorder({ dir, serverLabel: "shop", witness: unreachable, logger: quiet }));
    expect(b.record(sampleInput("K-B-0")).ok).toBe(true);
    await new Promise((r) => setTimeout(r, 100));
    expect(readFileSync(join(dir, "chains", `${b.session_id}.lock`), "utf8").trim()).toBe(String(process.pid));
    utimesSync(chainOf(dir, b.session_id), past, past);

    // E: closed, but modified within the last 10 minutes.
    const e = createTrialRecorder({ dir, serverLabel: "shop", logger: quiet });
    expect(e.record(sampleInput("K-E-0")).ok).toBe(true);
    await e.close(500);

    // D: signed by another key, copied in and aged.
    const other = data();
    const d = createTrialRecorder({ dir: other.dir, serverLabel: "shop", logger: quiet });
    expect(d.record(sampleInput("K-D-0")).ok).toBe(true);
    await d.close(500);
    const dChain = chainOf(dir, d.session_id);
    copyFileSync(chainOf(other.dir, d.session_id), dChain);
    utimesSync(dChain, past, past);

    const stub = await stubOf();
    const c = track(createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    const sids = () => stub.rows.map((r) => r["session_id"]);
    expect(await waitFor(() => sids().includes(a.session_id), 10_000)).toBe(true);
    await new Promise((r) => setTimeout(r, 1_000));
    expect(stub.rows.filter((r) => r["session_id"] === a.session_id).map((r) => r["count"])).toEqual(["3"]);
    for (const s of [b.session_id, e.session_id, d.session_id, c.session_id]) expect(sids()).not.toContain(s);
    expect(stub.posts).toBe(1);

    // The receipt went to A's own sidecar, and verifies against A's chain.
    const aChain = chainOf(dir, a.session_id);
    const v = runCli([
      "verify", aChain, "--key", join(dir, "identity.json"),
      "--witness-file", aChain + ".witness.ndjson", "--witness-key", stub.publicKeyHex, "--witness-name", STUB_WITNESS_NAME,
    ]);
    expect(v.stdout + v.stderr).toContain("WITNESSED through count 3");
    expect(v.status).toBe(0);
  }, 60_000);
});

describe("trial recorder: what reaches the witness", () => {
  it("(l) each POST carries exactly the checkpoint members and public_key_jwk, the list the README states", async () => {
    const stub = await stubOf();
    const bodies: Record<string, unknown>[] = [];
    // Capture and forward: records each body's members, passes the bytes on unchanged.
    const capture = createServer((req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const raw = Buffer.concat(chunks);
        if (req.method === "POST") bodies.push(JSON.parse(raw.toString("utf8")) as Record<string, unknown>);
        const headers: Record<string, string> = {};
        for (const h of ["content-type", "authorization"]) {
          const v = req.headers[h];
          if (typeof v === "string") headers[h] = v;
        }
        const up = await fetch(stub.url + (req.url ?? "/"), { method: req.method ?? "GET", headers, ...(req.method === "POST" ? { body: raw } : {}) });
        res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
        res.end(Buffer.from(await up.arrayBuffer()));
      });
    });
    await new Promise<void>((r) => capture.listen(0, "127.0.0.1", r));
    try {
      const url = `http://127.0.0.1:${(capture.address() as AddressInfo).port}`;
      const { dir } = data();
      const rec = track(
        createTrialRecorder({ dir, serverLabel: "shop", witness: { baseUrl: url, name: STUB_WITNESS_NAME, pinnedKey: stub.publicKeyHex }, logger: quiet }),
      );
      let last = "";
      for (let i = 0; i < 3; i++) {
        const r = rec.record(sampleInput(`L-${i}`));
        if (r.ok) last = r.entry_hash;
        await new Promise((r) => setTimeout(r, 30));
      }
      expect((await rec.awaitWitness(last, 3_500)).ok).toBe(true);
      await rec.close(1_000);
      expect(bodies.length).toBeGreaterThanOrEqual(1);
      for (const b of bodies) {
        expect(Object.keys(b).sort()).toEqual(["checkpoint", "public_key_jwk"]);
        expect(Object.keys(b["checkpoint"] as object).sort()).toEqual(["count", "kid", "last_entry_hash", "session_id", "sig", "ts", "type", "v"]);
        expect(Object.keys(b["public_key_jwk"] as object).sort()).toEqual(["crv", "kty", "x"]);
      }
    } finally {
      capture.closeAllConnections();
      await new Promise<void>((r) => capture.close(() => r()));
    }

    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    const start = readme.indexOf("## Chirindo trial recorder");
    expect(start).toBeGreaterThan(-1);
    const next = readme.indexOf("\n## ", start + 1);
    const section = readme.slice(start, next === -1 ? undefined : next);
    for (const m of ["v", "type", "session_id", "count", "last_entry_hash", "ts", "kid", "sig"]) expect(section).toContain("`" + m + "`");
    expect(section).toContain("public key");
    expect(section).toContain("account key");
    expect(section).toContain("IP address");
    // R11: the limits, verbatim, and before anything else in the section.
    const firstLimit = section.indexOf(LIMIT_TEXTS.L1);
    expect(firstLimit).toBeGreaterThan(-1);
    for (const id of ["L1", "L3", "L5", "L7", "L24", "L25"]) expect(section, id).toContain((LIMIT_TEXTS as Record<string, string>)[id]);
    expect(section.indexOf("chains/")).toBeGreaterThan(firstLimit);
  }, 60_000);
});
