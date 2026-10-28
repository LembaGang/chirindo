// The trial recorder after the ratification read: a part-written append is
// cut back (or the chain is marked broken), the caller's callbacks cannot
// crash the host, catch-up is not starved, the stricter rules, the driver's
// stop and resume, the endpoint's Bearer scheme, and the catch-up's torn tail
// and 10-chain cap.

import { randomBytes } from "node:crypto";
import { appendFileSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createTrialRecorder, type TrialRecorder } from "../src/trial/index.js";
import { openTrialRecorder } from "../src/trial/recorder.js";
import { appendReceipt } from "../src/receipt.js";
import { buildCheckpointFromHead } from "../src/checkpoint.js";
import { readSidecar } from "../src/witness.js";
import { readChainFile } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir, runCli } from "./helpers.js";
import { startStubWitness, STUB_WITNESS_NAME, type StubWitness } from "./witness-stub.js";
import {
  closedPortUrl,
  httpCall,
  listeningUrl,
  newDataDir,
  readNdjson,
  sampleInput,
  sampleOrder,
  startCli,
  waitFor,
  type CliChild,
} from "./trial-helpers.js";

const quiet = () => {};
const iso = () => new Date().toISOString();
const chainOf = (dir: string, sid: string) => join(dir, "chains", `${sid}.jsonl`);

const open: TrialRecorder[] = [];
const stubs: StubWitness[] = [];
const dirs: string[] = [];
const children: CliChild[] = [];
afterEach(async () => {
  vi.useRealTimers();
  for (const r of open.splice(0)) await r.close(500);
  for (const s of stubs.splice(0)) await s.close();
  for (const c of children.splice(0)) {
    c.child.kill();
    await c.exited;
  }
  for (const d of dirs.splice(0)) cleanupTmpDir(d);
});
function track<T extends TrialRecorder>(r: T): T {
  open.push(r);
  return r;
}
function data() {
  const d = newDataDir();
  dirs.push(d.dir);
  return d;
}
async function stubOf(o: Parameters<typeof startStubWitness>[0] = {}) {
  const s = await startStubWitness(o);
  stubs.push(s);
  return s;
}
const witnessOf = (s: StubWitness) => ({ baseUrl: s.url, name: STUB_WITNESS_NAME, pinnedKey: s.publicKeyHex });

// An append that writes part of a line and then fails, on its nth call.
function tornOn(n: number): typeof appendReceipt {
  let calls = 0;
  return (inputs) => {
    if (++calls === n) {
      appendFileSync(inputs.chainPath, '{"v":"evidence.action/1","seq":' + String(calls - 1) + ',"session_id":"', "utf8");
      throw new Error("ENOSPC: injected");
    }
    return appendReceipt(inputs);
  };
}

describe("F1: a part-written append", () => {
  it("is cut back, so the next record succeeds and the chain still verifies", async () => {
    const { dir } = data();
    const rec = track(openTrialRecorder({ dir, serverLabel: "shop", log: quiet, now: iso, appendEntry: tornOn(2) }));
    expect(rec.record(sampleInput("T-1", 1)).ok).toBe(true);
    expect(rec.record(sampleInput("T-2", 2))).toMatchObject({ ok: false, reason: "write-failed" });
    const r3 = rec.record(sampleInput("T-3", 3));
    expect(r3).toMatchObject({ ok: true, count: 2 });
    const chain = chainOf(dir, rec.session_id);
    expect(readChainFile(chain).records).toHaveLength(2);
    const v = runCli(["verify", chain, "--key", join(dir, "identity.json")]);
    expect(v.stdout).toContain("VALID");
    expect(v.status).toBe(0);
    expect(readNdjson(join(dir, "gaps.ndjson")).map((g) => g["reason"])).toEqual(["write-failed"]);
  }, 30_000);

  it("when the cut fails, marks the chain broken: one chain-broken gap line, every later record write-failed", async () => {
    const { dir } = data();
    const rec = track(
      openTrialRecorder({
        dir,
        serverLabel: "shop",
        log: quiet,
        now: iso,
        appendEntry: tornOn(2),
        truncateChain: () => {
          throw new Error("EIO: injected");
        },
      }),
    );
    expect(rec.record(sampleInput("B-1", 1)).ok).toBe(true);
    expect(rec.record(sampleInput("B-2", 2))).toMatchObject({ ok: false, reason: "write-failed" });
    expect(rec.record(sampleInput("B-3", 3))).toMatchObject({ ok: false, reason: "write-failed" });
    expect(rec.record(sampleInput("B-4", 4))).toMatchObject({ ok: false, reason: "write-failed" });
    const reasons = readNdjson(join(dir, "gaps.ndjson")).map((g) => g["reason"]);
    expect(reasons.filter((r) => r === "chain-broken")).toHaveLength(1);
    expect(reasons.filter((r) => r === "write-failed")).toHaveLength(3);
  }, 30_000);

  it("appendReceipt refuses a malformed head; buildCheckpointFromHead a count that is not a safe integer of at least 1", () => {
    const { dir, identity } = data();
    const base = {
      chainPath: join(dir, "h.jsonl"), sessionId: "s", identity, server: "shop", toolName: "record_agent_cart",
      toolArgs: { order: sampleOrder() }, decision: { kind: "allow" as const },
    };
    const good = "sha256:" + "a".repeat(64);
    for (const head of [{ seq: -1, prevHash: good }, { seq: 1.5, prevHash: good }, { seq: 0, prevHash: "sha256:xyz" }, { seq: 0, prevHash: "A".repeat(71) }]) {
      expect(() => appendReceipt({ ...base, head }), JSON.stringify(head)).toThrow(/head must be/);
    }
    expect(() => appendReceipt({ ...base, head: { seq: 0, prevHash: good } })).not.toThrow();
    for (const count of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => buildCheckpointFromHead({ sessionId: "s", count, lastEntryHash: good }, identity), String(count)).toThrow();
    }
  });
});

describe("F2: the caller's callbacks", () => {
  it("a log and a now that throw: recording continues, and nothing becomes an uncaught exception or an unhandled rejection", async () => {
    const uncaught: unknown[] = [];
    const onErr = (e: unknown) => uncaught.push(e);
    process.on("uncaughtException", onErr);
    process.on("unhandledRejection", onErr);
    try {
      const { dir } = data();
      const rec = createTrialRecorder({
        dir,
        serverLabel: "shop",
        witness: { baseUrl: await closedPortUrl(), name: STUB_WITNESS_NAME },
        logger: () => {
          throw new Error("logger down");
        },
        now: () => {
          throw new Error("clock down");
        },
      });
      const hashes: string[] = [];
      for (let i = 0; i < 5; i++) {
        const r = rec.record(sampleInput(`N-${i}`, i));
        expect(r.ok).toBe(true);
        if (r.ok) hashes.push(r.entry_hash);
        await new Promise((res) => setTimeout(res, 20));
      }
      expect(rec.reportGap({ order_ref: "N-gap", reason: "other" })).toEqual({ ok: true });
      expect(await rec.awaitWitness(hashes[4]!, 200)).toMatchObject({ ok: false });
      await rec.close(1_000);
      await new Promise((res) => setTimeout(res, 200));
      const { records } = readChainFile(chainOf(dir, rec.session_id));
      expect(records).toHaveLength(5);
      for (const e of records) expect(e.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(uncaught).toEqual([]);
    } finally {
      process.off("uncaughtException", onErr);
      process.off("unhandledRejection", onErr);
    }
  }, 30_000);
});

describe("F3: catch-up under load", () => {
  it("an earlier session's head is witnessed while this session keeps recording", async () => {
    const { dir } = data();
    const a = createTrialRecorder({ dir, serverLabel: "shop", logger: quiet });
    for (let i = 0; i < 2; i++) expect(a.record(sampleInput(`L-A-${i}`)).ok).toBe(true);
    await a.close(500);
    const past = new Date(Date.now() - 11 * 60_000);
    utimesSync(chainOf(dir, a.session_id), past, past);

    const stub = await stubOf({ delayMs: 30 });
    const c = track(createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    let seenWhileBusy = false;
    // The first record lands before the catch-up runs; then a new own head is
    // always waiting when a POST completes.
    for (let i = 0; i < 40 && !seenWhileBusy; i++) {
      expect(c.record(sampleInput(`L-C-${i}`)).ok).toBe(true);
      await new Promise((res) => setTimeout(res, 10));
      seenWhileBusy = stub.rows.some((r) => r["session_id"] === a.session_id);
    }
    expect(seenWhileBusy).toBe(true);
    expect(stub.rows.filter((r) => r["session_id"] === a.session_id).map((r) => r["count"])).toEqual(["2"]);
  }, 30_000);
});

describe("F5: rules", () => {
  it("expires_at must name a real instant", () => {
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
    const at = (expires_at: string) =>
      rec.record({ ...sampleInput("X-1"), agent_context: { payment_token_limits: { currency: "USD", max_amount_minor: "100", expires_at } } });
    for (const bad of ["2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z", "2026-12-31T23:59:60Z", "2026-11-10T12:00:00+01:00"]) {
      expect(at(bad), bad).toMatchObject({ ok: false, reason: "invalid-input", paths: ["/agent_context/payment_token_limits/expires_at"] });
    }
    for (const good of ["2026-11-10T12:00:00Z", "2026-11-10T12:00:00.5Z", "2028-02-29T23:59:59.999999999Z"]) {
      expect(at(good).ok, good).toBe(true);
    }
  });

  it("the length caps of the screened fields are checked before they are screened", () => {
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
    const card = "4111111111111111";
    const long = "x".repeat(260) + " " + card;
    const order = sampleOrder("C-1");
    const item = order.items[0]!;
    expect(rec.record({ order_ref: "C-1", order: { ...order, items: [{ ...item, name: long }] } })).toMatchObject({
      ok: false, reason: "invalid-order", paths: ["/order/items/0/name"],
    });
    expect(rec.record({ order_ref: "C-2", order: { ...order, items: [{ ...item, location: long }] } })).toMatchObject({
      ok: false, reason: "invalid-order", paths: ["/order/items/0/location"],
    });
    expect(rec.record({ order_ref: "C-3", order, agent_context: { agent_name: long } })).toMatchObject({
      ok: false, reason: "invalid-input", paths: ["/agent_context/agent_name"],
    });
    // Within the cap, the same card is refused by the screening.
    expect(rec.record({ order_ref: "C-4", order: { ...order, items: [{ ...item, name: "x " + card }] } })).toMatchObject({ reason: "refused-value" });
  });

  it("the input is read once, into a snapshot used for every check and for the write", () => {
    const { dir } = data();
    const rec = track(createTrialRecorder({ dir, serverLabel: "shop", logger: quiet }));
    let reads = 0;
    const good = sampleOrder("S-1");
    const input = Object.defineProperty({ order_ref: "S-1" }, "order", {
      enumerable: true,
      get: () => {
        reads++;
        // Valid the first two times it is read, then not: a check or a
        // write that read it again would see a different order.
        return reads <= 2 ? good : { ...good, total_minor: "bad" };
      },
    });
    const r = rec.record(input as never);
    expect(r.ok).toBe(true);
    expect(reads).toBeLessThanOrEqual(2);
    if (!r.ok) return;
    const { records } = readChainFile(chainOf(dir, rec.session_id));
    expect(records).toHaveLength(1);
    expect((records[0]!.event as { args_hash: string }).args_hash).toBe(r.args_hash);
  });
});

describe("F6: the driver's stop", () => {
  it("witness_plan_required stops sending; a head never sent is recorded as witness_stopped; sending resumes after 00:00 UTC", async () => {
    const key = "ho_live_" + randomBytes(32).toString("hex");
    const stub = await stubOf({ accounts: { [key]: { status: "active", plan: "starter" } } });
    const { dir } = data();
    const keyFile = join(dir, "witness.key");
    writeFileSync(keyFile, key);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-28T23:59:00.000Z"));
    const log: string[] = [];
    const rec = track(
      createTrialRecorder({ dir, serverLabel: "shop", witness: { ...witnessOf(stub), accountKeyFile: keyFile }, logger: (l) => log.push(l) }),
    );
    const settle = async (cond: () => boolean) => {
      for (let i = 0; i < 200 && !cond(); i++) await new Promise((res) => setTimeout(res, 10));
      return cond();
    };
    const r1 = rec.record(sampleInput("P-1"));
    expect(r1.ok).toBe(true);
    expect(await rec.awaitWitness(r1.ok ? r1.entry_hash : "", 3_000)).toEqual({ ok: false, reason: "stopped" });
    expect(stub.posts).toBe(1);
    expect(log.filter((l) => l.includes("witness_plan_required"))).toHaveLength(1);

    expect(rec.record(sampleInput("P-2")).ok).toBe(true);
    await new Promise((res) => setTimeout(res, 150));
    expect(stub.posts).toBe(1);

    vi.setSystemTime(new Date("2026-10-29T00:00:01.000Z"));
    expect(rec.record(sampleInput("P-3")).ok).toBe(true);
    expect(await settle(() => stub.posts === 2)).toBe(true);
    // Refused again: stopped until the next midnight; the head recorded next is never sent.
    expect(await settle(() => log.filter((l) => l.includes("witness_plan_required")).length === 2)).toBe(true);
    expect(rec.record(sampleInput("P-4")).ok).toBe(true);
    await rec.close(500);
    open.splice(open.indexOf(rec), 1);
    const side = readSidecar(chainOf(dir, rec.session_id) + ".witness.ndjson");
    expect(side.map((l) => l.witness_error)).toEqual(["witness_plan_required", "witness_plan_required", "witness_stopped"]);
    expect(side.at(-1)!.checkpoint.count).toBe(4);
  }, 30_000);
});

describe("F7: the endpoint's Bearer scheme", () => {
  it("is compared case-insensitively; the token is not", async () => {
    const { dir } = data();
    const tokenFile = join(dir, "token");
    writeFileSync(tokenFile, "tok-" + randomBytes(16).toString("hex"));
    const token = readFileSync(tokenFile, "utf8");
    const c = startCli(["trial-recorder", "--dir", dir, "--server-label", "shop", "--port", "0", "--token-file", tokenFile]);
    children.push(c);
    const url = await listeningUrl(c);
    expect(url, c.stderr()).not.toBeNull();
    if (url === null) return;
    const host = new URL(url).host;
    const call = (authorization: string, ref: string) =>
      httpCall(url, { path: "/record", headers: { "content-type": "application/json", host, authorization }, body: JSON.stringify(sampleInput(ref)) });
    expect((await call(`bearer ${token}`, "K-1")).status).toBe(200);
    expect((await call(`BEARER ${token}`, "K-2")).status).toBe(200);
    expect((await call(`Bearer ${token.toUpperCase()}`, "K-3")).status).toBe(401);
  }, 60_000);
});

describe("F8: catch-up's reading of earlier chains", () => {
  it("a torn last line is ignored: the head is the last complete line", async () => {
    const { dir } = data();
    const a = createTrialRecorder({ dir, serverLabel: "shop", logger: quiet });
    for (let i = 0; i < 3; i++) expect(a.record(sampleInput(`T-A-${i}`)).ok).toBe(true);
    await a.close(500);
    appendFileSync(chainOf(dir, a.session_id), '{"v":"evidence.action/1","seq":3,"sess');
    const past = new Date(Date.now() - 11 * 60_000);
    utimesSync(chainOf(dir, a.session_id), past, past);
    const stub = await stubOf();
    track(createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    expect(await waitFor(() => stub.rows.some((r) => r["session_id"] === a.session_id), 10_000)).toBe(true);
    expect(stub.rows.filter((r) => r["session_id"] === a.session_id).map((r) => r["count"])).toEqual(["3"]);
  }, 30_000);

  it("at most the 10 newest earlier chains are looked at", async () => {
    const { dir } = data();
    const sids: string[] = [];
    for (let i = 0; i < 12; i++) {
      const r = createTrialRecorder({ dir, serverLabel: "shop", logger: quiet });
      expect(r.record(sampleInput(`M-${i}`)).ok).toBe(true);
      await r.close(500);
      sids.push(r.session_id);
    }
    // sids[0] newest ... sids[11] oldest, all past the quiet window.
    sids.forEach((sid, i) => {
      const t = new Date(Date.now() - (11 + i) * 60_000);
      utimesSync(chainOf(dir, sid), t, t);
    });
    const stub = await stubOf();
    track(createTrialRecorder({ dir, serverLabel: "shop", witness: witnessOf(stub), logger: quiet }));
    expect(await waitFor(() => stub.rows.length >= 10, 15_000)).toBe(true);
    await new Promise((res) => setTimeout(res, 500));
    const posted = new Set(stub.rows.map((r) => r["session_id"]));
    expect(stub.rows).toHaveLength(10);
    for (const sid of sids.slice(0, 10)) expect(posted.has(sid), sid).toBe(true);
    for (const sid of sids.slice(10)) expect(posted.has(sid), sid).toBe(false);
  }, 60_000);
});

