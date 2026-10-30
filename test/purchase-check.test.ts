// B-432 tests 4 to 7 (design §8): restart, a deny is not a use, repeats, and
// record failure; with the lock (T0 ruling 5), the legacy-kid refusal, the
// gate clock failing closed (T0 ruling 4), and the witness.
//
// Test 5 runs bIns from examples/evidence-bundle/lib/instructions.mjs with the
// HOLD-4 inputs. evm.mjs needs viem, which CI does not install; it is replaced
// by a lowercase-only `address`, which no card-only instruction reaches.

import { spawnSync } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { createPurchaseCheck } from "../src/purchase/check.js";
import { readSidecar, sidecarPathFor } from "../src/witness.js";
import { createTrialRecorder } from "../src/trial/index.js";
import { appendReceipt } from "../src/receipt.js";
import { IDENTITY_FILENAME, argsHash, legacyKid, runVerify } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir } from "./helpers.js";
import {
  AT,
  GATE,
  argsFiles,
  chainPathOf,
  checkDir,
  checked,
  clockAt,
  constraintsOf,
  itemOf,
  openCheck,
  order,
  recordsOf,
  signedText,
  type Obj,
} from "./purchase-helpers.js";
import { startStubWitness, STUB_WITNESS_NAME } from "./witness-stub.js";
// @ts-expect-error -- plain .mjs without declarations; the reference verifier
import { ANNEX_A3, bIns, m6Instruction } from "../examples/evidence-bundle/lib/instructions.mjs";
// @ts-expect-error -- as above
import { orderProblem } from "../examples/evidence-bundle/lib/card.mjs";
// @ts-expect-error -- as above
import { parseChirindoLog } from "../examples/evidence-bundle/lib/records.mjs";

vi.mock("../examples/ordering-evidence-h4/lib/evm.mjs", () => ({
  address: (s: unknown, what: string) => {
    if (typeof s !== "string" || !/^0x[0-9a-f]{40}$/.test(s)) throw new Error(`${what} is not a lowercase 20-byte hex address`);
    return s;
  },
}));

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));
const fresh = () => {
  const d = checkDir();
  dirs.push(d);
  return d;
};
const ref = (id: string) => order((o) => (o["merchant_order_id"] = id));
const maxUses = (n: number) => signedText((b) => (constraintsOf(b)["max_uses"] = n));

describe("test 4: restart", () => {
  it("max_uses 3: three allows, close, create again, and the fourth is denied uses-exhausted", async () => {
    const dir = fresh();
    const ins = maxUses(3);
    const a = openCheck(dir, clockAt());
    for (const id of ["H-1", "H-2", "H-3"]) expect(checked(a, ins, ref(id)).decision).toBe("allow");
    await a.close();
    const b = openCheck(dir, clockAt());
    expect(checked(b, ins, ref("H-4"))).toMatchObject({ decision: "deny", reasons: ["uses-exhausted"], exceeded: ["max_uses"] });
    await b.close();
  });

  it("the repeat index survives restart: the same order replays, a changed order is order-ref-reused", async () => {
    const dir = fresh();
    const a = openCheck(dir, clockAt());
    const first = checked(a, signedText(), ref("H-1"));
    expect(first.decision).toBe("allow");
    await a.close();
    const sizeBefore = statSync(chainPathOf(dir, a.session_id)).size;
    const b = openCheck(dir, clockAt("2026-11-06T00:00:00.000Z"));
    const again = checked(b, signedText(), ref("H-1"));
    expect(again).toMatchObject({ decision: "allow", repeat: true, receipt: first.receipt, at: first.at, instruction_sha256: first.instruction_sha256 });
    expect(existsSync(chainPathOf(dir, b.session_id))).toBe(false);
    const changed = checked(b, signedText(), order((o) => (o["total_minor"] = "27000")));
    expect(changed).toMatchObject({ decision: "deny", reasons: ["order-ref-reused"], repeat: false });
    expect(changed.receipt).not.toBeNull();
    await b.close();
    expect(statSync(chainPathOf(dir, a.session_id)).size).toBe(sizeBefore);
  });

  it("a torn final line is truncated, with a log line, and create succeeds", async () => {
    const dir = fresh();
    const a = openCheck(dir, clockAt());
    checked(a, signedText(), ref("H-1"));
    await a.close();
    const chain = chainPathOf(dir, a.session_id);
    const good = statSync(chain).size;
    appendFileSync(chain, '{"v":"evidence.action/1","seq":1,"sess');
    const b = openCheck(dir, clockAt());
    expect(statSync(chain).size).toBe(good);
    expect(b.logs.join("\n")).toMatch(/cut a torn final line of 38 bytes/);
    // The rebuilt use count is 1: max_uses 1 is spent.
    expect(checked(b, signedText(), ref("H-2")).reasons).toEqual(["uses-exhausted"]);
    await b.close();
  });

  it("a mid-file break makes create throw, naming the file, and releases the lock", async () => {
    for (const breakIt of [
      (t: string) => t.replace('"seq":0', '"seq":7'),
      (t: string) => t.replace("\n", "\nnot json\n"),
      (t: string) => t.replace(/"sig":"(.)/, (_m, c: string) => `"sig":"${c === "A" ? "B" : "A"}`),
    ]) {
      const dir = fresh();
      const a = openCheck(dir, clockAt());
      checked(a, maxUses(2), ref("H-1"));
      checked(a, maxUses(2), ref("H-2"));
      await a.close();
      const chain = chainPathOf(dir, a.session_id);
      writeFileSync(chain, breakIt(readFileSync(chain, "utf8")));
      expect(() => openCheck(dir, clockAt())).toThrow(chain);
      expect(existsSync(join(dir, "purchase-chains", ".lock"))).toBe(false);
    }
  });

  it("a second create on a locked dir throws, naming the pid and the lock", async () => {
    const dir = fresh();
    const a = openCheck(dir, clockAt());
    const lock = join(dir, "purchase-chains", ".lock");
    expect(() => createPurchaseCheck({ dir })).toThrow(`lock ${lock} names process ${process.pid}, which is running`);
    await a.close();
    expect(existsSync(lock)).toBe(false);
    const b = openCheck(dir, clockAt());
    await b.close();
  });

  it("a stale lock is refused, not reclaimed, and so is a lock with no pid", async () => {
    const dir = fresh();
    const lock = join(dir, "purchase-chains", ".lock");
    const gone = spawnSync(process.execPath, ["-e", ""]).pid!;
    openCheck(dir, clockAt()).close();
    writeFileSync(lock, String(gone));
    expect(() => createPurchaseCheck({ dir })).toThrow(`stale lock ${lock} names process ${gone}, which is not running`);
    expect(readFileSync(lock, "utf8")).toBe(String(gone));
    writeFileSync(lock, "junk");
    expect(() => createPurchaseCheck({ dir })).toThrow(`lock ${lock} holds no process id`);
  });

  it("the trial recorder's chains in dir/chains are ignored", async () => {
    const dir = fresh();
    const rec = createTrialRecorder({ dir, serverLabel: "shop", logger: () => {} });
    expect(rec.record({ order_ref: "T-1", order: ref("T-1") as never }).ok).toBe(true);
    await rec.close(100);
    const pc = openCheck(dir, clockAt());
    expect(checked(pc, signedText(), ref("H-1")).decision).toBe("allow");
    await pc.close();
  });

  it("a legacy kid, or a kid that is not the key's thumbprint, is refused", () => {
    const dir = fresh();
    const idPath = join(dir, IDENTITY_FILENAME);
    const id = JSON.parse(readFileSync(idPath, "utf8"));
    id.kid = legacyKid(createPublicKey(GATE.priv));
    writeFileSync(idPath, JSON.stringify(id));
    expect(() => createPurchaseCheck({ dir })).toThrow(/legacy kid cannot run the purchase check/);
    expect(existsSync(join(dir, "purchase-chains", ".lock"))).toBe(false);
  });
});

describe("test 5: a deny is not a use", () => {
  it("max_uses 1: a deny, then an allow of an inside order, gives allow; bIns gives BOUND for the allow", async () => {
    const dir = fresh();
    const pc = openCheck(dir, clockAt());
    const ins = signedText();
    expect(checked(pc, ins, order((o) => (o["total_minor"] = "30001"))).decision).toBe("deny");
    const allow = checked(pc, ins, order());
    expect(allow.decision).toBe("allow");
    await pc.close();

    // The HOLD-4 call, as the T0 rulings fix it.
    const m6 = m6Instruction(Buffer.from(ins, "utf8"), ANNEX_A3);
    expect(m6.problem).toBeUndefined();
    expect(m6.digest).toBe(allow.instruction_sha256);
    const insRows = [{ member: "instruction", profile: ANNEX_A3, digest: m6.digest, value: m6.value, m6: "PASS" }];
    const { records } = parseChirindoLog(readFileSync(chainPathOf(dir, pc.session_id)));
    const logs = [{ member: "gate-log", profile: "chirindo-evidence.action/1", records }];
    const argMembers = [...argsFiles(dir).entries()].map(([name, bytes]) => {
      const value = JSON.parse(bytes.toString("utf8"));
      // The file's bytes are the JCS form: their SHA-256 is the args_hash.
      expect("sha256:" + createHash("sha256").update(bytes).digest("hex")).toBe(argsHash(value));
      return { member: name, digest: argsHash(value), value };
    });
    const rec = records.find((r: Obj) => (r["event"] as Obj)["decision"] === "allow");
    const A = argMembers.find((a) => a.digest === (rec.event as Obj)["args_hash"]);
    expect(A).toBeDefined();
    expect(orderProblem(A!.value.order)).toBeNull();
    const r = bIns({ ins: insRows, A, pv: null, bpayState: "NOT-EVALUATED", logs, argMembers, card: { order: A!.value.order, orderOk: true, kid: rec.kid, authorizedAt: rec.check.at } });
    expect(r.agg.state).toBe("BOUND");
    expect(r.rows[0]).toMatchObject({ cited: true, state: "BOUND", exceeded: [], uses: 1, records_without_arguments: 0 });
  });
});

describe("test 6: repeats", () => {
  it("an identical order replays the allow, with no new receipt and no use", async () => {
    const dir = fresh();
    const pc = openCheck(dir, clockAt());
    const ins = maxUses(2);
    const first = checked(pc, ins, ref("H-1"));
    const size = statSync(chainPathOf(dir, pc.session_id)).size;
    const files = argsFiles(dir).size;
    const again = checked(pc, ins, ref("H-1"));
    expect(again).toMatchObject({ decision: "allow", repeat: true, receipt: first.receipt });
    expect(again.card_limits).toEqual(first.card_limits);
    expect(statSync(chainPathOf(dir, pc.session_id)).size).toBe(size);
    expect(argsFiles(dir).size).toBe(files);
    // No use was consumed: a second purchase is still allowed under max_uses 2.
    expect(checked(pc, ins, ref("H-2"))).toMatchObject({ decision: "allow", repeat: false });
    expect(checked(pc, ins, ref("H-3")).reasons).toEqual(["uses-exhausted"]);
    await pc.close();
  });

  it("after valid_until the same order is judged fresh and denied expired, with a receipt", async () => {
    const dir = fresh();
    const clock = clockAt();
    const pc = openCheck(dir, clock);
    checked(pc, maxUses(2), ref("H-1"));
    clock.t = "2026-11-30T00:00:00.001Z";
    const late = checked(pc, maxUses(2), ref("H-1"));
    expect(late).toMatchObject({ decision: "deny", reasons: ["expired"], repeat: false, at: clock.t });
    expect(late.receipt).toMatchObject({ seq: 1 });
    await pc.close();
  });

  it("an earlier deny is not replayed", async () => {
    const dir = fresh();
    const clock = clockAt("2026-10-31T00:00:00.000Z");
    const pc = openCheck(dir, clock);
    expect(checked(pc, signedText(), ref("H-1")).reasons).toEqual(["not-yet-valid"]);
    clock.t = AT;
    expect(checked(pc, signedText(), ref("H-1"))).toMatchObject({ decision: "allow", repeat: false, receipt: { seq: 1 } });
    await pc.close();
  });
});

describe("test 7: record failure", () => {
  const boom = () => {
    throw Object.assign(new Error("EIO"), { code: "EIO" });
  };

  it("an unwritable chain gives deny record-failed, never allow, and nothing is written", async () => {
    const dir = fresh();
    let failing = true;
    const pc = openCheck(dir, clockAt(), { appendEntry: (i) => (failing ? boom() : appendReceipt(i)) });
    const r = checked(pc, signedText(), order());
    expect(r).toMatchObject({ decision: "deny", reasons: ["record-failed"], receipt: null });
    expect(argsFiles(dir).size).toBe(0);
    expect(statSync(chainPathOf(dir, pc.session_id)).size).toBe(0);
    // The append was cut back, so the chain is not broken: the next check is recorded.
    failing = false;
    expect(checked(pc, signedText(), order())).toMatchObject({ decision: "allow", receipt: { seq: 0 } });
    await pc.close();
    expect(runVerify({ chainPath: chainPathOf(dir, pc.session_id), identityPath: join(dir, IDENTITY_FILENAME) }).kind).toBe("valid");
  });

  it("a part-written line is cut back to the known-good length", async () => {
    const dir = fresh();
    let mode: "ok" | "torn" = "ok";
    const pc = openCheck(dir, clockAt(), {
      appendEntry: (i) => {
        if (mode === "ok") return appendReceipt(i);
        appendFileSync(i.chainPath, '{"v":"evidence.act');
        return boom();
      },
    });
    checked(pc, maxUses(3), ref("H-1"));
    mode = "torn";
    expect(checked(pc, maxUses(3), ref("H-2")).reasons).toEqual(["record-failed"]);
    mode = "ok";
    expect(checked(pc, maxUses(3), ref("H-3"))).toMatchObject({ decision: "allow", receipt: { seq: 1 } });
    await pc.close();
    expect(runVerify({ chainPath: chainPathOf(dir, pc.session_id), identityPath: join(dir, IDENTITY_FILENAME) })).toMatchObject({ kind: "valid", count: 2 });
  });

  it("an append that cannot be cut back breaks the chain: every later check is record-failed", async () => {
    const dir = fresh();
    let failing = true;
    const pc = openCheck(dir, clockAt(), { appendEntry: (i) => (failing ? boom() : appendReceipt(i)), truncateChain: boom });
    expect(checked(pc, signedText(), order()).reasons).toEqual(["record-failed"]);
    failing = false;
    expect(checked(pc, signedText(), order()).reasons).toEqual(["record-failed"]);
    expect(pc.logs.join("\n")).toMatch(/is broken and every later check is denied record-failed/);
    await pc.close();
  });

  it("unwritable arguments give record-failed; a failed deny keeps its reasons and adds record-failed", async () => {
    const dir = fresh();
    const pc = openCheck(dir, clockAt(), { writeArgs: boom });
    expect(checked(pc, signedText(), order())).toMatchObject({ decision: "deny", reasons: ["record-failed"], receipt: null });
    expect(checked(pc, signedText(), order((o) => (o["total_minor"] = "30001")))).toMatchObject({
      decision: "deny",
      reasons: ["limit-exceeded:max_total_minor", "record-failed"],
      exceeded: ["max_total_minor"],
      receipt: null,
    });
    await pc.close();
    expect(existsSync(chainPathOf(dir, pc.session_id))).toBe(false);
  });

  it("a gate clock that throws or answers no ISO UTC calendar instant gives record-failed, with nothing written", async () => {
    for (const now of [() => boom(), () => "2026-11-05T12:00:00+00:00", () => "2026-02-30T00:00:00Z", () => 1 as unknown as string, () => "2026-11-05T12:00:00.0000000001Z"]) {
      const dir = fresh();
      const pc = openCheck(dir, { now });
      expect(checked(pc, signedText(), order())).toMatchObject({ decision: "deny", reasons: ["record-failed"], at: null, receipt: null });
      await pc.close();
      expect(argsFiles(dir).size).toBe(0);
    }
  });

  it("a gate clock more than 5 s behind the last receipt gives record-failed", async () => {
    const dir = fresh();
    const clock = clockAt();
    const pc = openCheck(dir, clock);
    checked(pc, maxUses(3), ref("H-1"));
    clock.t = "2026-11-05T11:59:54.999Z";
    expect(checked(pc, maxUses(3), ref("H-2"))).toMatchObject({ reasons: ["record-failed"], at: clock.t, receipt: null });
    clock.t = "2026-11-05T11:59:55.000Z";
    expect(checked(pc, maxUses(3), ref("H-2")).decision).toBe("allow");
    await pc.close();
  });

  it("after close, check is record-failed", async () => {
    const pc = openCheck(fresh(), clockAt());
    await pc.close();
    expect(checked(pc, signedText(), order()).reasons).toEqual(["record-failed"]);
  });
});

describe("the witness", () => {
  it("each receipt's checkpoint goes to the witness, and close records the last", async () => {
    const stub = await startStubWitness();
    try {
      const dir = fresh();
      const pc = createPurchaseCheck({ dir, now: () => AT, witness: { baseUrl: stub.url, name: STUB_WITNESS_NAME, pinnedKey: stub.publicKeyHex } });
      expect(pc.check({ instruction: maxUses(2), order: ref("H-1") }).decision).toBe("allow");
      expect(pc.check({ instruction: maxUses(2), order: ref("H-2") }).decision).toBe("allow");
      await pc.close();
      const lines = readSidecar(sidecarPathFor(chainPathOf(dir, pc.session_id)));
      expect(lines.length).toBeGreaterThan(0);
      expect(lines.every((l) => l.witness_error === null && l.witness_receipt !== null)).toBe(true);
      expect(Math.max(...lines.map((l) => Number(l.witness_receipt!["count"])))).toBe(2);
      expect(recordsOf(dir, pc.session_id)).toHaveLength(2);
    } finally {
      await stub.close();
    }
  });

  it("an unreachable witness never changes an answer", async () => {
    const dir = fresh();
    const pc = createPurchaseCheck({ dir, now: () => AT, witness: { baseUrl: "http://127.0.0.1:9", name: STUB_WITNESS_NAME } });
    expect(pc.check({ instruction: signedText(), order: order() }).decision).toBe("allow");
    await pc.close();
    const lines = readSidecar(sidecarPathFor(chainPathOf(dir, pc.session_id)));
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.every((l) => l.witness_receipt === null && typeof l.witness_error === "string")).toBe(true);
  });
});
