// B-481 T2: the receiver's writer (src/otel/append.ts, ruling L1 c). Its
// bytes are held to the vendored Chain.append's, line for line, and its chain
// to the repository's own verifier.

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openObservedWriter } from "../src/otel/append.js";
import { GATE_AGENT } from "../src/receipt.js";
import {
  Chain,
  argsHash,
  entryHashOfCanonical,
  genesisPrevHash,
  jcsBytes,
  loadFullIdentity,
  runInit,
  runVerify,
  type ToolCallEvent,
} from "../src/vendor/recorder/index.js";

const tmp = () => mkdtempSync(join(tmpdir(), "b481-t2-append-"));
function key(dir: string) {
  const r = runInit({ dir });
  if (r.kind !== "created") throw new Error("init " + r.kind);
  return { ...loadFullIdentity(r.identityPath, r.privateKeyPath), identityPath: r.identityPath };
}
const ev = (i: number, outcome: "executed" | "errored" = "executed"): ToolCallEvent => ({
  type: "tool_call",
  outcome,
  tool_name: i % 2 ? "lookup" : `otel.span:step ${i}`,
  args_hash: argsHash({ i }),
  decision: "observed",
  decision_source: "n/a",
});
const ts = (i: number) => `2026-11-16T10:00:${String(i).padStart(2, "0")}.000Z`;
const lines = (p: string) => readFileSync(p, "utf8").split("\n").filter(Boolean);
const SESSION = "0123456789abcdef0123456789abcdef";

describe("openObservedWriter", { timeout: 120_000 }, () => {
  it("writes the same bytes as the vendored Chain.append, record for record", () => {
    const dir = tmp();
    const id = key(dir);
    const w = openObservedWriter({ chainPath: join(dir, "w.jsonl"), sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    const chain = new Chain({ sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey });
    const ref: string[] = [];
    for (let i = 0; i < 5; i++) {
      const e = ev(i, i === 3 ? "errored" : "executed");
      const a = w.append(e, ts(i));
      const b = chain.append(e, ts(i));
      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
      ref.push(JSON.stringify(b));
    }
    expect(lines(join(dir, "w.jsonl"))).toEqual(ref);
    expect(w.count).toBe(5);
  });

  it("writes a chain the repository's verifier accepts, with gate null and decision observed", () => {
    const dir = tmp();
    const id = key(dir);
    const p = join(dir, "c.jsonl");
    const w = openObservedWriter({ chainPath: p, sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    for (let i = 0; i < 7; i++) w.append(ev(i, i === 3 ? "errored" : "executed"), ts(i));
    const r = runVerify({ chainPath: p, identityPath: id.identityPath });
    expect(r.kind).toBe("valid");
    if (r.kind === "valid") expect(r.count).toBe(7);
    const recs = lines(p).map((l) => JSON.parse(l));
    expect(recs.map((x) => x.seq)).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(new Set(recs.map((x) => JSON.stringify([x.gate, x.event.decision, x.event.decision_source])))).toEqual(new Set([JSON.stringify([null, "observed", "n/a"])]));
    expect(recs.filter((x) => x.event.outcome === "errored").length).toBe(1);
  });

  it("links each record to the last: prev_hash and lastEntryHash", () => {
    const dir = tmp();
    const id = key(dir);
    const w = openObservedWriter({ chainPath: join(dir, "c.jsonl"), sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    expect(w.lastEntryHash).toBe(genesisPrevHash(SESSION));
    const r0 = w.append(ev(0), ts(0));
    expect(r0.prev_hash).toBe(genesisPrevHash(SESSION));
    const { sig: _sig, ...content0 } = r0;
    expect(w.lastEntryHash).toBe(entryHashOfCanonical(jcsBytes(content0)));
    const r1 = w.append(ev(1), ts(1));
    expect(r1.prev_hash).toBe(entryHashOfCanonical(jcsBytes(content0)));
    expect(r1.seq).toBe(1);
  });

  it("refuses an event that is not tool_call, observed, n/a, and writes nothing", () => {
    const dir = tmp();
    const id = key(dir);
    const p = join(dir, "c.jsonl");
    const w = openObservedWriter({ chainPath: p, sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    expect(() => w.append({ ...ev(0), decision: "allow" }, ts(0))).toThrow(/only tool_call events/);
    expect(() => w.append({ ...ev(0), decision_source: "config" }, ts(0))).toThrow(/only tool_call events/);
    expect(() => w.append({ ...ev(0), type: "mcp_call" } as unknown as ToolCallEvent, ts(0))).toThrow(/only tool_call events/);
    expect(w.count).toBe(0);
    expect(() => readFileSync(p)).toThrow();
  });

  it("moves the head only after the line is written: a failed write leaves seq and prev_hash as they were", () => {
    const dir = tmp();
    const id = key(dir);
    const p = join(dir, "c.jsonl");
    const w = openObservedWriter({ chainPath: p, sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    w.append(ev(0), ts(0));
    const head = w.lastEntryHash;
    const bad = openObservedWriter({ chainPath: join(dir, "missing", "c.jsonl"), sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    expect(() => bad.append(ev(0), ts(0))).toThrow();
    expect(bad.count).toBe(0);
    expect(bad.lastEntryHash).toBe(genesisPrevHash(SESSION));
    mkdirSync(join(dir, "missing"));
    expect(bad.append(ev(0), ts(0)).seq).toBe(0);
    expect(w.lastEntryHash).toBe(head);
    expect(w.append(ev(1), ts(1)).seq).toBe(1);
    expect(runVerify({ chainPath: p, identityPath: id.identityPath }).kind).toBe("valid");
  });

  it("a chain it wrote fails verification after an edit, a removal or a swap", () => {
    const dir = tmp();
    const id = key(dir);
    const p = join(dir, "c.jsonl");
    const w = openObservedWriter({ chainPath: p, sessionId: SESSION, agent: GATE_AGENT, kid: id.kid, privateKey: id.privateKey, publicKey: id.publicKey });
    for (let i = 0; i < 7; i++) w.append(ev(i), ts(i));
    const ls = lines(p);
    const edited = [...ls];
    edited[4] = edited[4]!.replace('"outcome":"executed"', '"outcome":"errored"');
    expect(edited[4]).not.toBe(ls[4]);
    const removed = ls.filter((_, i) => i !== 4);
    const swapped = [...ls];
    [swapped[2], swapped[3]] = [swapped[3]!, swapped[2]!];
    for (const [name, body] of [["edited", edited], ["removed", removed], ["swapped", swapped]] as const) {
      const q = join(dir, `${name}.jsonl`);
      writeFileSync(q, body.join("\n") + "\n");
      expect(runVerify({ chainPath: q, identityPath: id.identityPath }).kind, name).not.toBe("valid");
    }
  });
});
