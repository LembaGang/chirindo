// The two additive changes the trial recorder needs: appendReceipt's optional
// head, and buildCheckpointFromHead. Each must give the same bytes as the
// path that reads the chain.

import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { appendReceipt, type ReceiptInputs } from "../src/receipt.js";
import { buildCheckpoint, buildCheckpointFromHead } from "../src/checkpoint.js";
import { contentOf, entryHashOfCanonical, genesisPrevHash, jcsBytes, readChainFile } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { newDataDir, sampleOrder } from "./trial-helpers.js";

const { dir, identity } = newDataDir("chirindo-additive-");
afterAll(() => cleanupTmpDir(dir));

const inputs = (chainPath: string, i: number): ReceiptInputs => ({
  chainPath,
  sessionId: "sess-additive",
  identity,
  server: "shop",
  toolName: "record_agent_cart",
  toolArgs: { order: sampleOrder(`A-${i}`) },
  decision: { kind: "allow" },
  jwksUri: "https://shop.example/.well-known/jwks.json",
  ts: `2026-10-28T12:00:0${i}.000Z`,
});

describe("additive changes", () => {
  it("appendReceipt with a head writes the bytes it writes when it reads the chain", () => {
    const read = join(dir, "read.jsonl");
    const held = join(dir, "held.jsonl");
    let head = { seq: 0, prevHash: genesisPrevHash("sess-additive") };
    for (let i = 0; i < 5; i++) {
      appendReceipt(inputs(read, i));
      const r = appendReceipt({ ...inputs(held, i), head });
      head = { seq: i + 1, prevHash: entryHashOfCanonical(jcsBytes(contentOf(r))) };
    }
    const a = readChainFile(read).records.map((r) => JSON.stringify(r));
    const b = readChainFile(held).records.map((r) => JSON.stringify(r));
    expect(a).toHaveLength(5);
    expect(b).toEqual(a);
    // The head is used, not the file: an empty file with a head at seq 7.
    const prevHash = "sha256:" + "ab".repeat(32);
    const r = appendReceipt({ ...inputs(join(dir, "fresh.jsonl"), 0), head: { seq: 7, prevHash } });
    expect(r.seq).toBe(7);
    expect(r.prev_hash).toBe(prevHash);
  });

  it("buildCheckpointFromHead equals buildCheckpoint for the same head and ts", () => {
    const { records } = readChainFile(join(dir, "read.jsonl"));
    for (let n = 1; n <= records.length; n++) {
      const ts = `2026-10-28T13:00:0${n}.000Z`;
      const last = records[n - 1]!;
      const fromHead = buildCheckpointFromHead(
        { sessionId: "sess-additive", count: n, lastEntryHash: entryHashOfCanonical(jcsBytes(contentOf(last))) },
        identity,
        ts,
      );
      expect(JSON.stringify(fromHead)).toBe(JSON.stringify(buildCheckpoint(records.slice(0, n), identity, ts)));
    }
    expect(() => buildCheckpointFromHead({ sessionId: "s", count: 0, lastEntryHash: "sha256:" + "0".repeat(64) }, identity)).toThrow(
      "cannot checkpoint an empty chain",
    );
  });
});
