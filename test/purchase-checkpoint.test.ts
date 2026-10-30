// B-432 T2 ruling 3: the purchase check signs each witness checkpoint from its
// in-memory head (buildCheckpointFromHead), never by re-reading the chain. The
// checkpoints it sent, as its sidecar records them, must equal byte for byte
// what the re-read path (buildCheckpoint over the chain's records) signs for
// the same head and ts, at 1, 2 and 50 receipts.

import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { buildCheckpoint } from "../src/checkpoint.js";
import { createPurchaseCheck } from "../src/purchase/check.js";
import { readSidecar, sidecarPathFor } from "../src/witness.js";
import { IDENTITY_FILENAME, PRIVATE_KEY_FILENAME, loadFullIdentity, readChainFile } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { AT, chainPathOf, checkDir, constraintsOf, order, signedText } from "./purchase-helpers.js";
import { startStubWitness, STUB_WITNESS_NAME } from "./witness-stub.js";

// Counts reads of a chain file, so the test can show none happen while the
// checks run: the same bytes from a re-read would otherwise pass unnoticed.
const reads = vi.hoisted(() => ({ n: 0 }));
vi.mock("../src/vendor/recorder/index.js", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../src/vendor/recorder/index.js")>();
  return { ...orig, readChainFile: (p: string) => (reads.n++, orig.readChainFile(p)) };
});

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));

describe("checkpoints from the in-memory head", () => {
  it("equal the re-read path's bytes at 1, 2 and 50 receipts", async () => {
    const stub = await startStubWitness();
    try {
      const dir = checkDir();
      dirs.push(dir);
      const pc = createPurchaseCheck({ dir, now: () => AT, witness: { baseUrl: stub.url, name: STUB_WITNESS_NAME, pinnedKey: stub.publicKeyHex } });
      const ins = signedText((b) => (constraintsOf(b)["max_uses"] = 100));
      for (let i = 0; i < 50; i++) {
        // Allows and denies alike are receipts.
        const ord = order((o) => ((o["merchant_order_id"] = `C-${i}`), i % 7 === 3 && (o["total_minor"] = "99999")));
        expect(pc.check({ instruction: ins, order: ord }).receipt).not.toBeNull();
      }
      await pc.close();
      // 50 receipts, 50 or more checkpoints signed and sent, and no chain file read.
      expect(reads.n).toBe(0);

      const chain = chainPathOf(dir, pc.session_id);
      const { records } = readChainFile(chain);
      expect(records).toHaveLength(50);
      const identity = loadFullIdentity(join(dir, IDENTITY_FILENAME), join(dir, PRIVATE_KEY_FILENAME));
      const byCount = new Map(readSidecar(sidecarPathFor(chain)).map((l) => [Number((l.checkpoint as { count: number }).count), l.checkpoint]));
      for (const n of [1, 2, 50]) {
        const sent = byCount.get(n);
        expect([n, sent !== undefined]).toEqual([n, true]);
        const reread = buildCheckpoint(records.slice(0, n), identity, (sent as { ts: string }).ts);
        expect([n, JSON.stringify(sent)]).toEqual([n, JSON.stringify(reread)]);
      }
      // Every checkpoint sent equals the re-read path's, not only the three named.
      for (const [n, cp] of byCount) expect(JSON.stringify(cp)).toBe(JSON.stringify(buildCheckpoint(records.slice(0, n), identity, (cp as { ts: string }).ts)));
    } finally {
      await stub.close();
    }
  }, 60_000);
});
