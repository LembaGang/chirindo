// D3(a): a record costs the same at entry 10,000 as at entry 100 (the head is
// kept in memory), with the witness unreachable. Slow on Windows with
// real-time scanning: 10,000 retained files are written, hence 600 s.

import { performance } from "node:perf_hooks";
import { afterAll, describe, expect, it } from "vitest";
import { createTrialRecorder } from "../src/trial/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { STUB_WITNESS_NAME } from "./witness-stub.js";
import { closedPortUrl, newDataDir, p95, sampleInput } from "./trial-helpers.js";

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) cleanupTmpDir(d);
});

function timed(rec: ReturnType<typeof createTrialRecorder>, from: number, n: number): { ms: number[]; ok: boolean } {
  const ms: number[] = [];
  let ok = true;
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    const r = rec.record(sampleInput(`P-${from + i}`, from + i));
    ms.push(performance.now() - t0);
    if (!r.ok) ok = false;
  }
  return { ms, ok };
}

describe("trial recorder: cost at length", () => {
  it("(a) 100 records after 100 and after 10,000 entries: p95 under 50 ms, and the second at most max(3x the first, 10 ms)", async () => {
    const { dir } = newDataDir();
    dirs.push(dir);
    const rec = createTrialRecorder({
      dir,
      serverLabel: "shop",
      witness: { baseUrl: await closedPortUrl(), name: STUB_WITNESS_NAME },
      logger: () => {},
    });
    let filled = 0;
    let fillOk = true;
    const fill = async (to: number) => {
      while (filled < to) {
        const r = rec.record(sampleInput(`F-${filled}`, filled));
        if (!r.ok) fillOk = false;
        filled++;
        // Let the witness driver run now and then, as it would in a service.
        if (filled % 500 === 0) await new Promise((res) => setImmediate(res));
      }
    };
    await fill(100);
    const first = timed(rec, filled, 100);
    filled += 100;
    await fill(10_000);
    const second = timed(rec, filled, 100);
    filled += 100;
    await rec.close(1_000);

    const p1 = p95(first.ms);
    const p2 = p95(second.ms);
    console.log(`D3(a) p95 after 100 entries: ${p1.toFixed(2)} ms; after 10,000 entries: ${p2.toFixed(2)} ms`);
    expect(fillOk).toBe(true);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    expect(p1).toBeLessThan(50);
    expect(p2).toBeLessThan(50);
    expect(p2).toBeLessThanOrEqual(Math.max(3 * p1, 10));
  }, 600_000);
});
