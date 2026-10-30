// The test memory guard (scripts/test-guard.mjs, B-432 T2 ruling 2): the
// decision at the three bands and both edges, the vitest arguments it adds,
// and that a refusal starts nothing.

import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT } from "./trial-helpers.js";
// @ts-expect-error -- plain .mjs without declarations
import { FLOOR_KB, MIN_KB, decide, main, message, vitestArgs } from "../scripts/test-guard.mjs";

describe("test guard: the decision", () => {
  it("bands and edges: 3,000,000 KB and above parallel, 1,000,000 to 2,999,999 serial, below refuse", () => {
    expect([FLOOR_KB, MIN_KB]).toEqual([3_000_000, 1_000_000]);
    const cases: [number, string][] = [
      [8_000_000, "parallel"],
      [3_000_000, "parallel"],
      [2_999_999, "serial"],
      [2_000_000, "serial"],
      [1_000_000, "serial"],
      [999_999, "refuse"],
      [0, "refuse"],
      [Number.NaN, "refuse"],
    ];
    for (const [kb, want] of cases) expect([kb, decide(kb)]).toEqual([kb, want]);
  });

  it("vitest arguments: serial adds --no-file-parallelism once; caller arguments pass through", () => {
    expect(vitestArgs("parallel", ["test/a.test.ts"])).toEqual(["run", "test/a.test.ts"]);
    expect(vitestArgs("serial", ["-t", "x"])).toEqual(["run", "--no-file-parallelism", "-t", "x"]);
    expect(vitestArgs("serial", ["--no-file-parallelism"])).toEqual(["run", "--no-file-parallelism"]);
    expect(vitestArgs("refuse", [])).toBeNull();
  });

  it("messages print the reading and the decision; the refusal names the floor and the closable apps", () => {
    expect(message("parallel", 3_250_600)).toMatch(/3,250,600 KB free .*running vitest normally/);
    expect(message("serial", 1_924_068)).toMatch(/1,924,068 KB free.*--no-file-parallelism/);
    const r = message("refuse", 999_999);
    expect(r).toMatch(/vitest NOT started/);
    expect(r).toMatch(/3,000,000 KB/);
    expect(r).toMatch(/NordVPN/);
    expect(r).toMatch(/Google Drive for desktop \(restart it after the run\)/);
  });
});

describe("test guard: main", () => {
  const fake = () => {
    const calls: string[][] = [];
    return { calls, spawnVitest: async (a: string[]) => (calls.push(a), 7) };
  };

  it("below 1,000,000 KB it exits 2 and starts nothing", async () => {
    const f = fake();
    const logs: string[] = [];
    expect(await main(["x"], { freeKb: 999_999, spawnVitest: f.spawnVitest, log: (l: string) => logs.push(l) })).toBe(2);
    expect(f.calls).toEqual([]);
    expect(logs).toHaveLength(1);
  });

  it("between the bands it runs vitest serially and returns vitest's exit code", async () => {
    const f = fake();
    expect(await main(["y"], { freeKb: 1_500_000, spawnVitest: f.spawnVitest, log: () => {} })).toBe(7);
    expect(f.calls).toEqual([["run", "--no-file-parallelism", "y"]]);
  });

  it("at the floor it runs vitest normally", async () => {
    const f = fake();
    await main([], { freeKb: 3_000_000, spawnVitest: f.spawnVitest, log: () => {} });
    expect(f.calls).toEqual([["run"]]);
  });

  it("imported, it does not run itself; executed, it prints its reading first", () => {
    // Executed with --help, so vitest prints its help and runs no test (never
    // this file again): what matters is the guard's own first line.
    const r = spawnSync(process.execPath, [join(ROOT, "scripts", "test-guard.mjs"), "--help"], { cwd: ROOT, encoding: "utf8", timeout: 60_000 });
    expect(r.stderr.split("\n")[0]).toMatch(/^\[test-guard\] [0-9,]+ KB free/);
  }, 60_000);
});
