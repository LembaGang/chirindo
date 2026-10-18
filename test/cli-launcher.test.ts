// The one launcher every CLI end-to-end test uses (test/helpers.ts runCli,
// B-329). It runs node on tsx's CLI file with a spawn timeout below the
// per-test budget, so a child that hangs fails the test with a message that
// names a spawn timeout, before vitest's own test timeout would fire.

import { describe, expect, it } from "vitest";
import {
  CLI_E2E_TIMEOUT_MS,
  CLI_SPAWN_TIMEOUT_MS,
  runCli,
} from "./helpers.js";

describe("CLI e2e launcher (test/helpers.ts)", () => {
  it("runs the CLI through node and tsx directly: --help exits 0", () => {
    const r = runCli(["--help"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Usage:");
  }, CLI_E2E_TIMEOUT_MS);

  it("a child that outlives its spawn timeout fails as a spawn timeout, not an assertion", () => {
    // 1 ms: node cannot start tsx and the CLI that fast, so the timeout fires.
    expect(() => runCli(["--help"], { timeoutMs: 1 })).toThrow(
      /^spawn timeout: `chirindo --help` did not exit within 1 ms and was killed/,
    );
  }, CLI_E2E_TIMEOUT_MS);

  it("the spawn timeout (25 s) is below the per-test budget (30 s)", () => {
    expect(CLI_SPAWN_TIMEOUT_MS).toBe(25_000);
    expect(CLI_E2E_TIMEOUT_MS).toBe(30_000);
    expect(CLI_SPAWN_TIMEOUT_MS).toBeLessThan(CLI_E2E_TIMEOUT_MS);
  });
});
