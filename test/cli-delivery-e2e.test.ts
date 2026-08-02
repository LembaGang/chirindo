// End-to-end for the delivery exit-code contract (§5.2). The machine-readable
// `delivery` discriminant is covered as a unit in delivery-proof-verify.test.ts;
// what only a real process can prove is the coarse signal the shell/CI caller
// actually reads: `$?`. A scripted caller that gates on exit 0 must NOT be told
// "success" for a receipt that referenced a payment and committed to no output.

import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  IDENTITY_FILENAME,
  paymentRefFromArtifacts,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

const CLI_ENTRY = resolve(import.meta.dirname, "..", "src", "cli.ts");
const IS_WIN = process.platform === "win32";

function runCli(args: string[]): {
  stdout: string;
  status: number | null;
} {
  const r = spawnSync(IS_WIN ? "npx.cmd" : "npx", ["tsx", CLI_ENTRY, ...args], {
    encoding: "utf8",
    shell: IS_WIN,
  });
  return { stdout: r.stdout ?? "", status: r.status };
}

const PAYMENT_REF = paymentRefFromArtifacts(
  {
    requirements: {
      resource: { url: "http://localhost:4021/paid" },
      accepts: [
        {
          scheme: "exact",
          network: "eip155:84532",
          amount: "1000",
          asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        },
      ],
    },
    settle: { success: true, transaction: "0x" + "ab".repeat(32) },
  },
  {
    scheme: "exact",
    network: "eip155:84532",
    facilitator: "coinbase-cdp",
    acceptsIndex: 0,
  },
);

describe("chirindo verify — delivery exit codes (CLI end-to-end)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-delivery-cli-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  // One paid-but-undelivered receipt: cryptographically VALID, delivery
  // unproven. Used by both cases below.
  async function buildUnprovenChain(): Promise<{
    chainPath: string;
    identityPath: string;
  }> {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery-cli",
      identity,
      server: "fake",
      toolName: "summarize",
      toolArgs: {},
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "deny", reason: "policy" },
    });
    return { chainPath, identityPath: join(tmp, IDENTITY_FILENAME) };
  }

  it("DELIVERY UNPROVEN exits 1 by default, on an otherwise VALID chain", async () => {
    const { chainPath, identityPath } = await buildUnprovenChain();
    const r = runCli(["verify", chainPath, "--key", identityPath]);
    expect(r.stdout).toContain("VALID —");
    expect(r.stdout).toContain(
      "DELIVERY UNPROVEN (payment referenced, no output commitment)",
    );
    expect(r.status).toBe(1);
  });

  it("--allow-unproven-delivery exits 0 but still prints the verdict", async () => {
    const { chainPath, identityPath } = await buildUnprovenChain();
    // Flag placed BEFORE the positional on purpose: a scripted caller will not
    // be careful about ordering, and the flag must never swallow the path.
    const r = runCli([
      "verify",
      "--allow-unproven-delivery",
      chainPath,
      "--key",
      identityPath,
    ]);
    expect(r.stdout).toContain("DELIVERY UNPROVEN");
    expect(r.stdout).not.toContain("DELIVERY PROVEN");
    expect(r.status).toBe(0);
  });

  it("a delivered paid call exits 0 and reads DELIVERY PROVEN", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery-cli",
      identity,
      server: "fake",
      toolName: "summarize",
      toolArgs: {},
      toolResult: { content: [{ type: "text", text: "ok" }], isError: false },
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "allow" },
    });
    const r = runCli([
      "verify",
      chainPath,
      "--key",
      join(tmp, IDENTITY_FILENAME),
    ]);
    expect(r.stdout).toContain("DELIVERY PROVEN");
    expect(r.status).toBe(0);
  });
});
