// Pinning surface + honest output (spec C).
//
// Without a pin, VALID means only "internally consistent under the presented
// key." Pinning a set of RFC 7638 thumbprints turns VALID into an assertion
// about WHO signed: a resolved key outside the set is INVALID(untrusted_key).
// Either way the output ALWAYS names the verifying key + where it came from.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  formatVerifyResult,
  loadIdentity,
  rfc7638Thumbprint,
  runVerify,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

const FIXTURE_DIR = join(import.meta.dirname, "fixtures", "legacy-v0");

describe("verify pinning + honest output", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  async function makeChain(): Promise<{ chainPath: string; identityPath: string; tp: string }> {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    appendReceipt({
      chainPath,
      sessionId: "sess-pin",
      identity,
      server: "files",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      decision: { kind: "allow" },
    });
    return {
      chainPath,
      identityPath: join(tmp, "identity.json"),
      tp: rfc7638Thumbprint(identity.publicKey),
    };
  }

  it("pinned-pass: resolved key IS in the pinned set → VALID, key named", async () => {
    const { chainPath, identityPath, tp } = await makeChain();
    const result = runVerify({
      chainPath,
      identityPath,
      expectThumbprints: [tp],
      keySource: "flag",
      keyOrigin: identityPath,
    });
    expect(result.kind).toBe("valid");
    if (result.kind === "valid") {
      expect(result.key.thumbprint).toBe(tp);
      expect(result.key.source).toBe("flag");
      expect(result.key.origin).toBe(identityPath);
    }
  });

  it("pinned-fail: resolved key NOT in the pinned set → INVALID(untrusted_key)", async () => {
    const { chainPath, identityPath, tp } = await makeChain();
    const result = runVerify({
      chainPath,
      identityPath,
      expectThumbprints: ["not-the-key-you-are-looking-for"],
      keySource: "flag",
      keyOrigin: identityPath,
    });
    expect(result.kind).toBe("invalid");
    if (result.kind === "invalid") {
      expect(result.reason).toBe("untrusted_key");
      expect(result.entry).toBe("chain");
      // The rejected key is still named — the consumer sees WHICH key failed.
      expect(result.key.thumbprint).toBe(tp);
    }
  });

  it("honest output ALWAYS names the verifying key on VALID", async () => {
    const { chainPath, identityPath, tp } = await makeChain();
    const result = runVerify({
      chainPath,
      identityPath,
      keySource: "flag",
      keyOrigin: identityPath,
    });
    const { line, exitCode } = formatVerifyResult(result);
    expect(exitCode).toBe(0);
    expect(line).toContain(
      `verified under key ${tp} resolved from flag (${identityPath})`,
    );
  });

  it("untrusted_key formats as INVALID exit 1 and still names the key", async () => {
    const { chainPath, identityPath, tp } = await makeChain();
    const result = runVerify({
      chainPath,
      identityPath,
      expectThumbprints: ["some-other-thumbprint"],
      keySource: "flag",
      keyOrigin: identityPath,
    });
    const { line, exitCode } = formatVerifyResult(result);
    expect(exitCode).toBe(1);
    expect(line).toMatch(/^INVALID — entry chain: untrusted_key/);
    expect(line).toContain(`verified under key ${tp}`);
  });

  it("no pin ⇒ VALID (internally consistent), pinning is opt-in", async () => {
    const { chainPath, identityPath } = await makeChain();
    // Empty/absent expectThumbprints must NOT reject.
    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid");
  });

  it("pinning works for a legacy /0 chain too", () => {
    const chainPath = join(FIXTURE_DIR, "chain.jsonl");
    const identityPath = join(FIXTURE_DIR, "identity.json");
    const tp = rfc7638Thumbprint(loadIdentity(identityPath).publicKey);

    // Sanity: the fixture is genuinely v0.
    const rec = JSON.parse(
      readFileSync(chainPath, "utf8").split("\n")[0]!,
    ) as { v: string };
    expect(rec.v).toBe("evidence.action/0");

    const pass = runVerify({ chainPath, identityPath, expectThumbprints: [tp] });
    expect(pass.kind).toBe("valid");

    const fail = runVerify({
      chainPath,
      identityPath,
      expectThumbprints: ["wrong"],
    });
    expect(fail.kind).toBe("invalid");
    if (fail.kind === "invalid") expect(fail.reason).toBe("untrusted_key");
  });
});
