// TAMPER — the produced receipt is real recomputable evidence, not just a
// log line. Mutating a receipt's recorded event MUST be caught by the
// recorder's `runVerify` as TAMPERED with reason "request_commitment
// mismatch" (the A1.4 reorder), without any code change to the recorder.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  parseChainJsonl,
  runVerify,
  serializeChainJsonl,
} from "../src/vendor/recorder/index.js";
import { loadPolicy } from "../src/policy.js";
import { runProxy } from "../src/proxy.js";
import {
  cleanupTmpDir,
  collectJsonLines,
  initIdentity,
  makeClientPipes,
  makeFakeDownstream,
  makeTmpDir,
  writeLine,
  writePolicy,
} from "./helpers.js";

describe("receipt tamper detection (cross-tool: recorder verify)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("mutating a DENY receipt's tool_name breaks verify as request_commitment mismatch", async () => {
    const identity = await initIdentity(tmp);
    const policyPath = writePolicy(tmp, {
      deny: [{ tool: "delete", reason: "destructive" }],
    });
    const chainPath = join(tmp, "chain.jsonl");

    const { clientIn, clientOut } = makeClientPipes();
    const downstream = makeFakeDownstream();

    const handle = runProxy({
      clientIn,
      clientOut,
      spawnDownstream: () => downstream.downstream,
      loadPolicy: () => {
        try {
          return loadPolicy(policyPath);
        } catch {
          return null;
        }
      },
      identity,
      sessionId: "sess-tamper",
      serverLabel: "fake",
      chainPath,
      log: () => {
        /* quiet */
      },
    });

    const collector = collectJsonLines(
      clientOut,
      (latest) =>
        typeof latest === "object" &&
        latest !== null &&
        (latest as { id?: unknown }).id === 1,
    );
    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "delete", arguments: { path: "/etc" } },
    });
    await collector;

    // Sanity: clean chain verifies.
    const identityPath = join(tmp, "identity.json");
    expect(runVerify({ chainPath, identityPath }).kind).toBe("valid");

    // Tamper: rewrite the recorded tool_name (the attacker pretends the
    // denied call was for a benign tool, while keeping the signature).
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    const rec = file.records[0]!;
    if (rec.event.type !== "mcp_call") throw new Error("expected mcp_call");
    rec.event.tool_name = "echo";
    writeFileSync(chainPath, serializeChainJsonl(file), "utf8");

    const result = runVerify({ chainPath, identityPath });
    expect(result).toMatchObject({
      kind: "tampered",
      entry: 0,
      // After A1.4's reorder, event mutation trips request_commitment recompute.
      reason: "request_commitment mismatch",
    });

    downstream.exit(0);
    await handle.done;
  });
});
