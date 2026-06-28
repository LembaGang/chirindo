// FAIL-CLOSED — when policy is unevaluable, the proxy DENIES, even for
// tools that would otherwise be allowed. The recorder is observe-only;
// the gate is fail-closed. This is the opposite posture and it is correct.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, runVerify } from "../src/vendor/recorder/index.js";
import { runProxy } from "../src/proxy.js";
import {
  cleanupTmpDir,
  collectJsonLines,
  initIdentity,
  makeClientPipes,
  makeFakeDownstream,
  makeTmpDir,
  writeLine,
} from "./helpers.js";

describe("proxy FAIL-CLOSED path", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("denies a would-be-allowed call when policy returns null (unevaluable)", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");

    const { clientIn, clientOut } = makeClientPipes();
    const downstream = makeFakeDownstream();

    let downstreamSawAnyCall = false;
    downstream.fromClient.on("data", (chunk: Buffer | string) => {
      const lines = chunk.toString("utf8").split("\n").filter((l) => l.trim());
      for (const line of lines) {
        const msg = JSON.parse(line) as { method?: string };
        if (msg.method === "tools/call") downstreamSawAnyCall = true;
      }
    });

    const handle = runProxy({
      clientIn,
      clientOut,
      spawnDownstream: () => downstream.downstream,
      // Policy is unevaluable — loader returns null. The gate MUST deny.
      loadPolicy: () => null,
      identity,
      sessionId: "sess-failclosed",
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
        (latest as { id?: unknown }).id === 99,
    );

    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 99,
      method: "tools/call",
      params: { name: "echo", arguments: { text: "should not run" } },
    });

    const received = (await collector) as Array<{
      id: number;
      result?: { content: Array<{ text: string }>; isError: boolean };
    }>;
    const resp = received.find((r) => r.id === 99)!;
    expect(resp.result?.isError).toBe(true);
    expect(resp.result?.content[0]?.text).toContain("fail-closed");

    // The would-be-allowed call did NOT reach the downstream.
    expect(downstreamSawAnyCall).toBe(false);

    // A DENY receipt was written.
    expect(handle.receiptCount()).toBe(1);
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    expect(file.records[0]!.gate?.result).toBe("halt");

    const verifyResult = runVerify({
      chainPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(verifyResult.kind).toBe("valid");

    downstream.exit(0);
    await handle.done;
  });

  it("denies when policy evaluator throws", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");

    const { clientIn, clientOut } = makeClientPipes();
    const downstream = makeFakeDownstream();

    const handle = runProxy({
      clientIn,
      clientOut,
      spawnDownstream: () => downstream.downstream,
      loadPolicy: () => {
        throw new Error("policy file corrupted on disk");
      },
      identity,
      sessionId: "sess-throw",
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
        (latest as { id?: unknown }).id === 100,
    );

    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 100,
      method: "tools/call",
      params: { name: "echo", arguments: { text: "x" } },
    });

    const received = (await collector) as Array<{
      id: number;
      result?: { content: Array<{ text: string }>; isError: boolean };
    }>;
    const resp = received.find((r) => r.id === 100)!;
    expect(resp.result?.isError).toBe(true);
    expect(resp.result?.content[0]?.text).toContain("fail-closed");

    downstream.exit(0);
    await handle.done;
  });
});
