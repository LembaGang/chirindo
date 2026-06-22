// DENY path — the headline. A denied tool call is NOT forwarded to the
// downstream; the client receives an isError result; a DENY receipt is
// written. The downstream never sees the call (proven by the fact that
// our fake downstream's `data` handler is never invoked for this id).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, runVerify } from "recorder";
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

describe("proxy DENY path", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("blocks tools/call without forwarding; returns isError; writes DENY receipt", async () => {
    const identity = await initIdentity(tmp);
    const policyPath = writePolicy(tmp, {
      deny: [{ tool: "delete", reason: "destructive: blocked by policy" }],
    });
    const chainPath = join(tmp, "chain.jsonl");

    const { clientIn, clientOut } = makeClientPipes();
    const downstream = makeFakeDownstream();

    // Crucial: track whether the downstream EVER saw the denied call.
    let downstreamSawDeniedCall = false;
    downstream.fromClient.on("data", (chunk: Buffer | string) => {
      const lines = chunk.toString("utf8").split("\n").filter((l) => l.trim());
      for (const line of lines) {
        const msg = JSON.parse(line) as {
          method?: string;
          params?: { name?: string };
        };
        if (msg.method === "tools/call" && msg.params?.name === "delete") {
          downstreamSawDeniedCall = true;
        }
      }
    });

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
      sessionId: "sess-deny",
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
        (latest as { id?: unknown }).id === 42,
    );

    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 42,
      method: "tools/call",
      params: { name: "delete", arguments: { path: "/etc" } },
    });

    const received = (await collector) as Array<{
      id: number;
      result?: { content: Array<{ text: string }>; isError: boolean };
    }>;
    const resp = received.find((r) => r.id === 42)!;
    // Per MCP spec §"Error Handling": tool execution errors use isError:true,
    // not a JSON-RPC `error` object. The agent sees the tool as failed.
    expect(resp.result?.isError).toBe(true);
    expect(resp.result?.content[0]?.text).toContain("destructive: blocked");

    // The headline: the downstream NEVER saw the denied call.
    expect(downstreamSawDeniedCall).toBe(false);

    // A DENY receipt was written.
    expect(handle.receiptCount()).toBe(1);
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    expect(file.records).toHaveLength(1);
    const rec = file.records[0]!;
    if (rec.event.type !== "mcp_call") throw new Error("expected mcp_call");
    expect(rec.event.outcome).toBe("denied");
    expect(rec.event.decision).toBe("deny");
    expect(rec.event.result_hash).toBeUndefined();
    expect(rec.gate?.result).toBe("halt");
    expect(rec.gate?.request_commitment).toBe(rec.request_commitment);

    const verifyResult = runVerify({
      chainPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(verifyResult.kind).toBe("valid");

    downstream.exit(0);
    await handle.done;
  });
});
