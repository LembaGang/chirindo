// ALLOW path — the request is forwarded to the downstream, the real
// response comes back to the client, and an ALLOW receipt is written.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, runVerify } from "../src/vendor/recorder/index.js";
import { runProxy } from "../src/proxy.js";
import { loadPolicy } from "../src/policy.js";
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

describe("proxy ALLOW path", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir();
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("forwards tools/call, returns downstream result, writes ALLOW receipt", async () => {
    const identity = await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [{ tool: "delete" }] });
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
      sessionId: "sess-allow",
      serverLabel: "fake",
      chainPath,
      log: () => {
        /* quiet */
      },
    });

    // Simulate a "downstream" that replies with a normal text result.
    downstream.fromClient.on("data", (chunk: Buffer | string) => {
      const lines = chunk.toString("utf8").split("\n").filter((l) => l.trim());
      for (const line of lines) {
        const req = JSON.parse(line) as {
          id: number;
          method: string;
          params: { name: string; arguments?: Record<string, unknown> };
        };
        if (req.method === "tools/call" && req.params.name === "echo") {
          const text = String(req.params.arguments?.["text"] ?? "");
          downstream.toClient.write(
            JSON.stringify({
              jsonrpc: "2.0",
              id: req.id,
              result: {
                content: [{ type: "text", text: `echo: ${text}` }],
                isError: false,
              },
            }) + "\n",
          );
        }
      }
    });

    const collector = collectJsonLines(
      clientOut,
      (latest) =>
        typeof latest === "object" &&
        latest !== null &&
        (latest as { id?: unknown }).id === 7,
    );

    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "echo", arguments: { text: "hello" } },
    });

    const received = (await collector) as Array<{
      id: number;
      result?: { content: Array<{ text: string }>; isError: boolean };
    }>;
    const resp = received.find((r) => r.id === 7)!;
    expect(resp.result?.isError).toBe(false);
    expect(resp.result?.content[0]?.text).toBe("echo: hello");

    // Receipt was written.
    expect(handle.receiptCount()).toBe(1);
    expect(existsSync(chainPath)).toBe(true);
    const file = parseChainJsonl(readFileSync(chainPath, "utf8"));
    expect(file.records).toHaveLength(1);
    const rec = file.records[0]!;
    expect(rec.event.type).toBe("mcp_call");
    if (rec.event.type === "mcp_call") {
      expect(rec.event.outcome).toBe("executed");
      expect(rec.event.tool_name).toBe("echo");
      expect(rec.event.decision).toBe("allow");
      expect(rec.event.result_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
    expect(rec.gate?.result).toBe("act");
    expect(rec.gate?.gate_family).toBe("permit");
    // Continuity invariant: gate.request_commitment == record.request_commitment.
    expect(rec.gate?.request_commitment).toBe(rec.request_commitment);

    // Chain verifies via the recorder's verify CLI.
    const verifyResult = runVerify({
      chainPath,
      identityPath: join(tmp, "identity.json"),
    });
    expect(verifyResult.kind).toBe("valid");

    downstream.exit(0);
    await handle.done;
  });
});
