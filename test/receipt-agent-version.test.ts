// A receipt's `agent` names the version of the gate that wrote it (0.5.3).
// Before 0.5.3 every receipt carried the constant {vendor:"chirindo",
// version:"0.0.1"} whatever the package version was (src/receipt.ts
// GATE_AGENT). Receipts already written keep their bytes; this is about new
// ones, written through appendReceipt directly and through the proxy.

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, runVerify } from "../src/vendor/recorder/index.js";
import { GATE_AGENT, appendReceipt } from "../src/receipt.js";
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

const PACKAGE_VERSION = (
  JSON.parse(
    readFileSync(resolve(import.meta.dirname, "..", "package.json"), "utf8"),
  ) as { version: string }
).version;

describe("receipt agent: the gate's package version", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-agent-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("a new receipt's agent.version equals package.json's version", async () => {
    const identity = await initIdentity(tmp);
    const chainPath = join(tmp, "chain.jsonl");
    const rec = appendReceipt({
      chainPath,
      sessionId: "sess-agent-version",
      identity,
      server: "fake",
      toolName: "echo",
      toolArgs: { text: "hi" },
      toolResult: { content: [{ type: "text", text: "hi" }], isError: false },
      decision: { kind: "allow" },
    });
    expect(GATE_AGENT).toEqual({ vendor: "chirindo", version: PACKAGE_VERSION });
    expect(rec.agent).toEqual({ vendor: "chirindo", version: PACKAGE_VERSION });
    const onDisk = parseChainJsonl(readFileSync(chainPath, "utf8")).records[0]!;
    expect(onDisk.agent).toEqual({ vendor: "chirindo", version: PACKAGE_VERSION });
    expect(
      runVerify({ chainPath, identityPath: join(tmp, "identity.json") }).kind,
    ).toBe("valid");
  });

  it("the proxy's ALLOW and DENY receipts carry the package version", async () => {
    const identity = await initIdentity(tmp);
    const policyPath = writePolicy(tmp, { deny: [{ tool: "delete" }] });
    const chainPath = join(tmp, "chain.jsonl");
    const { clientIn, clientOut } = makeClientPipes();
    const downstream = makeFakeDownstream();
    downstream.fromClient.on("data", (chunk: Buffer | string) => {
      for (const line of chunk.toString("utf8").split("\n").filter((l) => l.trim())) {
        const req = JSON.parse(line) as { id: number };
        downstream.toClient.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: req.id,
            result: { content: [{ type: "text", text: "ok" }], isError: false },
          }) + "\n",
        );
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
      sessionId: "sess-agent-proxy",
      serverLabel: "fake",
      chainPath,
      log: () => {},
    });
    const collector = collectJsonLines(
      clientOut,
      (_latest, all) => all.length === 2,
    );
    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "echo", arguments: {} },
    });
    writeLine(clientIn, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "delete", arguments: {} },
    });
    await collector;

    const records = parseChainJsonl(readFileSync(chainPath, "utf8")).records;
    expect(records).toHaveLength(2);
    const decisions = records.map((r) =>
      r.event.type === "mcp_call" ? r.event.decision : "?",
    );
    expect(decisions.sort()).toEqual(["allow", "deny"]);
    for (const r of records) {
      expect(r.agent).toEqual({ vendor: "chirindo", version: PACKAGE_VERSION });
    }
    downstream.exit(0);
    await handle.done;
  });
});
