// Every tools/call goes through the gate, whatever its id (0.5.3).
//
// Before 0.5.3 a tools/call with no `id` member, or without `"jsonrpc":"2.0"`,
// was forwarded to the downstream with no policy check and no receipt, and one
// whose id was null or not a string or an integer was forwarded and then never
// matched to a receipt. These tests drive the proxy in-process against a fake
// downstream that records every line it receives, so "the downstream never saw
// it" is an assertion on that record, not an inference.
//
// MCP (basic/, Messages > Requests, revisions 2025-11-25 and 2026-07-28):
// "Requests MUST include a string or integer ID." and "Unlike base JSON-RPC,
// the ID MUST NOT be null." Batching was removed in 2025-06-18; the stdio
// transport carries "a single JSON-RPC request, notification, or response" per
// line.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChainJsonl, runVerify } from "../src/vendor/recorder/index.js";
import type { SignedRecord } from "../src/vendor/recorder/index.js";
import { loadPolicy, type Policy } from "../src/policy.js";
import { runProxy, type ProxyHandle } from "../src/proxy.js";
import {
  cleanupTmpDir,
  collectJsonLines,
  initIdentity,
  makeClientPipes,
  makeFakeDownstream,
  makeTmpDir,
  writePolicy,
} from "./helpers.js";

const INVALID_ID_ERROR = {
  jsonrpc: "2.0",
  id: null,
  error: {
    code: -32600,
    message: "Invalid Request: tools/call needs a string or integer id",
  },
};

interface Gate {
  clientIn: PassThrough;
  clientOut: PassThrough;
  handle: ProxyHandle;
  chainPath: string;
  // Every line the downstream received, exactly as written to its stdin.
  forwarded: string[];
  logs: string[];
  stop: () => Promise<void>;
}

async function startGate(tmp: string, policy: Policy): Promise<Gate> {
  const identity = await initIdentity(tmp);
  const policyPath = writePolicy(tmp, policy);
  const chainPath = join(tmp, "chain.jsonl");
  const { clientIn, clientOut } = makeClientPipes();
  const downstream = makeFakeDownstream();
  const forwarded: string[] = [];
  let buf = "";
  downstream.fromClient.on("data", (chunk: Buffer | string) => {
    buf += chunk.toString("utf8");
    const parts = buf.split("\n");
    buf = parts.pop() ?? "";
    for (const line of parts) {
      if (line.length === 0) continue;
      forwarded.push(line);
      // A minimal MCP server: answer every single message that carries an id.
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (
        typeof msg === "object" &&
        msg !== null &&
        !Array.isArray(msg) &&
        Object.prototype.hasOwnProperty.call(msg, "id")
      ) {
        downstream.toClient.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: (msg as { id: unknown }).id,
            result: { content: [{ type: "text", text: "ran" }], isError: false },
          }) + "\n",
        );
      }
    }
  });
  const logs: string[] = [];
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
    sessionId: "sess-request-ids",
    serverLabel: "fake",
    chainPath,
    log: (m) => logs.push(m),
  });
  return {
    clientIn,
    clientOut,
    handle,
    chainPath,
    forwarded,
    logs,
    stop: async () => {
      downstream.exit(0);
      await handle.done;
    },
  };
}

// Write raw lines, then a ping with id "sync". Lines are handled in order, so
// once the ping's answer reaches the client every earlier line has been dealt
// with. Returns every message the client received, the ping's answer last.
async function send(gate: Gate, lines: string[]): Promise<unknown[]> {
  const collector = collectJsonLines(
    gate.clientOut,
    (latest) =>
      typeof latest === "object" &&
      latest !== null &&
      (latest as { id?: unknown }).id === "sync",
  );
  for (const l of lines) gate.clientIn.write(l + "\n");
  gate.clientIn.write(JSON.stringify({ jsonrpc: "2.0", id: "sync", method: "ping" }) + "\n");
  return collector;
}

function receipts(gate: Gate): SignedRecord[] {
  try {
    return parseChainJsonl(readFileSync(gate.chainPath, "utf8")).records;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw e;
  }
}

function forwardedMethods(gate: Gate): string[] {
  return gate.forwarded.map((l) => {
    try {
      const m = JSON.parse(l) as { method?: unknown };
      return typeof m.method === "string" ? m.method : "<no method>";
    } catch {
      return "<not json>";
    }
  });
}

function refuseLogs(gate: Gate): string[] {
  return gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
}

function expectDenyReceipt(rec: SignedRecord, toolName: string): void {
  if (rec.event.type !== "mcp_call") throw new Error("expected mcp_call");
  expect(rec.event.tool_name).toBe(toolName);
  expect(rec.event.decision).toBe("deny");
  expect(rec.event.outcome).toBe("denied");
  expect(rec.event.result_hash).toBeUndefined();
  expect(rec.gate?.result).toBe("halt");
  expect(rec.gate?.request_commitment).toBe(rec.request_commitment);
}

function expectChainValid(gate: Gate, tmp: string): void {
  const v = runVerify({ chainPath: gate.chainPath, identityPath: join(tmp, "identity.json") });
  expect(v.kind).toBe("valid");
}

const swapCall = (extra: Record<string, unknown>, amount: number): string =>
  JSON.stringify({
    jsonrpc: "2.0",
    ...extra,
    method: "tools/call",
    params: { name: "mock_swap", arguments: { pair: "ETH/USDC", amount_in: amount } },
  });

describe("proxy: every tools/call is gated, whatever its id", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-ids-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("a tools/call with no id under a deny rule: not forwarded, no reply, DENY receipt", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    const received = await send(gate, [swapCall({}, 1)]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    // A message without an id is a notification: JSON-RPC sends nothing back.
    expect(received).toHaveLength(1);
    expect((received[0] as { id?: unknown }).id).toBe("sync");
    const recs = receipts(gate);
    expect(recs).toHaveLength(1);
    expectDenyReceipt(recs[0]!, "mock_swap");
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(1);
    expect(refused[0]).toContain("has no id");
    await gate.stop();
  });

  it("a tools/call with no id under an allow-all policy: still not forwarded, DENY receipt", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const received = await send(gate, [swapCall({}, 1)]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(1);
    const recs = receipts(gate);
    expect(recs).toHaveLength(1);
    expectDenyReceipt(recs[0]!, "mock_swap");
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(1);
    await gate.stop();
  });

  it("id null: -32600 with id null, DENY receipt, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const received = await send(gate, [swapCall({ id: null }, 3)]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(2);
    expect(received[0]).toEqual(INVALID_ID_ERROR);
    const recs = receipts(gate);
    expect(recs).toHaveLength(1);
    expectDenyReceipt(recs[0]!, "mock_swap");
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(1);
    expect(refused[0]).toContain("null id");
    await gate.stop();
  });

  it("an id that is an object, a float, a boolean or an array: -32600 each, DENY receipts, none forwarded", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const ids: unknown[] = [{ k: 1 }, 1.5, true, [7]];
    const received = await send(
      gate,
      ids.map((id, i) => swapCall({ id }, 10 + i)),
    );

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(ids.length + 1);
    for (let i = 0; i < ids.length; i++) expect(received[i]).toEqual(INVALID_ID_ERROR);
    const recs = receipts(gate);
    expect(recs).toHaveLength(ids.length);
    for (const r of recs) expectDenyReceipt(r, "mock_swap");
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(ids.length);
    for (const l of refused) expect(l).toContain("neither a string nor an integer");
    await gate.stop();
  });

  it("a tools/call without the jsonrpc member is gated like any other (DENY under a deny rule, ALLOW with a receipt otherwise)", async () => {
    const deny = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    const noVersion = JSON.stringify({
      id: 7,
      method: "tools/call",
      params: { name: "mock_swap", arguments: { amount_in: 7 } },
    });
    const r1 = await send(deny, [noVersion]);
    expect(forwardedMethods(deny)).toEqual(["ping"]);
    const denied = r1.find((m) => (m as { id?: unknown }).id === 7) as {
      result?: { isError?: boolean };
    };
    expect(denied.result?.isError).toBe(true);
    expect(receipts(deny)).toHaveLength(1);
    expectDenyReceipt(receipts(deny)[0]!, "mock_swap");
    await deny.stop();

    const tmp2 = makeTmpDir("chirindo-ids-allow-");
    try {
      const allow = await startGate(tmp2, { deny: [] });
      const r2 = await send(allow, [noVersion]);
      expect(forwardedMethods(allow)).toEqual(["tools/call", "ping"]);
      const ran = r2.find((m) => (m as { id?: unknown }).id === 7) as {
        result?: { isError?: boolean };
      };
      expect(ran.result?.isError).toBe(false);
      const recs = receipts(allow);
      expect(recs).toHaveLength(1);
      if (recs[0]!.event.type !== "mcp_call") throw new Error("expected mcp_call");
      expect(recs[0]!.event.decision).toBe("allow");
      expect(recs[0]!.event.outcome).toBe("executed");
      expectChainValid(allow, tmp2);
      await allow.stop();
    } finally {
      cleanupTmpDir(tmp2);
    }
  });

  it("a batch holding a tools/call: nothing forwarded, a DENY receipt per tools/call, one -32600", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const batch = JSON.stringify([
      JSON.parse(swapCall({ id: 1 }, 6)),
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "get_quote", arguments: { pair: "ETH/USDC" } },
      },
    ]);
    const received = await send(gate, [batch]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(2);
    const err = received[0] as { id: unknown; error: { code: number } };
    expect(err.id).toBeNull();
    expect(err.error.code).toBe(-32600);
    const recs = receipts(gate);
    expect(recs).toHaveLength(2);
    expectDenyReceipt(recs[0]!, "mock_swap");
    expectDenyReceipt(recs[1]!, "get_quote");
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(1);
    await gate.stop();
  });

  it("a batch with no tools/call, and an empty batch, are refused too: -32600, no receipt, nothing forwarded", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const batch = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "ping" },
      { jsonrpc: "2.0", method: "notifications/initialized" },
    ]);
    const received = await send(gate, [batch, "[]"]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(3);
    for (const m of received.slice(0, 2)) {
      expect((m as { id: unknown }).id).toBeNull();
      expect((m as { error: { code: number } }).error.code).toBe(-32600);
    }
    expect(receipts(gate)).toHaveLength(0);
    expect(refuseLogs(gate)).toHaveLength(2);
    await gate.stop();
  });

  it("a line that is not JSON: -32700, not forwarded, no receipt", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    // A parser that accepts NaN reads this as a tools/call; JSON.parse does not.
    const nan =
      '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"mock_swap","arguments":{"amount_in":NaN}}}';
    const received = await send(gate, [nan, "not json at all"]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(3);
    for (const m of received.slice(0, 2)) {
      expect((m as { id: unknown }).id).toBeNull();
      expect((m as { error: { code: number } }).error.code).toBe(-32700);
    }
    expect(receipts(gate)).toHaveLength(0);
    expect(refuseLogs(gate)).toHaveLength(2);
    await gate.stop();
  });

  it("a member name twice in one object, at any depth: -32600, not forwarded, no receipt", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    // JSON.parse keeps the last "method" (ping); a first-wins parser keeps tools/call.
    const dupMethod =
      '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"mock_swap","arguments":{"amount_in":7}},"method":"ping"}';
    const dupNested =
      '{"jsonrpc":"2.0","id":15,"method":"tools/list","params":{"cursor":{"a":1,"a":2}}}';
    const received = await send(gate, [dupMethod, dupNested]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expect(received).toHaveLength(3);
    for (const m of received.slice(0, 2)) {
      expect((m as { id: unknown }).id).toBeNull();
      expect((m as { error: { code: number } }).error.code).toBe(-32600);
    }
    expect(receipts(gate)).toHaveLength(0);
    expect(refuseLogs(gate)).toHaveLength(2);
    await gate.stop();
  });

  it("a carriage return inside a line: -32600, not forwarded, no receipt (a trailing CR is still accepted)", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    // One JSON object to JSON.parse ({"x": {...}}); a reader that ends lines at
    // a bare CR (Node readline, Python text I/O) reads the inner tools/call alone.
    const crSplit = '{"x":\r' + swapCall({ id: 10 }, 4) + "\r}";
    const crlf = JSON.stringify({ jsonrpc: "2.0", id: "crlf", method: "tools/list" }) + "\r";
    const received = await send(gate, [crSplit, crlf]);

    expect(forwardedMethods(gate)).toEqual(["tools/list", "ping"]);
    const err = received[0] as { id: unknown; error: { code: number } };
    expect(err.id).toBeNull();
    expect(err.error.code).toBe(-32600);
    expect(receipts(gate)).toHaveLength(0);
    expect(refuseLogs(gate)).toHaveLength(1);
    await gate.stop();
  });

  it("control: string and integer ids ALLOW and DENY with receipts as before", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "delete" }] });
    const call = (id: string | number, name: string) =>
      JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: { n: 1 } } });
    const received = await send(gate, [call("s-1", "echo"), call(42, "delete"), call(43, "echo")]);

    expect(forwardedMethods(gate)).toEqual(["tools/call", "tools/call", "ping"]);
    const byId = new Map(received.map((m) => [(m as { id: unknown }).id, m]));
    expect((byId.get("s-1") as { result: { isError: boolean } }).result.isError).toBe(false);
    expect((byId.get(42) as { result: { isError: boolean } }).result.isError).toBe(true);
    expect((byId.get(43) as { result: { isError: boolean } }).result.isError).toBe(false);
    const recs = receipts(gate);
    expect(recs.map((r) => (r.event.type === "mcp_call" ? r.event.decision : "?"))).toEqual([
      "allow",
      "deny",
      "allow",
    ]);
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(0);
    await gate.stop();
  });

  it("control: notifications and other methods are forwarded byte for byte", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const initialized = '{"jsonrpc":"2.0","method":"notifications/initialized"}';
    const list = '{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}';
    // An integer past 2^53 is not refused: only duplicate member names are (C1 (e)).
    const big = '{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"n":12345678901234567890}}';
    const received = await send(gate, [initialized, list, big]);

    expect(gate.forwarded.slice(0, 3)).toEqual([initialized, list, big]);
    // The notification gets no answer; the two requests and the sync ping do.
    expect(received.map((m) => (m as { id: unknown }).id)).toEqual([5, 6, "sync"]);
    expect(receipts(gate)).toHaveLength(0);
    expect(refuseLogs(gate)).toHaveLength(0);
    await gate.stop();
  });
});
