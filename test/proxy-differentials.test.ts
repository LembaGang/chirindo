// Client lines the gate and a downstream could read differently (0.5.3).
//
// The gate parses each line with JSON.parse: member names match exactly and
// numbers become IEEE-754 doubles. A downstream may match member names without
// regard to case (Go's encoding/json decoding into a struct does: "Method" is
// method there, and a later member overwrites an earlier one), and a call the
// gate allows is forwarded re-encoded from JSON.parse's value. So these lines
// are refused and never forwarded, each with one stderr line:
//
//   (a) a top-level member that is jsonrpc, id, method or params in another
//       case: -32600, and a DENY receipt when the exact method or such a
//       member says "tools/call";
//   (b) a tools/call whose params has name, arguments or _meta in another
//       case: -32600, DENY receipt;
//   (c) two top-level members, or two params members, that differ only in
//       case: -32600, DENY receipt when it is a tools/call;
//   (d) a tools/call whose params is not an object, or whose params.name is
//       not a non-empty string: -32602, DENY receipt for tool "";
//   (e) a tools/call whose id is already in flight: -32600, DENY receipt;
//   (f) a tools/call with an integer outside the JavaScript safe range: -32600,
//       DENY receipt. The same for a number too large for a double (1e400,
//       which JSON.parse reads as Infinity), except that no receipt can hash
//       it when it sits in the arguments.
//
// Each error carries the message's id when the message is a request (a member
// named method in any case), has one member named exactly "id", and that id
// is a string or a safe integer; otherwise its id is null.
//
// Members inside params.arguments are not checked for case (a control below).

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

interface Gate {
  clientIn: PassThrough;
  clientOut: PassThrough;
  handle: ProxyHandle;
  chainPath: string;
  // Every line the downstream received, exactly as written to its stdin.
  forwarded: string[];
  logs: string[];
  // Answer the held tools/calls (params.name "hold") now.
  release: () => void;
  stop: () => Promise<void>;
}

async function startGate(tmp: string, policy: Policy): Promise<Gate> {
  const identity = await initIdentity(tmp);
  const policyPath = writePolicy(tmp, policy);
  const chainPath = join(tmp, "chain.jsonl");
  const { clientIn, clientOut } = makeClientPipes();
  const downstream = makeFakeDownstream();
  const forwarded: string[] = [];
  const held: unknown[] = [];
  const answer = (id: unknown) =>
    downstream.toClient.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: "ran" }], isError: false },
      }) + "\n",
    );
  let buf = "";
  downstream.fromClient.on("data", (chunk: Buffer | string) => {
    buf += chunk.toString("utf8");
    const parts = buf.split("\n");
    buf = parts.pop() ?? "";
    for (const line of parts) {
      if (line.length === 0) continue;
      forwarded.push(line);
      // A minimal MCP server: answer every message that carries an id, except
      // a tools/call for the tool "hold", answered only on release().
      let msg: { id?: unknown; params?: { name?: unknown } };
      try {
        msg = JSON.parse(line) as typeof msg;
      } catch {
        continue;
      }
      if (typeof msg !== "object" || msg === null || Array.isArray(msg) || !("id" in msg)) continue;
      if (msg.params?.name === "hold") held.push(msg.id);
      else answer(msg.id);
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
    sessionId: "sess-differentials",
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
    release: () => {
      for (const id of held.splice(0)) answer(id);
    },
    stop: async () => {
      downstream.exit(0);
      await handle.done;
    },
  };
}

// Write raw lines in one chunk, then a ping with id "sync". Lines are handled
// in order, so once the ping's answer reaches the client every earlier line
// has been dealt with. Returns every message the client received, the ping's
// answer last.
async function send(gate: Gate, lines: string[]): Promise<unknown[]> {
  const collector = collectJsonLines(
    gate.clientOut,
    (latest) =>
      typeof latest === "object" && latest !== null && (latest as { id?: unknown }).id === "sync",
  );
  gate.clientIn.write(
    lines.map((l) => l + "\n").join("") +
      JSON.stringify({ jsonrpc: "2.0", id: "sync", method: "ping" }) +
      "\n",
  );
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

function denyReceiptTools(gate: Gate): string[] {
  return receipts(gate).map((r) => {
    if (r.event.type !== "mcp_call") throw new Error("expected mcp_call");
    expect(r.event.decision).toBe("deny");
    expect(r.event.decision_source).toBe("config");
    expect(r.event.outcome).toBe("denied");
    expect(r.event.result_hash).toBeUndefined();
    expect(r.gate?.result).toBe("halt");
    return r.event.tool_name;
  });
}

function expectChainValid(gate: Gate, tmp: string): void {
  const v = runVerify({ chainPath: gate.chainPath, identityPath: join(tmp, "identity.json") });
  expect(v.kind).toBe("valid");
}

function expectErrors(received: unknown[], code: number, ids: unknown[]): void {
  expect(received.slice(0, -1)).toEqual(
    ids.map((id) => ({ jsonrpc: "2.0", id, error: { code, message: expect.any(String) } })),
  );
}

const call = (envelope: string, id: number, params: string): string =>
  `{"jsonrpc":"2.0","id":${id},${envelope},"params":${params}}`;

describe("proxy: lines the gate and a downstream could read differently are refused", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-diff-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("(a) a tools/call carried by a case variant of method, or with params as paramſ: -32600 with its id, DENY receipt, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    const args = '{"name":"mock_swap","arguments":{"amount_in":1}}';
    const received = await send(gate, [
      call('"Method":"tools/call"', 21, args),
      call('"method":"ping","METHOD":"tools/call"', 22, args),
      `{"jsonrpc":"2.0","id":24,"method":"tools/call","paramſ":${args}}`,
      `{"JSONRPC":"2.0","id":25,"method":"tools/call","params":${args}}`,
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, [21, 22, 24, 25]);
    expect(denyReceiptTools(gate)).toEqual(["mock_swap", "mock_swap", "", "mock_swap"]);
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(4);
    expect(refused[0]).toContain('the member "Method", which is "method" in another case');
    expect(refused[2]).toContain('"paramſ", which is "params" in another case');
    await gate.stop();
  });

  it("(a) in a batch, an element whose method member is in another case still gets its DENY receipt", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const batch =
      '[{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"mock_swap","arguments":{}}},' +
      '{"jsonrpc":"2.0","id":2,"method":"ping"}]';
    const received = await send(gate, [batch]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, [null]);
    expect(denyReceiptTools(gate)).toEqual(["mock_swap"]);
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(1);
    await gate.stop();
  });

  it("(a) any other message with a case variant of jsonrpc, id, method or params: -32600, no receipt, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const received = await send(gate, [
      '{"jsonrpc":"2.0","ID":5,"method":"tools/list"}',
      '{"jsonrpc":"2.0","İd":6,"method":"tools/list"}',
      '{"jsonrpc":"2.0","id":7,"method":"tools/list","Params":{}}',
      '{"jsonrpc":"2.0","method":"notifications/initialized","Method":"x"}',
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    // No member is named exactly "id" in the first two, and the last is a notification.
    expectErrors(received, -32600, [null, null, 7, null]);
    expect(receipts(gate)).toHaveLength(0);
    expect(refuseLogs(gate)).toHaveLength(4);
    for (const l of refuseLogs(gate)) expect(l).toContain("no receipt (not a tools/call)");
    await gate.stop();
  });

  it("(b) a tools/call whose params has name, arguments or _meta in another case: -32600 with its id, DENY receipt, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    const env = '"method":"tools/call"';
    const received = await send(gate, [
      // JSON.parse reads get_quote; a case-insensitive reader, last member winning, reads mock_swap.
      call(env, 23, '{"name":"get_quote","Name":"mock_swap","arguments":{"amount_in":23}}'),
      call(env, 26, '{"nAme":"mock_swap","arguments":{"amount_in":26}}'),
      call(env, 27, '{"name":"echo","ARGUMENTS":{"amount_in":27}}'),
      call(env, 28, '{"name":"echo","arguments":{},"_Meta":{"progressToken":1}}'),
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, [23, 26, 27, 28]);
    expect(denyReceiptTools(gate)).toEqual(["get_quote", "", "echo", "echo"]);
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(4);
    expect(refused[0]).toContain('the params member "Name", which is "name" in another case');
    await gate.stop();
  });

  it("(c) two members that differ only in case, at the top level or in params: -32600 with its id, a DENY receipt only for a tools/call", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const received = await send(gate, [
      call('"method":"tools/call","x":1,"X":2', 30, '{"name":"echo","arguments":{}}'),
      '{"jsonrpc":"2.0","id":31,"method":"resources/read","params":{"uri":"a","URI":"b"}}',
      '{"jsonrpc":"2.0","id":32,"method":"tools/list","cursor":"a","CURSOR":"b"}',
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, [30, 31, 32]);
    expect(denyReceiptTools(gate)).toEqual(["echo"]);
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(3);
    expect(refused[0]).toContain('the members "x" and "X", which differ only in case');
    expect(refused[1]).toContain('the params members "uri" and "URI"');
    await gate.stop();
  });

  it("(d) a tools/call whose params is not an object, or whose name is not a non-empty string: -32602 with its id (null when the id is no safe integer), DENY receipt for tool \"\"", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    const env = '"method":"tools/call"';
    const received = await send(gate, [
      call(env, 40, '"mock_swap"'),
      call(env, 41, '["mock_swap"]'),
      call(env, 42, "null"),
      `{"jsonrpc":"2.0","id":43,"method":"tools/call"}`,
      call(env, 44, '{"name":5,"arguments":{}}'),
      call(env, 45, '{"name":["mock_swap"],"arguments":{}}'),
      call(env, 46, '{"name":"","arguments":{}}'),
      call(env, 47, '{"arguments":{}}'),
      `{"jsonrpc":"2.0","id":"s-48","method":"tools/call","params":{"name":""}}`,
      // An integer, but beyond the safe range (written with an exponent, so (f) does not apply).
      `{"jsonrpc":"2.0","id":1e20,"method":"tools/call","params":"mock_swap"}`,
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32602, [40, 41, 42, 43, 44, 45, 46, 47, "s-48", null]);
    expect(denyReceiptTools(gate)).toEqual(["", "", "", "", "", "", "", "", "", ""]);
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(10);
    await gate.stop();
  });

  it("(e) a tools/call whose id is already in flight: -32600 with that id, DENY receipt, not forwarded; the id is free again once answered", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const first = call('"method":"tools/call"', 7, '{"name":"hold","arguments":{"n":1}}');
    const second = call('"method":"tools/call"', 7, '{"name":"mock_swap","arguments":{"n":2}}');
    const sameDigitsAsString = '{"jsonrpc":"2.0","id":"7","method":"tools/call","params":{"name":"echo","arguments":{}}}';
    const received = await send(gate, [first, second, sameDigitsAsString]);

    // The held call went through; the second id 7 did not; the string "7" is another id.
    expect(gate.forwarded.map((l) => (JSON.parse(l) as { id: unknown }).id)).toEqual([7, "7", "sync"]);
    const refusal = received.find((m) => (m as { error?: unknown }).error !== undefined);
    expect(refusal).toEqual({ jsonrpc: "2.0", id: 7, error: { code: -32600, message: expect.any(String) } });
    const soFar = receipts(gate).map((r) => (r.event.type === "mcp_call" ? `${r.event.tool_name}:${r.event.decision}` : "?"));
    expect(soFar).toEqual(["mock_swap:deny", "echo:allow"]);
    expect(refuseLogs(gate)).toHaveLength(1);
    expect(refuseLogs(gate)[0]).toContain("still in flight");

    // Once the held call is answered, its ALLOW receipt is written and id 7 can be used again.
    const answered = collectJsonLines(gate.clientOut, (m) => (m as { id?: unknown }).id === 7);
    gate.release();
    await answered;
    const again = await send(gate, [call('"method":"tools/call"', 7, '{"name":"echo","arguments":{}}')]);
    expect((again[0] as { id: unknown; result: { isError: boolean } }).result.isError).toBe(false);
    const decisions = receipts(gate).map((r) => (r.event.type === "mcp_call" ? `${r.event.tool_name}:${r.event.decision}` : "?"));
    expect(decisions).toEqual(["mock_swap:deny", "echo:allow", "hold:allow", "echo:allow"]);
    expectChainValid(gate, tmp);
    await gate.stop();
  });

  it("(f) a tools/call with an integer outside the safe range, in its arguments or as its id: -32600 with its id (null for the unsafe id), DENY receipt, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const env = '"method":"tools/call"';
    const received = await send(gate, [
      call(env, 50, '{"name":"echo","arguments":{"n":12345678901234567891}}'),
      call(env, 51, '{"name":"echo","arguments":{"n":[1,-9007199254740993]}}'),
      call(env, 9007199254740993, '{"name":"echo","arguments":{}}'),
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, [50, 51, null]);
    expect(denyReceiptTools(gate)).toEqual(["echo", "echo", "echo"]);
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(3);
    expect(refused[0]).toContain("integer 12345678901234567891 is outside");
    await gate.stop();
  });

  it("(f) a number too large for a double in a tools/call: -32600 with its id, not forwarded; no receipt when it is in the arguments, a DENY receipt otherwise", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const env = '"method":"tools/call"';
    const received = await send(gate, [
      // An allowed call: before 0.5.3 the downstream got "pad":null and no receipt could be written.
      call(env, 52, '{"name":"echo","arguments":{"n":5,"pad":1e400}}'),
      call(env, 53, '{"name":"echo","arguments":{},"_meta":{"x":-1e999}}'),
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, [52, 53]);
    expect(denyReceiptTools(gate)).toEqual(["echo"]);
    expectChainValid(gate, tmp);
    const refused = refuseLogs(gate);
    expect(refused).toHaveLength(2);
    expect(refused[0]).toContain("a number too large for a double");
    expect(refused[0]).toContain("DENY receipt not written: its arguments hold a number too large for a double");
    expect(refused[1]).toContain("DENY receipt written");
    expect(gate.logs.filter((l) => l.includes("receipt write FAILED"))).toHaveLength(0);
    await gate.stop();
  });

  it("error ids: a refused request's error carries its id when that is a string or a safe integer; any other id, a notification and a client's response get id null", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const received = await send(gate, [
      '{"jsonrpc":"2.0","id":"q-1","Method":"tools/call","params":{"name":"echo","arguments":{}}}',
      '{"jsonrpc":"2.0","id":9007199254740991,"method":"tools/list","Params":{}}',
      '{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/list","Params":{}}',
      '{"jsonrpc":"2.0","id":1.5,"method":"tools/list","Params":{}}',
      '{"jsonrpc":"2.0","id":true,"method":"tools/list","Params":{}}',
      '{"jsonrpc":"2.0","id":[1],"method":"tools/list","Params":{}}',
      '{"jsonrpc":"2.0","method":"notifications/initialized","PARAMS":{}}',
      // Responses to the server's requests: their ids are the server's, not the client's.
      '{"jsonrpc":"2.0","id":8,"result":{},"Result":{}}',
      '{"jsonrpc":"2.0","id":9,"ID":10,"result":{}}',
    ]);

    expect(forwardedMethods(gate)).toEqual(["ping"]);
    expectErrors(received, -32600, ["q-1", 9007199254740991, null, null, null, null, null, null, null]);
    expect(denyReceiptTools(gate)).toEqual(["echo"]);
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(9);
    await gate.stop();
  });

  it("control: exact names, the largest safe integer, a number with a fraction, and case variants inside arguments are forwarded with an ALLOW receipt", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const env = '"method":"tools/call"';
    const received = await send(gate, [
      call(env, 60, '{"name":"echo","arguments":{"n":9007199254740991,"m":-9007199254740991},"_meta":{"progressToken":"p"}}'),
      call(env, 61, '{"name":"echo","arguments":{"x":12345678901234567891.5}}'),
      // Not checked for case: members inside params.arguments.
      call(env, 62, '{"name":"echo","arguments":{"amount":1,"Amount":2}}'),
    ]);

    expect(forwardedMethods(gate)).toEqual(["tools/call", "tools/call", "tools/call", "ping"]);
    expect(received.map((m) => (m as { id: unknown }).id)).toEqual([60, 61, 62, "sync"]);
    const decisions = receipts(gate).map((r) => (r.event.type === "mcp_call" ? r.event.decision : "?"));
    expect(decisions).toEqual(["allow", "allow", "allow"]);
    expect(JSON.parse(gate.forwarded[0]!).params.arguments.n).toBe(9007199254740991);
    expect(JSON.parse(gate.forwarded[2]!).params.arguments).toEqual({ amount: 1, Amount: 2 });
    expectChainValid(gate, tmp);
    expect(refuseLogs(gate)).toHaveLength(0);
    await gate.stop();
  });
});
