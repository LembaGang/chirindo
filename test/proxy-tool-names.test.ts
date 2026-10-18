// Tool names and method values a downstream may read differently from the
// gate (0.5.3).
//
// A deny rule names a tool. A downstream server may find a tool without regard
// to case, or after trimming or normalizing the name, so "MOCK_SWAP" or
// " mock_swap" can run mock_swap there. So:
//
//   - deny rules match a tool name without regard to case: under the fold the
//     gate uses for member names (src/member-names.ts foldName), or after a
//     full case mapping (ß and ss, the ligature ﬁ and fi);
//   - a tools/call whose params.name begins or ends with white space, or holds
//     a control or format character (Unicode Cc, Cf) anywhere, is refused:
//     -32602 with its id, a DENY receipt, never forwarded;
//   - by default, so is a tools/call whose name is outside MCP's tool-name
//     rule (1 to 128 characters, each an ASCII letter, a digit, _, - or .);
//     the proxy option allowNonstandardToolNames (CLI flag
//     --allow-nonstandard-tool-names) turns that one off and logs a warning;
//   - a message whose method is not a string, is tools/call only after
//     trimming white space or folding case ("TOOLS/CALL", "tools/call "), or
//     holds a control or format character, is refused: -32600 with its id, a
//     DENY receipt when it could be read as a tools/call, never forwarded;
//   - a message with a member named "__proto__" at the top level or in params
//     is refused: -32600, a DENY receipt when the method of the message or of
//     that member reads as tools/call, never forwarded (a downstream that
//     merges the message with Object.assign or a for...in copy would read that
//     member as the message's own);
//   - a tools/call nested past MAX_VALUE_DEPTH, too deep to canonicalize for a
//     receipt, is refused: -32600, a DENY receipt over the empty object, never
//     forwarded; a call at the limit still runs, its receipt computed first.
//
// The fake downstream here takes a message for a tools/call when
// String(method), with control and format characters dropped, trimmed and
// lowercased, is tools/call (or, with dispatch "handlers", when a table of
// handlers keyed by method has one for msg.method), looks the tool up with
// String(name).trim().toLowerCase() unless a test gives another lookup, and
// records each tool it would run.

import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { argsHash, parseChainJsonl, runVerify } from "../src/vendor/recorder/index.js";
import type { SignedRecord } from "../src/vendor/recorder/index.js";
import { loadPolicy, type Policy } from "../src/policy.js";
import { runProxy, type ProxyHandle } from "../src/proxy.js";
import { MAX_VALUE_DEPTH } from "../src/rpc.js";
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
  // The tool the downstream ran for each message it took for a tools/call,
  // after its lenient lookup.
  ran: string[];
  logs: string[];
  stop: () => Promise<void>;
}

interface GateOptions {
  lookup?: (name: string) => string;
  allowNonstandardToolNames?: boolean;
  // How the fake downstream finds a method's handler: through String(method)
  // (the default) or as HANDLERS[msg.method], a table keyed by method, which
  // turns an array such as ["tools/call"] into the key "tools/call".
  dispatch?: "string" | "handlers";
  // How the fake downstream reads each message: as JSON.parse returned it
  // (the default) or through a shallow merge into a fresh object, which a
  // server that clones or normalizes messages does. JSON.parse keeps a
  // "__proto__" member as an own data property, so both merges set the
  // clone's prototype from it, and the clone's method and params read from
  // that member (P18).
  merge?: "assign" | "forin";
}

// The depth limit, with a fallback so the depth cases still run at real depths
// against a build that predates MAX_VALUE_DEPTH (the red half of red/green).
const DEPTH_LIMIT: number = (MAX_VALUE_DEPTH as number | undefined) ?? 128;

const leniently = (method: unknown): string =>
  String(method).replace(/[\p{Cc}\p{Cf}]/gu, "").trim().toLowerCase();

const HANDLERS: Record<string, true> = Object.assign(Object.create(null) as Record<string, true>, { "tools/call": true as const });

function forinCopy(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k in o) out[k] = o[k];
  return out;
}

async function startGate(tmp: string, policy: Policy, options: GateOptions = {}): Promise<Gate> {
  const lookup = options.lookup ?? ((name: string) => name.trim().toLowerCase());
  const identity = await initIdentity(tmp);
  const policyPath = writePolicy(tmp, policy);
  const chainPath = join(tmp, "chain.jsonl");
  const { clientIn, clientOut } = makeClientPipes();
  const downstream = makeFakeDownstream();
  const forwarded: string[] = [];
  const ran: string[] = [];
  let buf = "";
  downstream.fromClient.on("data", (chunk: Buffer | string) => {
    buf += chunk.toString("utf8");
    const parts = buf.split("\n");
    buf = parts.pop() ?? "";
    for (const line of parts) {
      if (line.length === 0) continue;
      forwarded.push(line);
      let msg: { id?: unknown; method?: unknown; params?: { name?: unknown } };
      try {
        msg = JSON.parse(line) as typeof msg;
      } catch {
        continue;
      }
      if (typeof msg !== "object" || msg === null || Array.isArray(msg)) continue;
      const view = (
        options.merge === undefined
          ? msg
          : options.merge === "assign"
            ? Object.assign({}, msg)
            : forinCopy(msg as Record<string, unknown>)
      ) as { method?: unknown; params?: { name?: unknown } };
      const isCall =
        options.dispatch === "handlers"
          ? HANDLERS[view.method as string] === true
          : leniently(view.method) === "tools/call";
      if (isCall) ran.push(lookup(String(view.params?.name)));
      if (!("id" in msg)) continue;
      downstream.toClient.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: msg.id,
          result: { content: [{ type: "text", text: "ran" }], isError: false },
        }) + "\n",
      );
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
    sessionId: "sess-tool-names",
    serverLabel: "fake",
    chainPath,
    ...(options.allowNonstandardToolNames === true ? { allowNonstandardToolNames: true } : {}),
    log: (m) => logs.push(m),
  });
  return {
    clientIn,
    clientOut,
    handle,
    chainPath,
    forwarded,
    ran,
    logs,
    stop: async () => {
      downstream.exit(0);
      await handle.done;
    },
  };
}

// Write the lines in one chunk, then a ping with id "sync"; returns every
// message the client received, the ping's answer last.
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

const toolCall = (id: number, name: string, method = "tools/call"): string =>
  JSON.stringify({ jsonrpc: "2.0", id, method, params: { name, arguments: { amount_in: id } } });

function receipts(gate: Gate): SignedRecord[] {
  try {
    return parseChainJsonl(readFileSync(gate.chainPath, "utf8")).records;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw e;
  }
}

function decisions(gate: Gate): string[] {
  return receipts(gate).map((r) => {
    if (r.event.type !== "mcp_call") throw new Error("expected mcp_call");
    expect(r.event.decision_source).toBe("config");
    return `${JSON.stringify(r.event.tool_name)}:${r.event.decision}`;
  });
}

function forwardedTools(gate: Gate): string[] {
  return gate.forwarded.map((l) => {
    const m = JSON.parse(l) as { method?: unknown; params?: { name?: unknown } };
    return m.method === "tools/call" ? String(m.params?.name) : String(m.method);
  });
}

function expectChainValid(gate: Gate, tmp: string): void {
  const v = runVerify({ chainPath: gate.chainPath, identityPath: join(tmp, "identity.json") });
  expect(v.kind).toBe("valid");
}

const WARNING = "WARNING: --allow-nonstandard-tool-names";

const denied = (id: number) => ({
  jsonrpc: "2.0",
  id,
  result: { content: [{ type: "text", text: expect.stringContaining("[gate denied]") }], isError: true },
});
const refused = (id: number | null, code: number) => ({
  jsonrpc: "2.0",
  id,
  error: { code, message: expect.any(String) },
});

describe("proxy: tool names and method values a downstream may read differently", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-names-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("a deny rule on mock_swap stops MOCK_SWAP, Mock_Swap and \" mock_swap\", which a downstream that lowercases and trims names would run", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    const received = await send(gate, [
      toolCall(1, "MOCK_SWAP"),
      toolCall(2, "Mock_Swap"),
      toolCall(3, " mock_swap"),
      toolCall(4, "mock_swap\t"),
      // U+212A KELVIN SIGN, whose lower case is k: outside MCP's tool-name characters.
      toolCall(5, "mocK_swap"),
    ]);

    expect(gate.ran).toEqual([]);
    expect(forwardedTools(gate)).toEqual(["ping"]);
    expect(received.slice(0, -1)).toEqual([denied(1), denied(2), refused(3, -32602), refused(4, -32602), refused(5, -32602)]);
    expect(decisions(gate)).toEqual([
      '"MOCK_SWAP":deny',
      '"Mock_Swap":deny',
      '" mock_swap":deny',
      '"mock_swap\\t":deny',
      '"mocK_swap":deny',
    ]);
    expectChainValid(gate, tmp);
    expect(gate.logs.filter((l) => l.startsWith("[proxy] DENY"))).toHaveLength(2);
    const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
    expect(refusals).toHaveLength(3);
    expect(refusals[0]).toContain("begins or ends with white space");
    expect(refusals[2]).toContain("outside");
    expect(gate.logs.filter((l) => l.includes(WARNING))).toHaveLength(0);
    await gate.stop();
  });

  it("a tool name with a control or format character anywhere, or white space at either end, is refused under any policy: -32602 with its id, DENY receipt, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [] });
    const names = [
      "mock​swap", // ZERO WIDTH SPACE (Cf)
      "mock_swap\u0000", // NUL (Cc)
      "‮mock_swap", // RIGHT-TO-LEFT OVERRIDE (Cf)
      "mock_swap­", // SOFT HYPHEN (Cf)
      "mock\u0085swap", // NEXT LINE (Cc)
      "﻿mock_swap", // ZERO WIDTH NO-BREAK SPACE (Cf)
      "mock_swap　", // IDEOGRAPHIC SPACE (white space)
      " mock_swap", // NO-BREAK SPACE (white space)
      "mock_swap\n", // LINE FEED, written \n in the JSON text (Cc)
    ];
    const received = await send(gate, names.map((n, k) => toolCall(10 + k, n)));

    expect(gate.ran).toEqual([]);
    expect(forwardedTools(gate)).toEqual(["ping"]);
    expect(received.slice(0, -1)).toEqual(names.map((_, k) => refused(10 + k, -32602)));
    expect(decisions(gate)).toEqual(names.map((n) => `${JSON.stringify(n)}:deny`));
    expectChainValid(gate, tmp);
    const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
    expect(refusals).toHaveLength(names.length);
    expect(refusals[0]).toContain("the control or format character U+200B");
    for (const l of refusals) expect(l).not.toMatch(/[\u0000-\u001f\u0085­​‮﻿]/);
    await gate.stop();
  });

  it("by default a tool name outside MCP's rule (1 to 128 of A-Z, a-z, 0-9, _, - and .) is refused: -32602 with its id, DENY receipt, not forwarded; names inside it pass", async () => {
    // A downstream that applies NFKC before its lenient lookup.
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] }, {
      lookup: (name) => name.normalize("NFKC").trim().toLowerCase(),
    });
    const outside = [
      "ｍｏｃｋ＿ｓｗａｐ", // FULLWIDTH mock_swap: NFKC gives mock_swap
      "mock_͏swap", // COMBINING GRAPHEME JOINER (default ignorable, Mn)
      "mock_swáp", // COMBINING ACUTE ACCENT
      "café",
      "mock swap",
      "get/quote",
      "a,b",
      "x".repeat(129),
    ];
    const inside = ["get_quote", "DATA_EXPORT_v2", "admin.tools.list", "a-b", "x".repeat(128)];
    const received = await send(gate, [
      ...outside.map((n, k) => toolCall(20 + k, n)),
      ...inside.map((n, k) => toolCall(40 + k, n)),
    ]);

    expect(gate.ran).toEqual(inside.map((n) => n.toLowerCase()));
    expect(forwardedTools(gate)).toEqual([...inside, "ping"]);
    expect(received.slice(0, outside.length)).toEqual(outside.map((_, k) => refused(20 + k, -32602)));
    expect(received.slice(outside.length, -1).map((m) => (m as { id: unknown }).id)).toEqual(inside.map((_, k) => 40 + k));
    expect(decisions(gate)).toEqual([
      ...outside.map((n) => `${JSON.stringify(n)}:deny`),
      ...inside.map((n) => `${JSON.stringify(n)}:allow`),
    ]);
    expectChainValid(gate, tmp);
    const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
    expect(refusals).toHaveLength(outside.length);
    expect(refusals[7]).toContain("longer than 128 characters");
    await gate.stop();
  });

  it("a method that is tools/call only after trimming or folding case, or that holds a control or format character, is refused: -32600 with its id, DENY receipt when it reads as tools/call, not forwarded", async () => {
    const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] });
    // The last: U+017F LATIN SMALL LETTER LONG S, which the gate's fold (and Go's
    // strings.EqualFold) reads as s.
    const methods = ["tools/call ", "TOOLS/CALL", "Tools/Call", " tools/call", "tools/call​", "tools/call\u0000", " tools/call", "toolſ/call"];
    const received = await send(gate, [
      ...methods.map((m, k) => toolCall(60 + k, "mock_swap", m)),
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized\u0000" }),
      // Not tools/call in any reading: forwarded, as before.
      JSON.stringify({ jsonrpc: "2.0", id: 70, method: "tools/list " }),
    ]);

    expect(gate.ran).toEqual([]);
    expect(forwardedTools(gate)).toEqual(["tools/list ", "ping"]);
    expect(received.slice(0, methods.length + 1)).toEqual([...methods.map((_, k) => refused(60 + k, -32600)), refused(null, -32600)]);
    expect((received[methods.length + 1] as { id: unknown }).id).toBe(70);
    expect(decisions(gate)).toEqual(methods.map(() => '"mock_swap":deny'));
    expectChainValid(gate, tmp);
    const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
    expect(refusals).toHaveLength(methods.length + 1);
    expect(refusals[1]).toContain('the method "TOOLS/CALL"');
    expect(refusals[4]).toContain("control or format character U+200B");
    expect(refusals[methods.length]).toContain("no receipt");
    await gate.stop();
  });

  for (const dispatch of ["string", "handlers"] as const) {
    it(`a method that is not a string is refused: -32600 with its id, a DENY receipt when it reads as tools/call, not forwarded; well-formed lines pass as before (a downstream that dispatches with ${dispatch === "string" ? "String(msg.method)" : "HANDLERS[msg.method]"})`, async () => {
      const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] }, { dispatch });
      // Each method, and whether it reads as tools/call: through String(), or
      // through one of an array's elements.
      const cases: [unknown, boolean][] = [
        [["tools/call"], true], // an array
        [[["tools/call"]], true], // a nested array: String() gives "tools/call"
        [["TOOLS/CALL "], true],
        [["tools/call", "ping"], true], // String() gives "tools/call,ping"; its first element is tools/call
        [{ "tools/call": true }, false], // an object: "[object Object]"
        [7, false], // a number
        [true, false], // a boolean
        [null, false],
        [["tools/list"], false],
      ];
      const received = await send(gate, [
        ...cases.map(([method], k) =>
          JSON.stringify({ jsonrpc: "2.0", id: 80 + k, method, params: { name: "mock_swap", arguments: { amount_in: 80 + k } } }),
        ),
        // The adversarial read's line: no jsonrpc, no id.
        JSON.stringify({ method: ["tools/call"], params: { name: "mock_swap" } }),
        // Well-formed lines, handled as before: a notification, a request, a
        // client's response to a server request, and an allowed tools/call.
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
        JSON.stringify({ jsonrpc: "2.0", id: 95, method: "tools/list" }),
        JSON.stringify({ jsonrpc: "2.0", id: "srv-1", result: {} }),
        toolCall(96, "get_quote"),
      ]);

      expect(gate.ran).toEqual(["get_quote"]);
      expect(gate.forwarded.map((l) => {
        const m = JSON.parse(l) as { id?: unknown; method?: unknown };
        return m.id ?? m.method;
      })).toEqual(["notifications/initialized", 95, "srv-1", 96, "sync"]);
      expect(received.slice(0, cases.length + 1)).toEqual([...cases.map((_, k) => refused(80 + k, -32600)), refused(null, -32600)]);
      expect(received.slice(cases.length + 1, -1).map((m) => (m as { id: unknown }).id)).toEqual([95, "srv-1", 96]);
      expect(decisions(gate)).toEqual([
        ...cases.filter(([, reads]) => reads).map(() => '"mock_swap":deny'),
        '"mock_swap":deny',
        '"get_quote":allow',
      ]);
      expectChainValid(gate, tmp);
      const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
      expect(refusals).toHaveLength(cases.length + 1);
      expect(refusals[0]).toContain("a method that is an array, not a string");
      expect(refusals[4]).toContain("a method that is an object, not a string");
      expect(refusals[5]).toContain("a method that is a number, not a string");
      expect(refusals[6]).toContain("a method that is a boolean, not a string");
      expect(refusals[7]).toContain("a method that is null, not a string");
      cases.forEach(([, reads], k) => expect(refusals[k]).toContain(reads ? "DENY receipt written" : "no receipt"));
      await gate.stop();
    });
  }

  for (const merge of ["assign", "forin"] as const) {
    it(`a member named "__proto__" at the top level or in params is refused: -32600 with its id, a DENY receipt when the method of the message or of that member reads as tools/call, not forwarded; a downstream that merges the message with ${merge === "assign" ? "Object.assign({}, msg)" : "a for...in copy"} runs nothing`, async () => {
      const gate = await startGate(tmp, { deny: [{ tool: "mock_swap" }] }, { merge, lookup: (n) => n.trim().toLowerCase() });
      // Written as raw JSON text: a "__proto__" key in a JS object literal sets
      // the prototype and JSON.stringify drops it, so the member only reaches
      // the wire when the text carries it literally (as JSON.parse keeps it).
      const received = await send(gate, [
        // The P18 attack: method and params carried in a top-level "__proto__"
        // member. One with an id, one without (a notification shape).
        '{"jsonrpc":"2.0","id":131,"__proto__":{"method":"tools/call","params":{"name":"mock_swap","arguments":{"amount_in":131}}}}',
        '{"jsonrpc":"2.0","__proto__":{"method":"tools/call","params":{"name":"mock_swap","arguments":{"amount_in":132}}}}',
        // A real request (its own method is tools/list) that also carries a
        // "__proto__" tools/call: refused, DENY receipt names the member's tool.
        '{"jsonrpc":"2.0","id":133,"method":"tools/list","__proto__":{"method":"tools/call","params":{"name":"mock_swap"}}}',
        // A "__proto__" member in params, carrying a name but no method, on a
        // message whose own method is not tools/call: refused, and no receipt
        // (no method reads as tools/call), still not forwarded.
        '{"jsonrpc":"2.0","id":134,"method":"tools/list","params":{"name":"get_quote","__proto__":{"name":"mock_swap"}}}',
        // Well-formed lines, handled as before.
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
        JSON.stringify({ jsonrpc: "2.0", id: 95, method: "tools/list" }),
        toolCall(96, "get_quote"),
      ]);

      // Nothing the __proto__ lines carried ran: the gate refused and never
      // forwarded them, so the merging downstream never saw them.
      expect(gate.ran).toEqual(["get_quote"]);
      expect(gate.forwarded.map((l) => {
        const m = JSON.parse(l) as { id?: unknown; method?: unknown };
        return m.id ?? m.method;
      })).toEqual(["notifications/initialized", 95, 96, "sync"]);
      // id 131 and the no-id line have no top-level method, so their error id
      // is null (the C1c id rule); id 133 and 134 are requests, so they keep it.
      expect(received.slice(0, 4)).toEqual([refused(null, -32600), refused(null, -32600), refused(133, -32600), refused(134, -32600)]);
      expect(decisions(gate)).toEqual([
        '"mock_swap":deny', // id 131
        '"mock_swap":deny', // no-id line
        '"mock_swap":deny', // id 133: the __proto__ member's tools/call
        '"get_quote":allow', // id 96
      ]);
      // id 134's params.__proto__ carries no method, so no DENY receipt.
      expectChainValid(gate, tmp);
      const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
      expect(refusals).toHaveLength(4);
      expect(refusals[0]).toContain('member named "__proto__" at the top level');
      expect(refusals[0]).toContain('DENY receipt written (tool "mock_swap")');
      expect(refusals[3]).toContain('member named "__proto__" in params');
      expect(refusals[3]).toContain("no receipt");
      await gate.stop();
    });
  }

  // The message is `argsNesting`+3 levels deep (message, params, arguments, x,
  // then the array). MAX_VALUE_DEPTH works; one level deeper, and the 3,000 and
  // 20,000 that overflow the JCS canonicalizer, are refused and never run.
  for (const messageDepth of [DEPTH_LIMIT, DEPTH_LIMIT + 1, 3000, 20000]) {
    const works = messageDepth <= DEPTH_LIMIT;
    it(`a tools/call ${messageDepth} levels deep ${works ? "still runs (its receipt is computed before it is forwarded)" : "is refused: -32600 with its id, a DENY receipt over the empty object, not forwarded"}, and one deep line never stops the proxy`, async () => {
      const gate = await startGate(tmp, { deny: [] });
      const argsNesting = messageDepth - 3;
      const nested = "[".repeat(argsNesting) + "1" + "]".repeat(argsNesting);
      const deepCall = `{"jsonrpc":"2.0","id":140,"method":"tools/call","params":{"name":"get_quote","arguments":{"x":${nested}}}}`;
      const received = await send(gate, [deepCall, toolCall(141, "get_quote")]);

      if (works) {
        // At the limit the deep call runs and both are recorded as ALLOW.
        expect(gate.ran).toEqual(["get_quote", "get_quote"]);
        expect(received.slice(0, 2).map((m) => (m as { id: unknown }).id)).toEqual([140, 141]);
        expect(decisions(gate)).toEqual(['"get_quote":allow', '"get_quote":allow']);
      } else {
        // Over the limit the deep call is refused and never forwarded; the
        // plain call after it still runs, so one pathological line did not
        // stop the proxy. The DENY receipt's args_hash is over the empty
        // object (the deep arguments are never canonicalized).
        expect(gate.ran).toEqual(["get_quote"]);
        expect(received[0]).toEqual(refused(140, -32600));
        expect((received[1] as { id?: unknown; result?: unknown }).id).toBe(141);
        expect((received[1] as { result?: unknown }).result).toBeDefined();
        const recs = receipts(gate);
        expect(recs).toHaveLength(2);
        const first = recs[0]!.event;
        expect(first.type === "mcp_call" && first.decision).toBe("deny");
        expect(first.type === "mcp_call" && first.args_hash).toBe(argsHash({}));
        const second = recs[1]!.event;
        expect(second.type === "mcp_call" && second.decision).toBe("allow");
        const refusal = gate.logs.find((l) => l.startsWith("[proxy] REFUSE") && l.includes("nested more than"));
        expect(refusal).toContain(`${DEPTH_LIMIT} levels deep`);
      }
      expectChainValid(gate, tmp);
      await gate.stop();
    });
  }

  it("with allowNonstandardToolNames, deny rules still match without regard to case whichever side has the capitals, the server label matches exactly, an empty name is still refused, and other names pass with ALLOW receipts", async () => {
    const gate = await startGate(
      tmp,
      { deny: [{ tool: "Mock_Swap" }, { tool: "delete", server: "other" }] },
      { allowNonstandardToolNames: true },
    );
    const received = await send(gate, [
      // The flag does not let an empty name through.
      toolCall(8, ""),
      toolCall(1, "mock_swap"),
      toolCall(2, "MOCK_SWAP"),
      // U+017F LATIN SMALL LETTER LONG S, which Unicode folds to s.
      toolCall(3, "mock_ſwap"),
      toolCall(4, "delete"),
      toolCall(5, "DELETE"),
      toolCall(6, "mock swap"),
      toolCall(7, "mock_swap_v2"),
    ]);

    expect(received.slice(0, 4)).toEqual([refused(8, -32602), denied(1), denied(2), denied(3)]);
    expect(received.slice(4, -1).map((m) => (m as { id: unknown }).id)).toEqual([4, 5, 6, 7]);
    expect(forwardedTools(gate)).toEqual(["delete", "DELETE", "mock swap", "mock_swap_v2", "ping"]);
    expect(gate.ran).toEqual(["delete", "delete", "mock swap", "mock_swap_v2"]);
    expect(decisions(gate)).toEqual([
      '"":deny',
      '"mock_swap":deny',
      '"MOCK_SWAP":deny',
      '"mock_ſwap":deny',
      '"delete":allow',
      '"DELETE":allow',
      '"mock swap":allow',
      '"mock_swap_v2":allow',
    ]);
    expectChainValid(gate, tmp);
    const refusals = gate.logs.filter((l) => l.startsWith("[proxy] REFUSE"));
    expect(refusals).toHaveLength(1);
    expect(refusals[0]).toContain("no params object with a non-empty string name");
    expect(gate.logs.filter((l) => l.includes(WARNING))).toHaveLength(1);
    await gate.stop();
  });

  it("with allowNonstandardToolNames, a deny rule also stops a name equal to it after a full case mapping (the ligature ﬁ, ß), which a downstream comparing upper-cased names would run", async () => {
    const gate = await startGate(
      tmp,
      { deny: [{ tool: "delete_file" }, { tool: "strasse" }] },
      { lookup: (name) => name.toUpperCase(), allowNonstandardToolNames: true },
    );
    const received = await send(gate, [
      toolCall(1, "delete_ﬁle"), // LATIN SMALL LIGATURE FI: upper case FI
      toolCall(2, "straße"), // upper case SS
      toolCall(3, "STRAẞE"), // LATIN CAPITAL LETTER SHARP S: Python's casefold() gives ss
      toolCall(4, "DELETE_FİLE"), // Java's equalsIgnoreCase matches U+0130 to i
      toolCall(5, "delete_files"),
    ]);

    expect(gate.ran).toEqual(["DELETE_FILES"]);
    expect(received.slice(0, 4)).toEqual([denied(1), denied(2), denied(3), denied(4)]);
    expect((received[4] as { id: unknown }).id).toBe(5);
    expect(decisions(gate)).toEqual([
      '"delete_ﬁle":deny',
      '"straße":deny',
      '"STRAẞE":deny',
      '"DELETE_FİLE":deny',
      '"delete_files":allow',
    ]);
    expectChainValid(gate, tmp);
    await gate.stop();
  });

  it("the CLI refuses a nonstandard tool name by default, with --allow-nonstandard-tool-names forwards it and warns on stderr at start, and the flag takes no value", async () => {
    // node running tsx's CLI file on src/cli.ts, and "node" for the downstream,
    // as test/witness.test.ts starts the CLI proxy: no npx, no shell for the CLI.
    const root = resolve(import.meta.dirname, "..");
    const tsx = join(root, "node_modules", "tsx", "dist", "cli.mjs");
    const cli = join(root, "src", "cli.ts");
    const server = join(root, "scripts", "fake-mcp-server.ts");
    const policyPath = writePolicy(tmp, { deny: [] });
    await initIdentity(tmp);
    const run = (extra: string[], name: string) =>
      new Promise<{ status: number | null; stdout: string; stderr: string }>((done, fail) => {
        const child = spawn(
          process.execPath,
          [tsx, cli, "proxy", "--dir", tmp, "--chain", join(tmp, `cli-${extra.length}.jsonl`), "--session-id", "sess-cli-names",
            "--policy", policyPath, "--server-label", "fake", ...extra, "--", "node", tsx, server],
          { stdio: ["pipe", "pipe", "pipe"] },
        );
        // A child that does not exit is killed and fails the test by name,
        // inside the test's 60 s budget.
        const timer = setTimeout(() => {
          child.kill();
          fail(new Error(`spawn timeout: chirindo proxy ${extra.join(" ")} did not exit within 25000 ms and was killed`));
        }, 25_000);
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (c: Buffer) => {
          stdout += c.toString("utf8");
          if (stdout.includes('"id":2')) child.stdin.end();
        });
        child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
        child.on("exit", (status) => {
          clearTimeout(timer);
          done({ status, stdout, stderr });
        });
        child.stdin.write(
          JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: { text: "x" } } }) + "\n",
        );
      });

    const plain = await run([], "écho");
    expect(plain.status).toBe(0);
    const plainAnswer = JSON.parse(plain.stdout.trim().split("\n")[0]!) as { id: unknown; error?: { code: number; message: string } };
    expect(plainAnswer.id).toBe(2);
    expect(plainAnswer.error?.code).toBe(-32602);
    expect(plainAnswer.error?.message).toContain("--allow-nonstandard-tool-names");
    expect(plain.stderr).not.toContain(WARNING);
    expect(plain.stderr).toContain("[proxy] REFUSE");

    const flagged = await run(["--allow-nonstandard-tool-names"], "écho");
    expect(flagged.status).toBe(0);
    expect(flagged.stderr.split("\n").filter((l) => l.includes(WARNING))).toHaveLength(1);
    // Forwarded: the fake server itself answers that it has no such tool.
    const flaggedAnswer = JSON.parse(flagged.stdout.trim().split("\n")[0]!) as { id: unknown; error?: { message: string } };
    expect(flaggedAnswer.id).toBe(2);
    expect(flaggedAnswer.error?.message).toBe("Unknown tool: écho");

    // A value for the flag is a usage error (exit 2), before anything starts.
    const valued = spawnSync(
      process.execPath,
      [tsx, cli, "proxy", "--dir", tmp, "--chain", join(tmp, "cli-valued.jsonl"), "--policy", policyPath,
        "--server-label", "fake", "--allow-nonstandard-tool-names=yes", "--", "node", tsx, server],
      { encoding: "utf8", timeout: 25_000 },
    );
    expect(valued.status).toBe(2);
    expect(valued.stderr).toContain("--allow-nonstandard-tool-names takes no value");
    expect(valued.stderr).not.toContain(WARNING);
  }, 60_000);
});
