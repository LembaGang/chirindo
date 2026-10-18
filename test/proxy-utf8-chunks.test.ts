// A UTF-8 character split across two chunks of a stream (0.5.3).
//
// A pipe hands the gate its input in chunks of any size, and a chunk can end
// inside a multi-byte character. Up to 0.5.2 the gate decoded each chunk on
// its own, so each piece of such a character became U+FFFD in what it read,
// hashed and forwarded, in both directions. It now decodes client stdin and
// downstream stdout with one streaming decoder each.
//
// These tests write lines to the gate in several chunks, cut inside
// characters of two, three and four bytes, with a pause between chunks so
// each arrives as its own "data" event.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PassThrough, Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  argsHashFromJsonString,
  parseChainJsonl,
  resultHashFromJsonString,
  runVerify,
} from "../src/vendor/recorder/index.js";
import type { SignedRecord } from "../src/vendor/recorder/index.js";
import { loadPolicy } from "../src/policy.js";
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
  toClient: PassThrough;
  handle: ProxyHandle;
  chainPath: string;
  // Every byte the downstream received, in order.
  forwardedBytes: () => Buffer;
  // Every byte the client received, in order.
  receivedBytes: () => Buffer;
  stop: () => Promise<void>;
}

// The downstream answers each request with an id, writing each answer in one
// piece, unless `answer` is given for a tools/call: then that function writes
// the answer.
async function startGate(
  tmp: string,
  answer?: (id: unknown, toClient: PassThrough) => Promise<void>,
): Promise<Gate> {
  const identity = await initIdentity(tmp);
  const policyPath = writePolicy(tmp, { deny: [] });
  const chainPath = join(tmp, "chain.jsonl");
  const { clientIn, clientOut } = makeClientPipes();
  const downstream = makeFakeDownstream();
  const forwarded: Buffer[] = [];
  const received: Buffer[] = [];
  clientOut.on("data", (chunk: Buffer | string) => received.push(Buffer.from(chunk)));
  let pending = Buffer.alloc(0);
  downstream.fromClient.on("data", (chunk: Buffer | string) => {
    const bytes = Buffer.from(chunk);
    forwarded.push(bytes);
    pending = Buffer.concat([pending, bytes]);
    for (let nl = pending.indexOf(0x0a); nl >= 0; nl = pending.indexOf(0x0a)) {
      const line = pending.subarray(0, nl).toString("utf8");
      pending = pending.subarray(nl + 1);
      const msg = JSON.parse(line) as { id?: unknown; method?: unknown };
      if (!("id" in msg)) continue;
      if (answer !== undefined && msg.method === "tools/call") {
        void answer(msg.id, downstream.toClient);
      } else {
        downstream.toClient.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: {} }) + "\n");
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
    sessionId: "sess-utf8",
    serverLabel: "fake",
    chainPath,
    log: () => {
      /* quiet */
    },
  });
  return {
    clientIn,
    clientOut,
    toClient: downstream.toClient,
    handle,
    chainPath,
    forwardedBytes: () => Buffer.concat(forwarded),
    receivedBytes: () => Buffer.concat(received),
    stop: async () => {
      downstream.exit(0);
      await handle.done;
    },
  };
}

// The UTF-8 bytes of `text`, cut inside each character listed in `cuts`, after
// the number of that character's bytes given with it.
function pieces(text: string, cuts: Array<[string, number]>): Buffer[] {
  const bytes = Buffer.from(text, "utf8");
  const at = cuts
    .map(([ch, k]) => {
      const start = bytes.indexOf(Buffer.from(ch, "utf8"));
      if (start < 0) throw new Error(`no ${ch} in the text`);
      return start + k;
    })
    .sort((a, b) => a - b);
  const out: Buffer[] = [];
  let from = 0;
  for (const cut of at) {
    out.push(bytes.subarray(from, cut));
    from = cut;
  }
  out.push(bytes.subarray(from));
  return out;
}

async function writePieces(stream: Writable, parts: Buffer[]): Promise<void> {
  for (const part of parts) {
    stream.write(part);
    await new Promise((r) => setTimeout(r, 10));
  }
}

const CUTS: Array<[string, number]> = [
  ["é", 1], // two bytes, cut after the first
  ["☕", 2], // three bytes, cut after the second
  ["😀", 1], // four bytes, cut after the first ...
  ["😀", 3], // ... and after the third
];

function receipts(gate: Gate): SignedRecord[] {
  return parseChainJsonl(readFileSync(gate.chainPath, "utf8")).records;
}

function expectChainValid(gate: Gate, tmp: string): void {
  const v = runVerify({ chainPath: gate.chainPath, identityPath: join(tmp, "identity.json") });
  expect(v.kind).toBe("valid");
}

describe("proxy: a UTF-8 character split across chunks arrives whole", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-utf8-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  it("client to downstream: a tools/call cut inside characters reaches the downstream intact, and args_hash is the hash of the client's arguments", async () => {
    const gate = await startGate(tmp);
    const args = '{"note":"café ☕ 😀","n":1}';
    const line = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":${args}}}`;
    const answered = collectJsonLines(gate.clientOut, (m) => (m as { id?: unknown }).id === 1);
    await writePieces(gate.clientIn, pieces(line + "\n", CUTS));
    await answered;

    const forwarded = JSON.parse(gate.forwardedBytes().toString("utf8")) as {
      params: { arguments: unknown };
    };
    expect(forwarded.params.arguments).toEqual(JSON.parse(args));
    const recs = receipts(gate);
    expect(recs).toHaveLength(1);
    if (recs[0]!.event.type !== "mcp_call") throw new Error("expected mcp_call");
    expect(recs[0]!.event.decision).toBe("allow");
    expect(recs[0]!.event.args_hash).toBe(argsHashFromJsonString(args));
    expectChainValid(gate, tmp);
    await gate.stop();
  });

  it("downstream to client: an answer cut inside characters reaches the client intact, and result_hash is the hash of the downstream's result", async () => {
    const result = '{"content":[{"type":"text","text":"naïve café ☕ 😀"}],"isError":false}';
    const gate = await startGate(tmp, async (id, toClient) => {
      const answer = `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":${result}}\n`;
      await writePieces(toClient, pieces(answer, CUTS));
    });
    const answered = collectJsonLines(gate.clientOut, (m) => (m as { id?: unknown }).id === 2);
    gate.clientIn.write(
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: {} } }) + "\n",
    );
    const [msg] = await answered;

    expect((msg as { result: unknown }).result).toEqual(JSON.parse(result));
    const recs = receipts(gate);
    expect(recs).toHaveLength(1);
    if (recs[0]!.event.type !== "mcp_call") throw new Error("expected mcp_call");
    expect(recs[0]!.event.result_hash).toBe(resultHashFromJsonString(result));
    expectChainValid(gate, tmp);
    await gate.stop();
  });

  it("other lines cut inside characters pass byte for byte in both directions", async () => {
    const gate = await startGate(tmp);
    const up = '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"café ☕ 😀"}}\n';
    const down = '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"café ☕ 😀"}}\n';
    const answered = collectJsonLines(gate.clientOut, (m) => (m as { id?: unknown }).id === 3);
    await writePieces(gate.clientIn, pieces(up, CUTS));
    await answered;
    expect(gate.forwardedBytes().equals(Buffer.from(up, "utf8"))).toBe(true);

    const notified = collectJsonLines(
      gate.clientOut,
      (m) => (m as { method?: unknown }).method === "notifications/message",
    );
    await writePieces(gate.toClient, pieces(down, CUTS));
    await notified;
    const answer = JSON.stringify({ jsonrpc: "2.0", id: 3, result: {} }) + "\n";
    expect(gate.receivedBytes().equals(Buffer.from(answer + down, "utf8"))).toBe(true);
    await gate.stop();
  });
});
