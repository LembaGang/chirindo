#!/usr/bin/env node
// Minimal MCP client for the ordering-evidence example. Run from the repo root:
//
//   node examples/ordering-evidence/client.mjs --policy <file> --session-id <id> --chain <path>
//
// It spawns the gate from this tree (`node dist/cli.js proxy`) in front of the
// observe-only example's downstream server, sends initialize,
// notifications/initialized and one tools/call of mock_swap, prints the
// response, closes stdin and waits for the gate to exit. The gate writes one
// signed receipt to --chain: ALLOW after the downstream answered, or DENY with
// nothing forwarded.
//
// The identity dir is always passed explicitly, from CHIRINDO_Y2_OPERATOR_DIR
// (a directory made with `chirindo init --dir`, outside the repository): the
// gate's default data dir in the repo root holds a different, published
// operator key.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";

const { env } = process;
const OPERATOR_DIR = env.CHIRINDO_Y2_OPERATOR_DIR;
if (!OPERATOR_DIR) {
  process.stderr.write("[client] CHIRINDO_Y2_OPERATOR_DIR is not set: set it to the operator identity directory (made with `chirindo init --dir <dir>`, outside this repository)\n");
  process.exit(2);
}

const { values } = parseArgs({
  options: {
    policy: { type: "string" },
    "session-id": { type: "string" },
    chain: { type: "string" },
  },
});
for (const k of ["policy", "session-id", "chain"]) {
  if (!values[k]) {
    process.stderr.write(`[client] --${k} is required\n`);
    process.exit(2);
  }
}

const proxy = spawn(
  process.execPath,
  [
    "dist/cli.js",
    "proxy",
    "--dir", OPERATOR_DIR,
    "--policy", values.policy,
    "--server-label", "ordering-evidence",
    "--session-id", values["session-id"],
    "--chain", values.chain,
    "--",
    // Bare "node": the proxy spawns the downstream with shell:true on Windows,
    // which does not quote an interpreter path containing spaces.
    "node", "examples/observe-only-agent/downstream-mcp-server.mjs",
  ],
  { stdio: ["pipe", "pipe", "inherit"] },
);

const pending = new Map();
let nextId = 1;

createInterface({ input: proxy.stdout }).on("line", (line) => {
  if (line.trim() === "") return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stderr.write(`[client] non-JSON line from gate: ${line}\n`);
    return;
  }
  if (msg.id !== undefined && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  }
});

function send(method, params) {
  const id = nextId++;
  proxy.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  return new Promise((resolve) => pending.set(id, resolve));
}

function notify(method, params) {
  proxy.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

const exited = new Promise((resolve) => proxy.on("exit", (code, signal) => resolve({ code, signal })));

const init = await send("initialize", {
  protocolVersion: "2025-11-25",
  capabilities: {},
  clientInfo: { name: "chirindo-ordering-evidence-client", version: "0.0.0" },
});
if (init.error) {
  process.stderr.write(`[client] initialize failed: ${JSON.stringify(init.error)}\n`);
  proxy.kill();
  process.exit(1);
}
notify("notifications/initialized", {});

const call = await send("tools/call", {
  name: "mock_swap",
  arguments: { pair: "ETH/USDC", amount_in: 0.25, slippage_bps: 50 },
});
process.stdout.write(`[client] tools/call mock_swap response: ${JSON.stringify(call)}\n`);

proxy.stdin.end();
const { code, signal } = await exited;
process.stdout.write(`[client] gate exited code=${code} signal=${signal}\n`);
process.exit(code === 0 ? 0 : 1);
