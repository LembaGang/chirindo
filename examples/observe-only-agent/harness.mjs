#!/usr/bin/env node
// Drive the Chirindo proxy as if we were Claude Desktop or Cursor.
//
// What this script proves: an integrator running ONLY the published
// `@headlessoracle/chirindo` package — no local Chirindo checkout — can
// stand up an observe-only sidecar in front of an arbitrary stdio MCP
// server and obtain a signed receipt for a consequential tool call.
//
// Steps:
//   1. Spawn `chirindo proxy` (via the installed dist/cli.js) with our
//      downstream MCP server as the child it mediates.
//   2. Speak MCP over the proxy's stdin/stdout: initialize, tools/list,
//      tools/call mock_swap.
//   3. Close stdin to let the proxy shut down cleanly. The chain file is
//      now on disk at .gate/sessions/<session-id>.jsonl.
//
// stderr from the proxy and the downstream are forwarded to this
// process's stderr so a reader can see the gate's boot line and the
// downstream's "CONSEQUENTIAL mock_swap executed" line.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Resolve the published CLI through node_modules so we never depend on
// the host's PATH (the same reason the main README uses absolute paths
// in client config snippets).
const chirindoPkg = require.resolve("@headlessoracle/chirindo/package.json");
const chirindoCli = join(dirname(chirindoPkg), "dist", "cli.js");

const downstream = join(__dirname, "downstream-mcp-server.mjs");
const policy = join(__dirname, "policy.json");
// GATE_DIR override lets the README's "verify against the live JWKS"
// step reuse an already-published signing identity (the main repo's
// .gate/, whose public key is on headlessoracle.com's JWKS). A fresh
// integrator's own .gate/ key isn't on the JWKS until they publish it,
// so by default we use the local example .gate/ — see README §5.
const gateDir = process.env.GATE_DIR ?? join(__dirname, ".gate");

const sessionId = process.env.SESSION_ID ?? cryptoRandomUuid();

const proxy = spawn(
  process.execPath,
  [
    chirindoCli,
    "proxy",
    "--policy", policy,
    "--server-label", "observe-only-example",
    "--dir", gateDir,
    "--session-id", sessionId,
    "--",
    // Pass bare "node" rather than process.execPath. On Windows the proxy
    // spawns the downstream via `shell: true` to handle `.cmd` shims (the
    // documented Windows fix in chirindo's spawn layer); shell:true does
    // not escape arguments, so an interpreter path containing spaces
    // (e.g. C:\Program Files\nodejs\node.exe) is mangled. Bare `node` is
    // already on PATH in any environment where the package installed.
    "node", downstream,
  ],
  { stdio: ["pipe", "pipe", "inherit"] },
);

const responses = new Map();
let nextId = 1;
let initialized = false;

const rl = createInterface({ input: proxy.stdout });
rl.on("line", (line) => {
  if (line.trim().length === 0) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    process.stderr.write(`[harness] non-JSON proxy line: ${line}\n`);
    return;
  }
  if (msg.id !== undefined && responses.has(msg.id)) {
    const resolver = responses.get(msg.id);
    responses.delete(msg.id);
    resolver(msg);
  }
});

function send(method, params) {
  const id = nextId++;
  const frame = { jsonrpc: "2.0", id, method, params };
  proxy.stdin.write(JSON.stringify(frame) + "\n");
  return new Promise((resolve) => responses.set(id, resolve));
}

function notify(method, params) {
  proxy.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

async function main() {
  const initResp = await send("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "chirindo-observe-only-example-harness", version: "0.0.0" },
  });
  if (initResp.error) throw new Error(`initialize failed: ${JSON.stringify(initResp.error)}`);
  initialized = true;
  notify("notifications/initialized", {});

  const toolsResp = await send("tools/list", {});
  if (toolsResp.error) throw new Error(`tools/list failed: ${JSON.stringify(toolsResp.error)}`);
  process.stderr.write(
    `[harness] downstream exposes tools: ${toolsResp.result.tools.map((t) => t.name).join(", ")}\n`,
  );

  // Consequential call — in production this would move funds. Here it
  // produces a chain entry whose event.tool_name = "mock_swap" with the
  // gate's signature over canonical bytes.
  const swapResp = await send("tools/call", {
    name: "mock_swap",
    arguments: {
      pair: "ETH/USDC",
      amount_in: 0.25,
      slippage_bps: 50,
    },
  });
  if (swapResp.error) throw new Error(`mock_swap failed: ${JSON.stringify(swapResp.error)}`);
  const text = swapResp.result?.content?.[0]?.text ?? "(no content)";
  process.stderr.write(`[harness] mock_swap response: ${text}\n`);

  proxy.stdin.end();
  process.stderr.write(`[harness] session_id=${sessionId}\n`);
  process.stderr.write(
    `[harness] chain file: ${join(gateDir, "sessions", sessionId + ".jsonl")}\n`,
  );
}

proxy.on("exit", (code, signal) => {
  if (!initialized) {
    process.stderr.write(
      `[harness] proxy exited before initialize completed (code=${code} signal=${signal})\n`,
    );
    process.exit(1);
  }
});

main().catch((e) => {
  process.stderr.write(`[harness] error: ${e.message}\n`);
  try { proxy.kill(); } catch {}
  process.exit(1);
});

function cryptoRandomUuid() {
  return require("node:crypto").randomUUID();
}
