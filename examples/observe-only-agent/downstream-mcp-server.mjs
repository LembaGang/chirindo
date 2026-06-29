#!/usr/bin/env node
// A small realistic downstream MCP server, used solely as the example
// agent's tool source. Implements newline-delimited JSON-RPC 2.0 over
// stdio per MCP's stdio transport. Three tools:
//
//   get_quote    — read-only: return a fake price quote (safe).
//   mock_swap    — "consequential": pretend to execute a token swap.
//                  Logs loudly on execution so the chain file can be
//                  cross-checked against actual side effects.
//   mock_send    — "consequential": pretend to send funds. Same idea.
//
// Nothing here actually touches the network or a wallet — this is the
// downstream surface that demonstrates *why* you'd want a fail-closed
// gate in front of an agent: each call name maps to an action with
// real-world cost in a production deployment.

import { createInterface } from "node:readline";

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function log(s) {
  process.stderr.write(`[downstream] ${s}\n`);
}

const TOOLS = [
  {
    name: "get_quote",
    description: "Get a (fake) price quote for a token pair. Read-only, safe.",
    inputSchema: {
      type: "object",
      properties: {
        pair: { type: "string", description: "e.g. ETH/USDC" },
      },
      required: ["pair"],
    },
  },
  {
    name: "mock_swap",
    description:
      "Execute a (mock) token swap. Consequential in production — should be gated.",
    inputSchema: {
      type: "object",
      properties: {
        pair: { type: "string" },
        amount_in: { type: "number" },
        slippage_bps: { type: "number" },
      },
      required: ["pair", "amount_in"],
    },
  },
  {
    name: "mock_send",
    description:
      "Send (mock) funds to an address. Consequential in production — should be gated.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "string" },
        amount: { type: "number" },
        asset: { type: "string" },
      },
      required: ["to", "amount", "asset"],
    },
  },
];

function handle(req) {
  if (req.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: req.id ?? null,
      result: {
        protocolVersion: "2025-11-25",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "observe-only-example-downstream", version: "0.0.0" },
      },
    });
    return;
  }
  if (req.method === "notifications/initialized") return;
  if (req.method === "tools/list") {
    send({ jsonrpc: "2.0", id: req.id ?? null, result: { tools: TOOLS } });
    return;
  }
  if (req.method === "tools/call") {
    const params = req.params ?? {};
    const name = params.name;
    const args = params.arguments ?? {};
    if (name === "get_quote") {
      const pair = String(args.pair ?? "");
      log(`get_quote called for pair='${pair}'`);
      send({
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [
            { type: "text", text: `quote ${pair}: 1 ${pair.split("/")[0] ?? "?"} = 3421.55 ${pair.split("/")[1] ?? "?"}` },
          ],
          isError: false,
        },
      });
      return;
    }
    if (name === "mock_swap") {
      const pair = String(args.pair ?? "");
      const amountIn = Number(args.amount_in ?? 0);
      log(`CONSEQUENTIAL mock_swap executed: pair='${pair}' amount_in=${amountIn}`);
      send({
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [
            {
              type: "text",
              text: `swap submitted (mock): ${amountIn} of ${pair} — tx 0xMOCK${Math.floor(Math.random() * 1e9).toString(16)}`,
            },
          ],
          isError: false,
        },
      });
      return;
    }
    if (name === "mock_send") {
      const to = String(args.to ?? "");
      const amount = Number(args.amount ?? 0);
      const asset = String(args.asset ?? "");
      log(`CONSEQUENTIAL mock_send executed: to='${to}' amount=${amount} asset='${asset}'`);
      send({
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [
            { type: "text", text: `sent (mock): ${amount} ${asset} -> ${to}` },
          ],
          isError: false,
        },
      });
      return;
    }
    send({
      jsonrpc: "2.0",
      id: req.id ?? null,
      error: { code: -32602, message: `Unknown tool: ${String(name)}` },
    });
    return;
  }
  if (req.id !== undefined && req.id !== null) {
    send({
      jsonrpc: "2.0",
      id: req.id,
      error: { code: -32601, message: `Method not found: ${String(req.method)}` },
    });
  }
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (line.trim().length === 0) return;
  try {
    handle(JSON.parse(line));
  } catch (e) {
    log(`bad line: ${e.message}`);
  }
});
rl.on("close", () => process.exit(0));
