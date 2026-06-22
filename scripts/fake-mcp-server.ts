#!/usr/bin/env node
// Minimal MCP server used as the downstream in spike tests.
//
// Implements just enough of the protocol to exercise the gate's tools/call
// path: `initialize`, `tools/list`, `tools/call`. Two test tools:
//
//   echo   — returns the input string in a text content block (safe).
//   delete — pretends to delete a path; SHOULD be blocked by policy in
//            the deny tests so we can prove the proxy intercepts before
//            this server ever runs the action.
//
// Logging goes to stderr per stdio transport rules.

import { createInterface } from "node:readline";

interface JsonRpc {
  jsonrpc: "2.0";
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

const TOOLS = [
  {
    name: "echo",
    description: "Echo back the input text. Safe.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"],
    },
  },
  {
    name: "delete",
    description: "Pretend to delete a path. Destructive.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
    },
  },
];

function send(msg: JsonRpc): void {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function log(s: string): void {
  process.stderr.write(`[fake-mcp] ${s}\n`);
}

function handle(req: JsonRpc): void {
  if (req.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: req.id ?? null,
      result: {
        protocolVersion: "2025-11-25",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "fake-mcp-server", version: "0.0.0" },
      },
    });
    return;
  }
  if (req.method === "notifications/initialized") {
    return; // notification, no response
  }
  if (req.method === "tools/list") {
    send({ jsonrpc: "2.0", id: req.id ?? null, result: { tools: TOOLS } });
    return;
  }
  if (req.method === "tools/call") {
    const params = (req.params ?? {}) as {
      name?: string;
      arguments?: Record<string, unknown>;
    };
    if (params.name === "echo") {
      const text = String(params.arguments?.["text"] ?? "");
      log(`echo called with text='${text}'`);
      send({
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [{ type: "text", text: `echo: ${text}` }],
          isError: false,
        },
      });
      return;
    }
    if (params.name === "delete") {
      // For the spike, executing this CONFIRMS the gate did NOT intercept
      // — which is what the deny tests must NOT see. We do nothing
      // destructive (no fs writes), but we DO log loudly so a test can
      // assert this branch wasn't taken.
      const path = String(params.arguments?.["path"] ?? "");
      log(`DESTRUCTIVE delete tool ran for path='${path}' — gate did not intercept`);
      send({
        jsonrpc: "2.0",
        id: req.id ?? null,
        result: {
          content: [{ type: "text", text: `deleted (fake): ${path}` }],
          isError: false,
        },
      });
      return;
    }
    send({
      jsonrpc: "2.0",
      id: req.id ?? null,
      error: { code: -32602, message: `Unknown tool: ${String(params.name)}` },
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
    handle(JSON.parse(line) as JsonRpc);
  } catch (e) {
    log(`bad line: ${(e as Error).message}`);
  }
});
rl.on("close", () => process.exit(0));
