// JSON-RPC framing for MCP stdio transport.
//
// Per https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#stdio
// (fetched 2026-06-22):
//   - Messages are JSON-RPC 2.0, UTF-8 encoded.
//   - Messages are delimited by newlines.
//   - Messages MUST NOT contain embedded newlines.
//   - stderr is for logging only and MUST NOT be assumed to carry MCP.
//
// We treat each incoming line as one message. Partial lines are buffered
// until the next newline. Empty lines are ignored. A downstream line that
// fails to JSON-parse is passed to the client raw with a warning to stderr.
// Some client lines are refused with a JSON-RPC error and never forwarded
// (src/proxy.ts): a line that is not JSON, carries a carriage return inside
// it, names a member twice in one object, or is a batch, and a tools/call
// without a usable id.

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number | string | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export type JsonRpcMessage =
  | JsonRpcRequest
  | JsonRpcResponse
  | JsonRpcNotification;

// The gate no longer uses this to find a tools/call (see isToolsCall): a
// tools/call without an `id` or without `"jsonrpc": "2.0"` is still one.
export function isRequest(m: unknown): m is JsonRpcRequest {
  return (
    typeof m === "object" &&
    m !== null &&
    (m as Record<string, unknown>)["jsonrpc"] === "2.0" &&
    typeof (m as Record<string, unknown>)["method"] === "string" &&
    "id" in (m as Record<string, unknown>)
  );
}

// A tools/call is recognised by its method alone. The gate does not require
// `"jsonrpc": "2.0"` or an `id` before treating a message as a tools/call, so
// leaving either out cannot carry a call past the gate.
export function isToolsCall(m: unknown): m is Record<string, unknown> {
  return (
    typeof m === "object" &&
    m !== null &&
    !Array.isArray(m) &&
    (m as Record<string, unknown>)["method"] === "tools/call"
  );
}

// MCP, basic/ "Messages > Requests" (revisions 2025-11-25 and 2026-07-28):
// "Requests MUST include a string or integer ID." and "Unlike base JSON-RPC,
// the ID MUST NOT be null."
export function isValidRequestId(id: unknown): id is string | number {
  return (
    typeof id === "string" || (typeof id === "number" && Number.isInteger(id))
  );
}

// JSON-RPC 2.0 error codes the gate answers with when it refuses a client line.
export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;

// An error response for a line whose id could not be used. JSON-RPC 2.0 sets
// the id to null when it cannot be read from the request.
export function errorResponse(code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id: null, error: { code, message } };
}

export function isResponse(m: unknown): m is JsonRpcResponse {
  return (
    typeof m === "object" &&
    m !== null &&
    (m as Record<string, unknown>)["jsonrpc"] === "2.0" &&
    "id" in (m as Record<string, unknown>) &&
    !("method" in (m as Record<string, unknown>))
  );
}

// Line splitter: accumulates partial chunks (e.g. from stream events) and
// emits complete lines. Returns the residual buffer for the next call.
export function splitLines(
  buffer: string,
  chunk: string,
): { lines: string[]; rest: string } {
  const combined = buffer + chunk;
  const parts = combined.split("\n");
  const rest = parts.pop() ?? "";
  return { lines: parts.map((l) => l.replace(/\r$/, "")), rest };
}

export function encodeMessage(msg: JsonRpcMessage): string {
  return JSON.stringify(msg) + "\n";
}

// Build a deny-style tool result. Per MCP spec §"Tool Result" + §"Error
// Handling": tool execution errors are reported via `result.isError: true`
// + a `content` array — NOT via a JSON-RPC error object. The client/LLM
// then sees the tool as having failed (and is allowed to retry, but each
// retry will be denied again because policy is stateless wrt the gate).
export function denyToolResult(
  id: number | string | null,
  reason: string,
): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: `[gate denied] ${reason}`,
        },
      ],
      isError: true,
    },
  };
}
