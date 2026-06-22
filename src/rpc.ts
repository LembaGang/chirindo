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
// until the next newline. Empty lines are ignored. Anything that fails to
// JSON-parse is forwarded raw with a warning to stderr (so we don't break
// a downstream server that produces a payload we don't understand).

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

export function isRequest(m: unknown): m is JsonRpcRequest {
  return (
    typeof m === "object" &&
    m !== null &&
    (m as Record<string, unknown>)["jsonrpc"] === "2.0" &&
    typeof (m as Record<string, unknown>)["method"] === "string" &&
    "id" in (m as Record<string, unknown>)
  );
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
