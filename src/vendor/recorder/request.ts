// Request descriptor + commitment.
//
// The `request_descriptor` is the closed, canonical identity of a dispatched
// action. Its JCS canonicalization is hashed to produce `request_commitment`,
// which appears on every record and binds the recorder's view of the action
// to whatever a pre-action gate (later) authorized.
//
// Determinism rests on:
//   1. The field sets per type are CLOSED — do not add fields.
//   2. The same JCS routine used elsewhere.
//   3. The builder reads only fields that ARE part of the descriptor — never
//      timing, env, outcome, or anything else mutable.

import { jcsBytes } from "./canonicalize.js";
import { sha256Hex } from "./hash.js";
import type { RecordEvent } from "./record.js";

export interface ShellDescriptor {
  class: "shell";
  argv: string[];
  cwd: string;
}

export interface FileEditDescriptor {
  class: "file_edit";
  path: string;
  content_hash: string;
}

export interface FileReadDescriptor {
  class: "file_read";
  path: string;
}

export interface ToolCallDescriptor {
  class: "tool_call";
  tool: string;
  args_hash: string;
}

export interface McpCallDescriptor {
  class: "mcp_call";
  server: string;
  tool: string;
  args_hash: string;
}

export type RequestDescriptor =
  | ShellDescriptor
  | FileEditDescriptor
  | FileReadDescriptor
  | ToolCallDescriptor
  | McpCallDescriptor;

// Build the canonical descriptor for an event. Pure function — same input,
// byte-identical output. NEVER reads `outcome` or any post-dispatch field.
//
// Note: tool_call / mcp_call events use the field name `tool_name`; the
// descriptor uses the (closed, immutable) name `tool`. The mapping happens
// here so the closed descriptor schema stays stable across event-field
// renames.
export function requestDescriptor(event: RecordEvent): RequestDescriptor {
  switch (event.type) {
    case "shell":
      return { class: "shell", argv: event.argv, cwd: event.cwd };
    case "file_edit":
      return {
        class: "file_edit",
        path: event.path,
        content_hash: event.content_hash,
      };
    case "file_read":
      return { class: "file_read", path: event.path };
    case "tool_call":
      return {
        class: "tool_call",
        tool: event.tool_name,
        args_hash: event.args_hash,
      };
    case "mcp_call":
      return {
        class: "mcp_call",
        server: event.server,
        tool: event.tool_name,
        args_hash: event.args_hash,
      };
  }
}

export function requestCommitment(event: RecordEvent): string {
  return "sha256:" + sha256Hex(jcsBytes(requestDescriptor(event)));
}
