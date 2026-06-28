// Cursor hook adapter — payload-to-record mapping.
//
// THIS MODULE IS OBSERVE-ONLY. The dispatcher returns the permissive
// response for every input. There is no code path that returns deny / ask /
// block; there is no flag that enables one. Gating is a deliberately
// separate, later, opt-in mode.
//
// Even if `mapToRecord` returns null (no record produced) or `appendFn`
// throws, the dispatcher's caller (the CLI handler) MUST still emit the
// permissive output and exit 0. See src/cli/hook.ts.
//
// Live-doc references (https://cursor.com/docs/hooks, fetched 2026-06-22):
//   - beforeShellExecution: { command, cwd, sandbox } -> { permission, ... }
//   - afterShellExecution:  { command, output, duration, sandbox } -> {}
//     NOTE: docs do NOT carry exit_code on afterShellExecution; the
//     recorder leaves event.exit_code undefined. Flagged in gate report.
//   - beforeReadFile:       { file_path, content, attachments? } -> { permission }
//   - afterFileEdit:        { file_path, edits[{old_string,new_string}] } -> {}
//   - beforeMCPExecution:   { tool_name, tool_input (JSON string), url|command } -> { permission }
//   - afterMCPExecution:    { tool_name, tool_input, result_json, duration, url|command } -> {}

import { createHash } from "node:crypto";
import { argsHashFromJsonString, sha256Hex } from "../hash.js";
import type { RecordEvent } from "../record.js";
import { shellSplit } from "./shell-split.js";
import type {
  AfterFileEditInput,
  AfterMCPExecutionInput,
  AfterShellExecutionInput,
  BeforeMCPExecutionInput,
  BeforeReadFileInput,
  BeforeShellExecutionInput,
  CursorHookInput,
} from "./payloads.js";

export interface AdapterOptions {
  // When true, the adapter writes command_hash instead of command for
  // shell events. NOTE: argv is still recorded (it feeds the closed
  // request_descriptor). Hash-sensitive mode redacts the plaintext
  // command from the event body only — the descriptor identity is
  // unchanged. This is a known limitation, flagged in the gate report.
  hashSensitive?: boolean;
}

// Map a Cursor hook payload to a recorder RecordEvent. Returns null when
// the hook fires but doesn't correspond to a recorder event type (e.g. the
// payload is malformed; we never reject — null means "nothing to record,
// just allow the agent through").
export function mapToRecord(
  input: CursorHookInput,
  opts: AdapterOptions = {},
): RecordEvent | null {
  try {
    switch (input.hook_event_name) {
      case "beforeShellExecution":
        return shellEventFromBefore(input, opts);
      case "afterShellExecution":
        return shellEventFromAfter(input, opts);
      case "beforeReadFile":
        return fileReadEventFrom(input);
      case "afterFileEdit":
        return fileEditEventFrom(input);
      case "beforeMCPExecution":
        return mcpEventFromBefore(input);
      case "afterMCPExecution":
        return mcpEventFromAfter(input);
    }
  } catch {
    // Never propagate — observe-only.
    return null;
  }
  return null;
}

// ---- shell --------------------------------------------------------------

function shellEventFromBefore(
  input: BeforeShellExecutionInput,
  opts: AdapterOptions,
): RecordEvent {
  const argv = shellSplit(input.command);
  return {
    type: "shell",
    outcome: "executed", // pre-event records the dispatch intent
    argv,
    cwd: input.cwd,
    ...commandFields(input.command, opts),
    decision: "observed",
    decision_source: "n/a",
  };
}

function shellEventFromAfter(
  input: AfterShellExecutionInput,
  opts: AdapterOptions,
): RecordEvent {
  const argv = shellSplit(input.command);
  return {
    type: "shell",
    outcome: "executed",
    argv,
    cwd: argvCwdFallback(),
    // exit_code not provided by Cursor's afterShellExecution payload.
    ...commandFields(input.command, opts),
    decision: "observed",
    decision_source: "n/a",
  };
}

// afterShellExecution does not include cwd. The pre-event already recorded
// the working directory; recording a placeholder here keeps the event shape
// consistent without inventing data. Empty string is a deliberate signal
// "not provided by hook"; readers see it as "unknown".
function argvCwdFallback(): string {
  return "";
}

function commandFields(
  command: string,
  opts: AdapterOptions,
): { command: string } | { command_hash: string } {
  if (opts.hashSensitive) {
    return { command_hash: "sha256:" + sha256Hex(Buffer.from(command, "utf8")) };
  }
  return { command };
}

// ---- file_read ----------------------------------------------------------

function fileReadEventFrom(input: BeforeReadFileInput): RecordEvent {
  return {
    type: "file_read",
    outcome: "executed",
    path: input.file_path,
    content_hash:
      "sha256:" + sha256Hex(Buffer.from(input.content, "utf8")),
  };
}

// ---- file_edit ----------------------------------------------------------

// Cursor's afterFileEdit gives us the list of edits as before/after string
// pairs, not the final file content. We reconstruct the *post-edit content
// hash* from the new_strings concatenated by position (best-effort) — the
// hash is over the concatenated new_strings, which is stable for a given
// edit list. For the descriptor identity we need a content_hash that's
// reproducible from the payload; this is it.
function fileEditEventFrom(input: AfterFileEditInput): RecordEvent {
  const h = createHash("sha256");
  let totalBytes = 0;
  for (const e of input.edits) {
    h.update(e.new_string, "utf8");
    totalBytes += Buffer.byteLength(e.new_string, "utf8");
  }
  const contentHash = "sha256:" + h.digest("hex");

  // prev_content_hash: hash of the concatenated old_strings (same shape).
  const ph = createHash("sha256");
  for (const e of input.edits) ph.update(e.old_string, "utf8");
  const prevHash = "sha256:" + ph.digest("hex");

  return {
    type: "file_edit",
    outcome: "executed",
    path: input.file_path,
    content_hash: contentHash,
    prev_content_hash: prevHash,
    bytes: totalBytes,
  };
}

// ---- mcp_call / tool_call -----------------------------------------------

function mcpServerOf(input: { url?: string; command?: string }): string {
  // Per the docs, exactly one of url / command identifies the server. We
  // canonicalize to a single string for the event body. If both are absent
  // (shouldn't happen per the contract), use empty string.
  return input.url ?? input.command ?? "";
}

function mcpEventFromBefore(input: BeforeMCPExecutionInput): RecordEvent {
  return {
    type: "mcp_call",
    outcome: "executed",
    server: mcpServerOf(input),
    tool_name: input.tool_name,
    args_hash: argsHashFromJsonString(input.tool_input),
    decision: "observed",
    decision_source: "n/a",
  };
}

function mcpEventFromAfter(input: AfterMCPExecutionInput): RecordEvent {
  return {
    type: "mcp_call",
    outcome: "executed",
    server: mcpServerOf(input),
    tool_name: input.tool_name,
    args_hash: argsHashFromJsonString(input.tool_input),
    result_hash:
      "sha256:" + sha256Hex(Buffer.from(input.result_json, "utf8")),
    decision: "observed",
    decision_source: "n/a",
  };
}
