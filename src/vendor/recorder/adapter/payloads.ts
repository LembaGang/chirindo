// Cursor hook payload types.
//
// Source of truth: https://cursor.com/docs/hooks (fetched while writing
// A1.3). Only the fields the recorder needs are typed here; Cursor may
// pass additional fields. We tolerate extras (don't fail on unknown
// keys), but treat the listed fields as required where the docs do.

// Common fields present on every agent hook event. `workspaceOpen`
// omits several of these; we do not subscribe to that event.
export interface CursorCommonFields {
  hook_event_name: string;
  conversation_id?: string;
  generation_id?: string;
  cursor_version?: string;
  workspace_roots?: string[];
  user_email?: string | null;
}

// beforeShellExecution input — https://cursor.com/docs/hooks (§ beforeShellExecution)
export interface BeforeShellExecutionInput extends CursorCommonFields {
  hook_event_name: "beforeShellExecution";
  command: string;
  cwd: string;
  sandbox?: boolean;
}

// afterShellExecution input — § afterShellExecution.
// Note: docs do NOT include an exit_code field. `output` is the captured
// terminal output, `duration` is in milliseconds.
export interface AfterShellExecutionInput extends CursorCommonFields {
  hook_event_name: "afterShellExecution";
  command: string;
  output: string;
  duration: number;
  sandbox?: boolean;
}

// beforeReadFile input — § beforeReadFile
export interface BeforeReadFileInput extends CursorCommonFields {
  hook_event_name: "beforeReadFile";
  file_path: string;
  content: string;
  attachments?: Array<{ type: "file" | "rule"; file_path: string }>;
}

// afterFileEdit input — § afterFileEdit
export interface AfterFileEditInput extends CursorCommonFields {
  hook_event_name: "afterFileEdit";
  file_path: string;
  edits: Array<{ old_string: string; new_string: string }>;
}

// beforeMCPExecution input — § beforeMCPExecution.
// `tool_input` is a JSON-STRINGIFIED string of params (per docs). Server
// is identified by `url` XOR `command` (CJS-style invocation).
export interface BeforeMCPExecutionInput extends CursorCommonFields {
  hook_event_name: "beforeMCPExecution";
  tool_name: string;
  tool_input: string;
  url?: string;
  command?: string;
}

// afterMCPExecution input — § afterMCPExecution.
// `result_json` is a JSON-stringified string of the tool response.
export interface AfterMCPExecutionInput extends CursorCommonFields {
  hook_event_name: "afterMCPExecution";
  tool_name: string;
  tool_input: string;
  result_json: string;
  duration: number;
  url?: string;
  command?: string;
}

export type CursorHookInput =
  | BeforeShellExecutionInput
  | AfterShellExecutionInput
  | BeforeReadFileInput
  | AfterFileEditInput
  | BeforeMCPExecutionInput
  | AfterMCPExecutionInput;

// Output shapes. The adapter is OBSERVE-ONLY: we always emit the permissive
// value, regardless of inputs or recording outcome.

export interface PermissionAllowOutput {
  permission: "allow";
}

export interface EmptyOutput {
  // Fire-and-forget hooks accept `{}`.
}

export type CursorHookOutput = PermissionAllowOutput | EmptyOutput;

// Permissive output appropriate for each hook event.
export function permissiveOutputFor(
  hookEventName: string,
): CursorHookOutput {
  switch (hookEventName) {
    case "beforeShellExecution":
    case "beforeMCPExecution":
    case "beforeReadFile":
      return { permission: "allow" };
    default:
      return {};
  }
}
