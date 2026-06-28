// Record schema for the agent-action evidence chain.
//
// Version token is intentionally name-independent — it comes from the
// Internet-Draft (draft-msebenzi-evidence-state-00), not the product name.
// See README "Renaming" for why this constant is NOT a placeholder.

export const RECORD_VERSION = "evidence.action/0" as const;
export type RecordVersion = typeof RECORD_VERSION;

export type EventType =
  | "shell"
  | "file_edit"
  | "file_read"
  | "tool_call"
  | "mcp_call";

// Action outcome — required on every event. Chosen to map cleanly onto a
// later Capsule `verdict_class`.
//   executed   — the action ran to completion (`exit_code` may still be != 0).
//   blocked    — a gate/policy stopped the action BEFORE dispatch.
//   denied     — a human or policy refused the action BEFORE dispatch.
//   errored    — the action ran and threw; final state unknown.
//   timed_out  — the action exceeded its time budget.
//
// In observe-only mode, failed/blocked/denied attempts MUST still be
// recorded — a success-only log is survivorship-biased and cannot show
// that a gate ever fired.
export type Outcome =
  | "executed"
  | "blocked"
  | "denied"
  | "errored"
  | "timed_out";

// Decision metadata carried on events whose source semantics include a
// permission decision (Cursor's beforeShellExecution / preToolUse /
// beforeMCPExecution etc). In observe-only mode, the recorder emits
// `"observed"` unless the hook payload explicitly carries a decision.
export type Decision = "allow" | "deny" | "ask" | "observed";

export type DecisionSource = "user" | "config" | "hook" | "n/a";

export interface AgentInfo {
  vendor: string;
  version: string;
}

// Event subtypes. Fields ARE NOT a free-for-all: anything used by the
// request_descriptor (see src/request.ts) is part of the canonical identity
// and must be present in stable form. Other fields are audit metadata.
//
// `argv` (shell) / `tool_name` (tool_call, mcp_call) feed the descriptor
// even though the descriptor uses the field name `tool` internally — the
// builder remaps.

export interface ShellEvent {
  type: "shell";
  outcome: Outcome;
  argv: string[]; // canonical, feeds the descriptor
  cwd: string;
  exit_code?: number;
  // Plaintext display of the command vs the --hash-sensitive variant. The
  // adapter writes EXACTLY ONE of these. Both optional in the type because
  // existing fixtures predate the field; adapter-side runtime enforces.
  command?: string;
  command_hash?: string;
  decision?: Decision;
  decision_source?: DecisionSource;
}

export interface FileEditEvent {
  type: "file_edit";
  outcome: Outcome;
  path: string;
  content_hash: string; // SHA-256 of new content, "sha256:..." — never the content
  prev_content_hash?: string;
  bytes?: number; // size of the new content in bytes
}

export interface FileReadEvent {
  type: "file_read";
  outcome: Outcome;
  path: string;
  content_hash?: string;
}

export interface ToolCallEvent {
  type: "tool_call";
  outcome: Outcome;
  // The descriptor uses field name `tool`; here we use `tool_name` to match
  // the field set the brief documents for the event body. The builder maps.
  tool_name: string;
  args_hash: string;
  result_hash?: string;
  decision?: Decision;
  decision_source?: DecisionSource;
}

export interface McpCallEvent {
  type: "mcp_call";
  outcome: Outcome;
  server: string;
  tool_name: string;
  args_hash: string;
  result_hash?: string;
  decision?: Decision;
  decision_source?: DecisionSource;
}

export type RecordEvent =
  | ShellEvent
  | FileEditEvent
  | FileReadEvent
  | ToolCallEvent
  | McpCallEvent;

// Gate block — populated only in gated mode (A1.3+ recorder is observe-only,
// so this is null here). When populated, the verifier checks:
//
//   record.request_commitment == record.gate.request_commitment
//
// That equality is the proof that the gate authorized exactly the request
// that got recorded (the bytes match end-to-end).
export interface GateBlock {
  request_commitment: string; // "sha256:..."
  gate_receipt: string; // ref/hash of pre-action receipt bytes
  gate_family: "environment" | "verification" | "permit";
  result: "act" | "halt";
}

// The content of a record is everything the signature covers — i.e. the
// record object MINUS `sig`. JCS canonicalization runs over `RecordContent`.
export interface RecordContent {
  v: RecordVersion;
  seq: number;
  session_id: string;
  ts: string;
  agent: AgentInfo;
  event: RecordEvent;
  // SHA-256 over JCS(request_descriptor(event)). Computed unconditionally,
  // present on every record. In gated mode, must equal gate.request_commitment.
  request_commitment: string;
  gate: GateBlock | null;
  prev_hash: string;
  kid: string;
}

export interface SignedRecord extends RecordContent {
  sig: string;
}

// Checkpoint content; signed the same way over its own canonical form.
export interface CheckpointContent {
  v: RecordVersion;
  type: "checkpoint";
  session_id: string;
  count: number;
  last_entry_hash: string;
  ts: string;
  kid: string;
}

export interface SignedCheckpoint extends CheckpointContent {
  sig: string;
}

// Strip the signature from a signed record to recover the canonical content.
export function contentOf(record: SignedRecord): RecordContent {
  const { sig: _sig, ...content } = record;
  return content;
}

export function checkpointContentOf(cp: SignedCheckpoint): CheckpointContent {
  const { sig: _sig, ...content } = cp;
  return content;
}
