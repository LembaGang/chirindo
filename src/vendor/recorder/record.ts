// Record schema for the agent-action evidence chain.
//
// Version token is intentionally name-independent — it comes from the
// Internet-Draft (draft-msebenzi-evidence-action-00), not the product name.
// See README "Renaming" for why these constants are NOT placeholders.
//
// Two versions are live:
//   evidence.action/0 — original. No key binding in the signed payload.
//   evidence.action/1 — adds `iss` + `key_thumbprint` (RFC 7638 thumbprint of
//     the signing key's JWK) to the signed bytes. The thumbprint turns
//     `jwks_uri` from untrusted transport into a key-identity binding the
//     verifier checks BEFORE the signature (see cli/verify.ts).
// NEW receipts are written at v1 (RECORD_VERSION). Verifiers accept BOTH — a
// pre-existing /0 receipt must still verify unchanged.
export const RECORD_VERSION_V0 = "evidence.action/0" as const;
export const RECORD_VERSION_V1 = "evidence.action/1" as const;

// The version NEW receipts are stamped with. Writers (Chain, appendReceipt)
// use this; verifiers accept any member of SUPPORTED_RECORD_VERSIONS.
export const RECORD_VERSION = RECORD_VERSION_V1;

export type RecordVersion =
  | typeof RECORD_VERSION_V0
  | typeof RECORD_VERSION_V1;

export const SUPPORTED_RECORD_VERSIONS = [
  RECORD_VERSION_V0,
  RECORD_VERSION_V1,
] as const;

export function isSupportedRecordVersion(v: string): v is RecordVersion {
  return v === RECORD_VERSION_V0 || v === RECORD_VERSION_V1;
}

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
  // OPTIONAL — HTTPS URL of the JWKS document where this receipt's signing
  // key (matching `kid`) is published. When present, the verifier uses it as
  // the preferred key source ("self-describing receipt"). Inside the signed
  // bytes — a post-sign mutation breaks the signature, so this is the signer
  // committing to a specific publication location, not a rewritable hint.
  //
  // Backward compatibility: absent on receipts produced before this field was
  // introduced. Verifiers MUST treat absence as "fall back to the configured
  // JWKS / identity key source." Same RECORD_VERSION; no schema bump (an
  // additive optional field is a wire-compatible extension under JCS — the
  // canonical bytes of a pre-existing receipt are unchanged when the
  // canonicalizer encounters no `jwks_uri` key).
  jwks_uri?: string;
  // v1+ ONLY (evidence.action/1). RFC 7638 JWK thumbprint of the signing key.
  // This is the key binding: a verifier recomputes the thumbprint of whatever
  // key it resolves (from jwks_uri, a flag, env, or the local identity) and
  // compares it to THIS value BEFORE checking the signature. Without it,
  // jwks_uri binds the signer to a URL, not to a key identity — the
  // jku-injection shape where a substituted key at the resolved URL would
  // "pass." With it, the URL is untrusted transport. Absent on v0 receipts;
  // a v1 receipt missing this field is malformed and verifies INVALID.
  key_thumbprint?: string;
  // v1+ ONLY. Issuer identifier — who signed this receipt. Informational (the
  // cryptographic binding is `key_thumbprint`), but inside the signed bytes so
  // it cannot be rewritten post-hoc. Defaults to the origin of `jwks_uri`
  // (the operator's domain — Headless Oracle is deliberately NOT the issuer of
  // an adopter's receipts), falling back to `urn:chirindo:key:<thumbprint>`
  // when no jwks_uri is published. Absent on v0 receipts.
  iss?: string;
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
