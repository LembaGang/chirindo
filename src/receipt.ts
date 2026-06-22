// Receipts — signed evidence records emitted by the gate.
//
// Uses the recorder's primitives as the single source of truth for
// canonicalization, hashing, signing, and chain linkage. The spike does
// NOT reimplement any of these. The only thing the spike does that the
// recorder library doesn't (yet) is populate the `gate` block: every
// receipt this gate writes carries:
//
//   gate.request_commitment == record.request_commitment   (continuity invariant)
//   gate.gate_receipt       == record's own entry_hash      (self-anchored ref)
//   gate.gate_family        == "permit"                     (policy permit family)
//   gate.result             == "act" | "halt"               (allow / deny)
//
// The chain file is JSONL with the same shape `recorder verify` consumes,
// so produced receipts cross-verify without any modification to the
// verifier.

import {
  RECORD_VERSION,
  appendRecordLine,
  contentOf,
  entryHashOfCanonical,
  genesisPrevHash,
  jcsBytes,
  readChainFileOrEmpty,
  requestCommitment,
  signEd25519,
  type LoadedFullIdentity,
  type McpCallEvent,
  type Outcome,
  type RecordContent,
  type SignedRecord,
} from "recorder";

export interface GateDecisionAllow {
  kind: "allow";
}
export interface GateDecisionDeny {
  kind: "deny";
  reason: string;
}
export type GateDecision = GateDecisionAllow | GateDecisionDeny;

export interface ReceiptInputs {
  chainPath: string;
  sessionId: string;
  identity: LoadedFullIdentity;
  server: string;
  toolName: string;
  toolInputJson: string; // raw JSON-stringified params per MCP spec
  resultJson?: string | undefined; // tool response (allow path only)
  decision: GateDecision;
  ts?: string;
}

export const GATE_AGENT = {
  vendor: "mcp-gate-spike",
  version: "0.0.0",
} as const;

// Build the mcp_call event matching the recorder's adapter shape. Outcome
// is derived from the gate decision (allow→executed, deny→denied).
export function buildEvent(inputs: ReceiptInputs): McpCallEvent {
  const outcome: Outcome =
    inputs.decision.kind === "allow" ? "executed" : "denied";
  const event: McpCallEvent = {
    type: "mcp_call",
    outcome,
    server: inputs.server,
    tool_name: inputs.toolName,
    args_hash: "sha256:" + sha256OfUtf8(inputs.toolInputJson),
    decision: inputs.decision.kind === "allow" ? "allow" : "deny",
    decision_source: "config",
  };
  if (inputs.resultJson !== undefined) {
    event.result_hash = "sha256:" + sha256OfUtf8(inputs.resultJson);
  }
  return event;
}

// Append one signed receipt to the chain file. Returns the record so
// callers can use record.sig / record's entry_hash for follow-up logs.
export function appendReceipt(inputs: ReceiptInputs): SignedRecord {
  const file = readChainFileOrEmpty(inputs.chainPath);
  const seq = file.records.length;
  const prev_hash =
    seq === 0
      ? genesisPrevHash(inputs.sessionId)
      : entryHashOfCanonical(jcsBytes(contentOf(file.records[seq - 1]!)));

  const event = buildEvent(inputs);
  const commitment = requestCommitment(event);
  const ts = inputs.ts ?? new Date().toISOString();

  // We build the gate block such that:
  //   gate.request_commitment == record.request_commitment
  // (the continuity invariant). The gate_receipt is a self-reference — for
  // the spike, the receipt's own entry_hash, which a verifier can recompute.
  // Productization: gate_receipt becomes a hash of an external pre-action
  // attestation bundle (resolved via the JWKS path), not the record itself.
  const partial: RecordContent = {
    v: RECORD_VERSION,
    seq,
    session_id: inputs.sessionId,
    ts,
    agent: GATE_AGENT,
    event,
    request_commitment: commitment,
    gate: {
      request_commitment: commitment,
      gate_receipt: "self", // placeholder; rewritten below to the entry_hash
      gate_family: "permit",
      result: inputs.decision.kind === "allow" ? "act" : "halt",
    },
    prev_hash,
    kid: inputs.identity.kid,
  };

  // Two-pass: first canonicalize+hash with placeholder gate_receipt to
  // derive the record's entry_hash; then rewrite gate_receipt to that hash
  // (so the receipt anchors to itself); then re-canonicalize + sign.
  const provisionalEntryHash = entryHashOfCanonical(jcsBytes(partial));
  const content: RecordContent = {
    ...partial,
    gate: { ...partial.gate!, gate_receipt: provisionalEntryHash },
  };
  const canon = jcsBytes(content);
  const sig = signEd25519(inputs.identity.privateKey, canon);
  const record: SignedRecord = { ...content, sig };
  appendRecordLine(inputs.chainPath, record);
  return record;
}

import { createHash } from "node:crypto";
function sha256OfUtf8(s: string): string {
  return createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
}
