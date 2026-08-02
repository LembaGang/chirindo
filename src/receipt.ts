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
  argsHash,
  contentOf,
  defaultIssuer,
  entryHashOfCanonical,
  genesisPrevHash,
  isPaymentRefFormat,
  jcsBytes,
  readChainFileOrEmpty,
  requestCommitment,
  resultHash,
  rfc7638Thumbprint,
  signEd25519,
  type LoadedFullIdentity,
  type McpCallEvent,
  type Outcome,
  type RecordContent,
  type SignedRecord,
} from "./vendor/recorder/index.js";

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
  // Tool-call arguments as the structured value the client sent (already
  // parsed from JSON-RPC `params.arguments`). Hashed via the recorder's
  // `argsHash` helper, which canonicalizes with RFC 8785 JCS — see that
  // function's doc for why this changed from JSON.stringify.
  toolArgs: unknown;
  // The MCP tool result — the `result` field of the JSON-RPC response from
  // the downstream (typically `{ content, isError }`). Hashed via the
  // recorder's `resultHash` helper (RFC 8785 JCS over the value) so an
  // independent verifier given the same result derives byte-identical
  // bytes — recomputability, same as args_hash. Undefined on the deny
  // path (no downstream response was generated).
  toolResult?: unknown;
  // OPTIONAL HTTPS URL where this gate's JWKS is published. When set, every
  // emitted receipt carries it in `jwks_uri` inside the signed bytes —
  // committing the signer to the location where verifiers can fetch this
  // receipt's signing key, with no Headless Oracle / Chirindo-hosted JWKS
  // in the trust path. Omitted ⇒ existing fallback behavior (verifier uses
  // its configured JWKS URL or local identity).
  jwksUri?: string;
  // OPTIONAL issuer identifier for the v1 `iss` field. When omitted it defaults
  // to the origin of `jwksUri` (the operator's own domain), falling back to a
  // key-scoped URN. Explicit override lets an operator name a stable issuer
  // identity independent of where the JWKS happens to be hosted.
  iss?: string;
  // OPTIONAL x402 delivery-proof commitment — "sha256:" + hex(sha256(JCS(
  // payment_ref_subset))) per docs/spec/delivery-proof.md §2/§3. Set it ONLY
  // from the registry-gated producers (`paymentRefFromArtifacts` /
  // `paymentRefFromJsonStrings`), which refuse to emit for any
  // (scheme, network, facilitator) without a VERIFIED §3.4 row. Omitted ⇒ the
  // receipt makes no payment claim and its bytes are unchanged (§7).
  //
  // Pairing note: the delivery verdict is PROVEN only when the same record
  // also carries `event.result_hash` (i.e. `toolResult` was supplied). A
  // payment ref on a deny-path receipt (no result) is, correctly, an
  // `unproven` delivery — settled, nothing committed about what was delivered.
  x402PaymentRef?: string;
  decision: GateDecision;
  ts?: string;
}

export const GATE_AGENT = {
  vendor: "chirindo",
  version: "0.0.1",
} as const;

// Build the mcp_call event matching the recorder's adapter shape. Outcome
// is derived from the gate decision (allow→executed, deny→denied).
//
// args_hash is computed via the recorder's `argsHash` (RFC 8785 JCS over the
// arguments value). Any recorder/verifier given the same `toolArgs` will
// derive byte-identical bytes — the recomputability property.
export function buildEvent(inputs: ReceiptInputs): McpCallEvent {
  const outcome: Outcome =
    inputs.decision.kind === "allow" ? "executed" : "denied";
  const event: McpCallEvent = {
    type: "mcp_call",
    outcome,
    server: inputs.server,
    tool_name: inputs.toolName,
    args_hash: argsHash(inputs.toolArgs),
    decision: inputs.decision.kind === "allow" ? "allow" : "deny",
    decision_source: "config",
  };
  if (inputs.toolResult !== undefined) {
    event.result_hash = resultHash(inputs.toolResult);
  }
  return event;
}

// Append one signed receipt to the chain file. Returns the record so
// callers can use record.sig / record's entry_hash for follow-up logs.
export function appendReceipt(inputs: ReceiptInputs): SignedRecord {
  // Boundary guard: a payment ref that did not come from the registry-gated
  // producer cannot be a free-form string inside signed bytes. This is a shape
  // check, not the trust gate — the trust gate is the VERIFIED-row requirement
  // in payment-ref.ts, which is the only conformant way to obtain this value.
  if (
    inputs.x402PaymentRef !== undefined &&
    !isPaymentRefFormat(inputs.x402PaymentRef)
  ) {
    throw new Error(
      `x402_payment_ref must be "sha256:" + 64 lowercase hex chars, got: ${inputs.x402PaymentRef}`,
    );
  }
  const file = readChainFileOrEmpty(inputs.chainPath);
  const seq = file.records.length;
  const prev_hash =
    seq === 0
      ? genesisPrevHash(inputs.sessionId)
      : entryHashOfCanonical(jcsBytes(contentOf(file.records[seq - 1]!)));

  const event = buildEvent(inputs);
  const commitment = requestCommitment(event);
  const ts = inputs.ts ?? new Date().toISOString();

  // v1 key binding (evidence.action/1). The RFC 7638 thumbprint of THIS
  // gate's signing key goes into the signed bytes so a verifier can bind the
  // resolved key to this receipt's declared key identity BEFORE checking the
  // signature. `iss` names the issuer — the operator's jwks_uri origin by
  // default (never Headless Oracle), so the receipt is self-describing and
  // neutral. Both fields are stamped unconditionally because RECORD_VERSION
  // is v1; a v1 receipt without them is malformed.
  const keyThumbprint = rfc7638Thumbprint(inputs.identity.publicKey);
  const iss = inputs.iss ?? defaultIssuer(keyThumbprint, inputs.jwksUri);

  // We build the gate block such that:
  //   gate.request_commitment == record.request_commitment
  // (the continuity invariant). The gate_receipt is a self-reference — for
  // the spike, the receipt's own entry_hash, which a verifier can recompute.
  // Productization: gate_receipt becomes a hash of an external pre-action
  // attestation bundle (resolved via the JWKS path), not the record itself.
  //
  // jwks_uri is added conditionally via spread — NOT as `jwks_uri: undefined`.
  // The canonicalize lib elides undefined properties at runtime, but spreading
  // an absent key keeps the produced object byte-identical to a pre-jwks_uri
  // receipt under JCS (the key simply doesn't appear in the canonical form).
  // That's the backward-compatibility guarantee: a verifier given an old
  // receipt and a new verifier given the same old receipt compute the same
  // canonical bytes, so signatures keep verifying.
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
    ...(inputs.jwksUri !== undefined ? { jwks_uri: inputs.jwksUri } : {}),
    key_thumbprint: keyThumbprint,
    iss,
    // Same conditional-spread contract as jwks_uri above: absent ⇒ the key is
    // not a member under JCS ⇒ byte-identical to a pre-feature receipt.
    ...(inputs.x402PaymentRef !== undefined
      ? { x402_payment_ref: inputs.x402PaymentRef }
      : {}),
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
