// Delivery verdict tri-state + exit codes — docs/spec/delivery-proof.md §5.
//
// The delivery axis is orthogonal to chain-integrity (TAMPERED) and key-trust
// (INVALID): every chain here is cryptographically VALID, and the only thing
// under test is whether the operator committed to an output for a payment it
// referenced — and whether a caller reading nothing but `$?` is told the truth.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  IDENTITY_FILENAME,
  RECORD_VERSION,
  contentOf,
  defaultIssuer,
  entryHashOfCanonical,
  formatVerifyResult,
  genesisPrevHash,
  jcsBytes,
  paymentRefFromArtifacts,
  requestCommitment,
  rfc7638Thumbprint,
  runVerify,
  serializeChainJsonl,
  signEd25519,
  type McpCallEvent,
  type RecordContent,
  type SignedRecord,
  type X402Artifacts,
} from "../src/vendor/recorder/index.js";
import { appendReceipt } from "../src/receipt.js";
import { cleanupTmpDir, initIdentity, makeTmpDir } from "./helpers.js";

// Observed-shape x402 artifacts (see payment-ref.test.ts for provenance).
const ARTIFACTS: X402Artifacts = {
  requirements: {
    x402Version: 2,
    resource: { url: "http://localhost:4021/paid", mimeType: "application/json" },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532",
        amount: "1000",
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      },
    ],
  },
  settle: {
    success: true,
    transaction: "0x" + "ab".repeat(32),
    network: "eip155:84532",
  },
};

const SELECTOR = {
  scheme: "exact",
  network: "eip155:84532",
  facilitator: "coinbase-cdp",
  acceptsIndex: 0,
};

const PAYMENT_REF = paymentRefFromArtifacts(ARTIFACTS, SELECTOR);

describe("delivery verdict + exit codes (spec §5, §5.2)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = makeTmpDir("chirindo-delivery-");
  });
  afterEach(() => cleanupTmpDir(tmp));

  async function fixture() {
    const identity = await initIdentity(tmp);
    return {
      identity,
      identityPath: join(tmp, IDENTITY_FILENAME),
      chainPath: join(tmp, "chain.jsonl"),
    };
  }

  it("outcome 1 — payment ref + result_hash ⇒ delivery proven, exit 0", async () => {
    const { identity, identityPath, chainPath } = await fixture();
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "summarize",
      toolArgs: { url: "http://localhost:4021/paid" },
      toolResult: { content: [{ type: "text", text: "ok" }], isError: false },
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "allow" },
    });

    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid");
    if (result.kind !== "valid") return;
    expect(result.delivery).toBe("proven");

    const formatted = formatVerifyResult(result);
    expect(formatted.line).toContain("DELIVERY PROVEN");
    expect(formatted.exitCode).toBe(0);
  });

  it("outcome 2 — payment ref, no result_hash ⇒ delivery_unproven, exit NON-ZERO by default", async () => {
    const { identity, identityPath, chainPath } = await fixture();
    // A deny-path receipt: the gate refused, so no downstream result exists —
    // a payment referenced with nothing committed about what was delivered.
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "summarize",
      toolArgs: { url: "http://localhost:4021/paid" },
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "deny", reason: "policy" },
    });

    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid"); // the CHAIN is intact and authentic
    if (result.kind !== "valid") return;
    expect(result.delivery).toBe("unproven");
    expect(result.deliveryReason).toBe("no_output_commitment");
    expect(result.deliveryEntry).toBe(0);

    const formatted = formatVerifyResult(result);
    expect(formatted.line).toContain("VALID —");
    expect(formatted.line).toContain(
      "DELIVERY UNPROVEN (payment referenced, no output commitment)",
    );
    expect(formatted.exitCode).toBe(1);
  });

  it("--allow-unproven-delivery relaxes ONLY the exit gate; the verdict still reports", async () => {
    const { identity, identityPath, chainPath } = await fixture();
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "summarize",
      toolArgs: {},
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "deny", reason: "policy" },
    });

    const result = runVerify({ chainPath, identityPath });
    const lenient = formatVerifyResult(result, { allowUnprovenDelivery: true });
    expect(lenient.exitCode).toBe(0);
    // Never hidden, and never upgraded to PROVEN.
    expect(lenient.line).toContain("DELIVERY UNPROVEN");
    expect(lenient.line).not.toContain("DELIVERY PROVEN");
    if (result.kind === "valid") expect(result.delivery).toBe("unproven");
  });

  it("outcome 3 — no payment ref ⇒ ordinary VALID, no delivery suffix, exit 0", async () => {
    const { identity, identityPath, chainPath } = await fixture();
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "summarize",
      toolArgs: {},
      toolResult: { content: [], isError: false },
      decision: { kind: "allow" },
    });

    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid");
    if (result.kind !== "valid") return;
    expect(result.delivery).toBe("none");
    expect(result.deliveryReason).toBeUndefined();

    const formatted = formatVerifyResult(result);
    expect(formatted.line).not.toContain("DELIVERY");
    expect(formatted.exitCode).toBe(0);
  });

  it("aggregation is fail-closed: one unproven record makes the whole chain unproven", async () => {
    const { identity, identityPath, chainPath } = await fixture();
    // entry 0 — proven
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "a",
      toolArgs: {},
      toolResult: { content: [], isError: false },
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "allow" },
      ts: "2026-01-01T00:00:00.000Z",
    });
    // entry 1 — paid, nothing delivered
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "b",
      toolArgs: {},
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "deny", reason: "policy" },
      ts: "2026-01-01T00:00:01.000Z",
    });
    // entry 2 — proven again; must NOT lift the verdict
    appendReceipt({
      chainPath,
      sessionId: "sess-delivery",
      identity,
      server: "fake",
      toolName: "c",
      toolArgs: {},
      toolResult: { content: [], isError: false },
      x402PaymentRef: PAYMENT_REF,
      decision: { kind: "allow" },
      ts: "2026-01-01T00:00:02.000Z",
    });

    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid");
    if (result.kind !== "valid") return;
    expect(result.count).toBe(3);
    expect(result.delivery).toBe("unproven");
    expect(result.deliveryEntry).toBe(1); // the FIRST offending entry
    expect(formatVerifyResult(result).exitCode).toBe(1);
  });

  it("a signed but non-recomputable payment ref reads unproven, never proven", async () => {
    const { identity, identityPath, chainPath } = await fixture();
    // Hand-build a record whose x402_payment_ref is not a sha256 commitment,
    // then sign it properly: the chain is authentic, so only the delivery axis
    // can catch this. The normal emission paths refuse such a value outright
    // (covered below), which is why this record has to be built by hand.
    const sessionId = "sess-malformed";
    const event: McpCallEvent = {
      type: "mcp_call",
      outcome: "executed",
      server: "fake",
      tool_name: "summarize",
      args_hash: "sha256:" + "0".repeat(64),
      result_hash: "sha256:" + "1".repeat(64),
      decision: "allow",
      decision_source: "config",
    };
    const keyThumbprint = rfc7638Thumbprint(identity.publicKey);
    const content: RecordContent = {
      v: RECORD_VERSION,
      seq: 0,
      session_id: sessionId,
      ts: "2026-01-01T00:00:00.000Z",
      agent: { vendor: "chirindo", version: "0.0.1" },
      event,
      request_commitment: requestCommitment(event),
      gate: null,
      key_thumbprint: keyThumbprint,
      iss: defaultIssuer(keyThumbprint),
      x402_payment_ref: "not-a-commitment",
      prev_hash: genesisPrevHash(sessionId),
      kid: identity.kid,
    };
    const canon = jcsBytes(content);
    const record: SignedRecord = {
      ...content,
      sig: signEd25519(identity.privateKey, canon),
    };
    writeFileSync(
      chainPath,
      serializeChainJsonl({ records: [record], checkpoint: null }),
      "utf8",
    );

    const result = runVerify({ chainPath, identityPath });
    expect(result.kind).toBe("valid"); // authentic bytes — not TAMPERED
    if (result.kind !== "valid") return;
    expect(result.delivery).toBe("unproven");
    expect(result.deliveryReason).toBe("malformed_payment_ref");
    const formatted = formatVerifyResult(result);
    expect(formatted.exitCode).toBe(1);
    expect(formatted.line).toContain("not recomputable");
    // Sanity: the record really did carry an output commitment, so the
    // unproven verdict came from the ref itself, not from a missing result.
    expect(entryHashOfCanonical(jcsBytes(contentOf(record)))).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
  });

  it("emission refuses a malformed payment ref at the boundary", async () => {
    const { identity, chainPath } = await fixture();
    expect(() =>
      appendReceipt({
        chainPath,
        sessionId: "sess-delivery",
        identity,
        server: "fake",
        toolName: "summarize",
        toolArgs: {},
        toolResult: { content: [], isError: false },
        x402PaymentRef: "sha256:nope",
        decision: { kind: "allow" },
      }),
    ).toThrowError(/x402_payment_ref must be/);
  });
});
