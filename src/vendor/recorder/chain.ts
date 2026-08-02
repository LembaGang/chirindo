import { type KeyObject } from "node:crypto";
import { jcsBytes } from "./canonicalize.js";
import { entryHashOfCanonical, genesisPrevHash } from "./hash.js";
import { defaultIssuer, rfc7638Thumbprint } from "./identity.js";
import { publicKeyFromPrivate } from "./key.js";
import { isPaymentRefFormat } from "./payment-ref.js";
import { requestCommitment } from "./request.js";
import { signEd25519 } from "./sign.js";
import {
  RECORD_VERSION,
  contentOf,
  type AgentInfo,
  type CheckpointContent,
  type RecordContent,
  type RecordEvent,
  type SignedCheckpoint,
  type SignedRecord,
} from "./record.js";

export interface ChainOptions {
  sessionId: string;
  agent: AgentInfo;
  kid: string;
  privateKey: KeyObject;
  // Optional issuer identifier for the v1 `iss` field. Defaults to a
  // key-scoped URN derived from the signing key's thumbprint.
  iss?: string;
  // Optional deterministic clock for tests/fixtures.
  now?: () => string;
}

// Per-append extras that land inside the signed bytes.
export interface AppendOptions {
  // The x402 delivery-proof commitment (docs/spec/delivery-proof.md §2).
  // Build it with `paymentRefFromArtifacts` / `paymentRefFromJsonStrings` —
  // those fail closed on any scheme/network/facilitator without a VERIFIED
  // registry row, which is where the "do not guess" rule is enforced.
  x402PaymentRef?: string;
}

export class Chain {
  private readonly opts: ChainOptions;
  private readonly records: SignedRecord[] = [];
  private lastEntryHash: string;
  // Derived once from the signing key: the RFC 7638 thumbprint stamped into
  // every v1 record's `key_thumbprint` (the key binding the verifier checks
  // before the signature).
  private readonly keyThumbprint: string;

  constructor(opts: ChainOptions) {
    this.opts = opts;
    this.lastEntryHash = genesisPrevHash(opts.sessionId);
    this.keyThumbprint = rfc7638Thumbprint(publicKeyFromPrivate(opts.privateKey));
  }

  // Reconstruct a chain from existing records (read from disk) so that an
  // adapter handler can append a single new record without re-signing the
  // history. Existing records are NOT re-validated here — that is the
  // verifier's job. The factory assumes the records are well-formed (sig
  // verification is deferred to `recorder verify`).
  static fromRecords(
    records: readonly SignedRecord[],
    opts: ChainOptions,
  ): Chain {
    const chain = new Chain(opts);
    for (const r of records) {
      chain.records.push(r);
      chain.lastEntryHash = entryHashOfCanonical(jcsBytes(contentOf(r)));
    }
    return chain;
  }

  get length(): number {
    return this.records.length;
  }

  get last(): SignedRecord | undefined {
    return this.records[this.records.length - 1];
  }

  get genesisHash(): string {
    return genesisPrevHash(this.opts.sessionId);
  }

  all(): readonly SignedRecord[] {
    return this.records;
  }

  // Append a new event, sealing it into the chain with seq + prev_hash + sig.
  // request_commitment is computed unconditionally — observe-only mode still
  // produces the binding so every record is continuity-ready by default.
  //
  // `opts.x402PaymentRef` adds the optional delivery-proof commitment to the
  // signed bytes. Omitted ⇒ the key is not a member of the canonicalized
  // object at all, so the record's bytes are identical to a pre-feature record
  // (byte-invariance, spec §7). The value MUST come from the registry-gated
  // producer in payment-ref.ts; the format check below is a boundary guard
  // against a value that did not, never a substitute for that gate.
  append(event: RecordEvent, ts?: string, opts?: AppendOptions): SignedRecord {
    if (
      opts?.x402PaymentRef !== undefined &&
      !isPaymentRefFormat(opts.x402PaymentRef)
    ) {
      throw new Error(
        `x402_payment_ref must be "sha256:" + 64 lowercase hex chars, got: ${opts.x402PaymentRef}`,
      );
    }
    const content: RecordContent = {
      v: RECORD_VERSION,
      seq: this.records.length,
      session_id: this.opts.sessionId,
      ts: ts ?? this.timestamp(),
      agent: this.opts.agent,
      event,
      request_commitment: requestCommitment(event),
      gate: null,
      // v1 key binding — see record.ts. Stamped unconditionally because
      // RECORD_VERSION is v1; a v1 record without these is malformed.
      key_thumbprint: this.keyThumbprint,
      iss: this.opts.iss ?? defaultIssuer(this.keyThumbprint),
      // Conditional spread, NOT `x402_payment_ref: undefined` — spreading an
      // absent key keeps the canonical bytes identical to a receipt written
      // before the field existed. Same pattern, same reason, as jwks_uri.
      ...(opts?.x402PaymentRef !== undefined
        ? { x402_payment_ref: opts.x402PaymentRef }
        : {}),
      prev_hash: this.lastEntryHash,
      kid: this.opts.kid,
    };
    const canon = jcsBytes(content);
    const sig = signEd25519(this.opts.privateKey, canon);
    const record: SignedRecord = { ...content, sig };
    this.records.push(record);
    this.lastEntryHash = entryHashOfCanonical(canon);
    return record;
  }

  // Emit a signed checkpoint over the current chain head.
  // Signed the same way as records — over JCS canonical bytes of content.
  checkpoint(ts?: string): SignedCheckpoint {
    if (this.records.length === 0) {
      throw new Error("cannot checkpoint an empty chain");
    }
    const content: CheckpointContent = {
      v: RECORD_VERSION,
      type: "checkpoint",
      session_id: this.opts.sessionId,
      count: this.records.length,
      last_entry_hash: this.lastEntryHash,
      ts: ts ?? this.timestamp(),
      kid: this.opts.kid,
    };
    const canon = jcsBytes(content);
    const sig = signEd25519(this.opts.privateKey, canon);
    return { ...content, sig };
  }

  private timestamp(): string {
    return this.opts.now ? this.opts.now() : new Date().toISOString();
  }
}
