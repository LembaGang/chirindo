import type { KeyObject } from "node:crypto";
import { jcsBytes } from "./canonicalize.js";
import { entryHashOfCanonical, genesisPrevHash } from "./hash.js";
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
  // Optional deterministic clock for tests/fixtures.
  now?: () => string;
}

export class Chain {
  private readonly opts: ChainOptions;
  private readonly records: SignedRecord[] = [];
  private lastEntryHash: string;

  constructor(opts: ChainOptions) {
    this.opts = opts;
    this.lastEntryHash = genesisPrevHash(opts.sessionId);
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
  append(event: RecordEvent, ts?: string): SignedRecord {
    const content: RecordContent = {
      v: RECORD_VERSION,
      seq: this.records.length,
      session_id: this.opts.sessionId,
      ts: ts ?? this.timestamp(),
      agent: this.opts.agent,
      event,
      request_commitment: requestCommitment(event),
      gate: null,
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
