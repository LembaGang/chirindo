// Checkpoints into the witness sidecar — shared by `chirindo checkpoint` and the
// proxy's --checkpoint-every / shutdown checkpoint.
//
// A checkpoint is NEVER appended to the chain file: parseChainJsonl rejects a
// second checkpoint and any record after one, and appendReceipt re-reads the
// chain on every call, so a checkpoint in the live file would make every later
// receipt write fail (and the gate deny every call). It goes to the sidecar
// `<chain>.witness.ndjson` instead, one line per checkpoint.

import { appendFileSync } from "node:fs";
import {
  Chain,
  publicKeyFromPrivate,
  readChainFile,
  type LoadedFullIdentity,
  type SignedCheckpoint,
  type SignedRecord,
} from "./vendor/recorder/index.js";
import { GATE_AGENT } from "./receipt.js";
import {
  sidecarPathFor,
  witnessCheckpoint,
  type SidecarLine,
  type WitnessOutcome,
  type WitnessTarget,
} from "./witness.js";

export function buildCheckpoint(
  records: readonly SignedRecord[],
  identity: LoadedFullIdentity,
  ts?: string,
): SignedCheckpoint {
  return Chain.fromRecords(records, {
    sessionId: records[0]!.session_id,
    kid: identity.kid,
    privateKey: identity.privateKey,
    agent: GATE_AGENT,
  }).checkpoint(ts);
}

export function appendSidecarLine(sidecarPath: string, line: SidecarLine): void {
  appendFileSync(sidecarPath, JSON.stringify(line) + "\n", "utf8");
}

// Without --witness a checkpoint is recorded with neither receipt nor error.
type Recorded = WitnessOutcome | { receipt: null; error: null };

export interface ProxyCheckpointOptions {
  chainPath: string;
  identity: LoadedFullIdentity;
  every?: number; // checkpoint after every Nth receipt this process writes
  witness?: WitnessTarget;
  log: (msg: string) => void;
  now?: () => string;
}

// The proxy's checkpoint driver. Building a checkpoint is synchronous (it must
// capture the head at exactly the Nth receipt); witnessing it is asynchronous
// and queued so sidecar lines land in order. Nothing here can throw into the
// proxy loop, delay a forwarded response, or deny a call: a witness failure is
// one sidecar line with witness_error and one stderr line (log + permit).
export class ProxyCheckpointer {
  private readonly o: ProxyCheckpointOptions;
  private readonly sidecar: string;
  private queue: Promise<void> = Promise.resolve();
  // The most recent head this process built a checkpoint for, and whether it
  // has been recorded with a receipt (ok), with an error (failed), or not yet.
  private last: { count: number; hash: string; state: "pending" | "ok" | "failed" } | null = null;
  // Built, waiting for setImmediate to queue them.
  private readonly scheduled = new Set<SignedCheckpoint>();
  // Checkpoints queued but not yet written to the sidecar.
  private readonly inflight = new Set<SignedCheckpoint>();
  private closed = false;

  constructor(o: ProxyCheckpointOptions) {
    this.o = o;
    this.sidecar = sidecarPathFor(o.chainPath);
  }

  // Call after each receipt written. `written` is this process's receipt count.
  afterReceipt(written: number): void {
    if (this.o.every === undefined || written % this.o.every !== 0) return;
    const cp = this.buildHead();
    if (cp === null) return;
    this.noteBuilt(cp);
    // setImmediate: the caller forwards the tool-call response synchronously
    // after this returns, so the witness POST starts only once that is done.
    this.scheduled.add(cp);
    setImmediate(() => {
      if (this.scheduled.delete(cp)) this.enqueue(cp);
    });
  }

  // Clean shutdown: checkpoint the head (unless this process already has it
  // pending or recorded with a receipt) and wait at most `timeoutMs` for every
  // queued witness POST. Anything still unrecorded at the deadline is written
  // with witness_error "witness_timeout" so the sidecar shows the gap.
  async shutdown(written: number, timeoutMs: number): Promise<void> {
    // Anything built but not yet queued goes first, in order.
    for (const cp of this.scheduled) this.enqueue(cp);
    this.scheduled.clear();
    if (written > 0) {
      const cp = this.buildHead();
      if (
        cp !== null &&
        !(
          this.last !== null &&
          this.last.count === cp.count &&
          this.last.hash === cp.last_entry_hash &&
          this.last.state !== "failed"
        )
      ) {
        this.noteBuilt(cp);
        this.enqueue(cp);
      }
    }
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<void>((r) => {
      timer = setTimeout(r, timeoutMs);
    });
    await Promise.race([this.queue, deadline]);
    clearTimeout(timer);
    this.closed = true;
    for (const cp of this.inflight) {
      this.record(cp, { receipt: null, error: "witness_timeout" });
    }
  }

  private buildHead(): SignedCheckpoint | null {
    try {
      const { records } = readChainFile(this.o.chainPath);
      if (records.length === 0) return null;
      return buildCheckpoint(records, this.o.identity, this.o.now?.());
    } catch (e) {
      this.o.log(`[chirindo] checkpoint not built: ${(e as Error).message}`);
      return null;
    }
  }

  private noteBuilt(cp: SignedCheckpoint): void {
    this.last = { count: cp.count, hash: cp.last_entry_hash, state: "pending" };
  }

  private enqueue(cp: SignedCheckpoint): void {
    this.inflight.add(cp);
    this.queue = this.queue.then(async () => {
      if (this.closed) return;
      const outcome: Recorded =
        this.o.witness === undefined
          ? { receipt: null, error: null }
          : await witnessCheckpoint(cp, publicKeyFromPrivate(this.o.identity.privateKey), this.o.witness).catch(
              () => ({ receipt: null, error: "witness_unreachable" }) as WitnessOutcome,
            );
      if (this.closed) return;
      this.record(cp, outcome);
    });
  }

  private record(cp: SignedCheckpoint, outcome: Recorded): void {
    if (!this.inflight.delete(cp)) return;
    try {
      appendSidecarLine(this.sidecar, {
        checkpoint: cp,
        witness_receipt: outcome.receipt,
        witness_error: outcome.error,
      });
    } catch (e) {
      this.o.log(`[chirindo] sidecar write failed: ${(e as Error).message}`);
      return;
    }
    if (this.last !== null && this.last.count === cp.count && this.last.hash === cp.last_entry_hash) {
      this.last.state = outcome.error === null ? "ok" : "failed";
    }
    if (outcome.error !== null) {
      this.o.log(
        `[chirindo] witness failed for checkpoint at count ${cp.count}: ${outcome.error} (call permitted; recorded in ${this.sidecar})`,
      );
    }
  }
}
