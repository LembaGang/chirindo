// B-481 T2: the receiver's writer. It appends one signed `tool_call` record
// (decision observed, decision_source n/a, gate null) from a head the caller
// keeps in memory, so an append costs the same at any chain length and no
// record is held in memory after it is written.
//
// The bytes are exactly those the vendored Chain.append writes for the same
// event, timestamp, session, agent and key (test/otel-append.test.ts holds
// this byte for byte), and the chain file is the JSONL `chirindo verify`
// reads. It builds on the vendored primitives only (canonicalization,
// request commitment, thumbprint, issuer, signature, line append) and changes
// no existing file: ruling L1 (c) of the T2 handoff.

import type { KeyObject } from "node:crypto";
import {
  RECORD_VERSION,
  appendRecordLine,
  defaultIssuer,
  entryHashOfCanonical,
  genesisPrevHash,
  jcsBytes,
  requestCommitment,
  rfc7638Thumbprint,
  signEd25519,
  type AgentInfo,
  type RecordContent,
  type SignedRecord,
  type ToolCallEvent,
} from "../vendor/recorder/index.js";

export interface ObservedWriterOptions {
  chainPath: string;
  sessionId: string;
  agent: AgentInfo;
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export interface ObservedWriter {
  readonly sessionId: string;
  readonly chainPath: string;
  // The next record's seq (the number of records written so far).
  readonly count: number;
  // The entry hash of the last record written (the genesis hash before any).
  readonly lastEntryHash: string;
  append(event: ToolCallEvent, ts: string): SignedRecord;
}

export function openObservedWriter(o: ObservedWriterOptions): ObservedWriter {
  const thumbprint = rfc7638Thumbprint(o.publicKey);
  const iss = defaultIssuer(thumbprint);
  let seq = 0;
  let prevHash = genesisPrevHash(o.sessionId);
  return {
    sessionId: o.sessionId,
    chainPath: o.chainPath,
    get count() {
      return seq;
    },
    get lastEntryHash() {
      return prevHash;
    },
    append(event: ToolCallEvent, ts: string): SignedRecord {
      if (event.type !== "tool_call" || event.decision !== "observed" || event.decision_source !== "n/a") {
        throw new Error("openObservedWriter: only tool_call events with decision observed and decision_source n/a are written here");
      }
      const content: RecordContent = {
        v: RECORD_VERSION,
        seq,
        session_id: o.sessionId,
        ts,
        agent: o.agent,
        event,
        request_commitment: requestCommitment(event),
        gate: null,
        key_thumbprint: thumbprint,
        iss,
        prev_hash: prevHash,
        kid: o.kid,
      };
      const canon = jcsBytes(content);
      const record: SignedRecord = { ...content, sig: signEd25519(o.privateKey, canon) };
      // Written first; the head moves only once the line is on disk.
      appendRecordLine(o.chainPath, record);
      seq += 1;
      prevHash = entryHashOfCanonical(canon);
      return record;
    },
  };
}
