// `recorder verify` — independent verification of a chain file.
//
// Uses ONLY the chain file + a verifying key (resolved from local identity
// OR a remote JWKS document keyed by kid). Never trusts a recorder runtime;
// never re-asks the recorder anything. For each record in order:
//
//   1. seq == array index
//   2. record `v` matches the schema this verifier knows
//   3. record `kid` matches the verifying key's kid
//   4. canonicalize content -> entry_hash
//   5. prev_hash linkage (genesis for seq=0, prior entry_hash otherwise)
//   6. signature verifies over canonical bytes under the verifying key
//   7. ts non-decreasing within `maxSkewMs` (default 5s)
//   8. request_commitment recomputes from the recorded event
//
// If a checkpoint is present: check count, last_entry_hash, signature.
//
// On any failure, return TAMPERED with the first failing entry/reason and
// stop — the chain is broken; deeper findings would be noise.
//
// Key sources (alternative, not stacked):
//   * --key <identity.json>  — offline / air-gapped path. Trust root: the
//     local file. Unchanged from the original behavior.
//   * --jwks <url>           — cross-machine path. Trust root: the canonical
//     JWKS URL + TLS. The verifier fetches the kid declared by the receipt
//     and verifies against the JWK it finds. UNRESOLVED (NOT VALID) on any
//     fetch/parse/lookup failure.

import type { KeyObject } from "node:crypto";
import { jcsBytes } from "../canonicalize.js";
import { entryHashOfCanonical, genesisPrevHash } from "../hash.js";
import { loadIdentity } from "../identity.js";
import { readChainFile } from "../io.js";
import {
  resolveKeyFromJwks,
  type JwksResolveError,
} from "../jwks.js";
import {
  RECORD_VERSION,
  contentOf,
  checkpointContentOf,
  type SignedCheckpoint,
  type SignedRecord,
} from "../record.js";
import { requestCommitment } from "../request.js";
import { verifyEd25519 } from "../sign.js";

export interface VerifyOptionsBase {
  chainPath: string;
  maxSkewMs?: number;
}

export interface VerifyOptionsKey extends VerifyOptionsBase {
  identityPath: string;
}

export interface VerifyOptionsJwks extends VerifyOptionsBase {
  jwksUrl: string;
}

export type VerifyOptions = VerifyOptionsKey | VerifyOptionsJwks;

export type VerifyResult =
  | { kind: "valid"; count: number; sessionId: string; hasCheckpoint: boolean }
  | {
      kind: "tampered";
      entry: number | "checkpoint";
      reason: TamperReason;
    }
  | { kind: "empty" }
  | { kind: "unresolved"; reason: string };

export type TamperReason =
  | "prev_hash linkage broken"
  | "signature invalid"
  | "sequence gap"
  | "timestamp regression"
  | "unsupported record version"
  | "kid mismatch"
  | "request_commitment mismatch"
  | "count mismatch"
  | "last_entry_hash mismatch";

const DEFAULT_MAX_SKEW_MS = 5_000;

// Internal: resolved verification key + the kid it answers to.
interface VerifierKey {
  kid: string;
  publicKey: KeyObject;
}

function isJwksOpts(opts: VerifyOptions): opts is VerifyOptionsJwks {
  return "jwksUrl" in opts && typeof opts.jwksUrl === "string";
}

function formatJwksError(err: JwksResolveError): string {
  switch (err.kind) {
    case "non_https":
      return `JWKS URL must use HTTPS: ${err.url}`;
    case "fetch_failed":
      return `could not fetch JWKS at ${err.url}: ${err.message}`;
    case "malformed_jwks":
      return `malformed JWKS at ${err.url}: ${err.message}`;
    case "kid_not_found":
      return `could not find key for kid ${err.kid} at ${err.url}`;
    case "malformed_jwk":
      return `malformed JWK for kid ${err.kid} at ${err.url}: ${err.message}`;
  }
}

// Sync variant — pre-existing behavior for the local-identity path.
export function runVerify(opts: VerifyOptionsKey): VerifyResult;
// Async variant — JWKS resolution requires network IO.
export function runVerify(opts: VerifyOptionsJwks): Promise<VerifyResult>;
export function runVerify(
  opts: VerifyOptions,
): VerifyResult | Promise<VerifyResult> {
  if (isJwksOpts(opts)) {
    return runVerifyJwks(opts);
  }
  const identity = loadIdentity(opts.identityPath);
  return verifyChain(
    { kid: identity.kid, publicKey: identity.publicKey },
    opts.chainPath,
    opts.maxSkewMs,
  );
}

async function runVerifyJwks(opts: VerifyOptionsJwks): Promise<VerifyResult> {
  // Peek the chain to learn which kid the receipts declare. We have to read
  // the file anyway; resolving the JWKS first by guess would be wrong if
  // multiple kids ever appear in a chain (today they cannot, but the check
  // belongs in the per-record loop regardless).
  const file = readChainFile(opts.chainPath);
  if (file.records.length === 0) {
    return { kind: "empty" };
  }
  const kid = file.records[0]!.kid;
  const resolved = await resolveKeyFromJwks({ url: opts.jwksUrl, kid });
  if (!resolved.ok) {
    return {
      kind: "unresolved",
      reason: formatJwksError(resolved.error),
    };
  }
  return verifyChain(
    { kid, publicKey: resolved.publicKey },
    opts.chainPath,
    opts.maxSkewMs,
  );
}

// Shared verify body — identical to the original logic, parameterized on
// the verifying key source. The `kid` we check against is the resolver's
// idea of which key we hold; record `kid` must match it (otherwise the
// chain was signed by a different identity than the JWKS/identity we
// loaded).
function verifyChain(
  key: VerifierKey,
  chainPath: string,
  maxSkewMsOpt: number | undefined,
): VerifyResult {
  const maxSkewMs = maxSkewMsOpt ?? DEFAULT_MAX_SKEW_MS;
  const file = readChainFile(chainPath);

  if (file.records.length === 0) {
    return { kind: "empty" };
  }

  const sessionId = file.records[0]!.session_id;
  let lastEntryHash = genesisPrevHash(sessionId);
  let lastTs: number | null = null;

  for (let i = 0; i < file.records.length; i++) {
    const r = file.records[i]!;

    if (r.seq !== i) {
      return { kind: "tampered", entry: i, reason: "sequence gap" };
    }
    if (r.v !== RECORD_VERSION) {
      return {
        kind: "tampered",
        entry: i,
        reason: "unsupported record version",
      };
    }
    if (r.kid !== key.kid) {
      return { kind: "tampered", entry: i, reason: "kid mismatch" };
    }

    const canon = jcsBytes(contentOf(r));
    const computedEntryHash = entryHashOfCanonical(canon);

    if (r.prev_hash !== lastEntryHash) {
      return {
        kind: "tampered",
        entry: i,
        reason: "prev_hash linkage broken",
      };
    }
    // request_commitment is checked BEFORE the signature so an event-mutation
    // tamper (the common case the demo shows) reports the most legible
    // reason: the recorded action doesn't match its own committed identity.
    // A bare signature failure now means the sig field itself was mutated
    // with the rest of the content intact — a narrower, less interesting
    // case kept distinct so the failure mode is unambiguous.
    if (requestCommitment(r.event) !== r.request_commitment) {
      return {
        kind: "tampered",
        entry: i,
        reason: "request_commitment mismatch",
      };
    }
    if (!verifyEd25519(key.publicKey, canon, r.sig)) {
      return { kind: "tampered", entry: i, reason: "signature invalid" };
    }

    const tsMs = Date.parse(r.ts);
    if (Number.isFinite(tsMs)) {
      if (lastTs !== null && tsMs + maxSkewMs < lastTs) {
        return {
          kind: "tampered",
          entry: i,
          reason: "timestamp regression",
        };
      }
      lastTs = Math.max(lastTs ?? -Infinity, tsMs);
    }

    lastEntryHash = computedEntryHash;
  }

  if (file.checkpoint !== null) {
    const cp = file.checkpoint;
    const cpFailure = verifyCheckpoint(cp, key, {
      count: file.records.length,
      lastEntryHash,
    });
    if (cpFailure !== null) return cpFailure;
  }

  return {
    kind: "valid",
    count: file.records.length,
    sessionId,
    hasCheckpoint: file.checkpoint !== null,
  };
}

function verifyCheckpoint(
  cp: SignedCheckpoint,
  key: VerifierKey,
  expected: { count: number; lastEntryHash: string },
):
  | { kind: "tampered"; entry: "checkpoint"; reason: TamperReason }
  | null {
  if (cp.kid !== key.kid) {
    return { kind: "tampered", entry: "checkpoint", reason: "kid mismatch" };
  }
  if (cp.count !== expected.count) {
    return { kind: "tampered", entry: "checkpoint", reason: "count mismatch" };
  }
  if (cp.last_entry_hash !== expected.lastEntryHash) {
    return {
      kind: "tampered",
      entry: "checkpoint",
      reason: "last_entry_hash mismatch",
    };
  }
  const canon = jcsBytes(checkpointContentOf(cp));
  if (!verifyEd25519(key.publicKey, canon, cp.sig)) {
    return {
      kind: "tampered",
      entry: "checkpoint",
      reason: "signature invalid",
    };
  }
  return null;
}

// Format a result for CLI stdout.
export function formatVerifyResult(r: VerifyResult): {
  line: string;
  exitCode: 0 | 1;
} {
  switch (r.kind) {
    case "valid":
      return {
        line: `VALID — ${r.count} entries, chain intact, all signatures verified, session ${r.sessionId}`,
        exitCode: 0,
      };
    case "tampered":
      return {
        line: `TAMPERED — entry ${r.entry}: ${r.reason}`,
        exitCode: 1,
      };
    case "empty":
      return { line: "TAMPERED — chain: empty", exitCode: 1 };
    case "unresolved":
      return {
        line: `UNRESOLVED — ${r.reason}`,
        exitCode: 1,
      };
  }
}

// Re-export so callers don't import SignedRecord just to type a helper.
export type { SignedRecord };
