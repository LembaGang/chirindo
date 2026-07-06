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
import { loadIdentity, rfc7638Thumbprint } from "../identity.js";
import { readChainFile } from "../io.js";
import {
  resolveKeyFromJwks,
  type JwksResolveError,
} from "../jwks.js";
import {
  RECORD_VERSION_V1,
  contentOf,
  checkpointContentOf,
  isSupportedRecordVersion,
  type SignedCheckpoint,
  type SignedRecord,
} from "../record.js";
import { requestCommitment } from "../request.js";
import { verifyEd25519 } from "../sign.js";

// Where the verifying key came from, in precedence order. Surfaced in output
// so a consumer (human or agent) can never mistake "internally consistent
// under some key" for "signed by the key I trust."
export type KeySource = "flag" | "receipt-jwks" | "env" | "default";

// The key a verification actually ran under. `origin` is the concrete
// location (URL or file path) the key was read from.
export interface ResolvedKey {
  thumbprint: string;
  source: KeySource;
  origin: string;
}

export interface VerifyOptionsBase {
  chainPath: string;
  maxSkewMs?: number;
  // Pinning surface (spec C). When non-empty, the RFC 7638 thumbprint of the
  // resolved key MUST be a member or verification returns INVALID
  // (untrusted_key) — fail-closed. Empty/absent ⇒ no pinning: VALID then means
  // "internally consistent under the presented key," NOT "signed by a trusted
  // key." That distinction is the whole point of surfacing the resolved key.
  expectThumbprints?: string[];
  // Presentation only — how the key was resolved and from where. Echoed in the
  // honest-output line. Defaults are derived per key path when omitted.
  keySource?: KeySource;
  keyOrigin?: string;
}

export interface VerifyOptionsKey extends VerifyOptionsBase {
  identityPath: string;
}

export interface VerifyOptionsJwks extends VerifyOptionsBase {
  jwksUrl: string;
}

export type VerifyOptions = VerifyOptionsKey | VerifyOptionsJwks;

export type VerifyResult =
  | {
      kind: "valid";
      count: number;
      sessionId: string;
      hasCheckpoint: boolean;
      // The key this chain verified under. ALWAYS present on VALID so output
      // can name it — VALID is never anonymous.
      key: ResolvedKey;
    }
  | {
      kind: "tampered";
      entry: number | "checkpoint";
      reason: TamperReason;
    }
  | {
      // INVALID is distinct from TAMPERED: TAMPERED means the chain's own
      // integrity is broken (linkage, signature, sequence). INVALID means the
      // chain is internally intact but fails a KEY / TRUST check — the
      // verifier resolved a key that does not match the identity the receipt
      // committed to (key_binding_mismatch), or a key the caller did not
      // pin/trust (untrusted_key). Separate verdict so an agent consumer can
      // tell "someone rewrote the log" from "this is not the key you think it
      // is." Fail-closed: both exit non-zero. `entry` is "chain" for
      // key-level failures that are not tied to a single record.
      kind: "invalid";
      entry: number | "checkpoint" | "chain";
      reason: InvalidReason;
      // The key that was resolved — named even on rejection so a consumer can
      // see WHICH key failed the trust/binding check.
      key: ResolvedKey;
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

export type InvalidReason =
  // The resolved key's RFC 7638 thumbprint does not match the receipt's
  // committed `key_thumbprint` — or a v1 receipt omitted `key_thumbprint`
  // entirely (malformed / fail-closed). Checked BEFORE the signature so a
  // substituted key cannot "pass" by verifying under itself.
  | "key_binding_mismatch"
  // The resolved key's thumbprint is not in the caller's pinned set
  // (--expect-thumbprint / trust file). The chain may be internally
  // consistent, but it was not signed by a key the caller trusts.
  | "untrusted_key";

const DEFAULT_MAX_SKEW_MS = 5_000;

// Internal: everything verifyChain needs beyond the key itself.
interface VerifyControls {
  maxSkewMs: number | undefined;
  expectThumbprints: string[];
  keySource: KeySource;
  keyOrigin: string;
}

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
    controlsFrom(opts, "flag", opts.identityPath),
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
    controlsFrom(opts, "flag", opts.jwksUrl),
  );
}

// Build the internal controls from public options, applying per-path defaults
// for source/origin when the caller (the CLI, which knows the precedence it
// took) did not supply them.
function controlsFrom(
  opts: VerifyOptionsBase,
  defaultSource: KeySource,
  defaultOrigin: string,
): VerifyControls {
  return {
    maxSkewMs: opts.maxSkewMs,
    expectThumbprints: opts.expectThumbprints ?? [],
    keySource: opts.keySource ?? defaultSource,
    keyOrigin: opts.keyOrigin ?? defaultOrigin,
  };
}

// Shared verify body — identical to the original logic, parameterized on
// the verifying key source. The `kid` we check against is the resolver's
// idea of which key we hold; record `kid` must match it (otherwise the
// chain was signed by a different identity than the JWKS/identity we
// loaded).
function verifyChain(
  key: VerifierKey,
  chainPath: string,
  controls: VerifyControls,
): VerifyResult {
  const maxSkewMs = controls.maxSkewMs ?? DEFAULT_MAX_SKEW_MS;
  const file = readChainFile(chainPath);

  if (file.records.length === 0) {
    return { kind: "empty" };
  }

  // The RFC 7638 thumbprint of the key we resolved. For v1 receipts this must
  // equal the receipt's committed `key_thumbprint` (the key binding), checked
  // BEFORE the signature. Computed once — it is constant across the chain.
  const resolvedKeyThumbprint = rfc7638Thumbprint(key.publicKey);
  const resolvedKey: ResolvedKey = {
    thumbprint: resolvedKeyThumbprint,
    source: controls.keySource,
    origin: controls.keyOrigin,
  };

  // Pinning (spec C). If the caller pinned a set of trusted thumbprints and the
  // key we resolved is not among them, reject up front — fail-closed, before
  // spending any work on the chain body. The chain may well be internally
  // consistent; it simply was not signed by a key the caller trusts, and
  // saying VALID here would be the exact lie the pinning surface exists to
  // prevent.
  if (
    controls.expectThumbprints.length > 0 &&
    !controls.expectThumbprints.includes(resolvedKeyThumbprint)
  ) {
    return {
      kind: "invalid",
      entry: "chain",
      reason: "untrusted_key",
      key: resolvedKey,
    };
  }

  const sessionId = file.records[0]!.session_id;
  // Genesis is version-tied (see hash.ts): a /0 chain baked its seq=0
  // prev_hash over v="evidence.action/0". Recompute genesis with the version
  // that actually opened the chain so a legacy /0 chain still links — the
  // mandatory backward-compat property.
  let lastEntryHash = genesisPrevHash(sessionId, file.records[0]!.v);
  let lastTs: number | null = null;

  for (let i = 0; i < file.records.length; i++) {
    const r = file.records[i]!;

    if (r.seq !== i) {
      return { kind: "tampered", entry: i, reason: "sequence gap" };
    }
    if (!isSupportedRecordVersion(r.v)) {
      return {
        kind: "tampered",
        entry: i,
        reason: "unsupported record version",
      };
    }
    if (r.kid !== key.kid) {
      return { kind: "tampered", entry: i, reason: "kid mismatch" };
    }

    // Key binding (v1+). The receipt committed to a specific key identity via
    // its RFC 7638 `key_thumbprint`. The verifier compares the thumbprint of
    // the key it ACTUALLY resolved (from jwks_uri / flag / env / local
    // identity) to that committed value — and does so BEFORE verifying the
    // signature. Order is the whole point: verify-then-bind would let a
    // substituted key pass by verifying under itself. A v1 receipt that omits
    // `key_thumbprint` is malformed and fails closed here too.
    if (r.v === RECORD_VERSION_V1) {
      if (r.key_thumbprint !== resolvedKeyThumbprint) {
        return {
          kind: "invalid",
          entry: i,
          reason: "key_binding_mismatch",
          key: resolvedKey,
        };
      }
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
    key: resolvedKey,
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

// The honest-output line (spec C). Names WHICH key verified and from WHERE, so
// VALID is never mistaken for "signed by Headless Oracle." Without a pin,
// VALID means "internally consistent under THIS key" — the second half of this
// line is what makes that unambiguous to a human or an agent.
function keyLine(key: ResolvedKey): string {
  return `verified under key ${key.thumbprint} resolved from ${key.source} (${key.origin})`;
}

// Format a result for CLI stdout.
export function formatVerifyResult(r: VerifyResult): {
  line: string;
  exitCode: 0 | 1;
} {
  switch (r.kind) {
    case "valid":
      return {
        line:
          `VALID — ${r.count} entries, chain intact, all signatures verified, session ${r.sessionId}\n` +
          keyLine(r.key),
        exitCode: 0,
      };
    case "tampered":
      return {
        line: `TAMPERED — entry ${r.entry}: ${r.reason}`,
        exitCode: 1,
      };
    case "invalid":
      return {
        line: `INVALID — entry ${r.entry}: ${r.reason}\n` + keyLine(r.key),
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
