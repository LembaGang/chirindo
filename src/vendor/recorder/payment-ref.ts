// x402 delivery-proof payment reference — `docs/spec/delivery-proof.md` §2/§3.
//
// Produces `x402_payment_ref`: an OPTIONAL top-level member of the SIGNED
// record content, equal to
//
//   "sha256:" + hex( sha256( JCS( payment_ref_subset ) ) )
//
// where `payment_ref_subset` is EXACTLY the six §3.2 keys, extracted from the
// x402 exchange artifacts through a VERIFIED §3.4 registry row. The receipt
// carries the commitment; the preimage is reproduced out-of-band by whoever
// wants to check it — the raw PAYMENT-RESPONSE never enters the signed bytes,
// which is what keeps wallet internals and PII out of them.
//
// Fail-closed, in this order:
//   * no registry row for the (scheme, network, facilitator) tuple  -> throw
//   * row exists but is not VERIFIED                                -> throw
//   * a required subset key is absent / not a string                -> throw
//   * the artifacts disagree with the row's own tuple               -> throw
// A throw means the receipt makes NO payment claim (§5 outcome 3). It NEVER
// means "emit a weaker commitment": a subset missing a required key would be a
// different, silently weaker commitment under the same field name.

import { paymentRef } from "./hash.js";
import { strictJsonParse } from "./strict-json.js";
import {
  findRegistryRow,
  type FieldMapping,
  type RegistryLookup,
  type RegistryRow,
  type X402Artifact,
} from "./x402-registry.js";

// The exact §3.2 subset. `settlement` is the one optional member: present in
// the source ⇒ included, absent ⇒ the KEY IS OMITTED (never null — a null
// would change the JCS bytes; absence does not).
export interface PaymentRefSubset {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  resource: string;
  settlement?: string;
}

// Machine-readable failure reasons — an agent must be able to tell "this
// scheme is not registered" from "this receipt would have been malformed"
// without parsing prose.
export type PaymentRefErrorReason =
  | "unregistered_mapping"
  | "unverified_row"
  | "missing_artifact"
  | "malformed_artifact"
  | "accepts_index_out_of_range"
  | "missing_required_field"
  | "invalid_field_type"
  | "row_mismatch";

export class PaymentRefError extends Error {
  constructor(
    readonly reason: PaymentRefErrorReason,
    readonly detail: string,
  ) {
    super(`${reason}: ${detail}`);
    this.name = "PaymentRefError";
  }
}

// The decoded artifacts of one x402 exchange. Names match the registry's
// `X402Artifact` values.
//
// Observed wire sources (2026-08-02 capture, x402 v2):
//   requirements <- base64 JSON of the PAYMENT-REQUIRED *response* header.
//                   NOTE: not the 402 body — the observed body was `{}`.
//   payload      <- base64 JSON of the PAYMENT-SIGNATURE *request* header.
//   settle       <- base64 JSON of the PAYMENT-RESPONSE *response* header.
// (X-PAYMENT / X-PAYMENT-RESPONSE are the v1 names; v2 dropped the X- prefix.)
export interface X402Artifacts {
  requirements?: unknown;
  payload?: unknown;
  settle?: unknown;
}

// What the OPERATOR knows and the artifacts cannot tell us: which facilitator
// settled, and which `accepts[]` offer was actually paid. A 402 may offer
// several; only the payer knows which one it signed, and picking index 0 by
// default would be a guess — this project does not guess.
export interface PaymentRefSelector extends RegistryLookup {
  acceptsIndex: number;
}

// The pure hash step lives in hash.ts beside argsHash / resultHash (spec
// §2.1), reusing the ONE canonicalization path (D1) and the ONE hash
// primitive. Re-exported here so a consumer of the delivery-proof surface
// imports one module.
export { paymentRef };

// Shape of a well-formed `x402_payment_ref` value. Enforced where the field
// enters the signed bytes (chain.ts / receipt.ts) so a value that did not come
// from this module still cannot be a free-form string in a signed receipt.
const PAYMENT_REF_FORMAT = /^sha256:[0-9a-f]{64}$/;

export function isPaymentRefFormat(value: string): boolean {
  return PAYMENT_REF_FORMAT.test(value);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Resolve a registry `path` against an artifact root.
//
// Grammar: dot-separated member names, with ONE special token — `accepts[i]`,
// which selects `root.accepts[acceptsIndex]` (the offer that was paid). Kept
// deliberately tiny: a general path language would be more machinery than the
// registry needs, and every extra feature is another way two implementations
// can disagree about what a row means.
function resolvePath(
  root: unknown,
  path: string,
  acceptsIndex: number,
  where: string,
): unknown {
  let cur: unknown = root;
  for (const token of path.split(".")) {
    if (token === "accepts[i]") {
      if (!isPlainObject(cur) || !Array.isArray(cur["accepts"])) {
        throw new PaymentRefError(
          "malformed_artifact",
          `${where}: no accepts[] array at "${path}"`,
        );
      }
      const offers = cur["accepts"];
      if (acceptsIndex < 0 || acceptsIndex >= offers.length) {
        throw new PaymentRefError(
          "accepts_index_out_of_range",
          `${where}: acceptsIndex ${acceptsIndex} is outside accepts[0..${offers.length - 1}]`,
        );
      }
      cur = offers[acceptsIndex];
      continue;
    }
    if (!isPlainObject(cur)) return undefined;
    cur = cur[token];
  }
  return cur;
}

// Resolve the artifact a mapping reads from. A missing artifact is fatal for a
// REQUIRED key, but merely means "omit" for the optional `settlement`: §3.2
// explicitly allows a pre-confirmation exchange that has settled nothing yet,
// and there the settle response does not exist at all.
function artifactFor(
  artifacts: X402Artifacts,
  which: X402Artifact,
  subsetKey: string,
  required: boolean,
): unknown {
  const value = artifacts[which];
  if (value === undefined || value === null) {
    if (!required) return undefined;
    throw new PaymentRefError(
      "missing_artifact",
      `subset key "${subsetKey}" maps to the ${which} artifact, which was not supplied`,
    );
  }
  if (!isPlainObject(value)) {
    throw new PaymentRefError(
      "malformed_artifact",
      `the ${which} artifact is not a JSON object`,
    );
  }
  return value;
}

// Read one mapped field. `required` distinguishes the five required keys from
// the optional `settlement`: an absent required key is fail-closed, an absent
// optional key means "omit the subset member".
function readMapped(
  artifacts: X402Artifacts,
  mapping: FieldMapping,
  subsetKey: string,
  acceptsIndex: number,
  required: boolean,
): string | undefined {
  const root = artifactFor(artifacts, mapping.artifact, subsetKey, required);
  if (root === undefined) return undefined; // optional key, artifact absent
  const raw = resolvePath(
    root,
    mapping.path,
    acceptsIndex,
    `${mapping.artifact}.${mapping.path}`,
  );
  if (raw === undefined || raw === null) {
    if (required) {
      throw new PaymentRefError(
        "missing_required_field",
        `subset key "${subsetKey}" is absent at ${mapping.artifact}.${mapping.path}`,
      );
    }
    return undefined;
  }
  if (typeof raw !== "string") {
    // Includes the amount case: §3.1 rule 4 carries base-unit amounts as
    // decimal STRINGS. A JSON number here is a mapping/wire violation, not
    // something to coerce — coercion is exactly how two implementations end up
    // hashing different bytes.
    throw new PaymentRefError(
      "invalid_field_type",
      `subset key "${subsetKey}" at ${mapping.artifact}.${mapping.path} is ${typeof raw}, expected string`,
    );
  }
  return raw;
}

// The registry gate (spec §3.4.1 rules 1 + 3). Returns the row ONLY when it
// exists AND is VERIFIED. PROVISIONAL is treated as not-yet-registered: it
// exists so the mapping can be reviewed and promoted, not so it can be
// shipped on trust.
export function requireVerifiedRow(key: RegistryLookup): RegistryRow {
  const row = findRegistryRow(key);
  if (row === undefined) {
    throw new PaymentRefError(
      "unregistered_mapping",
      `no registry row for (scheme=${key.scheme}, network=${key.network}, facilitator=${key.facilitator})`,
    );
  }
  if (row.status !== "VERIFIED") {
    throw new PaymentRefError(
      "unverified_row",
      `registry row for (scheme=${key.scheme}, network=${key.network}, facilitator=${key.facilitator}) is ${row.status}; only a VERIFIED row may emit`,
    );
  }
  return row;
}

// Build the §3.2 subset from the exchange artifacts under a VERIFIED row.
// Throws PaymentRefError (fail closed) rather than returning a partial subset.
export function buildPaymentRefSubset(
  artifacts: X402Artifacts,
  selector: PaymentRefSelector,
): PaymentRefSubset {
  const row = requireVerifiedRow(selector);
  const idx = selector.acceptsIndex;

  const scheme = readMapped(artifacts, row.map.scheme, "scheme", idx, true)!;
  const network = readMapped(artifacts, row.map.network, "network", idx, true)!;
  const asset = readMapped(artifacts, row.map.asset, "asset", idx, true)!;
  const amount = readMapped(artifacts, row.map.amount, "amount", idx, true)!;
  const resource = readMapped(artifacts, row.map.resource, "resource", idx, true)!;

  // The mapping is only meaningful for the tuple it was registered under. If
  // the artifacts describe a different scheme/network than the row the caller
  // selected, the operator's configuration and the wire disagree — refuse
  // rather than commit under a row that does not describe this payment.
  if (scheme !== row.scheme || network !== row.network) {
    throw new PaymentRefError(
      "row_mismatch",
      `artifacts describe (scheme=${scheme}, network=${network}) but the selected row is (scheme=${row.scheme}, network=${row.network})`,
    );
  }

  const subset: PaymentRefSubset = { scheme, network, asset, amount, resource };
  // §3.2: `settlement` is the one optional member. Some schemes surface a tx
  // hash, some an opaque id, some (pre-confirmation) neither. Present ⇒
  // include; otherwise the key is omitted entirely.
  if (row.map.settlement !== undefined) {
    const settlement = readMapped(
      artifacts,
      row.map.settlement,
      "settlement",
      idx,
      false,
    );
    if (settlement !== undefined) subset.settlement = settlement;
  }
  return subset;
}

// Registry-gated producer: artifacts in, `x402_payment_ref` out.
export function paymentRefFromArtifacts(
  artifacts: X402Artifacts,
  selector: PaymentRefSelector,
): string {
  return paymentRef(buildPaymentRefSubset(artifacts, selector));
}

// The raw JSON text of each artifact, as decoded from its base64 wire header
// but NOT yet parsed.
export interface X402ArtifactJson {
  requirements?: string;
  payload?: string;
  settle?: string;
}

// JSON-string ingest (spec §2.1). Every artifact routes through
// `strictJsonParse` (D7) BEFORE extraction: unsafe integers and duplicate
// members are exactly the classes that make a commitment non-recomputable, and
// a payment artifact is integer-bearing by nature.
//
// Fail-closed with NO fallback of any kind. `argsHashFromJsonString` keeps a
// raw-UTF-8 fallback for the "not valid JSON at all" case because an
// observe-only recorder still wants a stable hash of whatever it saw; here
// there is nothing to fall back TO — a subset cannot be extracted from
// unparseable bytes, and hashing the raw text would produce a commitment no
// independent verifier could reproduce as a subset. StrictJsonParseError and
// SyntaxError both propagate.
export function paymentRefFromJsonStrings(
  json: X402ArtifactJson,
  selector: PaymentRefSelector,
): string {
  const artifacts: X402Artifacts = {};
  if (json.requirements !== undefined) {
    artifacts.requirements = strictJsonParse(json.requirements);
  }
  if (json.payload !== undefined) {
    artifacts.payload = strictJsonParse(json.payload);
  }
  if (json.settle !== undefined) {
    artifacts.settle = strictJsonParse(json.settle);
  }
  return paymentRefFromArtifacts(artifacts, selector);
}
