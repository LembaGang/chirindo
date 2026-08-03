// Normative x402 scheme-mapping registry — the machine-readable form of
// `docs/spec/delivery-proof.md` §3.4.
//
// §3.2 defines WHICH six keys the payment-ref subset has. This registry
// defines, per (scheme, network, facilitator), exactly WHICH source field
// supplies each key. Two implementations can agree byte-for-byte on JCS and
// still produce non-comparable commitments if they read different source
// fields into the same subset key, so the mapping is part of the wire
// contract — a commitment is only meaningful relative to the row it was
// built under.
//
// Registry rules encoded here (spec §3.4.1):
//   1. Fail closed on unknown tuples — no row ⇒ no commitment. Never guess.
//   2. Additive + immutable — rows are ADDED, never mutated. A correction is a
//      NEW row at a NEW registry version; the old row is retained and marked
//      `supersededBy` so past commitments stay recomputable.
//   3. Only a VERIFIED row may produce a production `x402_payment_ref`.
//      PROVISIONAL is treated as not-yet-registered for emission purposes.
//   4. Per-field provenance: `observed` (read out of a raw captured artifact)
//      or `documentation` (protocol knowledge — never authorizes VERIFIED).

// Which artifact of the x402 exchange a field is read from. The capture
// (2026-08-02) confirmed the spec's §3.4.2 structural caveat: the six values
// span more than one artifact, so the source artifact is part of the mapping,
// not an afterthought.
//
//   requirements — `PaymentRequirements`. OBSERVED to travel in the
//                  PAYMENT-REQUIRED *response header* (base64 JSON); the 402
//                  response body was literally `{}` (2 bytes).
//   payload      — `PaymentPayload`, the base64 JSON of the PAYMENT-SIGNATURE
//                  *request* header (v1 wire name: X-PAYMENT).
//   settle       — `SettleResponse`, the base64 JSON of the PAYMENT-RESPONSE
//                  *response* header (v1 wire name: X-PAYMENT-RESPONSE).
export type X402Artifact = "requirements" | "payload" | "settle";

export type FieldProvenance = "observed" | "documentation";

export type RowStatus = "VERIFIED" | "PROVISIONAL";

// One mapped subset key: where to read it, and on what authority.
//
// `path` is dot-separated. The single special token is `accepts[i]`, which
// selects the `accepts[]` entry the client actually paid against — the caller
// supplies that index, because a 402 may offer several and only the payer
// knows which one was signed. Everything else is a plain member lookup.
export interface FieldMapping {
  artifact: X402Artifact;
  path: string;
  provenance: FieldProvenance;
  // Free-text note recorded at mapping time (e.g. a corroborating field in
  // another artifact). Documentation only — never read by the extractor.
  note?: string;
}

export interface RegistryRow {
  // Lookup tuple.
  scheme: string;
  network: string;
  facilitator: string;
  status: RowStatus;
  // Registry version at which this row was introduced.
  since: number;
  // Set when a later row supersedes this one (rule 2 — the old row is kept so
  // commitments built under it remain recomputable).
  supersededBy?: { network: string; since: number };
  // One-line provenance statement. Required to be non-empty on a VERIFIED row.
  provenance: string;
  map: {
    scheme: FieldMapping;
    network: FieldMapping;
    asset: FieldMapping;
    amount: FieldMapping;
    resource: FieldMapping;
    // The one optional subset member (§3.2): present-and-non-null ⇒ include,
    // absent ⇒ omit the key entirely (never null).
    settlement?: FieldMapping;
  };
  // Corroborating sources that do NOT feed the subset (spec §8.1, amended
  // 2026-08-02). A cross-check never supplies a value; it can only cause the
  // emitter to REFUSE. Adding one therefore cannot change any commitment's
  // bytes — the mapped fields above are untouched — it can only narrow the set
  // of exchanges we are willing to commit to.
  //
  // `amount`: the signed authorization value. For the `exact` scheme the
  // requested amount (A) and the authorized amount (B) are expected to be
  // equal; when both are available and they DISAGREE, the payment evidence is
  // ambiguous and the emitter must not pick one — see `amount_disagreement`.
  crossCheck?: {
    amount?: FieldMapping;
  };
}

// Registry version. Incremented independently of the record/spec version.
//   v0 — draft, zero VERIFIED rows (the exact/base-sepolia/CDP row was
//        PROVISIONAL: every field name was documentation-derived).
//   v1 — promotes (exact, eip155:84532, coinbase-cdp) to VERIFIED against the
//        2026-08-02 live capture. Additive: the v0 row is retained below,
//        marked superseded.
//   v2 — adds the `amount` CROSS-CHECK to the v1 row (spec §8.1 amendment).
//        Not a mapping mutation and NOT a rule-2 violation: every mapped field
//        is byte-for-byte unchanged, so every commitment built under v1
//        recomputes identically under v2. What changed is the set of exchanges
//        an emitter is willing to commit to at all — a v1 reader emits on an
//        A/B amount disagreement, a v2 reader refuses — which is exactly the
//        kind of behavioural change a version exists to signal.
//   v3 — ADDS a second VERIFIED row: (exact, eip155:84532, x402org), against
//        the 2026-08-02 live x402.org-facilitator capture. Purely additive —
//        a new tuple, no existing row touched — so every commitment built
//        under v1/v2 recomputes identically under v3.
export const X402_REGISTRY_VERSION = 3;

// The v0 PROVISIONAL row, retained per rule 2. Never mutated — it is kept so
// that (a) the promotion history is legible and (b) a lookup under the old
// hypothesized network id fails closed with `unverified_row` rather than
// silently reading as "unknown scheme". It never authorized emission and
// still does not.
//
// Superseded because the observed network identifier is CAIP-2
// (`eip155:84532`), not the hypothesized `base-sepolia`.
const ROW_V0_EXACT_BASE_SEPOLIA_CDP: RegistryRow = {
  scheme: "exact",
  network: "base-sepolia",
  facilitator: "coinbase-cdp",
  status: "PROVISIONAL",
  since: 0,
  supersededBy: { network: "eip155:84532", since: 1 },
  provenance:
    "Documentation / protocol-knowledge derived; never confirmed against live output.",
  map: {
    scheme: { artifact: "requirements", path: "accepts[i].scheme", provenance: "documentation" },
    network: { artifact: "settle", path: "network", provenance: "documentation" },
    asset: { artifact: "requirements", path: "accepts[i].asset", provenance: "documentation" },
    // Hypothesized as `maxAmountRequired` — refuted by the capture; the
    // observed key is `amount` (see the v1 row).
    amount: {
      artifact: "requirements",
      path: "accepts[i].maxAmountRequired",
      provenance: "documentation",
    },
    resource: { artifact: "requirements", path: "resource", provenance: "documentation" },
    settlement: { artifact: "settle", path: "transaction", provenance: "documentation" },
  },
};

// The VERIFIED row (registry v1). Every path below was read out of a raw
// captured artifact file, not documentation — see `provenance`.
//
// Deliberate mapping calls, each backed by an observation:
//   * `resource` comes from A's TOP-LEVEL `resource.url` — in the observed
//     PaymentRequirements, `resource` is an object {url, description,
//     mimeType} and sits beside `accepts[]`, not inside the accepts entry.
//   * `amount` comes from A `accepts[i].amount` — the observed key is
//     `amount`, NOT the hypothesized `maxAmountRequired`, and its value is a
//     base-unit decimal STRING (validating §3.1 rule 4). B's signed
//     `payload.authorization.value` carried the same string; A is the single
//     authoritative source so two implementations cannot diverge.
//   * `network` comes from A `accepts[i].network` (CAIP-2). C carried the
//     same value; A is authoritative and is available before settlement.
//   * `asset` comes from A `accepts[i].asset`. C carries NO asset field at
//     all, so the two are not comparable — A is the only source.
//   * `settlement` comes from C `transaction`. Observed present on the one
//     successful settle; whether it is ALWAYS present is UNESTABLISHED from a
//     single observation, so it stays the optional member per §3.2.
const ROW_V1_EXACT_EIP155_84532_CDP: RegistryRow = {
  scheme: "exact",
  network: "eip155:84532",
  facilitator: "coinbase-cdp",
  status: "VERIFIED",
  since: 1,
  provenance:
    "Captured against live base-sepolia / Coinbase CDP facilitator on 2026-08-02; " +
    "every field name read from raw artifact files (x402-capture-rig/capture/), not documentation.",
  map: {
    scheme: {
      artifact: "requirements",
      path: "accepts[i].scheme",
      provenance: "observed",
      note: "echoed in B at accepted.scheme",
    },
    network: {
      artifact: "requirements",
      path: "accepts[i].network",
      provenance: "observed",
      note: "CAIP-2; agrees with C .network",
    },
    asset: {
      artifact: "requirements",
      path: "accepts[i].asset",
      provenance: "observed",
      note: "C carries no asset field — not comparable; the on-chain token matched A",
    },
    amount: {
      artifact: "requirements",
      path: "accepts[i].amount",
      provenance: "observed",
      note: "JSON string, base units; agrees with B payload.authorization.value",
    },
    resource: {
      artifact: "requirements",
      path: "resource.url",
      provenance: "observed",
      note: "A's resource is an object {url, description, mimeType}; the subset takes the url",
    },
    settlement: {
      artifact: "settle",
      path: "transaction",
      provenance: "observed",
      note: "0x + 64 hex; resolved on-chain. Always-vs-sometimes UNESTABLISHED (one observation)",
    },
  },
  crossCheck: {
    // Observed at B `payload.authorization.value` — the amount the payer
    // actually signed an EIP-3009 authorization for. In the capture it carried
    // the same decimal string as A `accepts[i].amount`.
    amount: {
      artifact: "payload",
      path: "payload.authorization.value",
      provenance: "observed",
      note: "the signed authorization value; corroborates A, never supplies the subset",
    },
  },
};

// The second VERIFIED row (registry v3): the same scheme and network settled
// through the x402.org facilitator instead of Coinbase CDP. A NEW tuple, so
// this is a pure rule-2 addition — the CDP rows above are untouched and every
// commitment built under v1/v2 recomputes identically.
//
// The facilitator is a distinct registry dimension for a reason, and this row
// is the evidence for it: the mapping had to be re-observed, not assumed. What
// the capture found is that it did NOT need to change — which is a finding
// about this facilitator pair, not a licence to skip the capture for the next
// one.
//
// Observed against the CDP capture (same rig, same wallet pair, ~1h apart):
//   * A is BYTE-IDENTICAL to the CDP-run A (the 402 is emitted by the resource
//     server, not the facilitator, so the facilitator choice does not reach it).
//     All five A-sourced paths therefore carry over unchanged and re-observed.
//   * B has the same shape; only per-payment values (nonce, validBefore,
//     signature) differ. `payload.authorization.value` was again the same
//     decimal string as A `accepts[i].amount`, so the v2 cross-check is carried
//     onto this row on its own observation — a row that omitted it would be
//     weaker than the CDP row on identical evidence.
//   * C has the same four keys (`success, payer, transaction, network`) and
//     again NO `asset` field, so `asset` is A-only here too. `transaction` was
//     0x + 64 hex; a different tx from the CDP settle, same network.
const ROW_V3_EXACT_EIP155_84532_X402ORG: RegistryRow = {
  scheme: "exact",
  network: "eip155:84532",
  // Matches the demo's FACILITATOR=x402org registry key (chirindo-x402-demo
  // src/config.ts `registryKey`), so a demo run under that id resolves this row.
  facilitator: "x402org",
  status: "VERIFIED",
  since: 3,
  provenance:
    "Captured against live base-sepolia / x402.org facilitator " +
    "(https://x402.org/facilitator) on 2026-08-02 with zero credentials; " +
    "same wallet pair as the CDP capture; settled tx block 44965211; " +
    "artifact shape byte-equivalent to the CDP row's A/B, C same four-key shape, " +
    "no asset field; field names from raw artifacts " +
    "(x402-capture-rig/capture/, .dup3 + exchange-4 series).",
  map: {
    scheme: {
      artifact: "requirements",
      path: "accepts[i].scheme",
      provenance: "observed",
      note: "echoed in B at accepted.scheme",
    },
    network: {
      artifact: "requirements",
      path: "accepts[i].network",
      provenance: "observed",
      note: "CAIP-2; agrees with C .network",
    },
    asset: {
      artifact: "requirements",
      path: "accepts[i].asset",
      provenance: "observed",
      note: "C carries no asset field — not comparable; A is the only source",
    },
    amount: {
      artifact: "requirements",
      path: "accepts[i].amount",
      provenance: "observed",
      note: "JSON string, base units; agrees with B payload.authorization.value",
    },
    resource: {
      artifact: "requirements",
      path: "resource.url",
      provenance: "observed",
      note: "A's resource is an object {url, description, mimeType}; the subset takes the url",
    },
    settlement: {
      artifact: "settle",
      path: "transaction",
      provenance: "observed",
      // Settlement presence is now OBSERVED TWICE, across two independent
      // facilitators (CDP 2026-08-02, x402.org 2026-08-02). Two observations
      // are still "observed", NOT "always": nothing here establishes that a
      // successful settle must carry `transaction`, so the member stays
      // optional per §3.2 and a verifier must not read its absence as
      // anomalous. A rule is not strengthened by counting samples.
      note: "0x + 64 hex; present on this settle. Presence now observed twice across two facilitators — still observed, NOT always; stays optional",
    },
  },
  crossCheck: {
    amount: {
      artifact: "payload",
      path: "payload.authorization.value",
      provenance: "observed",
      note: "the signed authorization value; corroborates A, never supplies the subset",
    },
  },
};

// Every row, newest last. Any (scheme, network, facilitator) tuple absent from
// this list has NO mapping — rule 1, fail closed.
export const X402_REGISTRY: readonly RegistryRow[] = [
  ROW_V0_EXACT_BASE_SEPOLIA_CDP,
  ROW_V1_EXACT_EIP155_84532_CDP,
  ROW_V3_EXACT_EIP155_84532_X402ORG,
];

export interface RegistryLookup {
  scheme: string;
  network: string;
  facilitator: string;
}

// Find the row for a tuple, or undefined when none is registered. Returns the
// LAST match so a superseding row wins if a tuple is ever re-registered
// (rows are immutable, so this only matters if a future row reuses a tuple).
export function findRegistryRow(key: RegistryLookup): RegistryRow | undefined {
  let found: RegistryRow | undefined;
  for (const row of X402_REGISTRY) {
    if (
      row.scheme === key.scheme &&
      row.network === key.network &&
      row.facilitator === key.facilitator
    ) {
      found = row;
    }
  }
  return found;
}
