// The words an issuer pack prints (B-439, spec rev 1 §5, §6 and §9 with the
// Lead's rulings of §11). Every limit is printed verbatim:
//   PURCHASE_LIMITS   README "Purchase check (before you charge)", the full list
//   BUNDLE_LIMITS     examples/evidence-bundle/lib/limits.mjs LIMIT_TEXTS
// Ports, not imports (the package never imports examples/);
// test/issuer-pack.test.ts holds each to its source.
//
// The rule quotes were read in cc-output/pins/visa-core-rules-2026-04-18.txt
// (the pinned "Visa Core Rules and Visa Product and Service Rules",
// 18 April 2026) on 2026-11-04; the pack quotes them and claims nothing more.

export const ISSUER_PACK_VERSION = "issuer-pack/1";

// Purchase-check limits 1 to 8 and 10 (spec §6: not 9, the MCP gate).
export const PURCHASE_LIMITS: Record<number, string> = {
  1: "It checks only purchases the provider sends through it. A purchase made around it is not checked, and a deny binds only if the provider obeys it. A repeat allow is not a second purchase.",
  2: "The instruction is signed by the provider, stating what its customer approved. Chirindo does not see or verify the customer's approval. The provider also holds the gate key. The record is the provider's own signed, chained record, with checkpoints sent to Headless Oracle's witness.",
  3: "The description is carried and signed over, not checked. The v0.1 mappers set no item or category limits.",
  4: "Spend is not summed across purchases. Each purchase is checked against the cap and uses are counted, so an instruction allows up to max_uses purchases, each up to the cap. Counts are shared only within one directory and one process.",
  5: "The order is what the caller states. The cap is judged on its stated total, and Chirindo does not see the charge. Only an after-the-fact comparison with the charge shows a mismatch (L24).",
  6: "These leave no receipt: input refused at step 1, record-failed, and a repeat (it returns the earlier receipt). `evaluatePurchase` is a dry run, not a record.",
  7: "Today's evidence-bundle verifier does not read `check`. In a bundle a deny shows only as a record that cites no instruction; its reason is read from the receipt itself. A verifier that reads it is planned.",
  8: "The witness is Headless Oracle's own, not independent (L3).",
  10: "A later evidence bundle judges the instruction's time window at the charge's authorization time, as the processor states it, not at the time of the check. A charge authorized after valid_until shows as outside the instruction, even when the check allowed it in time.",
};

// Evidence-bundle limits L1, L3, L7, L8, L9, L12, L14, L24 and L25 (spec §6).
export const BUNDLE_LIMITS: Record<string, string> = {
  L1: "A gate entry is the operator's own signed statement of what its gate saw and decided. The bundle does not show that a decision was wise, that the agent read the instruction correctly, or that any member's contents are true.",
  L3: "The witness receipt is Headless Oracle's signed statement that at received_at it was shown a checkpoint signed by the key with that thumbprint; it is only as reliable as Headless Oracle and its signing key. The witness is operated by Headless Oracle, which also publishes the gate software: it is independent of an operator other than Headless Oracle, not of Headless Oracle.",
  L7: "Times on the principal's, the issuer's, the operator's and Headless Oracle's clocks are those parties' statements, and the block timestamp is set by the block producer within the chain's rules. Only the orderings that need no clock rest on signatures and hashes alone.",
  L8: "This bundle is named in none of the card network rules read for this specification (scope: the pages its sources list; the dispute chapters of the Visa Core Rules and the body of the Mastercard Chargeback Guide could not be read). It is evidence a decider may weigh within the existing reason codes.",
  L9: "The bundle carries what its assembler chose to put in. A verifier can show that the pieces present bind; it cannot show that a piece which would contradict them was left out, except where the witness's receipts show a longer history than the log carried (TRUNCATED) or a different one (FAIL).",
  L12: "The principal key in a minimal instruction is bound to no person, account or payer; the bundle shows that the holder of that key signed the instruction.",
  L14: "Headless Oracle operates both the gate whose key signed this log and the witness, so the log and the witness receipt are statements by one party.",
  L24: "v0.10. For a card payment, the payment proof is the card network's authorization record, which the issuer holds; this bundle neither carries nor verifies it. What this verdict shows is whether the decision and the order the gate recorded were witnessed before the charge's authorization time as stated, and whether that order matches the stated charge: the stated charge and its time are the statements of the person running the verifier, taken from the processor's records.",
  L25: "v0.10. The committed order is the agent's statement at decision time, as the gate recorded it: its merchant, items, prices, refundability, dates and places are what the agent's call named. The bundle does not show that the merchant fulfilled that order, that the charge was for it beyond the fields compared, or that an item's attributes are true.",
};

// Spec §6, "New".
export const STATEMENTS_LIMIT = "The request, the consent references and any stated charge are the provider's statements, carried as supplied.";

export interface PackLimit {
  id: string; // "purchase-check 1", "L24", "pack"
  text: string;
}

// Every limit the pack prints, in spec §6's order. L14 only when one party
// runs both the gate and the witness (--same-party).
export function packLimits(sameParty: boolean): PackLimit[] {
  const out: PackLimit[] = [1, 2, 3, 4, 5, 6, 7, 8, 10].map((n) => ({ id: `purchase-check ${n}`, text: PURCHASE_LIMITS[n]! }));
  for (const id of ["L1", "L3", "L7", "L8", "L9", "L12", "L14", "L24", "L25"]) {
    if (id === "L14" && !sameParty) continue;
    out.push({ id, text: BUNDLE_LIMITS[id]! });
  }
  out.push({ id: "pack", text: STATEMENTS_LIMIT });
  return out;
}

// Spec §6's first screen, in its order.
export const FIRST_SCREEN_LIMITS = ["purchase-check 2", "purchase-check 1", "purchase-check 6", "purchase-check 7", "L1", "L9", "L3", "pack"];

// Spec §9.
export const NOT_ENDORSED = "Not reviewed or endorsed by any card network.";
export const NOT_THIS_FORMAT = "The rule requires the provider to supply this information on written request; it does not name this format.";
export const NOT_CONSENT = "Each decision is the provider's gate's decision on a purchase it was sent. It is not the Cardholder's consent.";
export const RULE_QUOTE = {
  source: "Visa Core Rules and Visa Product and Service Rules, 18 April 2026",
  provision: "4.1.24.3, ID# 0031169",
  text: "The Agentic Payment Provider must retain this information for the duration of the agreement and provide it to the Cardholder or Issuer upon written request.",
};
export const CONSENT_NOT_SUPPLIED = "CONSENT NOT SUPPLIED: the provider ran this pack with --consent-missing-ok, and at least one instruction below has no consent reference.";

export type MappingState = "CARRIED WITH LIMIT" | "NOT CARRIED" | "NOT MAPPED";

export interface MappingRow {
  category: string; // the category as the rule names it
  source: string; // where it is named
  carries: string; // what the pack carries for it
  state: MappingState;
  limit: string;
}

// Spec §5, as data. The APP login ID row follows ruling 2: carried when the
// provider supplies one, as its statement.
export function mappingRows(appLoginIdSupplied: boolean): MappingRow[] {
  const ce3 = "Table 11-28, ID# 0030254";
  return [
    {
      category: '"2 previous Transactions that the Issuer did not report as Fraud Activity", "more than 120 calendar days before the Dispute was submitted"',
      source: ce3,
      carries: "earlier decisions under the same instruction",
      state: "NOT CARRIED",
      limit: "Decisions are not Transactions; no processing record or fraud report.",
    },
    {
      category: '"A detailed description of the merchandise or services purchased"',
      source: ce3,
      carries: "committed order items",
      state: "CARRIED WITH LIMIT",
      limit: 'Purchase-check limit 3: "The description is carried and signed over, not checked." L25.',
    },
    {
      category: '"Purchase order number the Cardholder was sent"',
      source: ce3,
      carries: "merchant order id",
      state: "CARRIED WITH LIMIT",
      limit: "Does not show it was sent to the Cardholder.",
    },
    appLoginIdSupplied
      ? {
          category: '"Customer account or login ID used to authenticate the Cardholder at the time of the Transaction. This also includes login IDs for an Agentic Payment Provider"',
          source: ce3,
          carries: "the APP login ID the provider supplied, in clear text",
          state: "CARRIED WITH LIMIT",
          limit: "The provider's statement, carried as supplied; the gate holds a principal key bound to no person, account or payer (L12).",
        }
      : {
          category: '"Customer account or login ID used to authenticate the Cardholder at the time of the Transaction. This also includes login IDs for an Agentic Payment Provider"',
          source: ce3,
          carries: "nothing",
          state: "NOT CARRIED",
          limit: 'The gate holds a principal key "bound to no person, account or payer" (L12); the rule wants clear text. The provider supplied no APP login ID.',
        },
    {
      category: '"Full delivery address"',
      source: ce3,
      carries: "nothing",
      state: "NOT CARRIED",
      limit: "Not in the committed order.",
    },
    {
      category: '"Device ID", "device fingerprint", "Cardholder’s public IP address"',
      source: ce3,
      carries: "nothing",
      state: "NOT CARRIED",
      limit: "The gate sees the provider's server, not the Cardholder's device.",
    },
    {
      category: '4.1.24.3 instruction and "expiration date"',
      source: "4.1.24.3, ID# 0031169",
      carries: "instruction text, valid_until",
      state: "CARRIED WITH LIMIT",
      limit: 'Limit 2: "The instruction is signed by the provider".',
    },
    {
      category: "4.1.24.3 consent and acknowledgement",
      source: "4.1.24.3, ID# 0031169",
      carries: "consent reference",
      state: "CARRIED WITH LIMIT",
      limit: "The provider's statement, unverified.",
    },
    {
      category: "4.1.24.3 identity verification",
      source: "4.1.24.3, ID# 0031169",
      carries: "nothing",
      state: "NOT CARRIED",
      limit: "Not seen by the gate.",
    },
    {
      category: '4.1.24.4 "Use only the Cardholder-defined criteria"',
      source: "4.1.24.4, ID# 0031170",
      carries: "each decision and reason",
      state: "CARRIED WITH LIMIT",
      limit: 'Limit 1: only purchases "the provider sends through it".',
    },
    {
      category: "4.1.24.6 refund-policy consent",
      source: "4.1.24.6, ID#0031172",
      carries: "refundable-only result",
      state: "CARRIED WITH LIMIT",
      limit: "Shows the instruction's limit applied, not a separate consent.",
    },
    {
      category: "4.1.24.8 order confirmation",
      source: "4.1.24.8, ID# 0031174",
      carries: "nothing",
      state: "NOT CARRIED",
      limit: "The provider's own record.",
    },
    {
      category: "Settlement (cards)",
      source: "L24",
      carries: "nothing",
      state: "NOT CARRIED",
      limit: 'L24: "the payment proof is the card network\'s authorization record, which the issuer holds; this bundle neither carries nor verifies it."',
    },
    {
      category: "Card authorization (cards)",
      source: "L24",
      carries: "nothing",
      state: "NOT CARRIED",
      limit: "The pack carries no authorization record; any stated charge is the provider's statement (charge/).",
    },
    {
      category: "Mastercard First-Party Trust data elements",
      source: "none read",
      carries: "none",
      state: "NOT MAPPED",
      limit: "Not mapped in v1: no Mastercard source was readable when this version was written.",
    },
  ];
}
