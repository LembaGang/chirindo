// The `check` member of a purchase-check receipt (B-432, design §5): one new
// top-level member, added by the conditional-spread contract of
// src/receipt.ts, so a receipt without it is byte-identical to one written
// before it existed. Typed here, outside src/vendor/ (T0 ruling 1).

// The version of the member and of the reason vocabulary it carries
// (src/purchase/reasons.ts). A change to either is a change of this value.
export const PURCHASE_CHECK_VERSION = "purchase-check/0.1";

export interface PurchaseCheckMember {
  v: typeof PURCHASE_CHECK_VERSION;
  // The M6 digest on an allow; on a deny, the JCS SHA-256 of the
  // strict-parsed instruction (denied_instruction_sha256).
  instruction_sha256: string;
  // The JCS SHA-256 of the order.
  order_sha256: string;
  // The repeat key's parts besides the instruction digest (design §4.3).
  merchant_id: string;
  merchant_order_id: string | null;
  checkout_ref: string | null;
  // The gate clock's time of the decision; also the receipt's ts.
  at: string;
  reasons: string[];
  // The verifier's names for what the order exceeds.
  exceeded: string[];
}
