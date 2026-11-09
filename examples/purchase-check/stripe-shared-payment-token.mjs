// The purchase check on a Stripe Shared Payment Issued Token, as Stripe
// documents it.
//
//   npm --prefix ../.. run build    (once, from this folder)
//   node stripe-shared-payment-token.mjs
//
// The token is copied verbatim from Stripe's API reference, read
// 2026-11-09T08:47:23Z, byte for byte between its braces: the example object
// of "The Shared Payment Issued Token object",
// https://docs.stripe.com/api/shared-payment/issued-token/object (as its .md
// form). No value was changed.
//
// usage_limits.max_amount is the most that can be captured with the token,
// in the currency's minor unit (Stripe, docs.stripe.com/currencies: "All API
// requests expect amount values in the currency's minor unit"), less what
// usage_details says is already captured: a total for the token. The one
// merchant is seller_details.network_business_profile, the seller platform the
// token was created for, so an order's merchant_id is that profile id;
// seller_details.external_id, the seller within that platform, is not checked.
// usage_limits.expires_at is valid_until. Only an active token maps.
//
// The documented token expired at usage_limits.expires_at
// (2025-07-04T00:00:20Z). So that the example shows decisions inside its
// window, the check runs on an injected clock (the `now` option) at
// 2025-07-03T12:00:00Z, and the approval time is the token's created.
//
// mapStripeSharedPaymentIssuedToken is not yet in a published release of
// @headlessoracle/chirindo: this script runs against this repository's build
// (../../dist). The provider's key, the principal, is a throwaway Ed25519 key
// made at run time and never written to disk. Nothing printed is a key, a
// hash or a time, so the output is the same on every run.

import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPurchaseCheck, mapStripeSharedPaymentIssuedToken, signInstruction } from "../../dist/purchase/index.js";

// --- verbatim from Stripe's API reference ------------------------------------
const token = {
  "id": "spt_1RgaZcFPC5QUO6ZCDVZuVA8q",
  "object": "shared_payment.issued_token",
  "livemode": false,
  "created": 1751500820,
  "deactivated_at": null,
  "deactivated_reason": null,
  "payment_method": "pm_1RgaZbFPC5QUO6ZCe2ekOCNX",
  "seller_details": {
    "external_id": null,
    "network_business_profile": "profile_test_61TU90nIeGjU7NNVXA6TU90m7ISQWsBxpcx9lASWWXTk"
  },
  "setup_future_usage": null,
  "shared_metadata": {},
  "status": "active",
  "usage_details": {
    "amount_captured": {
      "value": 0,
      "currency": "usd"
    }
  },
  "usage_limits": {
    "currency": "usd",
    "expires_at": 1751587220,
    "max_amount": 1000
  }
};
// ------------------------------------------------------------------------------

const cli = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const dir = mkdtempSync(join(tmpdir(), "chirindo-stripe-"));
let pc;
let clock;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;
  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const body = mapStripeSharedPaymentIssuedToken(token, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 3,
    approvedAt: new Date(token.created * 1000).toISOString(),
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Stripe Shared Payment Issued Token: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${JSON.stringify(card.merchants)}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir, now: () => clock });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "ITEM", quantity: 1, unit_price_minor: total, name: "Item" }],
  });
  const seller = token.seller_details.network_business_profile;
  const other = "profile_test_OTHER"; // a made-up seller platform profile
  const AT = "2025-07-03T12:00:00.000Z";
  const cases = [
    ["(a) inside the instruction", order(seller, "S-1", "900"), AT],
    ["(b) over the cap", order(seller, "S-2", "1500"), AT],
    ["(c) at a different merchant", order(other, "O-1", "500"), AT],
  ];

  let receipts = 0;
  for (const [label, o, at] of cases) {
    clock = at;
    const r = pc.check({ instruction, order: o });
    if (r.receipt !== null) receipts++;
    console.log(`${label}: ${o.currency} ${o.total_minor} minor at ${o.merchant_id} -> ${r.decision} ${JSON.stringify(r.reasons)}`);
  }
  await pc.close();
  pc = undefined;
  console.log(`receipts written: ${receipts}`);

  // The chain the check wrote, read back by `chirindo verify` from the same build.
  let out;
  try {
    out = chirindo("verify", chain, "--key", join(dir, "identity.json"));
  } catch (e) {
    out = String(e.stdout ?? "");
  }
  const m = /^(VALID|INVALID)\b.*?(\d+) entries/m.exec(out);
  console.log(`chirindo verify: ${m ? `${m[1]}, ${m[2]} entries` : "INVALID"}`);
} finally {
  if (pc !== undefined) await pc.close();
  rmSync(dir, { recursive: true, force: true });
}
