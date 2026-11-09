// The purchase check on a Nevermined card delegation (the Stripe network), as
// Nevermined documents it.
//
//   npm --prefix ../.. run build    (once, from this folder)
//   node nevermined-card-delegation.mjs
//
// The delegation is copied verbatim from Nevermined's documentation, read
// 2026-11-09T08:47:31Z, byte for byte between its braces: the "Stripe
// Delegation" request of "Creating a Delegation", "Via the API",
// https://nevermined.ai/docs/products/payments/mandates (as its .md form). The
// page quotes the block in a Markdown blockquote; that "> " prefix on each
// line is removed, nothing else. No value was changed.
//
// spendingLimitCents is the cap on the cumulative amount charged over the
// delegation's lifetime, in cents: a total. durationSecs runs from the
// delegation's createdAt, which this request does not carry: the script fixes
// createdAt at 2026-11-09T00:00:00Z, so valid_until is 2026-11-16T00:00:00Z.
// maxUses may not exceed maxTransactions.
//
// The delegation names no merchant. The instruction therefore sets no
// merchants limit, and the check cannot refuse an order at another merchant:
// case (c) shows one allowed. The cases run in time order, as a chain
// records them: inside the window, over the cap, at another merchant, and
// past the expiry.
//
// mapNeverminedCardDelegation is not yet in a published release of
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
import { createPurchaseCheck, mapNeverminedCardDelegation, signInstruction } from "../../dist/purchase/index.js";

// --- verbatim from Nevermined's documentation --------------------------------
const delegation = {
  "provider": "stripe",
  "providerPaymentMethodId": "pm_1Abc2Def3Ghi4Jkl",
  "spendingLimitCents": 10000,
  "durationSecs": 604800,
  "maxTransactions": 100,
  "currency": "usd",
  "apiKeyId": "sk-abc123"
};
// ------------------------------------------------------------------------------

const CREATED_AT = "2026-11-09T00:00:00Z"; // fixed by this script, not by the page

const cli = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const dir = mkdtempSync(join(tmpdir(), "chirindo-nevermined-"));
let pc;
let clock;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;
  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const body = mapNeverminedCardDelegation(delegation, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 3,
    approvedAt: CREATED_AT,
    createdAt: CREATED_AT,
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Nevermined card delegation: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${card.merchants === undefined ? "none named" : JSON.stringify(card.merchants)}, valid_until ${body.constraints.valid_until}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir, now: () => clock });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "ITEM", quantity: 1, unit_price_minor: total, name: "Item" }],
  });
  const IN = "2026-11-10T00:00:00.000Z";
  const PAST = "2026-11-16T00:00:01.000Z"; // one second after valid_until
  const cases = [
    ["(a) inside the instruction", order("https://shop.example", "N-1", "9000"), IN],
    ["(b) over the cap", order("https://shop.example", "N-2", "12000"), IN],
    ["(c) at a different merchant", order("https://other.example.net", "N-3", "500"), IN],
    ["(d) past the expiry", order("https://shop.example", "N-4", "500"), PAST],
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
