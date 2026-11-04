// The purchase check on a Reap mandate, as Reap documents it.
//
//   npm --prefix ../.. run build    (once, from this folder)
//   node reap-mandate.mjs
//
// The mandate is copied verbatim from Reap's documentation, read
// 2026-11-04T17:03:11Z, byte for byte between its braces: the "Response"
// example under "What the mandate controls" on
// https://docs.reap.global/agentic-payments/recurring-purchases.md
// ("Recurring Purchases"). Only the wrapper changed: the docs show a response;
// here it is a const. The <...> values are the page's own placeholders and
// are left as they are; the mapper reads none of them except merchant.name,
// which it carries as the instruction's text.
//
// Reap's page says: "Mandates are not available yet. This section is
// published ahead of release so you can plan the integration, and the
// endpoints are not live in sandbox or production." This example therefore
// runs on the documented shape only.
//
// amount is the ceiling for each charge. The mandate states no end, so the
// provider names one (validUntil, here 30 days from approval). maxUses is
// the mandate's maxCharges. frequency is Reap's to enforce, not checked here.
//
// mapReapMandate is not yet in a published release of
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
import { createPurchaseCheck, mapReapMandate, signInstruction } from "../../dist/purchase/index.js";

// --- verbatim from Reap's documentation --------------------------------------
const mandate = {
  "id": "<mandate-id>",
  "status": "ACTIVE",
  "enrollmentId": "<enrollment-id>",
  "frequency": "MONTHLY",
  "maxCharges": 12,
  "merchantScope": "LISTED",
  "merchant": {
    "name": "<merchant-name>",
    "url": "https://example.com",
    "country": "US"
  },
  "amount": {
    "amount": 150,
    "currency": "USD"
  }
};
// ------------------------------------------------------------------------------

const cli = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const dir = mkdtempSync(join(tmpdir(), "chirindo-reap-"));
let pc;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;

  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const approvedAt = new Date(Date.now() - 60_000);
  const body = mapReapMandate(mandate, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 12,
    approvedAt: approvedAt.toISOString(),
    validUntil: new Date(approvedAt.getTime() + 30 * 86_400_000).toISOString(),
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Reap mandate: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${JSON.stringify(card.merchants)}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "SUB", quantity: 1, unit_price_minor: total, name: "Monthly order" }],
  });
  const cases = [
    ["(a) inside the instruction", order("https://example.com", "A-1", "14000")],
    ["(b) over the cap", order("https://example.com", "A-2", "16000")],
    ["(c) at a different merchant", order("https://other.example.net", "O-1", "5000")],
  ];
  let receipts = 0;
  for (const [label, o] of cases) {
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
