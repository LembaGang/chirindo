// The purchase check on a Prava mandate, as Prava documents it.
//
//   npm install
//   node prava-mandate.mjs
//
// Two objects are copied verbatim from Prava's documentation, both read
// 2026-10-30T16:05:51Z, byte for byte between their braces:
//
// - the mandate: the "200 Success" response example of
//   https://docs.prava.space/api-reference/mandate-get.md ("Get a Mandate");
// - the session that set it up: the JSON body (`-d`) of the "cURL · Mandate
//   setup" request example of
//   https://docs.prava.space/api-reference/create-session.md ("Create Session").
//
// Only the wrappers changed: the docs show a response and a curl request;
// here each is a const. No placeholder value was changed (the request's
// placeholder secret key, sk_test_..., is a header, not part of the body).
//
// The mandate example carries no merchantScope and no validUntil, so the
// mapper reads the scope, "listed", from the session's mandate_setup, and the
// merchant from its one custom entry. That entry has no
// effective_until_minutes, so the instruction is valid for the documented
// default of 15 minutes from approval. approvedAmount is the per-charge cap.
//
// The provider's key, the principal, is a throwaway Ed25519 key made at run
// time and never written to disk. Nothing printed is a key, a hash or a time,
// so the output is the same on every run.

import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPurchaseCheck, mapPravaMandate, signInstruction } from "@headlessoracle/chirindo/purchase-check";

// --- verbatim from Prava's documentation -------------------------------------
const mandate = {
  "id": "mdt_123",
  "status": "active",
  "approvedAmount": "40.00",
  "currency": "USD",
  "spent": "40.00",
  "chargeCount": 1,
  "charges": [
    { "transactionId": "txn_9", "amount": "40.00", "currency": "USD", "status": "completed", "reference": "invoice_2026_07", "createdAt": "2026-07-26T00:00:00Z" }
  ]
};
const session = {
    "user_id": "user_123",
    "user_email": "jane@example.com",
    "total_amount": "40.00",
    "currency": "USD",
    "purchase_context": {
      "custom": [{
        "merchant_details": { "name": "Acme Store", "url": "https://acme.example.com", "country_code_iso2": "US" },
        "product_details": [{ "description": "Monthly plan", "unit_price": "40.00" }]
      }]
    },
    "mandate_setup": {
      "intent": "mandate_setup",
      "recurring_frequency": "monthly",
      "merchant_scope": "listed",
      "max_charges": 12
    }
};
// ------------------------------------------------------------------------------

// The installed chirindo command, run the way a consumer runs it.
const pkgDir = dirname(fileURLToPath(import.meta.resolve("@headlessoracle/chirindo/package.json")));
const cli = join(pkgDir, JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).bin.chirindo);
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const dir = mkdtempSync(join(tmpdir(), "chirindo-prava-"));
let pc;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;

  // The provider maps the mandate and its session and signs them as its
  // customer's instruction. maxUses is the mandate's max_charges.
  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const body = mapPravaMandate({ mandate, session }, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 12,
    approvedAt: new Date(Date.now() - 60_000).toISOString(),
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Prava mandate: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${JSON.stringify(card.merchants)}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "PLAN", quantity: 1, unit_price_minor: total, name: "Monthly plan" }],
  });
  const cases = [
    ["(a) inside the instruction", order("https://acme.example.com", "A-1", "3500")],
    ["(b) over the cap", order("https://acme.example.com", "A-2", "4500")],
    ["(c) at a different merchant", order("https://other.example.net", "O-1", "2000")],
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

  // The chain the check wrote, read back by the installed `chirindo verify`.
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
