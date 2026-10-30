// The purchase check on a Crossmint order intent, as Crossmint documents it.
//
//   npm install
//   node crossmint-order-intent.mjs
//
// The order intent below is copied verbatim from Crossmint's documentation,
// https://docs.crossmint.com/agents/payment-methods/cards/create-card-permissions
// (read 2026-10-30T16:05:51Z, section "Create the Order Intent"): the
// `expiresAt` line and the members of the request body, byte for byte. Only
// the wrapper changed: the docs pass the object to JSON.stringify inside a
// fetch; here it is a const. No placeholder value was changed.
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
import { createPurchaseCheck, mapCrossmintOrderIntent, signInstruction } from "@headlessoracle/chirindo/purchase-check";

// --- verbatim from Crossmint's documentation ---------------------------------
const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
const orderIntent = {
        paymentMethodId: "pm_123",
        amount: { value: "150.00", currency: "USD" },
        merchant: {
            name: "Acme Store",
            url: "https://acme.example.com",
            countryCode: "US",
        },
        description: "Weekly grocery purchases",
        expiresAt,
};
// ------------------------------------------------------------------------------

// The installed chirindo command, run the way a consumer runs it.
const pkgDir = dirname(fileURLToPath(import.meta.resolve("@headlessoracle/chirindo/package.json")));
const cli = join(pkgDir, JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).bin.chirindo);
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const dir = mkdtempSync(join(tmpdir(), "chirindo-crossmint-"));
let pc;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;

  // The provider maps the order intent and signs it as its customer's
  // instruction. maxUses is this example's choice: the order intent has none.
  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const body = mapCrossmintOrderIntent(orderIntent, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 2,
    approvedAt: new Date(Date.now() - 60_000).toISOString(),
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Crossmint order intent: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${JSON.stringify(card.merchants)}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "GROCERIES", quantity: 1, unit_price_minor: total, name: "Weekly groceries" }],
  });
  const cases = [
    ["(a) inside the instruction", order("https://acme.example.com", "A-1", "12000")],
    ["(b) over the cap", order("https://acme.example.com", "A-2", "18000")],
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
