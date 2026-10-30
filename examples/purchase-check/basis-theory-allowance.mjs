// The purchase check on a Basis Theory allowance, as Basis Theory documents it.
//
//   npm install
//   node basis-theory-allowance.mjs
//
// The allowance below is copied verbatim from Basis Theory's documentation,
// https://developers.basistheory.com/docs/api/agentic-commerce/allowances
// (read 2026-10-30T16:05:51Z, section "Create an Allowance", Request): the
// JSON body of the documented request (`--data`), byte for byte, between its
// braces. Only the wrapper changed: the docs send it with curl; here it is a
// const. No placeholder value was changed (the only placeholder on that
// request, <PRIVATE_API_KEY>, is a header, not part of the body).
//
// The allowance expires at 2030-07-08T00:00:00.000Z, as documented; after
// that instant every order here is denied as expired.
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
import { createPurchaseCheck, mapBasisTheoryAllowance, signInstruction } from "@headlessoracle/chirindo/purchase-check";

// --- verbatim from Basis Theory's documentation ------------------------------
const allowance = {
  "payment_method_id": "pm_h2Kd91mAqLwX",
  "amount": { "value": "100.00", "currency": "USD" },
  "merchant": {
    "name": "Acme Store",
    "url": "https://acme.example.com",
    "country_code": "US",
    "category_code": "5732",
    "acquirer_bin": "545301"
  },
  "description": "Buy approved office supplies from Acme Store",
  "expires_at": "2030-07-08T00:00:00.000Z",
  "metadata": { "order_ref": "po-1138" }
};
// ------------------------------------------------------------------------------

// The installed chirindo command, run the way a consumer runs it.
const pkgDir = dirname(fileURLToPath(import.meta.resolve("@headlessoracle/chirindo/package.json")));
const cli = join(pkgDir, JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).bin.chirindo);
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const dir = mkdtempSync(join(tmpdir(), "chirindo-basis-theory-"));
let pc;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;

  // The provider maps the allowance and signs it as its customer's
  // instruction. maxUses is this example's choice: the allowance has none.
  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const body = mapBasisTheoryAllowance(allowance, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 2,
    approvedAt: new Date(Date.now() - 60_000).toISOString(),
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Basis Theory allowance: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${JSON.stringify(card.merchants)}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "OFFICE", quantity: 1, unit_price_minor: total, name: "Office supplies" }],
  });
  const cases = [
    ["(a) inside the instruction", order("https://acme.example.com", "A-1", "8000")],
    ["(b) over the cap", order("https://acme.example.com", "A-2", "12000")],
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
