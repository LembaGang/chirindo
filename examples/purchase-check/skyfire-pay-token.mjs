// The purchase check on a Skyfire PAY token, as Skyfire documents it.
//
//   npm --prefix ../.. run build    (once, from this folder)
//   node skyfire-pay-token.mjs
//
// The token payload is copied verbatim from Skyfire's documentation, read
// 2026-11-04T17:03:19Z, byte for byte between its braces, comments included:
// the "Payload" example of https://docs.skyfire.xyz/docs/example-pay-token.md
// ("Example PAY Token"). Only the wrapper changed: the docs show JSON with
// // comments; here it is a JavaScript const, where those comments are legal.
// No value was changed. The sti card values are the page's own sample values;
// the mapper does not read them and nothing here prints them.
//
// amt with cur is the cap, a total for the token; aud, the seller agent
// account, is the one merchant, so an order's merchant_id is the seller's
// account id; exp is valid_until; maxUses may not exceed mnr (sps is
// pay_per_use). The mapper reads the decoded payload; it does not verify the
// token's own ES256 signature (the provider maps a token it has verified).
//
// The documented token expired at exp (2026-03-18T21:00:54Z). So that the
// example shows decisions inside its window rather than three expiries, the
// check runs on an injected clock (the `now` option) at 2025-09-01T00:00:00Z,
// and the provider's approval is the token's iat.
//
// mapSkyfirePayToken is not yet in a published release of
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
import { createPurchaseCheck, mapSkyfirePayToken, signInstruction } from "../../dist/purchase/index.js";

// --- verbatim from Skyfire's documentation -----------------------------------
const payload = {
  "iss": "https://example.net/pay_token_issuer", // Issuer URL
  "iat": 1742245254,
  "exp": 1773867654,
  "jti": "b9821893-7699-4d24-af06-803a6a16476b",
  "sub": "8b810549-7443-494f-b4ad-5bc65871e32b", // Buyer Agent Account ID
  "aud": "37888095-2721-48d9-a2df-bfe4075f223a", // Seller Agent Account ID

  "env": "sandbox",
  "ssi": "274efc47-024e-466f-b278-152d2ee73955", // Seller Service ID
  "btg": "16c135ce-a99a-453d-a7b5-4958fd91de5f", // Buyer Tag (Internal Reference ID)

  "spr": "0.01",
  "sps": "pay_per_use",
  "amt": "15",
  "cur": "USD",
  "val": "15000000",
  "mnr": 1600,
  "stp": "card",
  "sti": {
    "type": "visa_vic",
    "payment_token": "1234567890123456",
    "token_expiration_month": "03",
    "token_expiration_year": "2030",
    "token_security_code": "123",
    "verifier": "https://verifier.example.info", // URL of payment method verifier
    "verified": true, // Outcome of the verifier's payment method verification
    "verification_id": "3a6e1b76-8f78-4c24-b1bd-dc78a8cc3711" // Identifier for the verification performed, such as a GUID.
  }
};
// ------------------------------------------------------------------------------

const cli = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));
const chirindo = (...args) => execFileSync(process.execPath, [cli, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

const NOW = "2025-09-01T00:00:00.000Z";
const dir = mkdtempSync(join(tmpdir(), "chirindo-skyfire-"));
let pc;
try {
  chirindo("init", "--dir", dir);
  const gateKid = JSON.parse(readFileSync(join(dir, "identity.json"), "utf8")).kid;

  const { privateKey: principal } = generateKeyPairSync("ed25519");
  const body = mapSkyfirePayToken(payload, {
    principalKey: principal,
    agentKids: [gateKid],
    maxUses: 3,
    approvedAt: new Date(payload.iat * 1000).toISOString(),
  });
  const instruction = JSON.stringify(signInstruction(body, principal));
  const card = body.constraints.card;
  console.log(`Skyfire PAY token: ${card.currency} max_total_minor ${card.max_total_minor}, merchants ${JSON.stringify(card.merchants)}, max_uses ${body.constraints.max_uses}`);

  pc = createPurchaseCheck({ dir, now: () => NOW });
  const chain = join(dir, "purchase-chains", `${pc.session_id}.jsonl`);
  const order = (merchant, id, total) => ({
    merchant_id: merchant,
    merchant_order_id: id,
    currency: "USD",
    total_minor: total,
    items: [{ sku: "CALL", quantity: 1, unit_price_minor: total, name: "Service call" }],
  });
  const other = "00000000-0000-4000-8000-000000000000"; // a made-up seller account
  const cases = [
    ["(a) inside the instruction", order(payload.aud, "S-1", "1000")],
    ["(b) over the cap", order(payload.aud, "S-2", "2000")],
    ["(c) at a different merchant", order(other, "O-1", "500")],
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
