// The online cases of a card subject (W3-10; spec 4.2 and 4.3, `--online`):
// the TEST card bundles of WE-4 run through the library entry with every
// online read answered by a fake (vectors/pointer-cases.mjs's fakeFetch), so
// no case reads the network. The fake witness lists receipts under the TEST
// witness key, which the TEST pins name; Headless Oracle's own witness serves
// no such key, so these verdicts are what the format gives under a witness
// that holds the receipt, never what the real witness says of these bundles
// (ruling A3-8).

import { readFileSync } from "node:fs";
import path from "node:path";
import { bundleBytes } from "../lib/we1.mjs";
import { FOLDER } from "./make-vectors.mjs";
import { fakeFetch } from "./pointer-cases.mjs";
import { cardArgs, cardDoc, cardPins, longerHead, T_AUTHORIZED, WE4_ORDER, WE4_ORDER_2, we4Instruction } from "./rows-a3.mjs";
import { checkpoint, testEd, witnessReceipt } from "./synth.mjs";

export const WITNESS = "https://api.headlessoracle.com";
// The page bundles' operator key set (ruling A3-15), and the bytes the site serves there.
export const JWKS_URI = "https://headlessoracle.com/evidence/examples/jwks.json";
export const EXAMPLES_JWKS = path.join(FOLDER, "pages", "evidence-examples-jwks.json");

const KID = testEd("card operator").kid;
const listUrl = (sessionId = "test-card-1") => `${WITNESS}/v1/witness/checkpoints?${new URLSearchParams({ kid: KID, session_id: sessionId }).toString()}`;
// The receipts a bundle's sidecar lines carry.
const carried = (doc) =>
  Buffer.from(doc.members.find((m) => m.id === "sidecar-d").bytes_b64, "base64")
    .toString("utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l).witness_receipt);
const list = (receipts) => ({ status: 200, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify({ receipts }), "utf8") });

const stated = (amount = "4800") => ({ authorizer: null, tx: null, charge: { id: "TEST-ch-we4-1", amount_minor: amount, currency: "USD", authorized_at: T_AUTHORIZED, merchant_order_id: "TEST-1001", checkout_ref: null } });
const we4 = (order = WE4_ORDER, o = {}) => {
  const ins = we4Instruction();
  return cardDoc({ args: cardArgs(order, ins), ins, ...o });
};
// [id, what, the bundle document, the stated charge's amount, the fake's table]
export const ONLINE_CASES = [
  ["V-72", "V-10's bundle; the witness lists its one covering receipt, read to its end", () => we4(), "4800", (doc) => ({ [listUrl()]: list(carried(doc)) })],
  ["V-73", "V-11's bundle (a final-sale item), the same witness", () => we4(WE4_ORDER_2), "4500", (doc) => ({ [listUrl()]: list(carried(doc)) })],
  ["V-74", "V-10 with records that name the examples' jwks_uri and carry that JWKS; the host answers 404", () => we4(WE4_ORDER, { jwksUri: JWKS_URI }), "4800", (doc) => ({ [listUrl()]: list(carried(doc)), [JWKS_URI]: { status: 404 } })],
  ["V-75", "V-74 with the host serving pages/evidence-examples-jwks.json", () => we4(WE4_ORDER, { jwksUri: JWKS_URI }), "4800", (doc) => ({ [listUrl()]: list(carried(doc)), [JWKS_URI]: () => Promise.resolve(new Response(readFileSync(EXAMPLES_JWKS), { status: 200, headers: { "content-type": "application/json" } })) })],
  ["V-76", "V-10's bundle; the witness's list answers 500 (not read to its end)", () => we4(), "4800", () => ({ [listUrl()]: { status: 500 } })],
  ["V-77", "V-10's bundle; the witness's list, read to its end, lacks the carried receipt", () => we4(), "4800", () => ({ [listUrl()]: list([]) })],
  ["V-78", "V-31's bundle (a receipt for a longer head, B-WIT TRUNCATED); the witness's list not read to its end", () => we4(WE4_ORDER, { edit: longerHead }), "4800", () => ({ [listUrl()]: { status: 503 } })],
  ["V-79", "V-10's bundle; the witness lists, beside the covering receipt, a verified receipt at the same count with another last_entry_hash (a rewrite)", () => we4(), "4800", (doc) => {
    const [rc] = carried(doc);
    const k = testEd("card operator");
    const other = witnessReceipt({ cp: checkpoint({ k, sessionId: "test-card-1", count: 1, lastEntryHash: "sha256:" + "cd".repeat(32), ts: "2026-11-02T10:00:01.500Z" }), receivedAt: "2026-11-02T10:00:03.000Z" });
    return { [listUrl()]: list([rc, other]) };
  }],
].map(([id, what, doc, amount, table]) => ({
  id,
  what,
  async run(verifyBundle, { online = true } = {}) {
    const d = doc();
    const fetch = fakeFetch(table(d));
    const r = await verifyBundle(bundleBytes(d), stated(amount), cardPins(), online ? { online: { fetch } } : {});
    return { ...r, doc: d, fetch };
  },
}));
