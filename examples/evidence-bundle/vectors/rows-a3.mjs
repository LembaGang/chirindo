// The vectors of format 0.10's card additions (spec D.5, v0.10, offline):
// each a recipe built at run time from throwaway test keys (vectors/synth.mjs)
// and labelled TEST values. Nothing these keys sign is evidence of anything;
// no card data appears anywhere (no card number, expiry, security code,
// network token or last four digits), and each stated charge is a labelled
// test record. vectors/make-vectors.mjs lists them after the A2 vectors, in
// the order the shape was widened.

import { readFileSync } from "node:fs";
import path from "node:path";
import { jcsSha256 } from "../../ordering-evidence-h4/lib/formats.mjs";
import { FOLDER, we1 } from "./make-vectors.mjs";
import { add } from "./refusal-cases.mjs";
import { cardInstruction, checkpoint, chirindoLog, instruction, json, jwksOf, sidecarLine, testEd, testWitnessEntry, witnessReceipt } from "./synth.mjs";

const JSONL = "application/x-ndjson";

const v = (id, description, change, args, build, base = "SYNTH") => ({ id, description, recipe: { base, change }, args, build });
const WE1_STATED = ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"];

// WE-4's card limits (spec section 7, WE-4).
export const WE4_CARD = { currency: "USD", max_total_minor: "5000", merchants: ["test-merchant.example"], refundable_only: true };

// The test values of the card worked examples (handoff Appendix V): the
// decision record's ts, the checkpoint's ts, the test receipt's received_at
// and the stated authorization time.
export const T_DECISION = "2026-11-02T10:00:00.000Z";
export const T_CHECKPOINT = "2026-11-02T10:00:01.000Z";
export const T_RECEIVED = "2026-11-02T10:00:02.000Z";
export const T_AUTHORIZED = "2026-11-02T10:05:00Z";

// TEST pins: the shipped pins with the TEST witness key added to the witness
// key history and the TEST operator key's kid added to Headless Oracle's own
// operator key ids (so that L14 attaches, as WE-4's limit says).
export function cardPins() {
  const pins = JSON.parse(readFileSync(path.join(FOLDER, "pins", "pins.json"), "utf8"));
  pins.note = "TEST pins for the card vectors: the witness key test_witness_2026 and the operator key of the card vectors are TEST keys from public seed strings (vectors/synth.mjs), never Headless Oracle's.";
  pins.witness_keys.keys.push(testWitnessEntry());
  pins.operator_key_ids.push(testEd("card operator").kid);
  return pins;
}

// A card bundle (the shape of WE-4 and WE-5): one decision record (log-d) of a
// TEST operator key, its arguments (args-d) when `args` is given, a sidecar
// line with its checkpoint and a TEST witness receipt (sidecar-d), the
// operator key (opkey-d), the witness key history as /v5/keys gives it, with
// the TEST key (wkey-d), and the instruction (ins-d) when given.
export function cardDoc({ args, ins = null, insProfile = "signed-instruction-ed25519/0.3", reference = "TEST WE-4 order TEST-1001", receivedAt = T_RECEIVED, logEdit, edit } = {}) {
  const k = testEd("card operator");
  const log = chirindoLog({ k, sessionId: "test-card-1", argsHash: jcsSha256(args ?? { note: "TEST arguments not carried" }), t0: Date.parse(T_DECISION), edit: logEdit });
  const cp = checkpoint({ k, sessionId: "test-card-1", count: 1, lastEntryHash: log.hashes[0], ts: T_CHECKPOINT });
  const rc = witnessReceipt({ cp, receivedAt });
  const doc = { type: "evidence-bundle/0.10", created_at: "2026-11-02T10:10:00Z", assembled_by: "examples/evidence-bundle/vectors/rows-a3.mjs (TEST)", subject: { kind: "card-payment", reference, cites: { log: "log-d", seq: 0 } }, members: [] };
  add(doc, { id: "log-d", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: log.bytes, media_type: JSONL });
  if (args) add(doc, { id: "args-d", role: "action-arguments", profile: "jcs-json", bytes: json(args) });
  add(doc, { id: "sidecar-d", role: "witness-sidecar", profile: "chirindo-witness-sidecar/1", bytes: sidecarLine(cp, rc), media_type: JSONL });
  add(doc, { id: "opkey-d", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
  const shipped = JSON.parse(readFileSync(path.join(FOLDER, "pins", "pins.json"), "utf8")).witness_keys.keys;
  add(doc, { id: "wkey-d", role: "witness-key", profile: "ho-v5-keys", bytes: json({ keys: [...shipped, testWitnessEntry()] }) });
  if (ins) add(doc, { id: "ins-d", role: "instruction", profile: insProfile, bytes: json(ins) });
  if (edit) edit(doc);
  return doc;
}

// The stated charge of WE-4 variant 1 (a labelled TEST record), as options.
export const charge = ({ id = "TEST-ch-we4-1", amount = "4800", currency = "USD", at = T_AUTHORIZED, orderId = "TEST-1001", checkoutRef } = {}) => [
  "--charge-id", id, "--charge-amount", amount, "--charge-currency", currency, "--charge-authorized-at", at,
  ...(orderId ? ["--merchant-order-id", orderId] : []), ...(checkoutRef ? ["--checkout-ref", checkoutRef] : []),
];
const withPins = (args) => [...args, "--pins", "<pins>"];

// W3-02: a disputed charge stated for a card subject (S3.charge), B-CARD's
// prerequisites (rule 1) and rule C3.
export const ROWS_W302 = [
  v("V-02", "a card subject with a stated charge, the cited record's arguments holding no order", "a TEST card bundle (log-d, args-d without an order, sidecar-d with a TEST witness receipt, opkey-d, wkey-d); WE-4 variant 1's stated charge; TEST pins", withPins(charge()), () => ({ doc: cardDoc({ args: { note: "TEST decision call arguments, no order" } }), pins: cardPins() })),
  ...[
    ["V-30a", "the charge options for an evm-payment subject", "WE-1 with WE-4 variant 1's charge options", () => ({ doc: we1() }), ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3", ...charge()], "WE-1"],
    ["V-30b", "one charge option alone", "V-02's bundle with --charge-amount 4800 alone", () => ({ doc: cardDoc({ args: { note: "TEST decision call arguments, no order" } }), pins: cardPins() }), withPins(["--charge-amount", "4800"]), "SYNTH"],
    ["V-30c", "--charge-amount with a leading zero", "V-02's bundle with --charge-amount 04800", () => ({ doc: cardDoc({ args: { note: "TEST decision call arguments, no order" } }), pins: cardPins() }), withPins(charge({ amount: "04800" })), "SYNTH"],
  ].map(([id, description, change, build, args, base]) => ({ ...v(id, `usage error: ${description}`, change, args, build, base), usage: true })),
];

// WE-4's committed orders (spec section 7): variant 1, and variant 2's
// final-sale item; and WE-4's instruction (Annex A.3), its window seven days
// around the decision.
export const WE4_ORDER = { merchant_id: "test-merchant.example", merchant_order_id: "TEST-1001", currency: "USD", total_minor: "4800", items: [{ sku: "TEST-JACKET-M", name: "TEST jacket, size M", category: "apparel", quantity: 1, unit_price_minor: "4800", refundable: true }] };
export const WE4_ORDER_2 = { ...WE4_ORDER, total_minor: "4500", items: [{ sku: "TEST-SNEAKER-FINAL", name: "TEST sneaker, final sale", category: "footwear", quantity: 1, unit_price_minor: "4500", refundable: false }] };
export const we4Instruction = ({ card = WE4_CARD, v = "0.3", constraints = {} } = {}) => {
  const base = { principal: testEd("card principal"), agentKid: testEd("card operator").kid, validFrom: "2026-10-30T10:00:00Z", validUntil: "2026-11-06T10:00:00Z" };
  if (v === "0.2") return instruction({ principal: base.principal, agentKid: base.agentKid, payee: "0x0000000000000000000000000000000000000001", token: "native", constraints: { valid_from: base.validFrom, valid_until: base.validUntil, ...constraints } });
  return cardInstruction({ ...base, card, constraints });
};
// The decision call's arguments: the committed order and, when an instruction
// is cited, its digest.
export const cardArgs = (order, ins) => (ins ? { instruction_sha256: jcsSha256(ins), order } : { order });

const W4 = "a TEST card bundle (log-d, args-d, sidecar-d with a TEST witness receipt, opkey-d, wkey-d)";
const card4 = (args, { ins = null } = {}) => () => ({ doc: cardDoc({ args, ins }), pins: cardPins() });

// W3-03: the committed order (M8.order) and B-CARD's rules 2 to 4.
export const ROWS_W303 = [
  v("V-03", "WE-4 variant 1, the instruction member left out", `${W4}; args-d commits to WE-4 variant 1's order and cites WE-4's instruction, which the bundle does not carry; WE-4 variant 1's stated charge`, withPins(charge()), card4(cardArgs(WE4_ORDER, we4Instruction()))),
  v("V-04", "WE-4 variant 1 with no instruction", `${W4}; args-d commits to WE-4 variant 1's order and carries no instruction_sha256; WE-4 variant 1's stated charge`, withPins(charge()), card4(cardArgs(WE4_ORDER))),
  v("V-05", "V-04 with no charge stated", "V-04's bundle; no charge options", withPins([]), card4(cardArgs(WE4_ORDER))),
  v("V-14", "V-04 with the amount stated as 4900", "V-04's bundle; --charge-amount 4900", withPins(charge({ amount: "4900" })), card4(cardArgs(WE4_ORDER))),
  v("V-15", "V-04 with the currency stated as EUR", "V-04's bundle; --charge-currency EUR", withPins(charge({ currency: "EUR" })), card4(cardArgs(WE4_ORDER))),
  v("V-16", "V-04 with the authorization time before the receipt's received_at", "V-04's bundle; --charge-authorized-at 2026-11-02T10:00:01Z", withPins(charge({ at: "2026-11-02T10:00:01Z" })), card4(cardArgs(WE4_ORDER))),
  v("V-17", "V-04 with the authorization time equal to the receipt's received_at", `V-04's bundle; --charge-authorized-at ${T_RECEIVED}`, withPins(charge({ at: T_RECEIVED })), card4(cardArgs(WE4_ORDER))),
  v("V-19", "V-04 with neither committed reference stated", "V-04's bundle; no --merchant-order-id", withPins(charge({ orderId: null })), card4(cardArgs(WE4_ORDER))),
  v("V-20", "an order committing only a checkout_ref, stated with --checkout-ref", `V-04 with the order's merchant_order_id replaced by checkout_ref "TEST-CART-1001"; --checkout-ref TEST-CART-1001, no --merchant-order-id`, withPins(charge({ orderId: null, checkoutRef: "TEST-CART-1001" })), () => {
    const { merchant_order_id, ...rest } = WE4_ORDER;
    return { doc: cardDoc({ args: cardArgs({ ...rest, checkout_ref: "TEST-CART-1001" }) }), pins: cardPins() };
  }),
  v("V-21", "an order with neither reference", "V-04 with the order's merchant_order_id left out", withPins(charge()), () => {
    const { merchant_order_id, ...rest } = WE4_ORDER;
    return { doc: cardDoc({ args: cardArgs(rest) }), pins: cardPins() };
  }),
  v("V-22", "an order with a member the committed order does not have", 'V-04 with the order holding a member "coupon": "TEST-10"', withPins(charge()), card4(cardArgs({ ...WE4_ORDER, coupon: "TEST-10" }))),
];

// WE-5's card limits, committed orders and instruction (spec section 7, WE-5),
// the window ending 2026-11-09T00:00:00Z, before the stay.
export const WE5_CARD = { currency: "EUR", max_unit_price_minor: "15000", service_window: { from: "2026-11-10", until: "2026-11-12" }, locations: ["Lisbon"], categories: ["lodging"], refundable_only: true };
const ROOM = { sku: "TEST-ROOM-STD-FLEX", name: "TEST standard room, flexible rate", category: "lodging", quantity: 2, unit_price_minor: "14000", refundable: true, service_from: "2026-11-10", service_until: "2026-11-12", location: "Lisbon" };
export const WE5_ORDER = { merchant_id: "test-hotel.example", merchant_order_id: "TEST-H-2001", currency: "EUR", total_minor: "28000", items: [ROOM] };
export const WE5_ORDER_2 = { ...WE5_ORDER, total_minor: "24000", items: [{ ...ROOM, sku: "TEST-ROOM-STD-NONREF", name: "TEST standard room, non-refundable rate", unit_price_minor: "12000", refundable: false }] };
export const we5Instruction = () => cardInstruction({ principal: testEd("card principal"), agentKid: testEd("card operator").kid, card: WE5_CARD, validFrom: "2026-11-02T00:00:00Z", validUntil: "2026-11-09T00:00:00Z" });
export const we5Charge = (o = {}) => charge({ id: "TEST-ch-we5-1", amount: "28000", currency: "EUR", orderId: "TEST-H-2001", ...o });
export const WE5_REF = "TEST WE-5 booking TEST-H-2001";
const we5 = (order, o = {}) => () => {
  const ins = we5Instruction();
  return { doc: cardDoc({ args: cardArgs(order, ins), ins, reference: WE5_REF, ...o }), pins: cardPins() };
};
const we4 = (order, { ins = we4Instruction(), insProfile, ...o } = {}) => () => ({ doc: cardDoc({ args: cardArgs(order, ins), ins, insProfile, ...o }), pins: cardPins() });
// A DENY record: chirindo's refusing triple in the cited record.
const deny = (recs) => recs.map((r) => ({ ...r, event: { ...r.event, decision: "deny", outcome: "denied" }, ["gate"]: { ...r["gate"], result: "halt" } }));
// A second sidecar line: a checkpoint of count 2, beyond the carried log, and
// a TEST witness receipt for it (B-CKP and B-WIT TRUNCATED).
const longerHead = (doc) => {
  const i = doc.members.findIndex((m) => m.id === "sidecar-d");
  const k = testEd("card operator");
  const cp2 = checkpoint({ k, sessionId: "test-card-1", count: 2, lastEntryHash: jcsSha256({ test: "a second record the bundle does not carry" }), ts: "2026-11-02T10:00:03.000Z" });
  const rc2 = witnessReceipt({ cp: cp2, receivedAt: "2026-11-02T10:00:04.000Z" });
  const old = Buffer.from(doc.members[i].bytes_b64, "base64");
  doc.members.splice(i, 1);
  add(doc, { id: "sidecar-d", role: "witness-sidecar", profile: "chirindo-witness-sidecar/1", bytes: Buffer.concat([old, sidecarLine(cp2, rc2)]), media_type: JSONL });
};

// W3-04: instructions of profile 0.3 (Annex A.3, M6) and B-INS for a card subject.
export const ROWS_W304 = [
  v("V-10", "WE-4 variant 1", `${W4}, with WE-4's instruction (ins-d, signed-instruction-ed25519/0.3) that args-d cites; WE-4 variant 1's stated charge`, withPins(charge()), we4(WE4_ORDER)),
  v("V-11", "WE-4 variant 2, a final-sale item", "V-10 with WE-4 variant 2's order (TEST-SNEAKER-FINAL, refundable false, 4500); the charge stated as 4500 USD", withPins(charge({ amount: "4500" })), we4(WE4_ORDER_2)),
  v("V-12", "WE-5 variant 1, a hotel booking", "a TEST card bundle with WE-5's instruction and order (TEST-H-2001, two nights at 14000 EUR); WE-5 variant 1's stated charge", withPins(we5Charge()), we5(WE5_ORDER)),
  v("V-13", "WE-5 variant 2, a non-refundable rate", "V-12 with WE-5 variant 2's order (TEST-ROOM-STD-NONREF, refundable false, 24000); the charge stated as 24000 EUR", withPins(we5Charge({ amount: "24000" })), we5(WE5_ORDER_2)),
  v("V-18", "V-10 with no charge stated", "V-10's bundle; no charge options", withPins([]), we4(WE4_ORDER)),
  v("V-23", "V-10 under a signed-instruction-ed25519/0.2 instruction", "V-10 with ins-d a TEST signed-instruction-ed25519/0.2 instruction (no card member) that args-d cites", withPins(charge()), we4(WE4_ORDER, { ins: we4Instruction({ v: "0.2" }), insProfile: "signed-instruction-ed25519/0.2" })),
  v("V-24", "V-10 under a 0.3 instruction without card", "V-10 with ins-d a TEST 0.3 instruction whose constraints hold no card (chain_id, asset native, max_amount, payees instead)", withPins(charge()), we4(WE4_ORDER, { ins: we4Instruction({ card: null, constraints: { chain_id: "eip155:84532", asset: "native", max_amount: "1", payees: ["0x0000000000000000000000000000000000000001"] } }) })),
  v("V-25", "a 0.3 card of only currency and refundable_only false", `V-10 with ins-d's card {"currency": "USD", "refundable_only": false}`, withPins(charge()), we4(WE4_ORDER, { ins: we4Instruction({ card: { currency: "USD", refundable_only: false } }) })),
  v("V-27a", "WE-5 with a night above the cap", "V-12 with the room at 16000 a night (total 32000, charge 32000)", withPins(we5Charge({ amount: "32000" })), we5({ ...WE5_ORDER, total_minor: "32000", items: [{ ...ROOM, unit_price_minor: "16000" }] })),
  v("V-27b", "WE-5 with a stay outside the window", "V-12 with the stay from 2026-11-09 to 2026-11-11", withPins(we5Charge()), we5({ ...WE5_ORDER, items: [{ ...ROOM, service_from: "2026-11-09", service_until: "2026-11-11" }] })),
  v("V-27c", "WE-5 with the city written Lisboa", `V-12 with the room's location "Lisboa"`, withPins(we5Charge()), we5({ ...WE5_ORDER, items: [{ ...ROOM, location: "Lisboa" }] })),
  v("V-28", "WE-5 with an item without refundable", "V-12 with the room's refundable member left out", withPins(we5Charge()), we5({ ...WE5_ORDER, items: [(({ refundable, ...rest }) => rest)(ROOM)] })),
  v("V-29", "V-10 with a DENY decision record cited", "V-10 with the decision record's event.decision deny, event.outcome denied and gate.result halt", withPins(charge()), we4(WE4_ORDER, { logEdit: deny })),
  v("V-31", "V-10 plus a receipt for a longer head (B-WIT TRUNCATED)", "V-10 with a second sidecar line: a checkpoint of count 2 signed by the operator key and a TEST witness receipt for it", withPins(charge()), we4(WE4_ORDER, { edit: longerHead })),
];

// W3-01: bundles of type evidence-bundle/0.10, whose members are 0.9's (M0).
export const ROWS_W301 = [
  v("V-01", "WE-1 with type evidence-bundle/0.10, its members unchanged", 'type = "evidence-bundle/0.10"; member digests unchanged', WE1_STATED, () => {
    const doc = we1();
    doc.type = "evidence-bundle/0.10";
    return { doc };
  }, "WE-1"),
];

// A regression row (C5 step 0): profile 0.3 is allowed only in an
// evidence-bundle/0.10 bundle (table 3-1, M1).
export const ROWS_A3_STEP0 = [
  v("V-26", "a 0.9-typed bundle carrying a signed-instruction-ed25519/0.3 instruction", "WE-1 (type evidence-bundle/0.9) with a TEST signed-instruction-ed25519/0.3 instruction (ins-c) added, with WE-4's card limits", WE1_STATED, () => {
    const doc = we1();
    const ins = cardInstruction({ principal: testEd("card principal"), agentKid: testEd("card operator").kid, card: WE4_CARD, validFrom: "2026-10-30T10:00:00Z", validUntil: "2026-11-06T10:00:00Z" });
    add(doc, { id: "ins-c", role: "instruction", profile: "signed-instruction-ed25519/0.3", bytes: json(ins) });
    return { doc };
  }, "WE-1"),
];
