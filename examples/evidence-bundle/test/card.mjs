// Card subjects with a stated charge (spec v0.10: 4.2, S3.charge; 4.3,
// B-CARD; 4.6, table 4-6c). Each vector of vectors/rows-a3.mjs that this
// file names is run once; its values are asserted as the specification
// states them ([spec], with the v0.10 lines) or as this build derives them
// where it is silent ([derived]).

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { runCli, runVector, VECTORS, we1 } from "../vectors/make-vectors.mjs";
import { add } from "../vectors/refusal-cases.mjs";
import { T_AUTHORIZED, T_RECEIVED, we4Instruction } from "../vectors/rows-a3.mjs";
import { json } from "../vectors/synth.mjs";

const IDS = ["V-02", "V-30a", "V-30b", "V-30c", "V-03", "V-04", "V-05", "V-14", "V-15", "V-16", "V-17", "V-19", "V-20", "V-21", "V-22", "V-10", "V-11", "V-12", "V-13", "V-18", "V-23", "V-24", "V-25", "V-27a", "V-27b", "V-27c", "V-28", "V-29", "V-31"];
let dir;
const runs = new Map();
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-card-"));
  for (const id of IDS) runs.set(id, await runVector(VECTORS.find((v) => v.id === id), dir));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const out = (id) => {
  const r = runs.get(id);
  assert.equal(r.status, 0, `${id}: ${r.stderr}`);
  return r.output;
};
const check = (o, id, member = null) => o.checks.find((x) => x.id === id && x.member === member);
const bind = (o, id) => o.bindings.find((b) => b.id === id);
export const CARD_TEXT = {
  FAILS: "FAILS",
  "DOES-NOT-MATCH-CHARGE": "DOES NOT MATCH THE CHARGE: the order the gate recorded does not match the stated charge",
  "PAYMENT-NOT-VERIFIED": "NOT VERIFIED: the record does not show that the decision was recorded before the charge and matches it",
  "OUTSIDE-INSTRUCTION": "OUTSIDE THE INSTRUCTION: the decision was recorded before the charge and matches it, and the order falls outside the instruction or goes against the decision",
  "RECORDED-BEFORE-CHARGE": "RECORDED BEFORE THE CHARGE: the decision and the instruction were recorded before the charge and match it",
  "RECORDED-WITH-GAPS": "RECORDED WITH GAPS: the decision was recorded before the charge and matches it; the gaps are listed",
};

test("V-02: a stated charge, no order committed: S3.charge PASS, B-CARD NOT-EVALUATED no-order-committed, PAYMENT-NOT-VERIFIED (C3) [spec, v0.10 232, 463, 629]", () => {
  const o = out("V-02");
  assert.equal(check(o, "S3.charge").status, "PASS");
  assert.deepEqual([bind(o, "B-CARD").state, bind(o, "B-CARD").reason], ["NOT-EVALUATED", "no-order-committed"]);
  assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "C3", "no-order-committed"]);
  assert.equal(o.verdict.text, CARD_TEXT["PAYMENT-NOT-VERIFIED"]);
  assert.ok(!o.checks.some((c) => c.id === "S1.authorizer" || c.id === "S2.tx"), "S1 and S2 are not listed for a card subject");
  for (const id of ["B-PAY", "B-CHAIN"]) assert.deepEqual([bind(o, id).state, bind(o, id).reason], ["NOT-EVALUATED", "card-subject"], id);
  assert.equal(o.limits[0].id === "L24" || o.limits.some((l) => l.id === "L24"), true, "L24 is attached");
});

test("V-02: the stated charge in stated.charge, the card member, and the stated time on the processor's clock [derived; v0.10 4.7, 523]", () => {
  const o = out("V-02");
  assert.deepEqual(o.stated.charge, { id: "TEST-ch-we4-1", amount_minor: "4800", currency: "USD", authorized_at: T_AUTHORIZED, merchant_order_id: "TEST-1001", checkout_ref: null });
  assert.equal(o.card.order, null);
  assert.deepEqual(o.card.matches, { amount: null, currency: null, merchant_order_id: null, checkout_ref: null });
  assert.equal(o.card.authorized_at, T_AUTHORIZED);
  assert.equal(o.card.before_authorization, null);
  assert.ok(o.times.some((t) => t.value === T_AUTHORIZED && t.clock === "processor"));
});

for (const id of ["V-30a", "V-30b", "V-30c"])
  test(`${id}: a usage error that names the charge rule, not an unknown option [spec for the exit, derived for the message; v0.10 232]`, () => {
    const r = runs.get(id);
    assert.equal(r.status, 2, r.stderr);
    assert.equal(r.stdout, "");
    assert.equal(r.stderr.trim().split("\n").length, 1);
    assert.match(r.stderr, /^usage error: /);
    assert.doesNotMatch(r.stderr, /unknown option/);
    assert.match(r.stderr, /charge/);
  });

// An expectation names: verdict [code, rule, reason], bindings {id: [state,
// reason]}, checks [[id, member, status, reason]], flags present (flagsHave)
// or absent (flagsLack), limits present (limitsHave), matches (card.matches)
// and before (card.before_authorization).
export function expectCard(o, id, e) {
  if (e.verdict) assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason].slice(0, e.verdict.length), e.verdict, `${id} verdict`);
  if (e.verdict && CARD_TEXT[e.verdict[0]] && e.verdict[1]?.startsWith("C")) assert.equal(o.verdict.text, CARD_TEXT[e.verdict[0]], `${id} verdict text`);
  for (const [b, [state, reason]] of Object.entries(e.bindings ?? {})) {
    assert.equal(bind(o, b).state, state, `${id} ${b} state`);
    if (reason !== undefined) assert.equal(bind(o, b).reason, reason, `${id} ${b} reason`);
  }
  for (const [cid, member, status, reason] of e.checks ?? []) {
    const c = check(o, cid, member);
    assert.ok(c, `${id}: ${cid} on ${member} is listed`);
    assert.equal(c.status, status, `${id} ${cid}: ${c.detail}`);
    if (reason !== undefined) assert.equal(c.reason, reason, `${id} ${cid} reason`);
  }
  for (const f of e.flagsHave ?? []) assert.ok(o.flags.some((x) => x.code === f), `${id}: flag ${f}`);
  for (const f of e.flagsLack ?? []) assert.ok(!o.flags.some((x) => x.code === f), `${id}: no flag ${f}`);
  for (const l of e.limitsHave ?? []) assert.ok(o.limits.some((x) => x.id === l), `${id}: limit ${l}`);
  if (e.matches) assert.deepEqual(o.card.matches, e.matches, `${id} card.matches`);
  if (e.before !== undefined) assert.equal(o.card.before_authorization, e.before, `${id} before_authorization`);
  if (e.limitsExact) assert.deepEqual(o.limits.map((l) => l.id).sort(), [...e.limitsExact].sort(), `${id} limits`);
  if (e.decision) assert.equal(o.decision.value, e.decision, `${id} decision`);
  for (const [m, [state, exceeded, reason]] of Object.entries(e.instructions ?? {})) {
    const i = o.instructions.find((x) => x.member === m);
    assert.ok(i, `${id}: instruction ${m} is reported`);
    assert.deepEqual([i.state, i.exceeded, i.reason], [state, exceeded, reason], `${id} instruction ${m}`);
  }
  for (const [m, want] of Object.entries(e.cardLimits ?? {})) {
    const i = o.instructions.find((x) => x.member === m);
    const got = Object.fromEntries(i.card_limits.map((l) => [l.limit, l.result]));
    assert.deepEqual(got, want, `${id} card_limits of ${m}`);
  }
  if (e.verdictNot) for (const c of e.verdictNot) assert.notEqual(o.verdict.code, c, `${id}: never ${c}`);
  if (e.gaps) assert.deepEqual(o.verdict.gaps.filter((g) => e.gaps.some(([b]) => b === g.binding)).map((g) => [g.binding, g.state, g.reason]), e.gaps, `${id} gaps`);
}

const OFFLINE_WIT = ["PAYMENT-NOT-VERIFIED", "C3", "offline-witness-data"];
const ALL_TRUE = { amount: true, currency: true, merchant_order_id: true, checkout_ref: null };
// [id, what, spec (v0.10 lines), derived]
export const W303_ROWS = [
  ["V-03", "WE-4 variant 1, instruction left out: B-CARD BOUND", { lines: "462 to 468", bindings: { "B-CARD": ["BOUND", null] }, checks: [["M8.order", "args-d", "PASS", null]] }, { bindings: { "B-INS": ["WITHHELD", null] }, verdict: OFFLINE_WIT }],
  ["V-04", "WE-4 variant 1, no instruction: B-CARD BOUND, B-INS ABSENT", {}, { bindings: { "B-CARD": ["BOUND", null], "B-INS": ["ABSENT", null] }, verdict: OFFLINE_WIT, matches: ALL_TRUE, before: true, limitsHave: ["L24", "L25"] }],
  ["V-05", "no charge stated: as v0.9, card-subject, L24 and L25", { lines: "232, 463, 617, 987, 988", checks: [["S3.charge", null, "NOT-EVALUATED", "charge-not-stated"]], bindings: { "B-CARD": ["NOT-EVALUATED", "charge-not-stated"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "card-subject"], limitsHave: ["L24", "L25"] }, {}],
  ["V-14", "the amount stated as 4900: DIFFERS, DOES-NOT-MATCH-CHARGE", { lines: "464, 628, 663", bindings: { "B-CARD": ["DIFFERS"] }, verdict: ["DOES-NOT-MATCH-CHARGE", "C2"] }, { matches: { amount: false, currency: true, merchant_order_id: true, checkout_ref: null } }],
  ["V-15", "the currency stated as EUR: DIFFERS", { lines: "464, 628", bindings: { "B-CARD": ["DIFFERS"] }, verdict: ["DOES-NOT-MATCH-CHARGE", "C2"] }, { matches: { amount: true, currency: false, merchant_order_id: true, checkout_ref: null } }],
  ["V-16", "authorized before received_at: AFTER-AUTHORIZATION, not-before-authorization", { lines: "465, 629, 675", bindings: { "B-CARD": ["AFTER-AUTHORIZATION", "not-before-authorization"] }, verdict: ["PAYMENT-NOT-VERIFIED", "C3", "not-before-authorization"] }, { before: false, flagsHave: ["two-clock-comparison"] }],
  ["V-17", "authorized at received_at: AFTER-AUTHORIZATION", { lines: "465", bindings: { "B-CARD": ["AFTER-AUTHORIZATION", "not-before-authorization"] } }, { before: false }],
  ["V-19", "neither reference stated: reference-not-stated, B-CARD BOUND with that gap", { lines: "464", flagsHave: ["reference-not-stated"], bindings: { "B-CARD": ["BOUND", "reference-not-stated"] }, gaps: [["B-CARD", "BOUND", "reference-not-stated"]] }, { verdict: OFFLINE_WIT, matches: { amount: true, currency: true, merchant_order_id: null, checkout_ref: null } }],
  ["V-20", "only a checkout_ref, stated: B-CARD BOUND", { lines: "454, 464", bindings: { "B-CARD": ["BOUND", null] }, flagsLack: ["reference-not-stated"] }, { matches: { amount: true, currency: true, merchant_order_id: null, checkout_ref: true }, verdict: OFFLINE_WIT }],
  ["V-21", "an order with neither reference: M8.order FAIL, FAILS", { lines: "454, 309, 642", checks: [["M8.order", "args-d", "FAIL"]], verdict: ["FAILS", "C1"] }, {}],
  ["V-22", "an order with a member it does not have: M8.order FAIL, FAILS", { lines: "458, 309, 642", checks: [["M8.order", "args-d", "FAIL"]], verdict: ["FAILS", "C1"] }, {}],
];
for (const [id, what, spec, derived] of W303_ROWS) {
  if (Object.keys(spec).length > 1) test(`${id}: ${what} [spec, v0.10 lines ${spec.lines}]`, () => expectCard(out(id), id, spec));
  if (Object.keys(derived).length) test(`${id}: ${what} [derived]`, () => expectCard(out(id), id, derived));
}

test("V-04: the card member reports the committed order, its items' sum and the two times side by side [derived; v0.10 458, 690, 4.7]", () => {
  const o = out("V-04");
  assert.deepEqual(o.card.order, { merchant_id: "test-merchant.example", merchant_order_id: "TEST-1001", checkout_ref: null, currency: "USD", total_minor: "4800", items_sum_minor: "4800", item_count: 1 });
  assert.equal(o.card.witness_received_at, T_RECEIVED);
  assert.equal(o.card.authorized_at, T_AUTHORIZED);
  assert.ok(o.times.some((t) => t.clock === "processor") && o.times.some((t) => t.clock === "headless-oracle"));
});

// W3-04: profile 0.3 and B-INS for a card subject. Every limit of Annex A.3 is
// listed with its result (spec 472); a limit the instruction does not set is
// not-declared.
const NOT_DECLARED = Object.fromEntries(["currency", "max_total_minor", "max_unit_price_minor", "merchants", "items", "categories", "refundable_only", "service_window", "locations"].map((k) => [k, "not-declared"]));
const WE4_LIMITS = { ...NOT_DECLARED, currency: "inside", max_total_minor: "inside", merchants: "inside", refundable_only: "inside" };
const WE5_LIMITS = { ...NOT_DECLARED, currency: "inside", max_unit_price_minor: "inside", service_window: "inside", locations: "inside", categories: "inside", refundable_only: "inside" };
export const W304_ROWS = [
  ["V-10", "WE-4 variant 1: B-CARD BOUND, B-INS BOUND, PAYMENT-NOT-VERIFIED (C3, row 10)", {
    lines: "935, 465, 472, 629, 651",
    bindings: { "B-CARD": ["BOUND", null], "B-INS": ["BOUND", null], "B-WIT": ["SUPPLIED", null] },
    checks: [["M6.instruction", "ins-d", "PASS", null]],
    before: true,
    cardLimits: { "ins-d": WE4_LIMITS },
    verdict: OFFLINE_WIT,
    limitsExact: ["L1", "L2", "L3", "L4", "L6", "L7", "L8", "L9", "L12", "L13", "L14", "L17", "L24", "L25"],
  }, { matches: { amount: true, currency: true, merchant_order_id: true, checkout_ref: null }, instructions: { "ins-d": ["BOUND", [], null] } }],
  ["V-11", "WE-4 variant 2: B-INS EXCEEDS refundable_only, offline-witness-data (row 4)", { lines: "937, 473, 645", bindings: { "B-CARD": ["BOUND", null], "B-INS": ["EXCEEDS", null] }, instructions: { "ins-d": ["EXCEEDS", ["refundable_only"], null] }, verdict: OFFLINE_WIT }, { cardLimits: { "ins-d": { ...WE4_LIMITS, refundable_only: "outside" } } }],
  ["V-12", "WE-5 variant 1: B-INS BOUND, every declared limit inside", { lines: "951, 472", bindings: { "B-CARD": ["BOUND", null], "B-INS": ["BOUND", null] }, cardLimits: { "ins-d": WE5_LIMITS }, verdict: OFFLINE_WIT }, {}],
  ["V-13", "WE-5 variant 2: B-INS EXCEEDS refundable_only", { lines: "951, 473", bindings: { "B-INS": ["EXCEEDS", null] }, instructions: { "ins-d": ["EXCEEDS", ["refundable_only"], null] }, verdict: OFFLINE_WIT }, {}],
  ["V-18", "V-10 with no charge: card-subject (table 4-6b row 49)", { lines: "232, 463, 617, 621", checks: [["S3.charge", null, "NOT-EVALUATED", "charge-not-stated"], ["M6.instruction", "ins-d", "PASS", null]], bindings: { "B-CARD": ["NOT-EVALUATED", "charge-not-stated"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "card-subject"] }, {}],
  ["V-23", "a 0.2 instruction: B-INS NOT-EVALUATED no-card-limits", { lines: "471", bindings: { "B-INS": ["NOT-EVALUATED", "no-card-limits"] }, verdict: OFFLINE_WIT }, {}],
  ["V-24", "a 0.3 instruction without card: card-limits-not-declared", { lines: "471", bindings: { "B-INS": ["NOT-EVALUATED", "card-limits-not-declared"] } }, { verdict: OFFLINE_WIT, checks: [["M6.instruction", "ins-d", "PASS", null]] }],
  ["V-25", "a card of currency and refundable_only false: M6.instruction FAIL, FAILS", { lines: "1106, 307", checks: [["M6.instruction", "ins-d", "FAIL"]], verdict: ["FAILS", "C1"] }, {}],
  ["V-27a", "a night above the cap: max_unit_price_minor outside", { lines: "472, 951", bindings: { "B-INS": ["EXCEEDS", null] }, instructions: { "ins-d": ["EXCEEDS", ["max_unit_price_minor"], null] } }, { verdict: OFFLINE_WIT }],
  ["V-27b", "a stay outside the window: service_window outside", { lines: "472, 951", bindings: { "B-INS": ["EXCEEDS", null] }, instructions: { "ins-d": ["EXCEEDS", ["service_window"], null] } }, { verdict: OFFLINE_WIT }],
  ["V-27c", "the city written Lisboa: locations outside", { lines: "472, 951", bindings: { "B-INS": ["EXCEEDS", null] }, instructions: { "ins-d": ["EXCEEDS", ["locations"], null] } }, { verdict: OFFLINE_WIT }],
  ["V-28", "an item without refundable: order-field-missing", { lines: "472, 473, 951", bindings: { "B-INS": ["NOT-EVALUATED", "order-field-missing"] } }, { verdict: OFFLINE_WIT, cardLimits: { "ins-d": { ...WE5_LIMITS, refundable_only: "not-evaluated" } } }],
  ["V-29", "a DENY record cited: decision refuse, offline-witness-data", {}, { decision: "refuse", verdict: OFFLINE_WIT }],
  ["V-31", "a receipt for a longer head: B-WIT TRUNCATED, offline-witness-data, never RECORDED-WITH-GAPS or OUTSIDE-INSTRUCTION", { lines: "79, 465, 629, 651", bindings: { "B-WIT": ["TRUNCATED", null] }, verdict: OFFLINE_WIT, verdictNot: ["RECORDED-WITH-GAPS", "OUTSIDE-INSTRUCTION"] }, {}],
];
for (const [id, what, spec, derived] of W304_ROWS) {
  if (Object.keys(spec).length > 1) test(`${id}: ${what} [spec, v0.10 lines ${spec.lines}]`, () => expectCard(out(id), id, spec));
  if (Object.keys(derived).length) test(`${id}: ${what} [derived]`, () => expectCard(out(id), id, derived));
}

// The decoded shape (README, "The shape this build judges"): an evm-payment
// subject with a profile 0.3 instruction for card orders only is refused, and
// the same instruction naming all four payment limits is not.
test("instruction:card-only: WE-1 typed 0.10 with a card-only 0.3 instruction is refused; with the four payment limits it is not [derived]", () => {
  const stated = ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"];
  const withIns = (ins) => {
    const doc = we1();
    doc.type = "evidence-bundle/0.10";
    add(doc, { id: "ins-c", role: "instruction", profile: "signed-instruction-ed25519/0.3", bytes: json(ins) });
    return doc;
  };
  const r = runCli(dir, "card-only", withIns(we4Instruction()), stated);
  assert.deepEqual([r.status, r.stdout, r.stderr], [2, "", "not supported in this build: instruction:card-only\n"]);
  const pay = { chain_id: "eip155:84532", asset: "native", max_amount: "1", payees: ["0x0000000000000000000000000000000000000001"] };
  const ok = runCli(dir, "card-and-payment", withIns(we4Instruction({ constraints: pay })), stated);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.output.checks.find((c) => c.id === "M6.instruction").status, "PASS");
});
