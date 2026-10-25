// Card verdicts never say the payment is verified (spec 4.6): every vector
// of the vectors file whose
// bundle has a card-payment subject is run, and its verdict is never one of
// the VERIFIES codes; with a stated charge it is one of table 4-6c's six,
// under rules C1 to C6; and no string anywhere in the output says "proven" or
// "payment verified".

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { runVector, VECTORS } from "../vectors/make-vectors.mjs";

const VERIFIES = ["VERIFIES", "VERIFIES-WITH-GAPS", "VERIFIES-OUTSIDE-INSTRUCTION"];
const CARD_CODES = ["FAILS", "DOES-NOT-MATCH-CHARGE", "PAYMENT-NOT-VERIFIED", "OUTSIDE-INSTRUCTION", "RECORDED-BEFORE-CHARGE", "RECORDED-WITH-GAPS"];
const CARD_RULES = ["C1", "C2", "C3", "C4", "C5", "C6"];
// The word boundary keeps "provenance" out.
const WORDS = [/\bproven\b/i, /payment verified/i];

let dir;
const card = [];
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-never-"));
  for (const v of VECTORS) {
    const built = await v.build();
    if (built.doc?.subject?.kind !== "card-payment") continue;
    card.push({ id: v.id, r: await runVector({ ...v, build: async () => built }, dir) });
  }
});
after(() => rmSync(dir, { recursive: true, force: true }));

// Every string of a value, with its path.
function* strings(x, at = "") {
  if (typeof x === "string") yield [at, x];
  else if (Array.isArray(x)) for (let i = 0; i < x.length; i++) yield* strings(x[i], `${at}[${i}]`);
  else if (x && typeof x === "object") for (const [k, v] of Object.entries(x)) yield* strings(v, `${at}.${k}`);
}

// The walk can fail: a planted word deep in an output is found, "provenance" is not.
test("the walk finds a planted word in a nested string, and passes provenance", () => {
  const found = (x) => [...strings(x)].some(([, s]) => WORDS.some((w) => w.test(s)));
  assert.equal(found({ checks: [{ detail: "the payment was Proven" }] }), true);
  assert.equal(found({ limits: [{ text: "PAYMENT VERIFIED" }] }), true);
  assert.equal(found({ flags: [{ detail: "the record's provenance" }] }), false);
});

test("the vectors file has card-payment vectors, some with a stated charge", () => {
  assert.ok(card.length > 0);
  assert.ok(card.some((c) => c.r.status === 0 && c.r.output.stated.charge !== null));
});

test("no card vector's verdict is VERIFIES, VERIFIES-WITH-GAPS or VERIFIES-OUTSIDE-INSTRUCTION", () => {
  for (const { id, r } of card) if (r.status === 0) assert.ok(!VERIFIES.includes(r.output.verdict.code), `${id}: ${r.output.verdict.code}`);
});

test("with a stated charge, the verdict is one of table 4-6c's six codes, under rules C1 to C6", () => {
  for (const { id, r } of card) {
    if (r.status !== 0 || r.output.stated.charge === null) continue;
    assert.ok(CARD_CODES.includes(r.output.verdict.code), `${id}: ${r.output.verdict.code}`);
    assert.ok(CARD_RULES.includes(r.output.verdict.rule), `${id}: ${r.output.verdict.rule}`);
  }
});

test('no string of a card vector\'s output (verdict text, every detail, every limit text) says "proven" or "payment verified"', () => {
  for (const { id, r } of card) {
    const texts = r.status === 0 ? [...strings(r.output)] : [["stderr", r.stderr]];
    for (const [at, s] of texts) for (const w of WORDS) assert.doesNotMatch(s, w, `${id} ${at}`);
  }
});
