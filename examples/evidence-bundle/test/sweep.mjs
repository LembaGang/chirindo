// The WE-1 sweep of spec 4.8.3 (sweep.mjs), run in-process with --out a
// temporary path: 0 UNEXPECTED in steps 1 and 2, every change of step 3 gives
// FAILS, and the positions equal the committed we1/sweep-positions.json. The
// classifier is shown to class as UNEXPECTED what it must.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { getAddress } from "viem";
import { buildWe1 } from "../build-we1.mjs";
import { classify } from "../lib/coverage.mjs";
import { DEFAULT_OUT, positionsFile, summary, sweep } from "../sweep.mjs";

const ctx = { readLogs: [0, 1], txIndex: 10, usedKeyIndexes: [0], resolvedKeyIds: ["key_2026_v1"], carriedKids: [] };
const member = (id) => Buffer.from(buildWe1().members.find((m) => m.id === id).bytes_b64, "base64");
const edit = (b, from, to) => Buffer.from(b.toString("utf8").replace(from, to), "utf8");

test("the classifier: covered values are UNEXPECTED, listed ones listed, whitespace same-values", () => {
  const tx = member("tx-a");
  const rc = member("rc-a");
  assert.equal(classify({ key: "payment-transaction", origBytes: tx, nextBytes: edit(tx, '"hash": "0x30', '"hash": "0x31'), ctx }), "UNEXPECTED");
  assert.equal(classify({ key: "payment-transaction", origBytes: tx, nextBytes: edit(tx, '"gasPrice": "0x5b8d80"', '"gasPrice": "0x5b8d81"'), ctx }), "listed");
  assert.equal(classify({ key: "payment-transaction", origBytes: tx, nextBytes: edit(tx, '"v": "0x1"', '"w": "0x1"'), ctx }), "listed");
  assert.equal(classify({ key: "payment-transaction", origBytes: tx, nextBytes: edit(tx, '"from": "0xd', '"from": "0xD'), ctx }), "UNEXPECTED");
  const f = "0xd407e409e34e0b9afb99ecceb609bdbcd5e7f1bf";
  assert.equal(classify({ key: "payment-transaction", origBytes: tx, nextBytes: edit(tx, f, getAddress(f)), ctx }), "same-values");
  assert.equal(classify({ key: "payment-transaction", origBytes: tx, nextBytes: edit(tx, "{\n  ", "{\n\t "), ctx }), "same-values");
  assert.equal(classify({ key: "payment-receipt", origBytes: rc, nextBytes: edit(rc, '"logIndex": "0x4d"', '"logIndex": "0x4e"'), ctx }), "listed");
  assert.equal(classify({ key: "payment-receipt", origBytes: rc, nextBytes: edit(rc, '"status": "0x1"', '"status": "0x0"'), ctx }), "UNEXPECTED");
  assert.equal(classify({ key: "payment-receipt", origBytes: rc, nextBytes: edit(rc, '"gasUsed": "0x191dc"', '"gasUsec": "0x191dc"'), ctx }), "listed");
  assert.equal(classify({ key: "payment-receipt", origBytes: rc, nextBytes: edit(rc, '"status": "0x1"', '"statuS": "0x1"'), ctx }), "UNEXPECTED");
  const blk = member("blk-a");
  assert.equal(classify({ key: "payment-block", origBytes: blk, nextBytes: edit(blk, '"size": "0x711a"', '"size": "0x711b"'), ctx }), "listed");
  assert.equal(classify({ key: "payment-block", origBytes: blk, nextBytes: edit(blk, '"timestamp": "0x6ac8fcec"', '"timestamp": "0x6ac8fced"'), ctx }), "UNEXPECTED");
});

test("the WE-1 sweep: 0 UNEXPECTED in steps 1 and 2, every change of step 3 FAILS, positions as committed", async (t) => {
  const r = await sweep();
  for (const line of summary(r)) t.diagnostic(line);
  assert.equal(r.baseVerdict, "PAYMENT-NOT-VERIFIED");
  assert.equal(r.counts.step1.UNEXPECTED ?? 0, 0);
  assert.equal(r.counts.step2.UNEXPECTED ?? 0, 0);
  assert.deepEqual(Object.keys(r.counts.step3), ["FAILS"]);
  assert.ok(r.counts.step3.FAILS > 0);
  assert.ok(positionsFile(r).equals(readFileSync(DEFAULT_OUT)), "the positions equal we1/sweep-positions.json byte for byte");
});
