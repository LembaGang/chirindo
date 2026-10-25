// The online witness read for card subjects (W3-10; spec 4.2, 4.3 B-WIT and
// B-KEY, table 4-6c): `--online` through the library entry, every read
// answered by the fake of vectors/online-cases.mjs, so no test reads the
// network. That an evm-payment subject keeps the offline-only usage error is
// a regression test of test/cli.mjs.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import "../vectors/make-vectors.mjs";
import { JWKS_URI, ONLINE_CASES, WITNESS } from "../vectors/online-cases.mjs";

let dir;
let verifyBundle;
const runs = new Map();
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-online-"));
  ({ verifyBundle } = await import("../lib/verify.mjs"));
  for (const c of ONLINE_CASES) runs.set(c.id, await c.run(verifyBundle));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const out = (id) => {
  const r = runs.get(id);
  assert.equal(r.kind, "verdict", `${id}: ${r.code}`);
  return r.output;
};
const check = (o, id) => o.checks.find((c) => c.id === id);
const bind = (o, id) => o.bindings.find((b) => b.id === id);
const flags = (o) => o.flags.map((f) => f.code);
const limits = (o) => o.limits.map((l) => l.id);
// verdict.gaps lists each binding not BOUND (spec 690, E-16): for a card
// subject B-PAY and B-CHAIN, NOT-EVALUATED card-subject, are listed too.
// Table 4-6d's R reads only these bindings.
const CARD_SUBJECT = (binding) => ({ binding, state: "NOT-EVALUATED", reason: "card-subject" });
const R_BINDINGS = ["B-LOG", "B-CKP", "B-WIT", "B-KEY", "B-GRC"];
const rGaps = (o) => o.verdict.gaps.filter((g) => R_BINDINGS.includes(g.binding)).map((g) => g.binding);

test("V-72: V-10's bundle online, the witness's list holding its covering receipt: O1.witness-list PASS, B-WIT BOUND, B-KEY KEY-ONLY, RECORDED-WITH-GAPS (C6), its one gap B-KEY KEY-ONLY [spec]", () => {
  const o = out("V-72");
  assert.equal(o.mode, "online");
  assert.equal(check(o, "O1.witness-list").status, "PASS");
  assert.equal(bind(o, "B-WIT").state, "BOUND");
  assert.equal(bind(o, "B-KEY").state, "KEY-ONLY");
  assert.equal(o.verdict.code, "RECORDED-WITH-GAPS");
  assert.equal(o.verdict.rule, "C6");
  assert.deepEqual(o.verdict.gaps, [CARD_SUBJECT("B-PAY"), CARD_SUBJECT("B-CHAIN"), { binding: "B-KEY", state: "KEY-ONLY", reason: null }]);
  assert.deepEqual(rGaps(o), ["B-KEY"], "B-KEY is the one gap table 4-6d's R reads");
});

test("V-72: the witness read is GET only, the log's kid and session_id in the query, the endpoint listed with its registrable domain; L4 is not attached when every read completed [derived]", () => {
  const r = runs.get("V-72");
  assert.ok(r.fetch.calls.length >= 1);
  for (const c of r.fetch.calls) {
    assert.equal(c.init.method, "GET");
    assert.ok(c.url.startsWith(`${WITNESS}/v1/witness/checkpoints?kid=`), c.url);
    assert.ok(c.url.includes("session_id=test-card-1"), c.url);
  }
  const o = r.output;
  assert.deepEqual(o.endpoints.filter((e) => e.answered).map((e) => [e.service, e.url, e.registrable_domain]), [["witness", WITNESS, "headlessoracle.com"]]);
  assert.ok(!limits(o).includes("L4"));
  const rc = o.times.find((t) => /received_at/.test(t.what));
  assert.equal(rc.as_supplied, false, "received_at is not as supplied once B-WIT is BOUND");
  assert.equal(o.card.before_authorization, true);
});

test("V-73: V-11's bundle online, the same witness: B-WIT BOUND, B-INS EXCEEDS, OUTSIDE-INSTRUCTION (C4) [spec]", () => {
  const o = out("V-73");
  assert.equal(bind(o, "B-WIT").state, "BOUND");
  assert.equal(bind(o, "B-INS").state, "EXCEEDS");
  assert.equal(o.verdict.code, "OUTSIDE-INSTRUCTION");
  assert.equal(o.verdict.rule, "C4");
});

test("V-74: records naming the examples' jwks_uri, its JWKS carried; offline B-KEY SUPPLIED; online, the host answering 404, O3.jwks and B-KEY NOT-EVALUATED online-read-failed, RECORDED-WITH-GAPS (C6), its one gap B-KEY [spec]", async () => {
  const off = await ONLINE_CASES.find((c) => c.id === "V-74").run(verifyBundle, { online: false });
  assert.equal(off.output.mode, "offline");
  assert.equal(bind(off.output, "B-KEY").state, "SUPPLIED");
  const o = out("V-74");
  assert.equal(check(o, "O3.jwks").status, "NOT-EVALUATED");
  assert.equal(check(o, "O3.jwks").reason, "online-read-failed");
  assert.equal(bind(o, "B-KEY").state, "NOT-EVALUATED");
  assert.equal(bind(o, "B-KEY").reason, "online-read-failed");
  assert.equal(o.verdict.code, "RECORDED-WITH-GAPS");
  assert.equal(o.verdict.rule, "C6");
  assert.deepEqual(o.verdict.gaps, [CARD_SUBJECT("B-PAY"), CARD_SUBJECT("B-CHAIN"), { binding: "B-KEY", state: "NOT-EVALUATED", reason: "online-read-failed" }]);
  assert.deepEqual(rGaps(o), ["B-KEY"], "B-KEY is the one gap table 4-6d's R reads");
  assert.ok(limits(o).includes("L4"), "an online read did not complete");
  assert.ok(runs.get("V-74").fetch.calls.some((c) => c.url === JWKS_URI && c.init.method === "GET"));
});

test("V-75: V-74 with the host serving pages/evidence-examples-jwks.json: O3.jwks PASS, B-KEY BOUND, RECORDED-BEFORE-CHARGE (C5, table 4-6d row 8) [spec]", () => {
  const o = out("V-75");
  assert.equal(check(o, "O3.jwks").status, "PASS");
  assert.equal(bind(o, "B-KEY").state, "BOUND");
  assert.equal(o.verdict.code, "RECORDED-BEFORE-CHARGE");
  assert.equal(o.verdict.rule, "C5");
  // spec 690 and E-16: each binding not BOUND, also with RECORDED-BEFORE-CHARGE.
  assert.deepEqual(o.verdict.gaps, [CARD_SUBJECT("B-PAY"), CARD_SUBJECT("B-CHAIN")]);
  assert.deepEqual(rGaps(o), []);
  assert.ok(!limits(o).includes("L4"));
  assert.deepEqual(o.endpoints.filter((e) => e.answered).map((e) => [e.service, e.registrable_domain]), [["witness", "headlessoracle.com"], ["jwks", "headlessoracle.com"]]);
});

test("V-76: the witness's list not read to its end: O1.witness-list NOT-EVALUATED online-read-failed, B-WIT SUPPLIED with online-check-incomplete, PAYMENT-NOT-VERIFIED (C3, offline-witness-data) [derived; spec B-WIT rule 4, ruling V-1]", () => {
  const o = out("V-76");
  assert.equal(check(o, "O1.witness-list").status, "NOT-EVALUATED");
  assert.equal(check(o, "O1.witness-list").reason, "online-read-failed");
  assert.equal(bind(o, "B-WIT").state, "SUPPLIED");
  assert.ok(flags(o).includes("online-check-incomplete"));
  assert.equal(o.verdict.code, "PAYMENT-NOT-VERIFIED");
  assert.equal(o.verdict.reason, "offline-witness-data");
  assert.ok(limits(o).includes("L4"));
});

test("V-77: the list read to its end lacks the carried receipt: B-WIT SUPPLIED with witness-list-inconsistent, never FAIL, PAYMENT-NOT-VERIFIED (C3) [derived; spec B-WIT rule 4]", () => {
  const o = out("V-77");
  assert.equal(check(o, "O1.witness-list").status, "PASS");
  assert.equal(bind(o, "B-WIT").state, "SUPPLIED");
  assert.ok(flags(o).includes("witness-list-inconsistent"));
  assert.equal(o.verdict.code, "PAYMENT-NOT-VERIFIED");
});

test("V-78: B-WIT TRUNCATED online with the list not read to its end: PAYMENT-NOT-VERIFIED (offline-witness-data), never RECORDED-WITH-GAPS or OUTSIDE-INSTRUCTION [spec 1302, ruling V-1]", () => {
  const o = out("V-78");
  // What only the online read gives: the mode, O1's state and the incomplete-read flag.
  assert.equal(o.mode, "online");
  assert.equal(check(o, "O1.witness-list").status, "NOT-EVALUATED");
  assert.equal(check(o, "O1.witness-list").reason, "online-read-failed");
  assert.ok(flags(o).includes("online-check-incomplete"));
  assert.equal(bind(o, "B-WIT").state, "TRUNCATED");
  assert.equal(o.verdict.code, "PAYMENT-NOT-VERIFIED");
  assert.equal(o.verdict.reason, "offline-witness-data");
});

test("V-79: a listed receipt at a count within the log with another last_entry_hash (a rewrite after witnessing): B-WIT FAIL, FAILS [derived; spec B-WIT rule 1]", () => {
  const o = out("V-79");
  assert.equal(bind(o, "B-WIT").state, "FAIL");
  assert.equal(o.verdict.code, "FAILS");
});
