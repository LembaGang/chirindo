// The vectors of vectors/evidence-bundle-0.9.json: each is regenerated from
// its recipe and run; the projection must equal the committed file, a fresh
// --write must give the committed bytes, and each vector's expected values
// are asserted on the parsed output.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { getAddress } from "viem";
import { ADDRESS_FLIPS, expectedOf, fileBytes, FOLDER, runVector, VECTOR_FILE, VECTORS } from "../vectors/make-vectors.mjs";

const a = "0xe65e3de1493171dcf0a706a3f407d7ddb38c5673";
let dir;
const runs = new Map();
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-vec-"));
  for (const v of VECTORS) runs.set(v.id, runVector(v, dir));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const out = (id) => {
  const r = runs.get(id);
  assert.equal(r.status, 0, `${id}: ${r.stderr}`);
  return r.output;
};
const check = (o, id, member = null) => o.checks.find((x) => x.id === id && x.member === member);
const bind = (o, id) => o.bindings.find((b) => b.id === id);
const verdict = (o) => [o.verdict.code, o.verdict.rule];

test("the committed vector file lists every vector, in order", () => {
  const committed = JSON.parse(readFileSync(VECTOR_FILE, "utf8"));
  assert.deepEqual(
    committed.vectors.map((v) => v.id),
    VECTORS.map((v) => v.id),
  );
});

for (const v of VECTORS) {
  test(`${v.id}: the committed projection is this run's`, () => {
    const c = JSON.parse(readFileSync(VECTOR_FILE, "utf8")).vectors.find((x) => x.id === v.id);
    assert.deepEqual(c.recipe, v.recipe);
    assert.deepEqual(c.args, v.args);
    assert.equal(c.mode, "offline");
    assert.deepEqual(c.expected, expectedOf(runs.get(v.id)));
  });
}

test("a fresh --write gives the committed bytes", () => {
  const tmp = path.join(dir, "fresh.json");
  const r = spawnSync(process.execPath, [path.join(FOLDER, "vectors", "make-vectors.mjs"), "--write", tmp], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(readFileSync(tmp).equals(readFileSync(VECTOR_FILE)));
  assert.ok(fileBytes(JSON.parse(readFileSync(VECTOR_FILE, "utf8"))).equals(readFileSync(VECTOR_FILE)));
});

test("R-01 to R-06 (asserted whole in test/we1.mjs): verdicts", () => {
  assert.deepEqual([...verdict(out("R-01")), out("R-01").verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data"]);
  assert.deepEqual([...verdict(out("R-02")), out("R-02").verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "authorizer-not-stated"]);
  assert.deepEqual(verdict(out("R-03")), ["DOES-NOT-CONNECT", "V2"]);
  assert.deepEqual(verdict(out("R-04")), ["FAILS", "V1"]);
  assert.equal(check(out("R-04"), "S2.tx").status, "FAIL");
  assert.deepEqual([...verdict(out("R-05")), out("R-05").verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data"]);
  assert.deepEqual([...verdict(out("R-06")), out("R-06").verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "tx-not-stated"]);
});

test("R-07: usage errors exit 2 with nothing on stdout and one line on stderr", () => {
  for (const v of VECTORS.filter((x) => x.id.startsWith("R-07"))) {
    const r = runs.get(v.id);
    assert.equal(r.status, 2, v.id);
    assert.equal(r.stdout, "", v.id);
    assert.equal(r.stderr.trim().split("\n").length, 1, v.id);
    assert.match(r.stderr, /^usage error: /, v.id);
  }
});

test("R-08: a subject that names expected_authorizer FAILs M0", () => {
  const o = out("R-08");
  const m0 = check(o, "M0.bundle");
  assert.equal(m0.status, "FAIL");
  assert.equal(m0.detail, "the account the payment must come from is stated by the person running the verifier, never by the bundle");
  assert.deepEqual(verdict(o), ["FAILS", "V1"]);
});

test("R-09: a carried_as claim the transaction does not bear out FAILs B-PAY", () => {
  for (const id of ["R-09a", "R-09b"]) {
    const o = out(id);
    assert.equal(bind(o, "B-PAY").state, "FAIL", id);
    assert.deepEqual(verdict(o), ["FAILS", "V1"], id);
  }
});

test("R-10: Case B's DENY record cited by a payment that does not carry its hash, claim none", () => {
  const o = out("R-10");
  const rec = o.decision.record;
  assert.equal(bind(o, "B-PAY").state, "ABSENT");
  assert.equal(o.decision.value, "refuse");
  assert.deepEqual([rec.event_decision, rec.event_outcome, rec["gate_result"]], ["deny", "denied", "halt"]);
  assert.deepEqual(verdict(o), ["DOES-NOT-CONNECT", "V2"]);
  assert.deepEqual(o.hash_search.matches, []);
});

test("R-11: the same with the claim eip3009-nonce FAILs", () => {
  const o = out("R-11");
  assert.equal(bind(o, "B-PAY").state, "FAIL");
  assert.equal(o.verdict.code, "FAILS");
});

test("R-12: both logs, Case B's record cited", () => {
  const o = out("R-12");
  const f = o.flags.filter((x) => x.code === "other-entry-hash");
  assert.equal(f.length, 1);
  assert.match(f[0].detail, /^log-a record 0:/);
  assert.equal(bind(o, "B-PAY").state, "ABSENT");
  assert.equal(o.verdict.code, "DOES-NOT-CONNECT");
  assert.equal(o.decision.value, "refuse");
  assert.deepEqual(o.decision.refusing_records, []);
});

test("R-13: a token the pins do not name", () => {
  const o = out("R-13");
  assert.deepEqual([check(o, "M5.token-domain").status, check(o, "M5.token-domain").reason], ["NOT-EVALUATED", "token-not-pinned"]);
  for (const [id, m] of [["M5.authorization", "tx-a"], ["M5.token-logs", "rc-a"], ["M5.validity-window", null]]) assert.deepEqual([check(o, id, m).status, check(o, id, m).reason], ["NOT-EVALUATED", "prerequisite-failed:M5.token-domain"], id);
  assert.deepEqual([bind(o, "B-PAY").state, bind(o, "B-PAY").reason], ["NOT-EVALUATED", "token-not-pinned"]);
  assert.deepEqual([...verdict(o), o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "token-not-pinned"]);
});

test("R-14: a witness receipt under a key id neither pinned nor carried", () => {
  const o = out("R-14");
  assert.deepEqual([check(o, "M4.witness-receipt", "sidecar-a").status, check(o, "M4.witness-receipt", "sidecar-a").reason], ["NOT-EVALUATED", "witness-key-unknown"]);
  assert.deepEqual([bind(o, "B-WIT").state, bind(o, "B-WIT").reason], ["NOT-EVALUATED", "witness-key-unknown"]);
  // A receipt key id the carried witness-key member lacks: not evaluated, never PASS or FAIL.
  assert.deepEqual([check(o, "M9.witness-key", "wkey").status, check(o, "M9.witness-key", "wkey").reason], ["NOT-EVALUATED", "witness-key-unknown"]);
  assert.deepEqual([...verdict(o), o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data"]);
});

test("R-15: the legacy kid", () => {
  const o = out("R-15");
  assert.deepEqual([check(o, "M2.log", "log-l").status, check(o, "M2.log", "log-l").reason], ["NOT-EVALUATED", "legacy-kid"]);
  assert.deepEqual([bind(o, "B-LOG").state, bind(o, "B-LOG").reason], ["NOT-EVALUATED", "legacy-kid"]);
  // evidence.action/0 records: the absent iss and key_thumbprint are flagged, never FAIL.
  const f = o.flags.filter((x) => x.code === "legacy-fields-absent");
  assert.equal(f.length, 1);
  assert.match(f[0].detail, /iss/);
  assert.match(f[0].detail, /key_thumbprint/);
  assert.ok(!o.checks.some((c) => c.status === "FAIL"));
  for (const b of o.bindings.filter((x) => x.id !== "B-LOG")) assert.deepEqual([b.state, b.reason], ["NOT-EVALUATED", "prerequisite-failed:B-LOG"], b.id);
  assert.deepEqual([...verdict(o), o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "prerequisite-failed:B-LOG"]);
});

test("R-16: a card subject", () => {
  const o = out("R-16");
  for (const id of ["B-PAY", "B-CHAIN"]) assert.deepEqual([bind(o, id).state, bind(o, id).reason], ["NOT-EVALUATED", "card-subject"], id);
  assert.deepEqual([...verdict(o), o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "card-subject"]);
  assert.ok(!o.checks.some((c) => c.id === "S1.authorizer" || c.id === "S2.tx"));
  assert.ok(o.limits.some((l) => l.id === "L17"));
  assert.equal(o.hash_search, null);
});

test("R-17: an address with one letter's case changed", () => {
  ADDRESS_FLIPS.forEach(([, , addr], k) => {
    const id = `R-17${"abcdef"[k]}`;
    const o = out(id);
    const changed = runs.get(id).built.changed;
    // FAILS, unless the changed spelling is the address's EIP-55 form (spec 4.1).
    if (changed === getAddress(addr)) assert.equal(o.verdict.code, out("R-01").verdict.code, id);
    else assert.deepEqual(verdict(o), ["FAILS", "V1"], id);
  });
  // The block's miner has no letter, so it is not changed.
  assert.ok(!/[a-f]/.test("0x4200000000000000000000000000000000000011".slice(2)));
});

test("R-18: a jcs-json spelling that parses to the same value", () => {
  const o = out("R-18");
  const r01 = out("R-01");
  assert.equal(check(o, "M8.arguments", "args-a").status, "PASS");
  assert.deepEqual([...verdict(o), o.verdict.reason], [...verdict(r01), r01.verdict.reason]);
  assert.deepEqual(o.bindings.map((b) => b.state), r01.bindings.map((b) => b.state));
});

test("no offline vector gives a verdict that contains VERIFIES (spec 4.6, the offline rule)", () => {
  for (const [id, r] of runs) if (r.status === 0) assert.ok(!["VERIFIES", "VERIFIES-WITH-GAPS", "VERIFIES-OUTSIDE-INSTRUCTION"].includes(r.output.verdict.code), id);
  assert.equal(a, out("R-01").payment.payer);
});
