// The adopted errata of spec v0.10, section 11, that no other test asserts
// (handoff C6): one test per erratum, named by its number, each asserting the
// erratum's value as section 11 states it, on a committed vector or on WE-1
// changed as the test says. The errata other tests assert are listed in the
// A3a report with those tests' names.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { jcsSha256 } from "../../ordering-evidence-h4/lib/formats.mjs";
// make-vectors.mjs first: it and rows-a3.mjs import each other.
import { FOLDER, runCli, runVector, VECTORS } from "../vectors/make-vectors.mjs";
import { add, addTestLog, stated, we1Parts } from "../vectors/refusal-cases.mjs";
import { annexBCase, addReceipts, PERMIT, pinsFor, withPins } from "../vectors/rows-a2.mjs";
import { annexBLog, gateReceipt, issuerProfile, json, jwksOf, testAccount, testEd, testSecp, testWitnessEntry, witnessReceipt } from "../vectors/synth.mjs";
import { CASES } from "../vectors/refusal-cases.mjs";

const WE1_STATED = ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"];
let dir;
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-errata-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const runs = new Map();
const vec = async (id) => {
  if (!runs.has(id)) runs.set(id, await runVector(VECTORS.find((v) => v.id === id), dir));
  const r = runs.get(id);
  assert.equal(r.status, 0, `${id}: ${r.stderr}`);
  return r.output;
};
const check = (o, id, member) => o.checks.find((c) => c.id === id && (member === undefined || c.member === member));
const bind = (o, id) => o.bindings.find((b) => b.id === id);
const memberJson = (doc, id) => JSON.parse(Buffer.from(doc.members.find((m) => m.id === id).bytes_b64, "base64").toString("utf8"));
// WE-1 with one member replaced by `bytes` (its digest recomputed), or left out.
function we1With(id, bytes) {
  const { doc } = we1Parts();
  const i = doc.members.findIndex((m) => m.id === id);
  const old = doc.members[i];
  doc.members.splice(i, 1);
  if (bytes) add(doc, { id, role: old.role, profile: old.profile, bytes, media_type: old.media_type });
  return doc;
}
const cli = (name, doc, args = WE1_STATED, o = {}) => {
  const r = runCli(dir, name, doc, args, o);
  assert.equal(r.status, 0, `${name}: ${r.stderr}`);
  return r.output;
};

test("E-13: after a check FAILs, the other bindings are NOT EVALUATED on the first FAIL, the decision not-read, hash_search null, payment.reason that code [spec, v0.10 section 11]", async () => {
  // R-04: S2.tx FAILs before M2, so B-LOG too is not evaluated on it.
  const o = await vec("R-04");
  for (const b of o.bindings) assert.deepEqual([b.state, b.reason], ["NOT-EVALUATED", "prerequisite-failed:S2.tx"], b.id);
  assert.deepEqual(o.decision, { value: "not-read", record: null, receipt: null, refusing_records: [] });
  assert.equal(o.hash_search, null);
  assert.equal(o.payment.reason, "prerequisite-failed:S2.tx");
  // SA-08: M6.instruction FAILs after M2 ran, so B-LOG keeps its own rule.
  const s = await vec("SA-08");
  assert.equal(bind(s, "B-LOG").state, "BOUND");
  for (const b of s.bindings.filter((x) => x.id !== "B-LOG")) assert.deepEqual([b.state, b.reason], ["NOT-EVALUATED", "prerequisite-failed:M6.instruction"], b.id);
  assert.equal(s.decision.value, "not-read");
  assert.equal(s.decision.record, null);
  assert.equal(s.hash_search, null);
  assert.equal(s.payment.reason, "prerequisite-failed:M6.instruction");
});

test("E-14: when B-LOG is not BOUND, the cited decision is not-read with record null [spec, v0.10 section 11]", async () => {
  const o = await vec("R-15");
  assert.equal(bind(o, "B-LOG").state, "NOT-EVALUATED");
  assert.deepEqual([o.decision.value, o.decision.record], ["not-read", null]);
});

test("E-15: hash_search is null when B-PAY stops at rule 1 [spec, v0.10 section 11]", async () => {
  const o = await vec("R-15");
  assert.deepEqual([bind(o, "B-PAY").state, bind(o, "B-PAY").reason], ["NOT-EVALUATED", "prerequisite-failed:B-LOG"]);
  assert.equal(o.hash_search, null);
});

test("E-16: verdict.gaps is empty for FAILS; otherwise each binding not BOUND, B-GRC ABSENT with a null reason excepted [spec, v0.10 section 11]", async () => {
  assert.deepEqual((await vec("R-04")).verdict.gaps, []);
  const o = await vec("R-01");
  const want = o.bindings.filter((b) => b.state !== "BOUND" && !(b.id === "B-GRC" && b.state === "ABSENT" && b.reason === null)).map((b) => ({ binding: b.id, state: b.state, reason: b.reason }));
  assert.ok(want.length > 0);
  assert.equal(bind(o, "B-GRC").state, "ABSENT");
  assert.deepEqual(o.verdict.gaps, want);
});

test("E-17: expected_authorizer's reason is in M0.bundle's detail, its reason null [spec, v0.10 section 11]", async () => {
  const m0 = check(await vec("R-08"), "M0.bundle");
  assert.deepEqual([m0.status, m0.reason], ["FAIL", null]);
  assert.match(m0.detail, /stated by the person running the verifier/);
});

test("E-18: payment members missing in an offline run FAIL at M1.manifest; M5.chain's step 0 FAIL is not reached [spec, v0.10 section 11]", () => {
  const o = cli("e18", we1With("tx-a", null));
  assert.equal(check(o, "M1.manifest").status, "FAIL");
  assert.ok(!o.checks.some((c) => c.id === "M5.chain" && c.status === "FAIL"));
  assert.equal(o.verdict.code, "FAILS");
});

test("E-19: M1's counts compare with the ids that can be read; a member that cannot be read is left to its own check [spec, v0.10 section 11]", () => {
  const o = cli("e19", we1With("wkey", Buffer.from("TEST: not a key document")));
  assert.equal(check(o, "M1.manifest").status, "PASS");
  assert.equal(check(o, "M9.witness-key", "wkey").status, "FAIL");
});

test("E-20: M5.receipt and M5.block run whatever M5.chain found; M5.support needs M5.chain; M5.call needs M5.transaction; step 5 listed for a recognised call when M5.support is NOT EVALUATED [spec, v0.10 section 11]", async () => {
  const tx = memberJson(we1Parts().doc, "tx-a");
  // WE-1 with another chain id: M5.chain FAILs, M5.receipt and M5.block still run, M5.support is not evaluated on it.
  const a = cli("e20a", we1With("tx-a", json({ ...tx, chainId: "0x1" })));
  assert.equal(check(a, "M5.chain", "tx-a").status, "FAIL");
  for (const [id, m] of [["M5.receipt", "rc-a"], ["M5.block", "blk-a"]]) assert.ok(["PASS", "FAIL"].includes(check(a, id, m).status), id);
  assert.deepEqual([check(a, "M5.support").status, check(a, "M5.support").reason], ["NOT-EVALUATED", "prerequisite-failed:M5.chain"]);
  // WE-1 with a signed field changed: M5.transaction FAILs, so M5.call and step 5 are not evaluated on it.
  const b = cli("e20b", we1With("tx-a", json({ ...tx, gas: "0x" + (BigInt(tx.gas) + 1n).toString(16) })));
  assert.equal(check(b, "M5.transaction", "tx-a").status, "FAIL");
  assert.deepEqual([check(b, "M5.call", "tx-a").status, check(b, "M5.call", "tx-a").reason], ["NOT-EVALUATED", "prerequisite-failed:M5.transaction"]);
  // T-20, type 0x3: M5.support NOT EVALUATED (unsupported-type), the recognised call's step 5 rows listed.
  const t20 = CASES.find((c) => c.id === "T-20");
  const { doc, args } = await t20.build();
  const c = cli("e20c", doc, args);
  assert.deepEqual([check(c, "M5.support").status, check(c, "M5.support").reason], ["NOT-EVALUATED", "unsupported-type"]);
  for (const id of ["M5.call", "M5.token-domain", "M5.authorization", "M5.token-logs", "M5.validity-window"]) assert.deepEqual([check(c, id).status, check(c, id).reason], ["NOT-EVALUATED", "prerequisite-failed:M5.support"], id);
});

test("E-21 (and E-4): two-clock-comparison once per comparison: three in WE-1 [spec, v0.10 section 11]", async () => {
  const f = (await vec("R-01")).flags.filter((x) => x.code === "two-clock-comparison");
  assert.equal(f.length, 3);
  assert.ok(f.some((x) => /cited entry's ts/.test(x.detail) && /block timestamp/.test(x.detail)));
  assert.ok(f.some((x) => /checkpoint's ts/.test(x.detail) && /received_at/.test(x.detail)));
  assert.ok(f.some((x) => /received_at/.test(x.detail) && /block timestamp/.test(x.detail)));
});

test("E-22: payment.reason is B-PAY's reason, no-payer-derived when it has none, card-subject for a card subject [spec, v0.10 section 11]", async () => {
  const r02 = await vec("R-02");
  assert.equal(r02.payment.reason, bind(r02, "B-PAY").reason);
  const r03 = await vec("R-03");
  assert.deepEqual([bind(r03, "B-PAY").state, bind(r03, "B-PAY").reason, r03.payment.reason], ["CARRIED-BY-OTHER", null, "no-payer-derived"]);
  assert.equal((await vec("R-16")).payment.reason, "card-subject");
});

test("E-23: a JWKS that holds no carried log's key FAILs M9.operator-key [spec, v0.10 section 11]", () => {
  const o = cli("e23", we1With("opkey-a", jwksOf(testEd("errata other operator"))));
  assert.equal(check(o, "M9.operator-key", "opkey-a").status, "FAIL");
  assert.equal(o.verdict.code, "FAILS");
});

test("E-24: with more than one receipt key id, a witness-key member lacking one is NOT EVALUATED witness-key-unknown [spec, v0.10 section 11]", () => {
  const { doc } = we1Parts();
  const line = JSON.parse(Buffer.from(doc.members.find((m) => m.id === "sidecar-a").bytes_b64, "base64").toString("utf8").split("\n")[0]);
  // A second receipt for the same checkpoint, under the TEST witness key, which wkey does not hold, and
  // a second witness-key member holding only that key (table 3-1: one member per distinct key id).
  add(doc, { id: "wr-e24", role: "witness-receipt", profile: "witness.checkpoint/1", bytes: json(witnessReceipt({ cp: line.checkpoint, receivedAt: line.witness_receipt.received_at })) });
  add(doc, { id: "wkey-e24", role: "witness-key", profile: "ho-v5-keys", bytes: json({ keys: [testWitnessEntry()] }) });
  const o = cli("e24", doc);
  assert.equal(check(o, "M1.manifest").status, "PASS");
  for (const m of ["wkey", "wkey-e24"]) assert.deepEqual([check(o, "M9.witness-key", m).status, check(o, "M9.witness-key", m).reason], ["NOT-EVALUATED", "witness-key-unknown"], m);
});

test("E-25: records_without_arguments counts records naming an arguments hash no member matches, not a record that names none [spec, v0.10 section 11]", async () => {
  const v = VECTORS.find((x) => x.id === "V-10");
  const built = await v.build();
  addTestLog(built.doc, { label: "e25a", sessionId: "test-e25-a", argsHash: jcsSha256({ test: "arguments the bundle does not carry" }) });
  // An Annex B log whose record names no arguments hash: not counted.
  const k = testEd("errata e25b");
  add(built.doc, { id: "log-e25b", role: "gate-log", profile: "jcs-sha256-chain/0.1", bytes: annexBLog({ k, sessionId: "test-e25-b" }).bytes, media_type: "application/x-ndjson" });
  add(built.doc, { id: "opkey-e25b", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
  const o = cli("e25", built.doc, v.args, { pins: built.pins });
  const i = o.instructions.find((x) => x.member === "ins-d");
  assert.equal(i.records_without_arguments, 1);
});

test("E-26: with B-INS BOUND, the instruction's iat against the cited entry's ts is flagged two-clock-comparison [spec, v0.10 section 11]", async () => {
  const o = await vec("SA-01");
  assert.equal(bind(o, "B-INS").state, "BOUND");
  assert.ok(o.flags.some((f) => f.code === "two-clock-comparison" && /iat/.test(f.detail) && /cited entry's ts/.test(f.detail)));
  assert.ok(!o.flags.some((f) => f.code === "clock-contradiction"));
});

test("E-27: when the bindings are not computed, each instruction is listed, FAIL when its M6 failed, uses 0 and records_without_arguments 0 [spec, v0.10 section 11]", async () => {
  const o = await vec("SA-08");
  assert.ok(o.instructions.length > 0);
  for (const i of o.instructions) {
    assert.equal(i.state, "FAIL", i.member);
    assert.deepEqual([i.uses, i.records_without_arguments], [0, 0], i.member);
  }
});

test("E-28: gate_receipts is empty when the bindings are not computed [spec, v0.10 section 11]", async () => {
  const o = await vec("S-87");
  assert.equal(o.verdict.code, "FAILS");
  assert.deepEqual(o.gate_receipts, []);
});

test("E-29: at_or_before_cited is null for a receipt whose record is in another log than the cited record [spec, v0.10 section 11]", async () => {
  const g1 = await gateReceipt(testSecp("issuer"), { action: "cited test action" });
  const g0 = await gateReceipt(testSecp("issuer"), { action: "test action of another log" });
  const c = await annexBCase({ log: { receiptUid: g1.uid } });
  const bytes = addReceipts(c.doc, [{ id: "gr-t", gr: g1 }, { id: "gr-o", gr: g0 }]);
  addTestLog(c.doc, { label: "e29", sessionId: "test-e29", argsHash: jcsSha256({ test: "e29 arguments" }), receiptUids: [g0.uid] });
  const o = cli("e29", c.doc, withPins(stated(c.p.tx.hash)), { pins: pinsFor([{ bytes, ...PERMIT }]) });
  const g = o.gate_receipts.find((x) => x.member === "gr-o");
  assert.ok(g, "gr-o is reported");
  assert.equal(g.log, "log-e29");
  assert.equal(g.at_or_before_cited, null);
});

test("E-30: the cited entry carried again in a prefix of its log is not flagged other-entry-hash [spec, v0.10 section 11]", async () => {
  assert.ok(!(await vec("SA-14")).flags.some((f) => f.code === "other-entry-hash"));
});

test("E-31: an issuer profile whose tokens list is empty is refused by M9.issuer-profile [spec, v0.10 section 11]", async () => {
  const gr = await gateReceipt(testSecp("issuer"));
  const c = await annexBCase({ log: { receiptUid: gr.uid } });
  const bytes = json({ ...issuerProfile(testAccount("issuer").address), tokens: [] });
  add(c.doc, { id: "ip-t", role: "issuer-profile", profile: "chirindo-h4-issuer-profile/1", bytes });
  add(c.doc, { id: "gr-t", role: "gate-receipt", profile: "eip712-gate-receipt/0.1", issuer_profile: "ip-t", bytes: json(gr.sealed) });
  const o = cli("e31", c.doc, stated(c.p.tx.hash));
  assert.equal(check(o, "M9.issuer-profile", "ip-t").status, "FAIL");
});

test("E-32: issuer profile pins: sha256 of 64 lowercase hex digits, permit and refuse lists of strings; provenance carried and read by no check [spec, v0.10 section 11]", () => {
  const pins = JSON.parse(readFileSync(path.join(FOLDER, "pins", "pins.json"), "utf8"));
  const { doc } = we1Parts();
  const usage = (name, ip) => {
    const r = runCli(dir, name, doc, ["--pins", "<pins>"], { pins: { ...pins, issuer_profiles: [ip] } });
    assert.equal(r.status, 2, name);
    assert.match(r.stderr, /^usage error: invalid pins/, name);
  };
  usage("e32a", { sha256: "A".repeat(64), permit: [], refuse: [] });
  usage("e32b", { sha256: "a".repeat(63), permit: [], refuse: [] });
  usage("e32c", { sha256: "a".repeat(64), permit: "allow", refuse: [] });
  usage("e32d", { sha256: "a".repeat(64), permit: [1], refuse: [] });
  const fine = runCli(dir, "e32e", doc, ["--pins", "<pins>"], { pins: { ...pins, issuer_profiles: [{ sha256: "a".repeat(64), label: "TEST", permit: ["allow"], refuse: ["deny"], values_source: { url: "TEST", label: "TEST", fetched_at: null, sha256: null } }] } });
  assert.equal(fine.status, 0);
});

test("E-33: a context receipt's own state is judged against the payment block's time and reported; it never changes B-GRC's state [spec, v0.10 section 11]", async () => {
  const o = await vec("S-84");
  const g0 = o.gate_receipts.find((g) => g.member === "gr-t0");
  const g1 = o.gate_receipts.find((g) => g.member === "gr-t1");
  assert.deepEqual([g0.cited, g0.state], [false, "EXCEEDS"]);
  assert.equal(g1.cited, true);
  assert.equal(bind(o, "B-GRC").state, g1.state);
  assert.notEqual(bind(o, "B-GRC").state, "EXCEEDS");
});

test("E-34: an Annex B cited record's decision members are reported as written; the decision is read only from the cited receipt under a pinned profile [spec, v0.10 section 11]", async () => {
  const s66 = await vec("S-66");
  const rec = s66.decision.record;
  assert.deepEqual([rec.event_decision, rec.event_outcome, rec.gate_result], [null, null, null]);
  assert.equal(s66.decision.value, "not-read");
  const s67 = await vec("S-67");
  assert.deepEqual([s67.decision.value, s67.decision.receipt.member], ["allow", "gr-t"]);
});
