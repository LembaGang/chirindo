// The vectors of vectors/evidence-bundle-0.10.json: each is regenerated from
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
import { ADDRESS_FLIPS, expectedOf, fileBytes, FOLDER, runCli, runVector, VECTOR_FILE, VECTORS } from "../vectors/make-vectors.mjs";
import { testAccount, testAddress } from "../vectors/synth.mjs";

const a = "0xe65e3de1493171dcf0a706a3f407d7ddb38c5673";
let dir;
const runs = new Map();
before(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-vec-"));
  for (const v of VECTORS) runs.set(v.id, await runVector(v, dir));
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
    assert.deepEqual(c.args, runs.get(v.id).args);
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

// The vectors of the widened shape (vectors/rows-a2.mjs). Each row's values
// are asserted as the specification states them (`spec`, with the lines that
// state them) and as this build derives them where it is silent (`derived`).
// An expectation names: exit (2 with nothing on stdout), verdict [code, rule,
// reason], bindings {id: [state, reason]}, checks [[id, member, status,
// reason]], decision (its value), flags and limits that must be present
// (flagsHave, limitsHave) or absent (flagsLack, limitsLack), instructions
// {member: [state, exceeded, reason]}, gateReceipts {member: [state,
// reason, flags, cited]}, movements that must be reported (movementsHave,
// [asset, amount, payee, source]), the payer (payer: an address or null),
// B-PAY's signed_by (signedBy), and the records the cited decision names as
// refusing (refusing: [[log, seq, source]]), and the matches hash_search names
// (searchHas: [[field, form]]); a verdict it must not be (verdictNot), and
// checks that must not be listed (checksLack).
function expectRow(id, e) {
  const r = runs.get(id);
  if (e.exit !== undefined) {
    assert.equal(r.status, e.exit, `${id}: ${r.stderr}`);
    assert.equal(r.stdout, "");
    return;
  }
  const o = out(id);
  if (e.verdict) assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason].slice(0, e.verdict.length), e.verdict, `${id} verdict`);
  if (e.verdictNot) assert.notEqual(o.verdict.code, e.verdictNot, `${id} verdict`);
  for (const cid of e.checksLack ?? []) assert.ok(!o.checks.some((c) => c.id === cid), `${id}: ${cid} is not listed`);
  for (const [b, [state, reason]] of Object.entries(e.bindings ?? {})) {
    assert.equal(bind(o, b).state, state, `${id} ${b} state`);
    if (reason !== undefined) assert.equal(bind(o, b).reason, reason, `${id} ${b} reason`);
  }
  for (const [cid, member, status, reason] of e.checks ?? []) {
    const c = check(o, cid, member);
    assert.ok(c, `${id}: ${cid} on ${member} is listed`);
    assert.equal(c.status, status, `${id} ${cid} on ${member}: ${c.detail}`);
    if (reason !== undefined) assert.equal(c.reason, reason, `${id} ${cid} on ${member} reason`);
  }
  if (e.decision) assert.equal(o.decision.value, e.decision, `${id} decision`);
  for (const f of e.flagsHave ?? []) assert.ok(o.flags.some((x) => x.code === f), `${id}: flag ${f}`);
  for (const f of e.flagsLack ?? []) assert.ok(!o.flags.some((x) => x.code === f), `${id}: no flag ${f}`);
  for (const l of e.limitsHave ?? []) assert.ok(o.limits.some((x) => x.id === l), `${id}: limit ${l}`);
  for (const l of e.limitsLack ?? []) assert.ok(!o.limits.some((x) => x.id === l), `${id}: no limit ${l}`);
  for (const [m, [state, exceeded, reason]] of Object.entries(e.instructions ?? {})) {
    const i = o.instructions.find((x) => x.member === m);
    assert.ok(i, `${id}: instruction ${m} is reported`);
    assert.deepEqual([i.state, i.exceeded, i.reason], [state, exceeded, reason], `${id} instruction ${m}`);
  }
  for (const [m, [state, reason, flags, cited]] of Object.entries(e.gateReceipts ?? {})) {
    const g = o.gate_receipts.find((x) => x.member === m);
    assert.ok(g, `${id}: gate receipt ${m} is reported`);
    assert.deepEqual([g.state, g.reason, g.flags, g.cited], [state, reason, flags, cited], `${id} gate receipt ${m}`);
  }
  for (const [field, form] of e.searchHas ?? []) assert.ok(o.hash_search.matches.some((m) => m.field === field && m.form === form), `${id}: hash_search names ${form} in ${field}`);
  if (e.payer !== undefined) assert.equal(o.payment.payer, e.payer, `${id} payer`);
  if (e.signedBy !== undefined) assert.equal(bind(o, "B-PAY").signed_by, e.signedBy, `${id} B-PAY signed_by`);
  if (e.refusing) assert.deepEqual(o.decision.refusing_records.map((r) => [r.log, r.seq, r.source]), e.refusing, `${id} refusing records`);
  for (const [asset, amount, payee, source] of e.movementsHave ?? [])
    assert.ok(o.payment.movements.some((m) => m.asset === asset && m.amount === amount && m.payee === payee && m.source === source), `${id}: movement ${amount} of ${asset} to ${payee} (${source})`);
  if (e.same) {
    const b = out(e.same);
    assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], [b.verdict.code, b.verdict.rule, b.verdict.reason], `${id}: the verdict of ${e.same}`);
    assert.deepEqual(o.bindings.map((x) => [x.id, x.state, x.reason]), b.bindings.map((x) => [x.id, x.state, x.reason]), `${id}: the bindings of ${e.same}`);
  }
}

const OFFLINE = ["PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data"];
// The test accounts of the payment side's rows (vectors/rows-a2b.mjs), lowercase.
const C_T = testAddress("test contract").toLowerCase();
const S_T = testAccount("payer").address.toLowerCase();
const K = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const F_T = testAccount("facilitator").address.toLowerCase();
const PAYEE = testAddress("payee").toLowerCase();
// [id, what, spec (lines), derived]
const A2_ROWS = [
  ["SA-03", "the instruction left out: WITHHELD", { lines: "390", bindings: { "B-INS": ["WITHHELD", null] } }, { verdict: OFFLINE }],
  ["S-18", "an argument above 2^53: M8.arguments PASS", { lines: "952", checks: [["M8.arguments", "args-t", "PASS", null]] }, { verdict: OFFLINE }],
  ["S-64", "Case B's DENY record, payer stated: BOUND, refuse, row 16", { lines: "958, 505", bindings: { "B-PAY": ["BOUND", null] }, decision: "refuse", verdict: OFFLINE }, {}],
  ["S-65", "Case B's DENY record, no account stated: row 40", { lines: "958, 529", bindings: { "B-PAY": ["NOT-EVALUATED", "authorizer-not-stated"] }, decision: "refuse", verdict: ["PAYMENT-NOT-VERIFIED", "V3", "authorizer-not-stated"] }, {}],
  ["S-73", "neither triple: decision not-read", { lines: "958", decision: "not-read" }, { verdict: OFFLINE }],
  ["S-79", "deny, executed, act: refuse", { lines: "958", decision: "refuse" }, { verdict: OFFLINE }],
  ["S-90", "pins whose permit and refuse share a value: the verifier does not run", { lines: "959", exit: 2 }, {}],
  // Wa-01
  ["SA-01", "a cited Annex A instruction, inside: BOUND, row 22", { lines: "701 to 710, 376", bindings: { "B-PAY": ["BOUND", null], "B-INS": ["BOUND", null] }, decision: "allow", verdict: OFFLINE, limitsHave: ["L12", "L13"] }, { checks: [["M6.instruction", "ins-t", "PASS", null]], instructions: { "ins-t": ["BOUND", [], null] } }],
  ["SA-02", "max_amount below the payment: EXCEEDS, row 16", { lines: "382, 388, 505", bindings: { "B-INS": ["EXCEEDS", null] }, instructions: { "ins-t": ["EXCEEDS", ["max_amount"], null] }, verdict: OFFLINE }, {}],
  ["SA-04", "an uncited instruction, inside: MATCHED", { lines: "377", instructions: { "ins-t": ["MATCHED", [], null] }, limitsHave: ["L18"] }, { bindings: { "B-INS": ["MATCHED", null] }, verdict: OFFLINE }],
  ["SA-05", "an uncited instruction naming another payee: UNBOUND-OUTSIDE", { lines: "377, 381", instructions: { "ins-t": ["UNBOUND-OUTSIDE", ["payees"], null] }, limitsHave: ["L18"] }, { bindings: { "B-INS": ["UNBOUND-OUTSIDE", null] }, verdict: OFFLINE }],
  ["SA-08", "an instruction's sig changed: FAILS", { lines: "260", checks: [["M6.instruction", "ins-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-74", "neither triple, outside the cited instruction: EXCEEDS", { lines: "958", bindings: { "B-INS": ["EXCEEDS", null] }, decision: "not-read" }, { verdict: OFFLINE }],
  // Wa-02
  ["SA-06", "a cited vi-0.1-draft member: PRESENT", { lines: "376", bindings: { "B-INS": ["PRESENT", null] }, limitsHave: ["L5"] }, { verdict: OFFLINE, instructions: { "ins-t": ["PRESENT", [], null] } }],
  ["SA-07", "an uncited ap2-0.2 member: PRESENT", { lines: "390", bindings: { "B-INS": ["PRESENT", null] }, limitsHave: ["L5"] }, { verdict: OFFLINE, instructions: { "ins-ap2": ["PRESENT", [], null] } }],
  // Wa-03
  ["SA-09", "an action result its record names: M8.result PASS", { lines: "262", checks: [["M8.result", "result-t", "PASS", null]] }, { verdict: OFFLINE }],
  ["SA-10", "an action result no record names: FAILS", { lines: "262", checks: [["M8.result", "result-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  // Wa-04
  ["S-66", "an Annex B log, no gate receipt: decision not-read, row 19", { lines: "958, 508", decision: "not-read", limitsHave: ["L22"], verdict: OFFLINE }, { checks: [["M2.log", "log-t", "PASS", null]], bindings: { "B-LOG": ["BOUND", null], "B-KEY": ["KEY-ONLY", null], "B-GRC": ["ABSENT", null], "B-PAY": ["BOUND", null] } }],
  ["S-85", "an Annex B record naming a receipt left out: B-GRC ABSENT receipt-missing", { lines: "959", bindings: { "B-GRC": ["ABSENT", "receipt-missing"] } }, { decision: "not-read", verdict: OFFLINE, limitsHave: ["L22"] }],
  // Wa-05
  ["S-16", "a profile carried under /1, unpinned: SUPPLIED", { lines: "951" }, { checks: [["M9.issuer-profile", "ip-t", "PASS", null], ["M7.envelope", "gr-t", "PASS", null], ["M7.uid", "gr-t", "PASS", null], ["M7.signature", "gr-t", "PASS", null], ["M7.signer-key", "gr-t", "PASS", null]], bindings: { "B-GRC": ["SUPPLIED", null] }, verdict: OFFLINE, flagsHave: ["test-profile"], limitsHave: ["L16", "L22"] }],
  ["S-17", "the same bytes carried under /2: FAILS", { lines: "951", checks: [["M9.issuer-profile", "ip-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-67", "a pinned profile, verdict permitted: allow, row 25", { lines: "958", decision: "allow" }, { bindings: { "B-GRC": ["BOUND", null] }, verdict: OFFLINE, gateReceipts: { "gr-t": ["BOUND", null, [], true] } }],
  ["S-68", "a pinned profile, verdict refused: refuse, B-GRC BOUND, row 16", { lines: "958", decision: "refuse", bindings: { "B-GRC": ["BOUND", null] }, verdict: OFFLINE }, {}],
  ["S-69", "a verdict in neither list: not-read", { lines: "958", decision: "not-read" }, { bindings: { "B-GRC": ["BOUND", null] }, verdict: OFFLINE }],
  ["S-70", "a profile pinned without verdict values: not-read", { lines: "958", decision: "not-read" }, { bindings: { "B-GRC": ["BOUND", null] }, verdict: OFFLINE }],
  ["S-71", "an unpinned profile: not-read", { lines: "958", decision: "not-read" }, { bindings: { "B-GRC": ["SUPPLIED", null] }, verdict: OFFLINE }],
  ["S-72", "an ALLOW record whose receipt the pins read as refusing: refuse", { lines: "958", decision: "refuse" }, { bindings: { "B-GRC": ["BOUND", null] }, verdict: OFFLINE }],
  ["S-77", "an ALLOW record, its receipt pinned without verdict values: not-read", { lines: "958", decision: "not-read" }, { bindings: { "B-GRC": ["BOUND", null] }, verdict: OFFLINE }],
  ["S-78", "an ALLOW record, its receipt unpinned: not-read", { lines: "958", decision: "not-read" }, { bindings: { "B-GRC": ["SUPPLIED", null] }, verdict: OFFLINE }],
  ["S-80", "after the cited receipt's valid-until time: EXCEEDS, row 16", { lines: "959", bindings: { "B-GRC": ["EXCEEDS", "after-receipt-expiry"] }, verdict: OFFLINE }, {}],
  ["S-81", "equal to the valid-until time: not EXCEEDS", { lines: "959", bindings: { "B-GRC": ["BOUND", null] } }, { verdict: OFFLINE }],
  ["S-82", "after the valid-until time, unpinned: SUPPLIED with the flag", { lines: "959", bindings: { "B-GRC": ["SUPPLIED", null] }, flagsHave: ["after-receipt-expiry"] }, { decision: "not-read", verdict: OFFLINE }],
  ["S-83", "before the receipt's check time: before-receipt-check", { lines: "959", bindings: { "B-GRC": ["NOT-EVALUATED", "before-receipt-check"] } }, { verdict: OFFLINE }],
  ["S-84", "an earlier action's receipt expired: context-receipt, B-GRC BOUND", { lines: "959", flagsHave: ["context-receipt"], flagsLack: ["clock-contradiction"], bindings: { "B-GRC": ["BOUND", null] } }, { gateReceipts: { "gr-t0": ["EXCEEDS", "after-receipt-expiry", ["context-receipt"], false], "gr-t1": ["BOUND", null, [], true] }, verdict: OFFLINE }],
  ["S-87", "two gate-receipt members with one uid: FAILS", { lines: "959", checks: [["M7.uid", "gr-t", "FAIL"], ["M7.uid", "gr-t2", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-88", "a receipt_uid in upper case: FAILS", { lines: "959", checks: [["M2.log", "log-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-89", "a context receipt under an unpinned profile: B-GRC BOUND, its own state reported", { lines: "959", bindings: { "B-GRC": ["BOUND", null] }, gateReceipts: { "gr-ctx": ["SUPPLIED", null, ["context-receipt"], false] } }, { gateReceipts: { "gr-t": ["BOUND", null, [], true] }, verdict: OFFLINE, decision: "allow" }],
  // Wa-06
  ["SA-11", "a checkpoint and a witness receipt carried as members: M3 and M4 PASS, R-01's states", { lines: "251, 252", checks: [["M3.checkpoint", "cp-a", "PASS", null], ["M3.signature", "cp-a", "PASS", null], ["M3.history", "cp-a", "PASS", null], ["M4.witness-receipt", "wr-a", "PASS", null]] }, { same: "R-01" }],
  // Wa-07
  ["SA-12", "an opaque supporting member: M1.member PASS, R-01's states", { lines: "164", checks: [["M1.member", "sup-a", "PASS", null]] }, { same: "R-01" }],
  // Wa-08
  ["SA-16", "a lone JWK for the operator: M9.operator-key PASS, R-01's states", { lines: "263, 264", checks: [["M9.operator-key", "opkey-a", "PASS", null], ["M2.log", "log-a", "PASS", null]] }, { same: "R-01" }],
  // Wa-09
  ["SA-13a", "a jwks_uri with the JWKS carried: B-KEY SUPPLIED", { lines: "365 to 371", bindings: { "B-KEY": ["SUPPLIED", null] } }, { checks: [["M2.log", "log-t", "PASS", null], ["O3.jwks", null, "NOT-EVALUATED", "offline"]], verdict: OFFLINE }],
  ["SA-13b", "a jwks_uri with no JWKS carried: B-KEY NOT-EVALUATED no-jwks-carried", { lines: "370", bindings: { "B-KEY": ["NOT-EVALUATED", "no-jwks-carried"] } }, { checks: [["M2.log", "log-t", "PASS", null]], verdict: OFFLINE }],
  // Wa-10
  ["SA-14", "a log carried twice: M2.prefix PASS, R-01's states", { lines: "250", checks: [["M2.prefix", "log-a", "PASS", null]] }, { same: "R-01", flagsLack: ["other-entry-hash"] }],
  // Wa-11
  ["SA-15", "a checkpoint beyond the carried log: B-CKP TRUNCATED, L9, offline-chain-data", { lines: "300, 304", bindings: { "B-CKP": ["TRUNCATED", null] }, limitsHave: ["L9"], verdict: OFFLINE }, { checks: [["M3.history", "sidecar-t15", "PASS", null]], bindings: { "B-PAY": ["BOUND", null] }, flagsHave: ["unwitnessed-attempt"] }],
  // The payment side, step 0 (already judged)
  ["S-03", "subject.expected_authorizer F_t: FAILS", { lines: "947", checks: [["M0.bundle", null, "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-04", "subject.expected_authorizer S_t: FAILS", { lines: "947", checks: [["M0.bundle", null, "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-19a", "a 17-field header: M5.block-hash PASS", { lines: "953, 257", checks: [["M5.block-hash", "blk-a", "PASS", null]] }, { verdict: OFFLINE, bindings: { "B-PAY": ["BOUND", null] } }],
  ["S-19b", "excessBlobGas without blobGasUsed: FAILS", { lines: "953, 257", checks: [["M5.block-hash", "blk-a", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-97", "a stated account other than the payer: DOES-NOT-CONNECT", { lines: "960", verdict: ["DOES-NOT-CONNECT", "V2"] }, { bindings: { "B-PAY": ["CARRIED-BY-OTHER", null] }, same: "R-03" }],
  // Wb-04
  ["S-86", "type 0x3 with an expired cited receipt: UNSUPPORTED-PATH unsupported-type", { lines: "959, 256", bindings: { "B-PAY": ["UNSUPPORTED-PATH", "unsupported-type"] }, checks: [["M5.support", null, "NOT-EVALUATED", "unsupported-type"]], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unsupported-type"] }, { bindings: { "B-GRC": ["BOUND", null] }, gateReceipts: { "gr-t": ["BOUND", null, [], true] } }],
  // Wb-06
  ["S-108", "a contract creation from S_t holding H: UNSUPPORTED-PATH unsupported-call", { lines: "964, 317", bindings: { "B-PAY": ["UNSUPPORTED-PATH", "unsupported-call"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unsupported-call"] }, { limitsHave: ["L20"], checks: [["M5.call", "tx-a", "PASS", null]] }],
  // Wb-07
  ...["S-01", "S-02", "S-05", "S-06"].map((id) => [id, "a relayer's calldata: UNSUPPORTED-PATH other-sender", { lines: "947, 328", bindings: { "B-PAY": ["UNSUPPORTED-PATH", "other-sender"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "other-sender"] }, { limitsHave: ["L20"] }]),
  ["S-09", "A0 with no account stated: authorizer-not-stated", { lines: "947, 326", bindings: { "B-PAY": ["NOT-EVALUATED", "authorizer-not-stated"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "authorizer-not-stated"] }, { flagsHave: ["authorizer-not-stated"] }],
  ...["S-11", "S-13"].map((id) => [id, "a transaction from S_t to itself: no-counted-movement", { lines: "949, 329", bindings: { "B-PAY": ["NOT-EVALUATED", "no-counted-movement"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "no-counted-movement"] }, {}]),
  ["S-20", "a pull of the pinned token outside the native instruction: B-INS EXCEEDS (asset), row 16", { lines: "954, 382", bindings: { "B-PAY": ["BOUND", null], "B-INS": ["EXCEEDS", null] }, instructions: { "ins-t": ["EXCEEDS", ["asset"], null] }, verdict: OFFLINE }, { limitsHave: ["L21"], movementsHave: [["native", "1", C_T, "counted"], [K, "10000", C_T, "log"]] }],
  ["S-21", "an unpinned token's pull: unread-outflow, row 19", { lines: "954, 388", bindings: { "B-INS": ["NOT-EVALUATED", "unread-outflow"] }, instructions: { "ins-t": ["NOT-EVALUATED", [], "unread-outflow"] } }, { verdict: OFFLINE, bindings: { "B-PAY": ["BOUND", null] } }],
  ...["S-22", "S-23", "S-24", "S-25", "S-26", "S-31", "S-32", "S-33", "S-34", "S-35", "S-36"].map((id) => [id, "an outflow this version cannot judge: unread-outflow", { lines: id < "S-31" ? "954, 347" : "955, 345, 347", bindings: { "B-INS": ["NOT-EVALUATED", "unread-outflow"] } }, { verdict: OFFLINE, bindings: { "B-PAY": ["BOUND", null] }, instructions: { "ins-t": ["NOT-EVALUATED", [], "unread-outflow"] } }]),
  ["S-27", "a pull of 0: reported, not compared; B-INS BOUND, row 22", { lines: "954, 347", bindings: { "B-INS": ["BOUND", null] }, movementsHave: [[K, "0", C_T, "log"]] }, { verdict: OFFLINE, instructions: { "ins-t": ["BOUND", [], null] } }],
  ["S-28", "no instruction, the pinned token's pull: B-INS ABSENT, row 25", { lines: "954, 390", bindings: { "B-INS": ["ABSENT", null] } }, { verdict: OFFLINE, movementsHave: [[K, "10000", C_T, "log"]] }],
  ["S-29", "no instruction, an unpinned token's pull: unread-outflow", { lines: "954, 390", bindings: { "B-INS": ["NOT-EVALUATED", "unread-outflow"] } }, { verdict: OFFLINE }],
  ["S-30", "R3's case sent by F_t: UNSUPPORTED-PATH other-sender", { lines: "954, 328", bindings: { "B-PAY": ["UNSUPPORTED-PATH", "other-sender"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "other-sender"] }, {}],
  ["S-37", "a merchant's event and an unindexed Transfer not naming S_t: not read, B-INS BOUND, row 22", { lines: "955, 345", bindings: { "B-INS": ["BOUND", null] } }, { verdict: OFFLINE, instructions: { "ins-t": ["BOUND", [], null] } }],
  ["S-38", "a native value above max_amount beside an unread Approval: EXCEEDS (max_amount, unread-outflow), row 16", { lines: "955, 388", bindings: { "B-INS": ["EXCEEDS", "unread-outflow"] }, instructions: { "ins-t": ["EXCEEDS", ["max_amount"], "unread-outflow"] } }, { verdict: OFFLINE }],
  ["S-39", "a pinned token's transfer from S_t to S_t: reported, not compared; B-INS BOUND", { lines: "955, 347", bindings: { "B-INS": ["BOUND", null] }, movementsHave: [[K, "10000", S_T, "log"]] }, { verdict: OFFLINE }],
  ["S-92", "a type 0x04 calldata payment whose own tuple's authority is S_t: account-has-code", { lines: "960, 330", bindings: { "B-PAY": ["NOT-EVALUATED", "account-has-code"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "account-has-code"] }, { limitsHave: ["L23"] }],
  ["S-98", "a calldata payment from S_t without H: DOES-NOT-CONNECT", { lines: "960, 329", verdict: ["DOES-NOT-CONNECT", "V2"] }, { bindings: { "B-PAY": ["ABSENT", null] } }],
  // Wb-08
  ["S-07", "A3, S_t stated: CARRIED-BY-OTHER with S_t the payer, signed by F_t, row 37", { lines: "947, 324", bindings: { "B-PAY": ["CARRIED-BY-OTHER", null] }, payer: S_T, signedBy: F_T, flagsHave: ["trailer"], verdict: OFFLINE }, { movementsHave: [[K, "10000", PAYEE, "counted"]] }],
  ["S-08", "A3, F_t stated: CARRIED-BY-OTHER, no payer, DOES-NOT-CONNECT", { lines: "947, 324", bindings: { "B-PAY": ["CARRIED-BY-OTHER", null] }, payer: null, verdict: ["DOES-NOT-CONNECT", "V2"] }, { flagsHave: ["trailer"] }],
  ["S-10", "A3, no account stated: authorizer-not-stated", { lines: "947, 326", bindings: { "B-PAY": ["NOT-EVALUATED", "authorizer-not-stated"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "authorizer-not-stated"] }, { flagsHave: ["authorizer-not-stated", "trailer"] }],
  ["S-63", "A3 outside a cited instruction: CARRIED-BY-OTHER with a payer, B-INS EXCEEDS", { lines: "957, 324", bindings: { "B-PAY": ["CARRIED-BY-OTHER", null] }, payer: S_T }, { bindings: { "B-INS": ["EXCEEDS", null] }, instructions: { "ins-t": ["EXCEEDS", ["max_amount"], null] }, verdict: OFFLINE }],
  ["S-75", "a DENY record's hash in bytes S_t signed: refuse, the DENY record named", { lines: "958, 297, 318", decision: "refuse", refusing: [["log-b", 0, "record"]] }, { bindings: { "B-PAY": ["BOUND", null] }, flagsHave: ["other-entry-hash", "trailer"], verdict: OFFLINE }],
  ["S-76", "the DENY hash only in F_t's suffix: other-entry-hash, the cited record's decision", { lines: "958, 318", flagsHave: ["other-entry-hash"], decision: "allow" }, { refusing: [], bindings: { "B-PAY": ["BOUND", null] }, verdict: OFFLINE }],
  // Wb-09
  ["S-91", "an authorization that recovers to another account: contract-signer, L23", { lines: "960, 259, 319", checks: [["M5.authorization", "tx-a", "NOT-EVALUATED", "contract-signer"]], bindings: { "B-PAY": ["NOT-EVALUATED", "contract-signer"] }, limitsHave: ["L23"], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "contract-signer"] }, {}],
  // Wb-10
  ...[
    ["accessList[0].storageKeys[0]", "raw-32-bytes"],
    ["authorizationList[0].s", "raw-32-bytes"],
    ...Array(6).fill(["input", "hex-text"]),
  ].flatMap(([field, form], k) =>
    ["none", "calldata"].map((claim, j) => [`S-${40 + 2 * k + j}`, `no raw H in the input, ${form} in ${field}, claim ${claim}: unread-carrier`, { lines: "956, 321", bindings: { "B-PAY": ["NOT-EVALUATED", "unread-carrier"] }, searchHas: [[field, form]], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unread-carrier"] }, form === "hex-text" ? { flagsHave: ["hash-as-ascii-hex"] } : {}]),
  ),
  ...[
    ["input", "hex-text"],
    ["validBefore", null],
  ].flatMap(([field, form], k) =>
    ["none", "calldata", "eip3009-nonce"].map((claim, j) => [`S-${56 + 3 * k + j}`, `EIP-3009 with H only where it does not bind, claim ${claim}: unread-carrier`, { lines: "956, 321", bindings: { "B-PAY": ["NOT-EVALUATED", "unread-carrier"] }, verdict: ["PAYMENT-NOT-VERIFIED", "V3", "unread-carrier"], ...(form ? { searchHas: [[field, form]] } : {}) }, form ? { flagsHave: ["hash-as-ascii-hex", "trailer"] } : { searchHas: [["input", "raw-32-bytes"]] }]),
  ),
  ["S-62", "a raw match in the calldata beside a text match: BOUND, hash-as-ascii-hex", { lines: "956, 318", bindings: { "B-PAY": ["BOUND", null] }, flagsHave: ["hash-as-ascii-hex"], searchHas: [["input", "raw-32-bytes"], ["input", "hex-text"]] }, { verdict: OFFLINE, bindings: { "B-INS": ["ABSENT", null] } }],
  // Wb-11
  ["S-12", "an authorization of 0 whose nonce is H: NO-PAYMENT, DOES-NOT-CONNECT", { lines: "949, 329", bindings: { "B-PAY": ["NO-PAYMENT", null] }, verdict: ["DOES-NOT-CONNECT", "V2"] }, {}],
  ["S-14", "an authorization from S_t to itself whose nonce is H: NO-PAYMENT, DOES-NOT-CONNECT", { lines: "949, 319", bindings: { "B-PAY": ["NO-PAYMENT", null] }, verdict: ["DOES-NOT-CONNECT", "V2"] }, {}],
  ["S-15", "the same with H only in F_t's suffix: CARRIED-BY-OTHER, no payer", { lines: "949, 324", bindings: { "B-PAY": ["CARRIED-BY-OTHER", null] }, payer: null, verdict: ["DOES-NOT-CONNECT", "V2"] }, { flagsHave: ["trailer"] }],
  // Wb-12
  ["S-95", "a parent block that is not the payment block's parent: FAILS", { lines: "960, 257", checks: [["M5.parent-block", "parent-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  // Wb-13
  ["S-93", "an account proof that does not verify under its header's stateRoot: FAILS", { lines: "960, 257", checks: [["M5.account-proof", "proof-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-94", "an account proof whose block_hash names no carried header: FAILS", { lines: "960, 257", checks: [["M5.account-proof", "proof-t", "FAIL"]], verdict: ["FAILS", "V1"] }, {}],
  ["S-96", "an account proof of S_t at N-1 showing code: account-has-code", { lines: "960, 330", bindings: { "B-PAY": ["NOT-EVALUATED", "account-has-code"] } }, { checks: [["M5.account-proof", "proof-t", "PASS", null], ["M5.parent-block", "parent-t", "PASS", null]], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "account-has-code"], limitsHave: ["L23"] }],
  // Wb-14
  ["S-99", "an earlier type 0x04 entry with a tuple for S_t: account-has-code", { lines: "961, 330", bindings: { "B-PAY": ["NOT-EVALUATED", "account-has-code"] } }, { checks: [["M5.block-transactions", "btx-t", "PASS", null]], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "account-has-code"], limitsHave: ["L23"] }],
  ...["S-100", "S-101", "S-102", "S-103"].map((id) => [id, "a carried list that does not match: carried-transactions-mismatch, not used, never FAILS", { lines: "961, 257", flagsHave: ["carried-transactions-mismatch"], verdictNot: "FAILS" }, { bindings: { "B-PAY": ["BOUND", null] }, verdict: OFFLINE, checksLack: ["M5.block-transactions"] }]),
  ["S-104", "an earlier type 0x04 entry that does not decode: prerequisite-failed:O7.account-code", { lines: "961, 257, 330", bindings: { "B-PAY": ["NOT-EVALUATED", "prerequisite-failed:O7.account-code"] } }, { checks: [["M5.block-transactions", "btx-t", "PASS", null]], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "prerequisite-failed:O7.account-code"], limitsHave: ["L23"] }],
  ["S-105", "a first entry of type 0x7e: read as bytes only, no effect", { lines: "961, 257", bindings: { "B-PAY": ["BOUND", null] } }, { checks: [["M5.block-transactions", "btx-t", "PASS", null]], verdict: OFFLINE }],
  ...["S-106", "S-107"].map((id) => [id, "an earlier entry of a type this version does not decode: prerequisite-failed:O7.account-code", { lines: "962, 330", bindings: { "B-PAY": ["NOT-EVALUATED", "prerequisite-failed:O7.account-code"] } }, { checks: [["M5.block-transactions", "btx-t", "PASS", null]], verdict: ["PAYMENT-NOT-VERIFIED", "V3", "prerequisite-failed:O7.account-code"] }]),
];

// Format 0.10 (vectors/rows-a3.mjs), the regression row of C5 step 0.
A2_ROWS.push(["V-26", "a 0.9-typed bundle carrying a 0.3 instruction: M1.member FAIL, FAILS", { lines: "v0.10 186, 285", checks: [["M1.member", "ins-c", "FAIL"]], verdict: ["FAILS", "V1"] }, {}]);

for (const [id, what, spec, derived] of A2_ROWS) {
  test(`${id}: ${what} [spec, lines ${spec.lines}]`, () => expectRow(id, spec));
  if (Object.keys(derived).length) test(`${id}: ${what} [derived]`, () => expectRow(id, derived));
}

test("S-86: the cited receipt's times reported, not judged, when the block hash is not recomputed [spec, lines 402, 959]", () => {
  const o = out("S-86");
  assert.equal(check(o, "M5.block-hash", "blk-a").status, "NOT-EVALUATED");
  assert.ok(o.times.some((t) => t.what === "gr-t evaluatedAt (check time)"), "the check time is reported");
  assert.ok(o.times.some((t) => t.what === "gr-t expiresAt (valid-until time)"), "the valid-until time is reported");
  assert.notEqual(bind(o, "B-GRC").state, "EXCEEDS");
  assert.ok(!o.flags.some((f) => f.code === "after-receipt-expiry"));
});

test("SA-09: the verdict and bindings as the same bundle without its action result [spec, lines 262]", async () => {
  const sa09 = VECTORS.find((x) => x.id === "SA-09");
  const { doc, argv } = await sa09.build();
  doc.members = doc.members.filter((m) => m.role !== "action-result");
  const r = runCli(dir, "SA-09-without", doc, argv);
  const o = out("SA-09");
  assert.deepEqual([r.output.verdict.code, r.output.verdict.rule, r.output.verdict.reason], [o.verdict.code, o.verdict.rule, o.verdict.reason]);
  assert.deepEqual(r.output.bindings.map((b) => [b.id, b.state, b.reason]), o.bindings.map((b) => [b.id, b.state, b.reason]));
});

// W3-01: a bundle of type evidence-bundle/0.10 reads as the same bundle of type 0.9.
test("V-01: WE-1 typed evidence-bundle/0.10 gives R-01's projection [derived; spec v0.10 285]", () => {
  const p = expectedOf(runs.get("V-01"));
  assert.equal(p.exit, 0);
  assert.deepEqual(p, expectedOf(runs.get("R-01")));
  assert.equal(check(out("V-01"), "M0.bundle").status, "PASS");
});
