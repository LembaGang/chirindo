// WE-1 (spec section 7) and its vectors R-01 to R-06: the bundle is built
// into a temporary directory, check-bundle.mjs runs on it, and every value is
// asserted on the parsed output, never on its text.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { getAddress } from "viem";
import { buildWe1 } from "../build-we1.mjs";
import { loadPins } from "../lib/cli.mjs";
import { LIMIT_TEXTS } from "../lib/limits.mjs";
import { SOURCES, ARGS_A_SHA256, WE1_AUTHORIZER, WE1_TX } from "../lib/we1.mjs";
import { runCli, setBytes, textOf, byId, we1 } from "../vectors/make-vectors.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");
// The /v5/keys response digest, as pins/pins.json records it.
const PINNED_RESPONSE_SHA256 = loadPins().witness_keys.response_sha256;
const A = WE1_AUTHORIZER;
const a = A.toLowerCase();
const T = WE1_TX;
const F = "0xd407e409e34e0b9afb99ecceb609bdbcd5e7f1bf";
const P = "0xd8e1d2faf5e4509ee295c50e0f5e369e71861215";
const K = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const T11 = "0x7806295f38acab4997d1108264edd821e650faddc5b785ac22c098b86388c267";

let dir;
const runs = {};
before(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "eb-we1-"));
  const doc = buildWe1();
  runs.r01 = runCli(dir, "r01", doc, ["--authorizer", A, "--tx", T]);
  runs.r02 = runCli(dir, "r02", doc, ["--tx", T]);
  runs.r03 = runCli(dir, "r03", doc, ["--authorizer", F, "--tx", T]);
  runs.r04 = runCli(dir, "r04", doc, ["--authorizer", A, "--tx", T11]);
  runs.r05 = runCli(dir, "r05", doc, ["--authorizer", A, "--tx", "0x" + T.slice(2).toUpperCase()]);
  runs.r06 = runCli(dir, "r06", doc, ["--authorizer", A]);
});
after(() => rmSync(dir, { recursive: true, force: true }));

const out = (k) => {
  assert.equal(runs[k].status, 0, runs[k].stderr);
  return runs[k].output;
};
const check = (o, id, member = null) => {
  const c = o.checks.find((x) => x.id === id && x.member === member);
  assert.ok(c, `check ${id} on ${member} is listed`);
  return c;
};
const bind = (o, id) => o.bindings.find((b) => b.id === id);
const limits = (o) => o.limits.map((l) => l.id);

test("the WE-1 builder reads the committed bytes and builds the eight members of spec section 7", () => {
  const doc = buildWe1();
  assert.equal(doc.type, "evidence-bundle/0.9");
  assert.deepEqual(doc.subject, { kind: "evm-payment", chain_id: "eip155:84532", tx_hash: T, cites: { log: "log-a", seq: 0 }, carried_as: "eip3009-nonce" });
  const want = [
    ["log-a", "gate-log", "chirindo-evidence.action/1", "f7ed6c4532f0a7f9e28c71cb74b6df409b33d914897b0cdbd760b679ecb6e998", 1169],
    ["args-a", "action-arguments", "jcs-json", ARGS_A_SHA256, 54],
    ["sidecar-a", "witness-sidecar", "chirindo-witness-sidecar/1", "bb65a5c18705e45da9697a5ec2cd2c4663b1815162c266124d9caa5a630f17a2", 1050],
    ["opkey-a", "operator-key", "jwks", "02041d6eba914bc4f1fe4dda9ad0201cbe2810ab66acecbb671d9881359d7993", 235],
    ["wkey", "witness-key", "ho-v5-keys", PINNED_RESPONSE_SHA256, 1913],
    ["tx-a", "payment-transaction", "eth-rpc-json", "ecdde59189ba98f5886cd16abf827db724581fec6e6363e066629c7db5d88664", 1374],
    ["rc-a", "payment-receipt", "eth-rpc-json", "0265be18fa45a34cf32c735546c73835d559deb54da31b5f65b4d3ef06618174", 2727],
    ["blk-a", "payment-block", "eth-rpc-json", "58ae84275cd531f60f88aa252b80a5c4fd980debbc021586d1a2a780c0dad10e", 4148],
  ];
  assert.deepEqual(
    doc.members.map((m) => [m.id, m.role, m.profile, m.sha256.slice(7), Buffer.from(m.bytes_b64, "base64").length]),
    want,
  );
  for (const m of doc.members) assert.equal(sha(Buffer.from(m.bytes_b64, "base64")), m.sha256.slice(7));
  assert.equal(Buffer.from(byId(doc, "args-a").bytes_b64, "base64").toString("utf8"), '{"amount_in":0.25,"pair":"ETH/USDC","slippage_bps":50}');
  assert.equal(byId(doc, "tx-a").capture, "reserialised-by examples/ordering-evidence/case-a/fetch-sealed.mjs:14-16");
  assert.equal(byId(doc, "args-a").capture, "reconstructed-from examples/ordering-evidence/client.mjs:105");
  assert.equal(Object.keys(SOURCES).length, 11);
});

test("the limits texts are table 8-1's, L2 with the sentence of spec section 8 (8,070 bytes joined)", () => {
  const texts = Object.values(LIMIT_TEXTS);
  assert.equal(texts.length, 23);
  const joined = Buffer.from(texts.join("\n"), "utf8");
  assert.equal(joined.length, 8070);
  assert.equal(sha(joined), "99d9eeb81510d529f739672e6133b9c75c051fa184093c7ba4ddfc3338133c01");
  assert.equal(Buffer.byteLength(LIMIT_TEXTS.L2), 492);
  assert.equal(sha(Buffer.from(LIMIT_TEXTS.L2, "utf8")), "085d31bef41d6aa9b8bba9a618b2d468ca1443dc28e469344c6c34a4162ec9f2");
});

test("every limit in an output carries its table 8-1 text", () => {
  for (const l of out("r01").limits) assert.equal(l.text, LIMIT_TEXTS[l.id]);
});

test("R-01: WE-1 offline with its stated account and transaction", () => {
  const o = out("r01");
  assert.equal(check(o, "S1.authorizer").status, "PASS");
  assert.equal(check(o, "S2.tx").status, "PASS");
  for (const [id, state] of [["B-LOG", "BOUND"], ["B-CKP", "BOUND"], ["B-WIT", "SUPPLIED"], ["B-PAY", "BOUND"], ["B-CHAIN", "SUPPLIED"], ["B-KEY", "KEY-ONLY"], ["B-INS", "ABSENT"], ["B-GRC", "ABSENT"]]) assert.equal(bind(o, id).state, state, id);
  assert.equal(bind(o, "B-GRC").reason, null);
  assert.equal(bind(o, "B-PAY").carrier, "eip3009-nonce");
  assert.equal(bind(o, "B-PAY").signed_by, a);
  assert.deepEqual(o.hash_search.matches, [{ field: "input", form: "raw-32-bytes", offset: 164 }]);
  assert.equal(o.payment.payer, a);
  assert.equal(o.payment.movements.length, 1);
  const mv = o.payment.movements[0];
  assert.equal(mv.asset, K);
  assert.equal(mv.amount, "10000");
  assert.equal(mv.payee, P);
  assert.equal(mv.source, "counted");
  assert.deepEqual(o.decision, { value: "allow", record: { log: "log-a", seq: 0, event_decision: "allow", event_outcome: "executed", gate_result: "act", receipt_uid: null }, receipt: null, refusing_records: [] });
  assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "offline-chain-data"]);
  assert.equal(o.mode, "offline");
  assert.deepEqual(limits(o), ["L1", "L2", "L3", "L4", "L6", "L7", "L8", "L9", "L10", "L11", "L14", "L15", "L19", "L23"]);
  // The movement's log_index is the Transfer log's logIndex as carried in rc-a (0x4d).
  assert.equal(mv.log_index, 77);
  // hash_search.fields: spec 4.3, B-PAY rule 3's field list for type 0x2, in its order.
  assert.deepEqual(o.hash_search.fields, ["chainId", "nonce", "gas", "maxPriorityFeePerGas", "maxFeePerGas", "to", "value", "input", "accessList"]);
  // Comparisons of two clocks are reported as such (spec 4.5).
  assert.ok(o.flags.length >= 1);
  assert.deepEqual([...new Set(o.flags.map((f) => f.code))], ["two-clock-comparison"]);
  assert.deepEqual(o.verifier, { name: "chirindo examples/evidence-bundle", version: "0.9.0", commit: "unrecorded" });
  const expect = [
    ["S1.authorizer", null, "PASS"], ["S2.tx", null, "PASS"], ["M0.bundle", null, "PASS"], ["M1.manifest", null, "PASS"],
    ...["log-a", "args-a", "sidecar-a", "opkey-a", "wkey", "tx-a", "rc-a", "blk-a"].map((m) => ["M1.member", m, "PASS"]),
    ["M2.log", "log-a", "PASS"], ["M3.checkpoint", "sidecar-a", "PASS"], ["M3.signature", "sidecar-a", "PASS"], ["M3.history", "sidecar-a", "PASS"],
    ["M4.witness-receipt", "sidecar-a", "PASS"], ["M5.chain", "tx-a", "PASS"], ["M5.receipt", "rc-a", "PASS"], ["M5.block", "blk-a", "PASS"],
    ["M5.support", null, "PASS"], ["M5.transaction", "tx-a", "PASS"], ["M5.sender", "tx-a", "PASS"], ["M5.block-hash", "blk-a", "PASS"],
    ["M5.call", "tx-a", "PASS"], ["M5.token-domain", null, "PASS"], ["M5.authorization", "tx-a", "PASS"], ["M5.token-logs", "rc-a", "PASS"],
    ["M5.validity-window", null, "PASS"], ["M8.arguments", "args-a", "PASS"], ["M9.operator-key", "opkey-a", "PASS"], ["M9.witness-key", "wkey", "PASS"],
    ["O1.witness-list", null, "NOT-EVALUATED"], ["O2.rpc", null, "NOT-EVALUATED"], ["O2.finality", null, "NOT-EVALUATED"],
    ["O5.token-domain-call", null, "NOT-EVALUATED"], ["O7.account-code", null, "NOT-EVALUATED"],
  ];
  assert.deepEqual(o.checks.map((c) => [c.id, c.member, c.status]), expect);
  for (const c of o.checks.slice(-5)) assert.equal(c.reason, "offline");
  for (const b of o.bindings.filter((x) => x.id !== "B-PAY")) assert.deepEqual([b.carrier, b.signed_by], [null, null]);
  assert.deepEqual(o.hash_search.forms, ["raw-32-bytes", "hex-text"]);
  assert.equal(o.payment.connected, true);
  assert.equal(o.payment.as_supplied, true);
  assert.deepEqual(o.stated, { authorizer: a, tx: T });
});

test("R-02: only the transaction stated", () => {
  const o = out("r02");
  assert.deepEqual([check(o, "S1.authorizer").status, check(o, "S1.authorizer").reason], ["NOT-EVALUATED", "authorizer-not-stated"]);
  assert.deepEqual([bind(o, "B-PAY").state, bind(o, "B-PAY").reason, bind(o, "B-PAY").signed_by], ["NOT-EVALUATED", "authorizer-not-stated", a]);
  assert.ok(o.flags.some((f) => f.code === "authorizer-not-stated"));
  assert.equal(bind(o, "B-INS").state, "ABSENT");
  assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "authorizer-not-stated"]);
  assert.deepEqual(limits(o), ["L1", "L2", "L3", "L4", "L6", "L7", "L8", "L9", "L14", "L19"]);
  assert.equal(bind(o, "B-PAY").carrier, "eip3009-nonce");
  assert.ok(!o.checks.some((c) => c.id === "O7.account-code"));
  assert.equal(o.payment.connected, false);
  assert.equal(o.payment.payer, null);
});

test("R-03: the facilitator stated as the account", () => {
  const o = out("r03");
  assert.equal(bind(o, "B-PAY").state, "CARRIED-BY-OTHER");
  assert.equal(o.payment.payer, null);
  assert.deepEqual([o.verdict.code, o.verdict.rule], ["DOES-NOT-CONNECT", "V2"]);
  assert.equal(bind(o, "B-PAY").signed_by, a);
  assert.deepEqual(limits(o), ["L1", "L2", "L3", "L4", "L6", "L7", "L8", "L9", "L10", "L11", "L14", "L19"]);
  assert.equal(o.payment.connected, false);
});

test("R-04: another transaction stated", () => {
  const o = out("r04");
  assert.equal(check(o, "S2.tx").status, "FAIL");
  assert.deepEqual([o.verdict.code, o.verdict.rule], ["FAILS", "V1"]);
});

test("R-05: the stated transaction in upper case reads as R-01", () => {
  const o = out("r05");
  const r01 = out("r01");
  assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], [r01.verdict.code, r01.verdict.rule, r01.verdict.reason]);
  assert.deepEqual(o.bindings.map((b) => b.state), r01.bindings.map((b) => b.state));
  assert.equal(o.stated.tx, T);
});

test("R-06: only the account stated", () => {
  const o = out("r06");
  assert.deepEqual([check(o, "S2.tx").status, check(o, "S2.tx").reason], ["NOT-EVALUATED", "tx-not-stated"]);
  assert.deepEqual([bind(o, "B-PAY").state, bind(o, "B-PAY").reason], ["NOT-EVALUATED", "tx-not-stated"]);
  assert.deepEqual([o.verdict.code, o.verdict.rule, o.verdict.reason], ["PAYMENT-NOT-VERIFIED", "V3", "tx-not-stated"]);
});

test("spec 4.8.1: a one-byte change to a member with the manifest digest left as it was FAILs M1", () => {
  const doc = we1();
  const m = byId(doc, "args-a");
  const bytes = Buffer.from(m.bytes_b64, "base64");
  bytes[20] ^= 1;
  m.bytes_b64 = bytes.toString("base64");
  const r = runCli(dir, "m1-digest", doc, ["--authorizer", A, "--tx", T]);
  assert.equal(r.status, 0);
  assert.equal(r.output.verdict.code, "FAILS");
  assert.equal(r.output.checks.find((c) => c.id === "M1.member" && c.member === "args-a").status, "FAIL");
});

test("spec 4.8.1: the same change with the digest recomputed FAILs at the check that reads the value", () => {
  const doc = we1();
  const text = textOf(byId(doc, "args-a")).replace("0.25", "0.24");
  setBytes(doc, "args-a", Buffer.from(text, "utf8"));
  const r = runCli(dir, "m8", doc, ["--authorizer", A, "--tx", T]);
  assert.equal(r.output.verdict.code, "FAILS");
  assert.equal(r.output.checks.find((c) => c.id === "M8.arguments").status, "FAIL");
});

test("the stated account in its EIP-55 form is the test payer", () => {
  assert.equal(getAddress(a), A);
});
