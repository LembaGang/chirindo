// The vectors of the shapes judged after the first build (spec D.5, offline):
// each a recipe built at run time, on WE-1's document, from the repository's
// own bytes and from throwaway test keys (vectors/synth.mjs). Nothing these
// keys sign is evidence of anything, and no transaction here was broadcast.
// vectors/make-vectors.mjs lists them after WE-1's vectors, in the order the
// shape was widened.

import canonicalize from "canonicalize";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { jcsSha256, withoutMember } from "../../ordering-evidence-h4/lib/formats.mjs";
import { caseB, FOLDER, PAY_CONTRACT } from "./make-vectors.mjs";
import { add, CASES, eipPayment, payee, stated, T0, usePayment, we1Parts } from "./refusal-cases.mjs";
import { annexBLog, chirindoLog, gateReceipt, instruction, issuerProfile, json, jwkOf, jwksOf, testAccount, testAddress, testEd, testSecp } from "./synth.mjs";

const JSONL = "application/x-ndjson";
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
const entryHex = (h) => "0x" + h.slice("sha256:".length);

// The pins of pins/pins.json, changed by `edit`, for a vector run with --pins.
export function testPins(edit) {
  const pins = JSON.parse(readFileSync(path.join(FOLDER, "pins", "pins.json"), "utf8"));
  edit(pins);
  return pins;
}

// WE-1's document with only its three payment members, which usePayment
// replaces: WE-1's log, arguments, sidecar and keys are left out.
function paymentOnly() {
  const { doc, blk } = we1Parts();
  doc.members = doc.members.filter((m) => ["tx-a", "rc-a", "blk-a"].includes(m.id));
  return { doc, blk };
}

// Arguments a test record names and the bundle does not carry.
const UNCARRIED_ARGS = jcsSha256({ note: "TEST FIXTURE arguments, not carried" });
// The test records' first ts: an hour before the test block's timestamp, so
// that no entry is later than the payment's block.
const LOG_T0 = Number(T0 - 3600n) * 1000;

// A test-key chirindo log (members log-t and opkey-t), its record `seq` cited
// by an EIP-3009 payment of the test payer whose nonce is that record's entry
// hash, sent by the test facilitator; the claim eip3009-nonce.
async function testLogCase({ log = {}, seq = 0, pay = {} } = {}) {
  const { doc, blk } = paymentOnly();
  const k = testEd("a2 operator");
  const l = chirindoLog({ k, sessionId: "test-a2", argsHash: UNCARRIED_ARGS, t0: LOG_T0, ...log });
  add(doc, { id: "log-t", role: "gate-log", profile: "chirindo-evidence.action/1", bytes: l.bytes, media_type: JSONL });
  add(doc, { id: "opkey-t", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
  const p = await eipPayment(blk, { nonce: entryHex(l.hashes[seq]), ...pay });
  usePayment(doc, p, "eip3009-nonce");
  doc.subject.cites = { log: "log-t", seq };
  return { doc, k, log: l, p };
}

// A test principal's Annex A instruction for the test payer's payment, and
// arguments that cite its digest (or not, with cite false).
function instructionAndArgs({ k, constraints = {}, cite = true }) {
  const ins = instruction({ principal: testEd("principal"), agentKid: k.kid, payee: payee.toLowerCase(), token: PAY_CONTRACT, constraints });
  const args = cite ? { note: "TEST FIXTURE arguments", instruction_sha256: jcsSha256(ins) } : { note: "TEST FIXTURE arguments" };
  return { ins, args, argsHash: jcsSha256(args) };
}

// The test log case whose cited record's arguments are carried (args-t) and,
// unless `withIns` is false, the instruction (ins-t), whose bytes `change` may
// alter after the arguments cite its digest.
async function instructionCase({ constraints, cite, withIns = true, log = {}, change } = {}) {
  const k = testEd("a2 operator");
  const { ins, args, argsHash } = instructionAndArgs({ k, constraints, cite });
  const c = await testLogCase({ log: { argsHash, ...log } });
  add(c.doc, { id: "args-t", role: "action-arguments", profile: "jcs-json", bytes: json(args) });
  if (withIns) add(c.doc, { id: "ins-t", role: "instruction", profile: "signed-instruction-ed25519/0.2", bytes: json(change ? change(structuredClone(ins)) : ins) });
  return { ...c, ins };
}

// One base64url character of an instruction's sig changed.
const changeSig = (ins) => ({ ...ins, sig: ins.sig.slice(0, 10) + (ins.sig[10] === "A" ? "B" : "A") + ins.sig.slice(11) });

// Case B's DENY record cited by the test payer's payment whose nonce is its
// entry hash (repository bytes for the log and its sidecar).
async function caseBCited() {
  const { doc, blk } = we1Parts();
  const [lb, sb] = caseB();
  doc.members.splice(0, 1, lb);
  doc.members.splice(doc.members.findIndex((m) => m.id === "sidecar-a"), 1, sb);
  doc.subject.cites = { log: "log-b", seq: 0 };
  const rec = JSON.parse(Buffer.from(lb.bytes_b64, "base64").toString("utf8").trim());
  const p = await eipPayment(blk, { nonce: entryHex(jcsSha256(withoutMember(rec, "sig"))) });
  usePayment(doc, p, "eip3009-nonce");
  return { doc, p };
}

// The decision members of every record of a test log set to a triple.
const decisionTriple = (decision, outcome, result) => (recs) => recs.map((r) => ({ ...r, event: { ...r.event, decision, outcome }, ["gate"]: { ...r["gate"], result } }));

const SYNTH = "synthetic: test keys of vectors/synth.mjs on WE-1's document";
const PAY = "an EIP-3009 payment of the test payer (value 10000 to the test payee, sent by the test facilitator) whose nonce is the cited entry hash; carried_as eip3009-nonce";
const v = (id, description, change, args, build, base = SYNTH) => ({ id, description, recipe: { base, change }, args, build });
const STATED = ["--authorizer", "<the test payer>", "--tx", "<the payment>"];

// Rows that need no widening: run on the shape of the first build, before any
// widening, as regression rows (each must give its stated values there).
export const ROWS_STEP0 = [
  v("SA-03", "an instruction's digest cited by the arguments, the instruction left out", `a test-key log whose cited record's arguments (args-t) carry instruction_sha256 of an Annex A instruction the bundle does not carry; ${PAY}`, STATED, async () => {
    const c = await instructionCase({ withIns: false });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("S-18", "a jcs-json argument above 2^53, hashed as the gate hashes it", `a test-key log whose cited record's args_hash is the JCS SHA-256 of JSON.parse('{"n":9007199254740993}'), with args-t holding those bytes; ${PAY}`, STATED, async () => {
    const bytes = Buffer.from('{"n":9007199254740993}', "utf8");
    const argsHash = "sha256:" + sha256Hex(Buffer.from(canonicalize(JSON.parse(bytes.toString("utf8"))), "utf8"));
    const c = await testLogCase({ log: { argsHash } });
    add(c.doc, { id: "args-t", role: "action-arguments", profile: "jcs-json", bytes });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  ...[
    ["S-64", "with the test payer stated", (p) => stated(p.tx.hash), STATED],
    ["S-65", "with no account stated", (p) => ["--tx", p.tx.hash], ["--tx", "<the payment>"]],
  ].map(([id, what, argv, shown]) =>
    v(id, `Case B's DENY record cited by a payment whose nonce is its hash, ${what}`, `log-b and sidecar-b in place of log-a and sidecar-a, subject.cites {log: log-b, seq: 0}; an EIP-3009 payment of the test payer whose nonce is Case B's entry hash; carried_as eip3009-nonce`, shown, async () => {
      const c = await caseBCited();
      return { doc: c.doc, argv: argv(c.p) };
    }, "WE-1, with Case B's log and sidecar (repository bytes) and a synthetic payment"),
  ),
  v("S-73", "a chirindo record whose decision members hold neither triple", `a test-key log whose records hold event.decision allow, event.outcome executed and gate.result audit; ${PAY}`, STATED, async () => {
    const c = await testLogCase({ log: { edit: decisionTriple("allow", "executed", "audit") } });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("S-79", "a chirindo record holding deny, executed and act", `a test-key log whose records hold event.decision deny, event.outcome executed and gate.result act; ${PAY}`, STATED, async () => {
    const c = await testLogCase({ log: { edit: decisionTriple("deny", "executed", "act") } });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("S-90", "pins in which one issuer profile's permit and refuse share a value", "none; --pins names a copy of pins/pins.json whose one issuer profile lists the value allow in both permit and refuse", ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3", "--pins", "<pins>"], async () => {
    const { doc } = we1Parts();
    const pins = testPins((p) => {
      p.issuer_profiles = [{ sha256: "0".repeat(64), permit: ["allow"], refuse: ["allow"] }];
    });
    return { doc, pins };
  }, "WE-1"),
];

const INS = "the cited record's arguments (args-t) carry instruction_sha256 of an Annex A instruction (ins-t) of a test principal key: asset the test token, max_amount 10000, payees [the test payee], agent_kid [the test operator kid], valid 2026-10-01 to 2026-12-31";
const insRow = (id, description, change, o) =>
  v(id, description, `a test-key log; ${change}; ${PAY}`, STATED, async () => {
    const c = await instructionCase(o);
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  });

// Wa-01: role instruction, profile signed-instruction-ed25519/0.2.
export const ROWS_WA01 = [
  insRow("SA-01", "an Annex A instruction cited by the action, the payment inside it", INS, {}),
  insRow("SA-02", "the payment above the cited instruction's max_amount", `${INS}, with max_amount 9999`, { constraints: { max_amount: "9999" } }),
  insRow("SA-04", "an instruction the arguments do not cite, the payment inside it", `${INS}, the arguments carrying no instruction_sha256`, { cite: false }),
  insRow("SA-05", "an uncited instruction whose payees name another address", `${INS}, the arguments carrying no instruction_sha256 and the instruction's payees [another test address]`, { cite: false, constraints: { payees: [testAddress("another payee").toLowerCase()] } }),
  insRow("SA-08", "an instruction whose sig was changed", `${INS}, one character of the instruction's sig changed and its member digest recomputed`, { change: changeSig }),
  v("S-74", "a record whose decision members hold neither triple, the payment outside the cited instruction", `a test-key log whose records hold event.decision allow, event.outcome executed and gate.result audit; ${INS}, with max_amount 9999; ${PAY}`, STATED, async () => {
    const c = await instructionCase({ constraints: { max_amount: "9999" }, log: { edit: decisionTriple("allow", "executed", "audit") } });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
];

// Wa-02: instructions of the profiles vi-0.1-draft and ap2-0.2, carried with
// their digests and not verified.
export const ROWS_WA02 = [
  v("SA-06", "a Verifiable Intent member cited by the action", `a test-key log whose cited record's arguments (args-t) carry instruction_sha256, the SHA-256 of the bytes of a vi-0.1-draft member (ins-t, TEST FIXTURE bytes); ${PAY}`, STATED, async () => {
    const bytes = Buffer.from("TEST FIXTURE vi-0.1-draft bytes: not a Verifiable Intent credential\n", "utf8");
    const args = { note: "TEST FIXTURE arguments", instruction_sha256: "sha256:" + sha256Hex(bytes) };
    const c = await testLogCase({ log: { argsHash: jcsSha256(args) } });
    add(c.doc, { id: "args-t", role: "action-arguments", profile: "jcs-json", bytes: json(args) });
    add(c.doc, { id: "ins-t", role: "instruction", profile: "vi-0.1-draft", bytes, media_type: "text/plain" });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("SA-07", "WE-1 with an uncited AP2 member", "an ap2-0.2 member (ins-ap2, TEST FIXTURE bytes) added; args-a carries no instruction_sha256", ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"], async () => {
    const { doc } = we1Parts();
    add(doc, { id: "ins-ap2", role: "instruction", profile: "ap2-0.2", bytes: Buffer.from("TEST FIXTURE ap2-0.2 bytes: not an AP2 mandate\n", "utf8"), media_type: "text/plain" });
    return { doc };
  }, "WE-1"),
];

// Wa-03: action results (M8.result).
const RESULT = { note: "TEST FIXTURE result", ok: true };
export const ROWS_WA03 = [
  v("SA-09", "an action result whose digest the cited record names", `a test-key log whose records carry event.result_hash, the JCS SHA-256 of an action-result member (result-t); ${PAY}`, STATED, async () => {
    const c = await testLogCase({ log: { resultHash: jcsSha256(RESULT) } });
    add(c.doc, { id: "result-t", role: "action-result", profile: "jcs-json", bytes: json(RESULT) });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("SA-10", "an action result whose digest no record names", `as SA-09, with result-t holding another value`, STATED, async () => {
    const c = await testLogCase({ log: { resultHash: jcsSha256(RESULT) } });
    add(c.doc, { id: "result-t", role: "action-result", profile: "jcs-json", bytes: json({ ...RESULT, ok: false }) });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
];

// A test-key Annex B log (members log-t and opkey-t), its record `seq` cited by
// an EIP-3009 payment of the test payer whose nonce is that record's entry
// hash, sent by the test facilitator; the claim eip3009-nonce.
export async function annexBCase({ log = {}, seq = 0, pay = {} } = {}) {
  const { doc, blk } = paymentOnly();
  const k = testEd("a2 annex-b operator");
  const l = annexBLog({ k, sessionId: "test-a2-annex-b", ...log });
  add(doc, { id: "log-t", role: "gate-log", profile: "jcs-sha256-chain/0.1", bytes: l.bytes, media_type: JSONL });
  add(doc, { id: "opkey-t", role: "operator-key", profile: "jwks", bytes: jwksOf(k) });
  const p = await eipPayment(blk, { nonce: entryHex(l.hashes[seq]), ...pay });
  usePayment(doc, p, "eip3009-nonce");
  doc.subject.cites = { log: "log-t", seq };
  return { doc, k, log: l, p };
}
const PAY_B = PAY.replace("the cited entry hash", "the cited Annex B record's entry hash");

// Wa-04: logs of the profile jcs-sha256-chain/0.1 (Annex B).
export const ROWS_WA04 = [
  v("S-66", "an Annex B log with no gate receipt", `a test-key Annex B log of one record that names no receipt_uid; ${PAY_B}`, STATED, async () => {
    const c = await annexBCase();
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("S-85", "an Annex B record that names a gate receipt the bundle leaves out", `a test-key Annex B log whose record names, as receipt_uid, the uid of a test issuer's gate receipt that the bundle does not carry; ${PAY_B}`, STATED, async () => {
    const gr = await gateReceipt(testSecp("issuer"));
    const c = await annexBCase({ log: { receiptUid: gr.uid } });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
];

// A test issuer's profile (ip-t, unless `profileId` names another) and the
// gate receipts `receipts` read through it, each { id, gr } with gr from
// gateReceipt. `profileAs` is the profile name the member declares.
export function addReceipts(doc, receipts, { profileId = "ip-t", profileAs = "chirindo-h4-issuer-profile/1", label } = {}) {
  const bytes = json(issuerProfile(testAccount("issuer").address, label));
  add(doc, { id: profileId, role: "issuer-profile", profile: profileAs, bytes });
  for (const { id, gr } of receipts) add(doc, { id, role: "gate-receipt", profile: "eip712-gate-receipt/0.1", issuer_profile: profileId, bytes: json(gr.sealed) });
  return bytes;
}

// Pins that name issuer profiles by the sha256 of their bytes: { bytes,
// permit?, refuse? }, a profile without permit and refuse being pinned
// without verdict values. The values are a test's, and say so.
const VALUES_SOURCE = { url: "examples/evidence-bundle/vectors/rows-a2.mjs", label: "TEST FIXTURE: verdict values set by this test, not taken from an issuer's documentation", fetched_at: null, sha256: null };
export const pinsFor = (profiles) =>
  testPins((p) => {
    p.issuer_profiles = profiles.map(({ bytes, permit, refuse }) => ({ sha256: sha256Hex(bytes), label: "TEST FIXTURE issuer profile", ...(permit || refuse ? { permit: permit ?? [], refuse: refuse ?? [], values_source: VALUES_SOURCE } : {}) }));
  });
export const withPins = (argv) => [...argv, "--pins", "<pins>"];
export const PERMIT = { permit: ["allow"], refuse: ["deny"] };

// An Annex B log whose record names the uid of a test issuer's gate receipt
// (gr-t, signed values `receipt`), carried with its profile (ip-t), cited by
// the test payer's payment; `pin` pins the profile ({ permit, refuse }, {}
// for no verdict values, or null for unpinned).
async function annexBReceiptCase({ receipt = {}, pin = PERMIT, profileAs } = {}) {
  const gr = await gateReceipt(testSecp("issuer"), receipt);
  const c = await annexBCase({ log: { receiptUid: gr.uid } });
  const bytes = addReceipts(c.doc, [{ id: "gr-t", gr }], { profileAs });
  return pin ? { doc: c.doc, pins: pinsFor([{ bytes, ...pin }]), argv: withPins(stated(c.p.tx.hash)) } : { doc: c.doc, argv: stated(c.p.tx.hash) };
}

// The same with a chirindo ALLOW record naming the receipt.
async function chirindoReceiptCase({ receipt = {}, pin = PERMIT } = {}) {
  const gr = await gateReceipt(testSecp("issuer"), receipt);
  const c = await testLogCase({ log: { receiptUids: [gr.uid] } });
  const bytes = addReceipts(c.doc, [{ id: "gr-t", gr }]);
  return pin ? { doc: c.doc, pins: pinsFor([{ bytes, ...pin }]), argv: withPins(stated(c.p.tx.hash)) } : { doc: c.doc, argv: stated(c.p.tx.hash) };
}

const T0S = 1792000000;
const RECEIPT = "a test issuer's gate receipt (gr-t; signed decision allow, evaluatedAt the block's timestamp, expiresAt 600 s later) and its issuer profile (ip-t, format chirindo-h4-issuer-profile/1, chain_id 84532, test true)";
const ANNEX_B_REC = "a test-key Annex B log whose record names the receipt's uid";
const pinsText = (what) => `; --pins names a copy of pins/pins.json pinning ip-t's sha256 ${what}`;
const STATED_PINS = withPins(STATED);
const rcRow = (id, description, change, args, build) => v(id, description, change, args, build);

// Wa-05: gate receipts (Annex C), read through issuer profiles.
export const ROWS_WA05 = [
  rcRow("S-16", "a gate receipt under an unpinned issuer profile carried under /1", `${ANNEX_B_REC}; ${RECEIPT}; ${PAY_B}`, STATED, () => annexBReceiptCase({ pin: null })),
  rcRow("S-17", "the same profile bytes carried under /2", `as S-16, ip-t declared as chirindo-h4-issuer-profile/2`, STATED, () => annexBReceiptCase({ pin: null, profileAs: "chirindo-h4-issuer-profile/2" })),
  rcRow("S-67", "a pinned profile whose permit values hold the receipt's verdict", `${ANNEX_B_REC}; ${RECEIPT}; ${PAY_B}${pinsText("with permit [allow] and refuse [deny]")}`, STATED_PINS, () => annexBReceiptCase()),
  rcRow("S-68", "a pinned profile whose refuse values hold the receipt's verdict", `as S-67, the receipt's signed decision deny`, STATED_PINS, () => annexBReceiptCase({ receipt: { decision: "deny" } })),
  rcRow("S-69", "a receipt's verdict in neither of the pinned lists", `as S-67, the receipt's signed decision review`, STATED_PINS, () => annexBReceiptCase({ receipt: { decision: "review" } })),
  rcRow("S-70", "a profile pinned without verdict values", `as S-67, ip-t pinned without permit and refuse`, STATED_PINS, () => annexBReceiptCase({ pin: {} })),
  rcRow("S-71", "an unpinned profile", `as S-67, ip-t not pinned`, STATED, () => annexBReceiptCase({ pin: null })),
  rcRow("S-72", "a chirindo ALLOW record whose receipt's verdict the pins read as refusing", `a test-key chirindo log whose record names the receipt's uid; ${RECEIPT}; ${PAY}${pinsText("with permit [] and refuse [allow]")}`, STATED_PINS, () => chirindoReceiptCase({ pin: { permit: [], refuse: ["allow"] } })),
  rcRow("S-77", "a chirindo ALLOW record whose receipt is under a profile pinned without verdict values", `as S-72, ip-t pinned without permit and refuse`, STATED_PINS, () => chirindoReceiptCase({ pin: {} })),
  rcRow("S-78", "a chirindo ALLOW record whose receipt is under an unpinned profile", `as S-72, ip-t not pinned`, STATED, () => chirindoReceiptCase({ pin: null })),
  rcRow("S-80", "a block time after the cited receipt's valid-until time", `as S-67, the receipt's evaluatedAt 1200 s and expiresAt 600 s before the block's timestamp`, STATED_PINS, () => annexBReceiptCase({ receipt: { evaluatedAt: T0S - 1200, expiresAt: T0S - 600 } })),
  rcRow("S-81", "a block time equal to the cited receipt's valid-until time", `as S-67, the receipt's evaluatedAt 600 s before the block's timestamp and expiresAt equal to it`, STATED_PINS, () => annexBReceiptCase({ receipt: { evaluatedAt: T0S - 600, expiresAt: T0S } })),
  rcRow("S-82", "a block time after the valid-until time of a receipt under an unpinned profile", `as S-80, ip-t not pinned`, STATED, () => annexBReceiptCase({ pin: null, receipt: { evaluatedAt: T0S - 1200, expiresAt: T0S - 600 } })),
  rcRow("S-83", "a block time before the cited receipt's check time", `as S-67, the receipt's evaluatedAt 60 s after the block's timestamp`, STATED_PINS, () => annexBReceiptCase({ receipt: { evaluatedAt: T0S + 60, expiresAt: T0S + 660 } })),
  rcRow("S-84", "two actions, the earlier one's receipt expired before the payment's block", `a test-key Annex B log of two records, each naming its own receipt (gr-t0: evaluatedAt 1200 s and expiresAt 600 s before the block's timestamp; gr-t1: valid), both under ip-t; record 1 cited by the test payer's payment whose nonce is its entry hash${pinsText("with permit [allow] and refuse [deny]")}`, STATED_PINS, async () => {
    const g0 = await gateReceipt(testSecp("issuer"), { action: "earlier test action", evaluatedAt: T0S - 1200, expiresAt: T0S - 600 });
    const g1 = await gateReceipt(testSecp("issuer"), { action: "cited test action" });
    const c = await annexBCase({ log: { n: 2, receiptUids: [g0.uid, g1.uid] }, seq: 1 });
    const bytes = addReceipts(c.doc, [{ id: "gr-t0", gr: g0 }, { id: "gr-t1", gr: g1 }]);
    return { doc: c.doc, pins: pinsFor([{ bytes, ...PERMIT }]), argv: withPins(stated(c.p.tx.hash)) };
  }),
  rcRow("S-87", "two gate-receipt members with one uid", `as S-67, the receipt carried twice (gr-t and gr-t2)`, STATED_PINS, async () => {
    const gr = await gateReceipt(testSecp("issuer"));
    const c = await annexBCase({ log: { receiptUid: gr.uid } });
    const bytes = addReceipts(c.doc, [{ id: "gr-t", gr }, { id: "gr-t2", gr }]);
    return { doc: c.doc, pins: pinsFor([{ bytes, ...PERMIT }]), argv: withPins(stated(c.p.tx.hash)) };
  }),
  rcRow("S-88", "a record's receipt_uid in upper case", `as S-67, the record naming the uid with its hex digits in upper case`, STATED_PINS, async () => {
    const gr = await gateReceipt(testSecp("issuer"));
    const c = await annexBCase({ log: { receiptUid: "0x" + gr.uid.slice(2).toUpperCase() } });
    const bytes = addReceipts(c.doc, [{ id: "gr-t", gr }]);
    return { doc: c.doc, pins: pinsFor([{ bytes, ...PERMIT }]), argv: withPins(stated(c.p.tx.hash)) };
  }),
  rcRow("S-89", "a context receipt under an unpinned profile beside a cited one that is pinned, permitting and valid", `a test-key Annex B log of two records; record 0, cited, names gr-t (under ip-t, pinned with permit [allow] and refuse [deny]); record 1 names gr-ctx, under a second profile ip-ctx (another label), not pinned; the test payer's payment whose nonce is record 0's entry hash`, STATED_PINS, async () => {
    const g0 = await gateReceipt(testSecp("issuer"));
    const g1 = await gateReceipt(testSecp("issuer"), { action: "context test action" });
    const c = await annexBCase({ log: { n: 2, receiptUids: [g0.uid, g1.uid] } });
    const bytes = addReceipts(c.doc, [{ id: "gr-t", gr: g0 }]);
    addReceipts(c.doc, [{ id: "gr-ctx", gr: g1 }], { profileId: "ip-ctx", label: "TEST FIXTURE second issuer profile, not pinned" });
    return { doc: c.doc, pins: pinsFor([{ bytes, ...PERMIT }]), argv: withPins(stated(c.p.tx.hash)) };
  }),
];

const WE1_STATED = ["--authorizer", "0xE65E3dE1493171dCF0A706a3f407d7DdB38C5673", "--tx", "0x30ca156899828709dac13ade34a3b2f2689bc9f2eb7690467a49c2fcaed55ce3"];
const sidecarLineOf = (doc) => JSON.parse(Buffer.from(doc.members.find((m) => m.id === "sidecar-a").bytes_b64, "base64").toString("utf8").trim());

// Wa-06: checkpoints and witness receipts carried as members of their own.
export const ROWS_WA06 = [
  v("SA-11", "WE-1 with its checkpoint and its witness receipt also carried as members", "sidecar-a's checkpoint added as a checkpoint member (cp-a, witness-spec-0.5-checkpoint) and its witness receipt as a witness-receipt member (wr-a, witness.checkpoint/1)", WE1_STATED, async () => {
    const { doc } = we1Parts();
    const line = sidecarLineOf(doc);
    add(doc, { id: "cp-a", role: "checkpoint", profile: "witness-spec-0.5-checkpoint", bytes: json(line.checkpoint) });
    add(doc, { id: "wr-a", role: "witness-receipt", profile: "witness.checkpoint/1", bytes: json(line.witness_receipt) });
    return { doc };
  }, "WE-1"),
];

// Wa-07: supporting members, carried with their digests and not verified.
export const ROWS_WA07 = [
  v("SA-12", "WE-1 with an opaque supporting member", "an opaque supporting member (sup-a, TEST FIXTURE text) added", WE1_STATED, async () => {
    const { doc } = we1Parts();
    add(doc, { id: "sup-a", role: "supporting", profile: "opaque", bytes: Buffer.from("TEST FIXTURE supporting document\n", "utf8"), media_type: "text/plain" });
    return { doc };
  }, "WE-1"),
];

// A refusal case's bundle, built as test/refusals.mjs builds it.
const caseDoc = async (id) => (await CASES.find((c) => c.id === id).build()).doc;

// Wa-08: an operator key carried as one JWK outside the legacy shape.
export const ROWS_WA08 = [
  v("SA-16", "WE-1 with its operator key carried as one JWK", "opkey-a carried as the JWK of Case A's key (profile jwk-okp-ed25519), the bundle of refusal case T-11", WE1_STATED, async () => ({ doc: await caseDoc("T-11") }), "WE-1"),
];

// Wa-09: records that name a jwks_uri.
const JWKS_URI = "https://example.invalid/.well-known/jwks.json";
export const ROWS_WA09 = [
  v("SA-13a", "records that name a jwks_uri, with the JWKS carried", `a test-key chirindo log whose records name ${JWKS_URI} as jwks_uri (iss its origin), its key carried as a JWKS (opkey-t); ${PAY}`, STATED, async () => {
    const c = await testLogCase({ log: { jwksUri: JWKS_URI } });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
  v("SA-13b", "records that name a jwks_uri, the key carried only as one JWK", `as SA-13a, the key carried only as a jwk-okp-ed25519 member (opkey-t)`, STATED, async () => {
    const c = await testLogCase({ log: { jwksUri: JWKS_URI } });
    c.doc.members = c.doc.members.filter((m) => m.id !== "opkey-t");
    add(c.doc, { id: "opkey-t", role: "operator-key", profile: "jwk-okp-ed25519", bytes: json(jwkOf(c.k)) });
    return { doc: c.doc, argv: stated(c.p.tx.hash) };
  }),
];

// Wa-10: two carried logs of one session.
export const ROWS_WA10 = [
  v("SA-14", "Case A's log carried twice", "log-a carried again as log-a2, the bundle of refusal case T-14", WE1_STATED, async () => ({ doc: await caseDoc("T-14") }), "WE-1"),
];

// Wa-11: a log that a checkpoint shows to be truncated.
export const ROWS_WA11 = [
  v("SA-15", "a truncated log cited by a payment that carries its record's hash", "the bundle of refusal case T-15 (log-t15, the first record of a two-record test-key log, and sidecar-t15, a checkpoint of count 2 signed by its key), with an EIP-3009 payment of the test payer whose nonce is log-t15 record 0's entry hash in place of WE-1's; subject.cites {log: log-t15, seq: 0}; carried_as eip3009-nonce", STATED, async () => {
    const doc = await caseDoc("T-15");
    const rec = JSON.parse(Buffer.from(doc.members.find((m) => m.id === "log-t15").bytes_b64, "base64").toString("utf8").trim());
    const blk = JSON.parse(Buffer.from(doc.members.find((m) => m.id === "blk-a").bytes_b64, "base64").toString("utf8"));
    const p = await eipPayment(blk, { nonce: entryHex(jcsSha256(withoutMember(rec, "sig"))) });
    usePayment(doc, p, "eip3009-nonce");
    doc.subject.cites = { log: "log-t15", seq: 0 };
    return { doc, argv: stated(p.tx.hash) };
  }, "WE-1, with the members of refusal case T-15 and a synthetic payment"),
];
