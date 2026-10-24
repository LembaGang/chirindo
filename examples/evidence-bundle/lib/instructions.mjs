// Instructions (spec Annex A, M6) and the instruction binding B-INS (spec
// 4.3, steps 1 to 5 and the aggregate).

import { createHash } from "node:crypto";
import { address } from "../../ordering-evidence-h4/lib/evm.mjs";
import { b64urlCanonical, ed25519Verify, isPlainObject, jcs, jcsSha256, okpThumbprint, parseStrictJson, withoutMember } from "../../ordering-evidence-h4/lib/formats.mjs";
import { built } from "./built.mjs";
import { tsMs } from "./records.mjs";
import { THUMBPRINT_RE } from "./table.mjs";

export const ANNEX_A = "signed-instruction-ed25519/0.2";
const isStr = (v) => typeof v === "string";
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");

class Bad extends Error {}
const bad = (m) => {
  throw new Bad(m);
};
function exactly(obj, required, optional, what) {
  if (!isPlainObject(obj)) bad(`${what} is not a JSON object`);
  for (const k of required) if (!Object.keys(obj).includes(k)) bad(`${what} lacks member ${k}`);
  for (const k of Object.keys(obj)) if (!required.includes(k) && !optional.includes(k)) bad(`${what} has a member Annex A does not name: ${JSON.stringify(k)}`);
}
const addr = (s, what) => {
  try {
    return address(s, what);
  } catch (e) {
    bad(e.message);
  }
};

// M6 (spec 4.2 and Annex A): exactly Annex A's members with their types; v;
// principal.kid the thumbprint of its key; sig over the JCS bytes without
// sig; valid_from not after valid_until; addresses by the rule of 4.1.
// Returns { value, digest } or { problem }.
built("M6.instruction");
export function m6Instruction(bytes) {
  let ins;
  try {
    ins = parseStrictJson(bytes);
  } catch (e) {
    return { problem: `the member does not read as strict JSON: ${e.message}` };
  }
  try {
    exactly(ins, ["v", "principal", "agent_kid", "text", "constraints", "iat", "sig"], [], "the instruction");
    if (ins.v !== ANNEX_A) bad(`v is not ${ANNEX_A}`);
    exactly(ins.principal, ["kid", "public_key_jwk"], [], "principal");
    const jwk = ins.principal.public_key_jwk;
    exactly(jwk, ["kty", "crv", "x"], [], "principal.public_key_jwk");
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") bad("principal.public_key_jwk is not kty OKP, crv Ed25519");
    let pub;
    try {
      pub = b64urlCanonical(jwk.x, 32, "principal.public_key_jwk.x");
    } catch (e) {
      bad(e.message);
    }
    if (ins.principal.kid !== okpThumbprint(jwk.x)) bad("principal.kid is not the RFC 7638 thumbprint of principal.public_key_jwk");
    if (!Array.isArray(ins.agent_kid) || ins.agent_kid.length === 0 || !ins.agent_kid.every((k) => isStr(k) && THUMBPRINT_RE.test(k))) bad("agent_kid is not a non-empty list of 43-character thumbprints");
    if (!isStr(ins.text)) bad("text is not a string");
    const c = ins.constraints;
    exactly(c, ["chain_id", "asset", "max_amount", "payees", "valid_from", "valid_until"], ["max_uses", "budget"], "constraints");
    if (!isStr(c.chain_id) || !/^eip155:[1-9][0-9]*$/.test(c.chain_id)) bad("constraints.chain_id is not eip155:<decimal chain id>");
    if (c.asset !== "native") addr(c.asset, "constraints.asset");
    if (!isStr(c.max_amount) || !DECIMAL.test(c.max_amount)) bad("constraints.max_amount is not a decimal string with no sign and no leading zero");
    if (Object.keys(c).includes("budget") && !(isStr(c.budget) && DECIMAL.test(c.budget))) bad("constraints.budget is not a decimal string with no sign and no leading zero");
    if (Object.keys(c).includes("max_uses") && !(Number.isSafeInteger(c.max_uses) && c.max_uses >= 1)) bad("constraints.max_uses is not an integer of at least 1");
    if (!Array.isArray(c.payees) || c.payees.length === 0) bad("constraints.payees is not a non-empty list");
    c.payees.forEach((p, i) => addr(p, `constraints.payees[${i}]`));
    if (tsMs(c.valid_from) === null || tsMs(c.valid_until) === null) bad("constraints.valid_from or valid_until is not a time");
    if (tsMs(c.valid_from) > tsMs(c.valid_until)) bad("constraints.valid_from is after valid_until");
    if (tsMs(ins.iat) === null) bad("iat is not a time");
    let sig;
    try {
      sig = b64urlCanonical(ins.sig, 64, "sig");
    } catch (e) {
      bad(e.message);
    }
    if (!ed25519Verify(pub, Buffer.from(jcs(withoutMember(ins, "sig")), "utf8"), sig)) bad("sig does not verify under principal.public_key_jwk");
  } catch (e) {
    if (e instanceof Bad) return { problem: e.message };
    throw e;
  }
  // The digest an action cites: the JCS SHA-256 of the whole object, sig included.
  return { value: ins, digest: jcsSha256(ins) };
}

// The digest of an instruction member that is not Annex A: its bytes as captured.
export const capturedDigest = (bytes) => "sha256:" + sha256Hex(bytes);

const EXCEEDED_ORDER = ["chain_id", "asset", "payees", "max_amount", "valid_from", "valid_until", "agent_kid", "max_uses", "budget"];

// Spec 4.3, B-INS step 5: an Annex A instruction's constraints against the
// payment values `pv` ({ chain, movements, blockTs, kid }) and its use count.
// Returns the constraints exceeded, in the order of the output schema.
built("B-INS.compare");
export function exceededBy(ins, pv, uses) {
  const c = ins.constraints;
  const out = new Set();
  const asset = c.asset === "native" ? "native" : c.asset.toLowerCase();
  const payees = c.payees.map((p) => p.toLowerCase());
  if (c.chain_id !== pv.chain) out.add("chain_id");
  if (pv.movements.some((m) => m.asset !== asset)) out.add("asset");
  if (pv.movements.some((m) => !payees.includes(m.payee))) out.add("payees");
  const inAsset = pv.movements.filter((m) => m.asset === asset).reduce((s, m) => s + BigInt(m.amount), 0n);
  if (inAsset > BigInt(c.max_amount)) out.add("max_amount");
  const t = Number(pv.blockTs) * 1000;
  if (t < tsMs(c.valid_from)) out.add("valid_from");
  if (t > tsMs(c.valid_until)) out.add("valid_until");
  if (!ins.agent_kid.includes(pv.kid)) out.add("agent_kid");
  if (uses > (c.max_uses ?? 1)) out.add("max_uses");
  // The payments the bundle binds: in this version, the subject payment alone.
  if (Object.keys(c).includes("budget") && inAsset > BigInt(c.budget)) out.add("budget");
  return EXCEEDED_ORDER.filter((x) => out.has(x));
}

// The arguments hash a record names: event.args_hash in a chirindo record, a
// top-level args_hash in an Annex B record.
export const argsHashOf = (rec, profile) => (profile === "jcs-sha256-chain/0.1" ? rec.args_hash : isPlainObject(rec.event) ? rec.event.args_hash : undefined);
// The result hash likewise (spec M8).
export const resultHashOf = (rec, profile) => (profile === "jcs-sha256-chain/0.1" ? rec.result_hash : isPlainObject(rec.event) ? rec.event.result_hash : undefined);

// Uses of an instruction digest over what the bundle carries (spec 4.3, step
// 5, max_uses; L13): the records whose carried arguments cite it, and the
// records whose arguments are not carried.
export function usesOf(digest, logs, argMembers) {
  let uses = 0;
  let without = 0;
  for (const l of logs)
    for (const r of l.records) {
      const h = argsHashOf(r, l.profile);
      if (!isStr(h)) continue;
      const a = argMembers.find((x) => x.digest === h);
      if (!a) without++;
      else if (isPlainObject(a.value) && a.value.instruction_sha256 === digest) uses++;
    }
  return { uses, without };
}

// Spec 4.3, B-INS steps 3 and 4: a vi-0.1-draft or ap2-0.2 member, cited or
// not, is carried with its digest and not verified.
built("B-INS.present");
const present = (row) => Object.assign(row, { state: "PRESENT" });

// B-INS (spec 4.3): per carried instruction, and the aggregate. `ins` are the
// instruction members ({ member, profile, digest, value, m6 }); `A` the
// cited record's carried arguments or null; `pv` the payment values, or null
// when no payer is derived (then `bpay` names B-PAY's state); `unread` the
// outflows the reading of the calldata path could not judge.
export function bIns({ ins, A, pv, bpayState, logs, argMembers, unread = [] }) {
  const D = A && isPlainObject(A.value) && Object.keys(A.value).includes("instruction_sha256") ? A.value.instruction_sha256 : null;
  const rows = ins.map((i) => {
    const { uses, without } = usesOf(i.digest, logs, argMembers);
    return { member: i.member, cited: D !== null && i.digest === D, state: null, exceeded: [], reason: null, uses, records_without_arguments: without, i };
  });
  const compare = (row, inside, outside) => {
    if (!pv) return Object.assign(row, { state: "NOT-EVALUATED", reason: "no-payer-derived" });
    const ex = exceededBy(row.i.value, pv, row.uses);
    // An incomplete outflow reading (step 5): what was read is judged first.
    if (unread.length) return Object.assign(row, ex.length ? { state: outside, exceeded: ex, reason: "unread-outflow" } : { state: "NOT-EVALUATED", exceeded: [], reason: "unread-outflow" });
    return Object.assign(row, { state: ex.length ? outside : inside, exceeded: ex });
  };
  for (const row of rows) {
    if (row.i.profile !== ANNEX_A) present(row);
    else if (row.i.m6 !== "PASS") row.state = "FAIL";
    else if (row.cited) compare(row, "BOUND", "EXCEEDS");
    else compare(row, "MATCHED", "UNBOUND-OUTSIDE");
  }
  const out = rows.map(({ i, ...r }) => r);
  const why = !pv ? ` (no payer is derived; B-PAY is ${bpayState})` : "";
  let agg;
  if (out.some((r) => r.state === "FAIL")) agg = { state: "FAIL", reason: null, detail: "an instruction fails M6" };
  else if (D !== null) {
    const c = out.find((r) => r.cited);
    agg = c ? { state: c.state, reason: c.reason, detail: `${c.member} is the instruction the arguments cite${why}` } : { state: "WITHHELD", reason: null, detail: `${A.member} cites ${D}, which no carried instruction has` };
  } else if (out.length === 0) agg = A ? { state: "ABSENT", reason: null, detail: `${A.member} carries no instruction_sha256` } : { state: "NOT-EVALUATED", reason: "args-not-carried", detail: "the cited record's arguments are not carried, and no instruction is" };
  else {
    const first = ["UNBOUND-OUTSIDE", "MATCHED", "NOT-EVALUATED", "PRESENT"].map((s) => out.find((r) => r.state === s)).find(Boolean);
    agg = { state: first.state, reason: first.reason, detail: `no instruction is cited; ${first.member} is ${first.state}${why}` };
  }
  // The aggregate with an incomplete outflow reading: EXCEEDS when the cited
  // instruction is, and otherwise NOT EVALUATED, whatever instructions are carried.
  if (unread.length && agg.state !== "FAIL") {
    const what = `the outflow reading is incomplete: ${unread.map((u) => `${u.event} (log ${u.log_index})`).join(", ")} not judged`;
    const c = out.find((r) => r.cited);
    agg = c && c.state === "EXCEEDS" ? { state: "EXCEEDS", reason: "unread-outflow", detail: `${c.member} is exceeded (${c.exceeded.join(", ")}); ${what}` } : { state: "NOT-EVALUATED", reason: "unread-outflow", detail: what };
  }
  return { agg, rows: out };
}
