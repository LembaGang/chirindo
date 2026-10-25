// Instructions (spec Annex A, M6) and the instruction binding B-INS (spec
// 4.3, steps 1 to 5 and the aggregate).

import { createHash } from "node:crypto";
import { address } from "../../ordering-evidence-h4/lib/evm.mjs";
import { b64urlCanonical, ed25519Verify, isPlainObject, jcs, jcsSha256, okpThumbprint, parseStrictJson, withoutMember } from "../../ordering-evidence-h4/lib/formats.mjs";
import { built } from "./built.mjs";
import { compareInstants, dateOk } from "./card.mjs";
import { tsMs } from "./records.mjs";
import { THUMBPRINT_RE } from "./table.mjs";

export const ANNEX_A = "signed-instruction-ed25519/0.2";
export const ANNEX_A3 = "signed-instruction-ed25519/0.3";
// The instruction profiles M6 verifies; the others are carried as PRESENT.
export const M6_PROFILES = [ANNEX_A, ANNEX_A3];
const PAYMENT_LIMITS = ["chain_id", "asset", "max_amount", "payees"];
// Annex A.3's card member, in its order (also the order of card_limits).
export const CARD_LIMITS = ["currency", "max_total_minor", "max_unit_price_minor", "merchants", "items", "categories", "refundable_only", "service_window", "locations"];
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

// Annex A.3's card member: currency and at least one other member that
// limits something (refundable_only false limits nothing, so it does not count).
function checkCard(card) {
  exactly(card, ["currency"], CARD_LIMITS.slice(1), "constraints.card");
  const has = (k) => Object.keys(card).includes(k);
  if (!isStr(card.currency) || !/^[A-Z]{3}$/.test(card.currency)) bad("constraints.card.currency is not three upper-case letters");
  for (const k of ["max_total_minor", "max_unit_price_minor"]) if (has(k) && !(isStr(card[k]) && DECIMAL.test(card[k]))) bad(`constraints.card.${k} is not a decimal string with no sign and no leading zero`);
  for (const k of ["merchants", "items", "categories", "locations"])
    if (has(k) && !(Array.isArray(card[k]) && card[k].length > 0 && card[k].every((x) => isStr(x) && x.length >= 1 && x.length <= 256))) bad(`constraints.card.${k} is not a non-empty list of strings of 1 to 256 characters`);
  if (has("refundable_only") && typeof card.refundable_only !== "boolean") bad("constraints.card.refundable_only is not a boolean");
  if (has("service_window")) {
    exactly(card.service_window, ["from", "until"], [], "constraints.card.service_window");
    if (!dateOk(card.service_window.from) || !dateOk(card.service_window.until)) bad("constraints.card.service_window.from or until is not a date YYYY-MM-DD");
    if (card.service_window.from > card.service_window.until) bad("constraints.card.service_window.from is after until");
  }
  if (!Object.keys(card).some((k) => k !== "currency" && !(k === "refundable_only" && card[k] === false))) bad("constraints.card holds no member beyond currency that limits something (refundable_only false limits nothing)");
}

// M6 (spec 4.2, Annex A and Annex A.3): exactly the profile's members with
// their types; v; principal.kid the thumbprint of its key; sig over the JCS
// bytes without sig; valid_from not after valid_until; addresses by the rule
// of 4.1; for profile 0.3, the card member. Returns { value, digest } or
// { problem }.
built("M6.instruction");
export function m6Instruction(bytes, profile = ANNEX_A) {
  let ins;
  try {
    ins = parseStrictJson(bytes);
  } catch (e) {
    return { problem: `the member does not read as strict JSON: ${e.message}` };
  }
  try {
    exactly(ins, ["v", "principal", "agent_kid", "text", "constraints", "iat", "sig"], [], "the instruction");
    if (ins.v !== profile) bad(`v is not ${profile}`);
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
    // Annex A.3: with card, chain_id, asset, max_amount and payees are all four or none.
    const hasCard = profile === ANNEX_A3 && isPlainObject(c) && Object.keys(c).includes("card");
    const named = isPlainObject(c) ? PAYMENT_LIMITS.filter((k) => Object.keys(c).includes(k)) : [];
    if (hasCard && named.length !== 0 && named.length !== PAYMENT_LIMITS.length) bad("constraints names some of chain_id, asset, max_amount and payees; with card, Annex A.3 allows all four or none");
    const payment = !hasCard || named.length === PAYMENT_LIMITS.length;
    exactly(c, [...(payment ? PAYMENT_LIMITS : []), "valid_from", "valid_until"], ["max_uses", "budget", ...(profile === ANNEX_A3 ? ["card"] : [])], "constraints");
    if (payment) {
      if (!isStr(c.chain_id) || !/^eip155:[1-9][0-9]*$/.test(c.chain_id)) bad("constraints.chain_id is not eip155:<decimal chain id>");
      if (c.asset !== "native") addr(c.asset, "constraints.asset");
      if (!isStr(c.max_amount) || !DECIMAL.test(c.max_amount)) bad("constraints.max_amount is not a decimal string with no sign and no leading zero");
    }
    if (Object.keys(c).includes("budget") && !(isStr(c.budget) && DECIMAL.test(c.budget))) bad("constraints.budget is not a decimal string with no sign and no leading zero");
    if (Object.keys(c).includes("max_uses") && !(Number.isSafeInteger(c.max_uses) && c.max_uses >= 1)) bad("constraints.max_uses is not an integer of at least 1");
    if (payment) {
      if (!Array.isArray(c.payees) || c.payees.length === 0) bad("constraints.payees is not a non-empty list");
      c.payees.forEach((p, i) => addr(p, `constraints.payees[${i}]`));
    }
    if (hasCard) checkCard(c.card);
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

const EXCEEDED_ORDER = ["chain_id", "asset", "payees", "max_amount", "valid_from", "valid_until", "agent_kid", "max_uses", "budget", ...CARD_LIMITS];

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

// Spec 4.3, "B-INS for a card subject", step 5: a profile 0.3 instruction's
// card limits against the committed order, each with its result, and its own
// members against the cited log's kid, the use count and the stated
// authorization time. Returns { card_limits, exceeded, missing }, where
// missing says a limit the instruction sets lacks a field of the order.
built("B-INS.card");
export function cardLimitsOf(ins, order, { kid, authorizedAt }, uses) {
  const card = ins.constraints.card;
  const items = order.items;
  const has = (o, k) => Object.keys(o).includes(k);
  // Each item read for one limit: true inside, false outside, null its field missing.
  const everyItem = (fields, ok) => {
    const r = items.map((it) => (fields.every((f) => has(it, f)) ? ok(it) : null));
    return r.includes(false) ? "outside" : r.includes(null) ? "not-evaluated" : "inside";
  };
  const judge = {
    currency: () => (order.currency === card.currency ? "inside" : "outside"),
    max_total_minor: () => (BigInt(order.total_minor) <= BigInt(card.max_total_minor) ? "inside" : "outside"),
    max_unit_price_minor: () => everyItem(["unit_price_minor"], (it) => BigInt(it.unit_price_minor) <= BigInt(card.max_unit_price_minor)),
    merchants: () => (card.merchants.includes(order.merchant_id) ? "inside" : "outside"),
    items: () => everyItem(["sku"], (it) => card.items.includes(it.sku)),
    categories: () => everyItem(["category"], (it) => card.categories.includes(it.category)),
    refundable_only: () => everyItem(["refundable"], (it) => it.refundable === true),
    service_window: () => everyItem(["service_from", "service_until"], (it) => it.service_from >= card.service_window.from && it.service_until <= card.service_window.until),
    locations: () => everyItem(["location"], (it) => card.locations.includes(it.location)),
  };
  // A limit the card does not set, and refundable_only false, limit nothing.
  const card_limits = CARD_LIMITS.map((k) => {
    const result = !has(card, k) || (k === "refundable_only" && card[k] === false) ? "not-declared" : judge[k]();
    return { limit: k, result, reason: result === "not-evaluated" ? "order-field-missing" : null };
  });
  const out = new Set(card_limits.filter((l) => l.result === "outside").map((l) => l.limit));
  const c = ins.constraints;
  if (compareInstants(authorizedAt, c.valid_from) < 0) out.add("valid_from");
  if (compareInstants(authorizedAt, c.valid_until) > 0) out.add("valid_until");
  if (!ins.agent_kid.includes(kid)) out.add("agent_kid");
  if (uses > (c.max_uses ?? 1)) out.add("max_uses");
  return { card_limits, exceeded: EXCEEDED_ORDER.filter((x) => out.has(x)), missing: card_limits.some((l) => l.result === "not-evaluated") };
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
// outflows the reading of the calldata path could not judge. `card`, for a
// card subject with a stated charge, gives { order, orderOk, kid,
// authorizedAt }, and step 5 then reads the committed order instead of pv.
export function bIns({ ins, A, pv, bpayState, logs, argMembers, unread = [], card = null }) {
  const D = A && isPlainObject(A.value) && Object.keys(A.value).includes("instruction_sha256") ? A.value.instruction_sha256 : null;
  const rows = ins.map((i) => {
    const { uses, without } = usesOf(i.digest, logs, argMembers);
    return { member: i.member, cited: D !== null && i.digest === D, state: null, exceeded: [], reason: null, uses, records_without_arguments: without, card_limits: [], i };
  });
  const compare = (row, inside, outside) => {
    if (card) return compareCard(row, inside, outside);
    if (!pv) return Object.assign(row, { state: "NOT-EVALUATED", reason: "no-payer-derived" });
    const ex = exceededBy(row.i.value, pv, row.uses);
    // An incomplete outflow reading (step 5): what was read is judged first.
    if (unread.length) return Object.assign(row, ex.length ? { state: outside, exceeded: ex, reason: "unread-outflow" } : { state: "NOT-EVALUATED", exceeded: [], reason: "unread-outflow" });
    return Object.assign(row, { state: ex.length ? outside : inside, exceeded: ex });
  };
  // Step 5 for a card subject: no order, a 0.2 instruction, a 0.3 one
  // without card, then the limits; an outside limit beside a missing field is
  // EXCEEDS with the reason order-field-missing.
  const compareCard = (row, inside, outside) => {
    if (!card.order) return Object.assign(row, { state: "NOT-EVALUATED", reason: "no-order-committed" });
    if (!card.orderOk) return Object.assign(row, { state: "NOT-EVALUATED", reason: "prerequisite-failed:M8.order" });
    if (row.i.profile === ANNEX_A) return Object.assign(row, { state: "NOT-EVALUATED", reason: "no-card-limits" });
    if (!Object.keys(row.i.value.constraints).includes("card")) return Object.assign(row, { state: "NOT-EVALUATED", reason: "card-limits-not-declared" });
    const { card_limits, exceeded, missing } = cardLimitsOf(row.i.value, card.order, card, row.uses);
    const reason = missing ? "order-field-missing" : null;
    return Object.assign(row, exceeded.length ? { state: outside, exceeded, reason, card_limits } : { state: missing ? "NOT-EVALUATED" : inside, exceeded: [], reason, card_limits });
  };
  for (const row of rows) {
    if (!M6_PROFILES.includes(row.i.profile)) present(row);
    else if (row.i.m6 !== "PASS") row.state = "FAIL";
    else if (row.cited) compare(row, "BOUND", "EXCEEDS");
    else compare(row, "MATCHED", "UNBOUND-OUTSIDE");
  }
  const out = rows.map(({ i, ...r }) => r);
  const why = !pv && !card ? ` (no payer is derived; B-PAY is ${bpayState})` : "";
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
