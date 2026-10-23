// Gate receipts (spec Annex C, M7), issuer profiles (M9.issuer-profile) and
// the gate receipt binding B-GRC (spec 4.3). A profile is read as the
// examples/ordering-evidence-h4 README's "Issuer profiles" section defines
// the format, under either of its two names; a receipt is read through the
// profile its member names, as that checker's checks b.<role>.envelope,
// .uid, .signature and .signer-key read one.

import { hashTypedData } from "viem";
import { address, recoverSigner, sigScalars } from "../../ordering-evidence-h4/lib/evm.mjs";
import { exactMembers, FormatError, hexBytes, isPlainObject, jcs, parseStrictJson } from "../../ordering-evidence-h4/lib/formats.mjs";
import { built } from "./built.mjs";

export const PROFILE_NAMES = ["chirindo-h4-issuer-profile/2", "chirindo-h4-issuer-profile/1"];
const BASE_MAINNET = 8453;
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

class Bad extends Error {}
const bad = (m) => {
  throw new Bad(m);
};
// Runs fn; a Bad, or a format error of the reused readers, is the problem it reports.
function attempt(fn) {
  try {
    return { value: fn() };
  } catch (e) {
    if (e instanceof Bad || e instanceof FormatError) return { problem: e.message };
    throw e;
  }
}
const plain = (v) => JSON.parse(JSON.stringify(v));
const sameJson = (a, b) => jcs(plain(a)) === jcs(plain(b));

export function getPath(obj, p) {
  let v = obj;
  for (const k of p.split(".")) {
    if (!isPlainObject(v) || !Object.prototype.hasOwnProperty.call(v, k)) return undefined;
    v = v[k];
  }
  return v;
}

function layoutOf(e, what) {
  if (!isPlainObject(e)) bad(`${what} is not an object`);
  exactMembers(e, ["domain", "types", "primaryType"], [], what);
  if (!isPlainObject(e.domain) || !isPlainObject(e.types) || typeof e.primaryType !== "string") bad(`${what} lacks domain, types or primaryType`);
  exactMembers(e.domain, [], ["name", "version", "chainId", "verifyingContract", "salt"], `${what}.domain`);
  if (Object.keys(e.domain).length === 0) bad(`${what}.domain is empty`);
  for (const [t, list] of Object.entries(e.types)) {
    if (!Array.isArray(list) || list.length === 0) bad(`${what}.types.${t} is not a non-empty list`);
    for (const f of list) {
      exactMembers(f, ["name", "type"], [], `${what}.types.${t} field`);
      if (typeof f.name !== "string" || typeof f.type !== "string") bad(`${what}.types.${t} has a malformed field`);
    }
  }
  const fields = e.types[e.primaryType];
  if (!Array.isArray(fields)) bad(`${what}.types has no ${e.primaryType}`);
  return { domain: plain(e.domain), types: plain(e.types), primaryType: e.primaryType, fields: plain(fields) };
}

// M9.issuer-profile (spec 4.2): the profile read strictly; its format equal
// to the member's profile; for an evm-payment subject, its chain_id (8453
// when it names none) equal to the subject's chain. Returns { profile } or
// { problem }.
built("M9.issuer-profile");
export function readIssuerProfile(bytes, memberProfile, subject) {
  const r = attempt(() => {
    let p;
    try {
      p = parseStrictJson(bytes);
    } catch (e) {
      bad(`the profile does not read as strict JSON: ${e.message}`);
    }
    exactMembers(p, ["format", "label", "test", "issuer", "receipt", "envelope", "signers"], ["sources", "request", "key_document", "chain_id", "tokens"], "issuer profile");
    if (p.format !== memberProfile) bad(`the profile's format ${JSON.stringify(p.format)} is not its member's profile ${memberProfile}`);
    if (typeof p.label !== "string" || typeof p.issuer !== "string" || typeof p.test !== "boolean") bad("label and issuer must be strings and test a boolean");
    if (p.chain_id !== undefined && (!Number.isSafeInteger(p.chain_id) || p.chain_id < 1)) bad("chain_id is not a positive integer");
    const chainId = p.chain_id ?? BASE_MAINNET;
    const tokens = [];
    if (p.tokens !== undefined) {
      if (!Array.isArray(p.tokens) || p.tokens.length === 0) bad("tokens is not a non-empty list");
      p.tokens.forEach((t, k) => {
        exactMembers(t, ["address", "name", "version"], [], `tokens[${k}]`);
        const a = address(t.address, `tokens[${k}].address`);
        if (typeof t.name !== "string" || t.name.length === 0 || typeof t.version !== "string" || t.version.length === 0) bad(`tokens[${k}] name and version must be non-empty strings`);
        if (tokens.some((x) => x.address === a)) bad("tokens list an address twice");
        tokens.push({ address: a, name: t.name, version: t.version });
      });
    }
    if (p.sources !== undefined) {
      if (!Array.isArray(p.sources)) bad("sources is not a list");
      p.sources.forEach((x, k) => {
        exactMembers(x, ["url", "fetched_at", "bytes", "sha256"], [], `sources[${k}]`);
        if (typeof x.url !== "string" || typeof x.fetched_at !== "string" || !Number.isSafeInteger(x.bytes) || typeof x.sha256 !== "string" || !SHA256_HEX_RE.test(x.sha256)) bad(`sources[${k}] is malformed`);
      });
    }
    const rc = p.receipt;
    exactMembers(rc, ["eip712", "fields", "schema_version"], [], "receipt");
    const layout = layoutOf(rc.eip712, "receipt.eip712");
    if (layout.fields.length === 0) bad(`receipt.eip712.types.${layout.primaryType} has no fields`);
    exactMembers(rc.fields, ["checked_at", "valid_until", "request_hash", "verdict", "schema_version"], [], "receipt.fields");
    const typeOf = new Map(layout.fields.map((f) => [f.name, f.type]));
    const want = { checked_at: /^uint\d+$/, valid_until: /^uint\d+$/, request_hash: /^bytes32$/, verdict: /^string$/, schema_version: /^uint\d+$/ };
    for (const [k, re] of Object.entries(want)) {
      const name = rc.fields[k];
      if (typeof name !== "string" || !typeOf.has(name)) bad(`receipt.fields.${k} names no field of ${layout.primaryType}`);
      if (!re.test(typeOf.get(name))) bad(`receipt.fields.${k} (${name}) has type ${typeOf.get(name)}`);
    }
    if (!Number.isSafeInteger(rc.schema_version) || rc.schema_version < 0) bad("receipt.schema_version is not a non-negative integer");
    const e = p.envelope;
    exactMembers(e, ["required", "optional", "uid", "signature", "signer", "message"], ["unwrap", "schema_version", "valid_until", "valid_for_seconds", "layout", "request_layout"], "envelope");
    for (const k of ["required", "optional"]) if (!Array.isArray(e[k]) || !e[k].every((x) => typeof x === "string" && NAME_RE.test(x))) bad(`envelope.${k} is not a list of member names`);
    if (new Set([...e.required, ...e.optional]).size !== e.required.length + e.optional.length) bad("envelope.required and envelope.optional repeat a name");
    if (e.unwrap !== undefined && (!Array.isArray(e.unwrap) || !e.unwrap.every((x) => typeof x === "string" && PATH_RE.test(x)))) bad("envelope.unwrap is not a list of member paths");
    for (const k of ["uid", "signature", "signer", "message", "schema_version", "valid_until", "valid_for_seconds", "layout"]) {
      if (e[k] === undefined) continue;
      if (typeof e[k] !== "string" || !NAME_RE.test(e[k])) bad(`envelope.${k} is not a member name`);
      if (!e.required.includes(e[k]) && !e.optional.includes(e[k])) bad(`envelope.${k} (${e[k]}) is in neither envelope.required nor envelope.optional`);
    }
    for (const k of ["uid", "signature", "signer", "message"]) if (!e.required.includes(e[k])) bad(`envelope.${k} must be a required member`);
    let request = null;
    if (p.request !== undefined) {
      exactMembers(p.request, ["eip712"], [], "request");
      request = layoutOf(p.request.eip712, "request.eip712");
      if (request.fields.length === 0) bad(`request.eip712.types.${request.primaryType} has no fields`);
    }
    if (e.request_layout !== undefined) {
      exactMembers(e.request_layout, ["domain", "types", "primaryType"], [], "envelope.request_layout");
      if (!Object.values(e.request_layout).every((x) => typeof x === "string" && NAME_RE.test(x))) bad("envelope.request_layout names are not member names");
      if (e.layout === undefined || !request) bad("envelope.request_layout needs envelope.layout and a request");
    }
    if (!Array.isArray(p.signers) || p.signers.length === 0) bad("signers is not a non-empty list");
    const signers = p.signers.map((x, k) => {
      exactMembers(x, ["address", "key_id", "valid_from", "valid_until"], [], `signers[${k}]`);
      const a = address(x.address, `signers[${k}].address`);
      if (typeof x.key_id !== "string") bad(`signers[${k}].key_id is not a string`);
      const from = typeof x.valid_from === "string" ? Date.parse(x.valid_from) : NaN;
      if (!Number.isFinite(from)) bad(`signers[${k}].valid_from is not a date`);
      let until = null;
      if (x.valid_until !== null) {
        until = typeof x.valid_until === "string" ? Date.parse(x.valid_until) : NaN;
        if (!Number.isFinite(until)) bad(`signers[${k}].valid_until is neither null nor a date`);
      }
      return { address: a, keyId: x.key_id, from, until, window: `${x.valid_from} to ${x.valid_until ?? "open"}` };
    });
    if (new Set(signers.map((x) => x.address)).size !== signers.length) bad("signers list an address twice");
    if (p.key_document !== undefined) {
      const k = p.key_document;
      exactMembers(k, ["url", "keys", "address"], ["key_id", "valid_from", "valid_until", "require", "role", "accepted_roles", "revoked_list", "layout"], "key_document");
      if (typeof k.url !== "string" || !/^https:\/\/\S+$/.test(k.url)) bad("key_document.url is not an https URL");
      for (const m of ["keys", "address", "key_id", "valid_from", "valid_until", "role", "revoked_list", "layout"]) if (k[m] !== undefined && (typeof k[m] !== "string" || !PATH_RE.test(k[m]))) bad(`key_document.${m} is not a member path`);
      if (k.require !== undefined) {
        if (!isPlainObject(k.require)) bad("key_document.require is not an object");
        for (const [m, x] of Object.entries(k.require)) if (!PATH_RE.test(m) || !(x === null || ["string", "boolean"].includes(typeof x) || Number.isSafeInteger(x))) bad(`key_document.require.${m} is not a plain value`);
      }
      if (k.accepted_roles !== undefined && (!Array.isArray(k.accepted_roles) || !k.accepted_roles.every((x) => typeof x === "string"))) bad("key_document.accepted_roles is not a list of strings");
    }
    // As the checker's a.chain-id: the subject's chain must be the profile's.
    if (subject.kind === "evm-payment" && `eip155:${chainId}` !== subject.chain_id) bad(`the profile's chain ${chainId}${p.chain_id === undefined ? " (Base mainnet, since it names no chain_id)" : ""} is not the subject's ${subject.chain_id}`);
    return { test: p.test, chainId, tokens, layout, fields: plain(rc.fields), schemaVersion: rc.schema_version, envelope: plain(e), request, signers, keyDocument: p.key_document !== undefined };
  });
  return r.problem ? { problem: r.problem } : { profile: r.value };
}

function typedValue(v, type, at) {
  if (type === "string") {
    if (typeof v !== "string") bad(`${at} is not a string`);
    return v;
  }
  if (type === "bytes32") return hexBytes(v, at, 32);
  if (type === "address") return address(v, at);
  if (type === "bool") {
    if (typeof v !== "boolean") bad(`${at} is not a boolean`);
    return v;
  }
  const m = /^uint(\d+)$/.exec(type);
  if (m) {
    if (!(typeof v === "number" && Number.isSafeInteger(v))) bad(`${at} is not a JSON integer`);
    const b = BigInt(v);
    if (b < 0n || b >= 1n << BigInt(m[1])) bad(`${at} is outside ${type}`);
    return b;
  }
  bad(`${at} has type ${type}, which this verifier does not read`);
}

// M7 (spec 4.2 and Annex C) for one gate receipt read through profile P:
// M7.envelope, M7.uid (its EIP-712 digest; that no other member has the same
// uid is checked across members), M7.signature and M7.signer-key, each NOT
// EVALUATED when the one before it did not pass. Returns { rows: [[id,
// status, reason, detail]], r } with r the receipt's uid, signed values,
// signer and times when the envelope reads.
built("M7.envelope", "M7.uid", "M7.signature", "M7.signer-key");
export async function m7Receipt(bytes, P) {
  const rows = [];
  const F = P.fields;
  const E = P.envelope;
  const env0 = attempt(() => {
    let env;
    try {
      env = parseStrictJson(bytes);
    } catch (e) {
      bad(`the receipt does not read as strict JSON: ${e.message}`);
    }
    let unwrapped = "";
    if (isPlainObject(env) && !Object.prototype.hasOwnProperty.call(env, E.uid))
      for (const u of E.unwrap ?? []) {
        const inner = getPath(env, u);
        if (isPlainObject(inner) && Object.prototype.hasOwnProperty.call(inner, E.uid)) {
          env = inner;
          unwrapped = `read ${u} of the member (its other members are not checked); `;
          break;
        }
      }
    exactMembers(env, E.required, E.optional, "the envelope");
    const uid = hexBytes(env[E.uid], `envelope ${E.uid}`, 32);
    hexBytes(env[E.signature], `envelope ${E.signature}`, 65);
    const claimed = address(env[E.signer], `envelope ${E.signer}`);
    if (E.schema_version !== undefined && env[E.schema_version] !== undefined && env[E.schema_version] !== P.schemaVersion) bad(`envelope ${E.schema_version} is ${JSON.stringify(env[E.schema_version])}, not ${P.schemaVersion}`);
    exactMembers(env[E.message], P.layout.fields.map((f) => f.name), [], `envelope ${E.message}`);
    const msg = {};
    for (const f of P.layout.fields) msg[f.name] = typedValue(env[E.message][f.name], f.type, `${E.message}.${f.name}`);
    if (msg[F.schema_version] !== BigInt(P.schemaVersion)) bad(`${E.message}.${F.schema_version} is ${msg[F.schema_version]}, not ${P.schemaVersion}`);
    for (const k of [E.valid_until, E.valid_for_seconds]) if (k !== undefined && env[k] !== undefined && !Number.isSafeInteger(env[k])) bad(`the envelope's ${k} is not a JSON integer`);
    if (E.valid_until !== undefined && env[E.valid_until] !== undefined && BigInt(env[E.valid_until]) !== msg[F.valid_until]) bad(`the envelope's ${E.valid_until} differs from the signed ${F.valid_until}`);
    if (E.valid_for_seconds !== undefined && env[E.valid_for_seconds] !== undefined && BigInt(env[E.valid_for_seconds]) !== msg[F.valid_until] - msg[F.checked_at]) bad(`the envelope's ${E.valid_for_seconds} is not ${F.valid_until} minus ${F.checked_at}`);
    if (E.layout !== undefined && env[E.layout] !== undefined) {
      const L = env[E.layout];
      const RL = E.request_layout;
      exactMembers(L, ["domain", "types", "primaryType"], RL ? [RL.domain, RL.types, RL.primaryType] : [], `envelope ${E.layout}`);
      if (!sameJson({ d: L.domain, t: L.types, p: L.primaryType }, { d: P.layout.domain, t: P.layout.types, p: P.layout.primaryType })) bad(`the envelope's ${E.layout} domain, types or primaryType differ from the profile's`);
      if (RL && [RL.domain, RL.types, RL.primaryType].some((n) => L[n] !== undefined) && !sameJson({ d: L[RL.domain], t: L[RL.types], p: L[RL.primaryType] }, { d: P.request.domain, t: P.request.types, p: P.request.primaryType })) bad("the envelope's request layout differs from the profile's");
    }
    return { env, uid, claimed, msg, unwrapped };
  });
  if (env0.problem) {
    rows.push(["M7.envelope", "FAIL", null, env0.problem]);
    for (const id of ["M7.uid", "M7.signature", "M7.signer-key"]) rows.push([id, "NOT-EVALUATED", `prerequisite-failed:${rows[rows.length - 1][0]}`, ""]);
    return { rows, r: null };
  }
  const { env, uid, claimed, msg, unwrapped } = env0.value;
  rows.push(["M7.envelope", "PASS", null, `${unwrapped}${P.layout.primaryType} envelope; the ${P.layout.fields.length} signed fields are exactly the profile's layout; ${E.message}.${F.schema_version} is ${P.schemaVersion}`]);
  const r = { uid, msg, claimed, verdict: msg[F.verdict], checkedAt: msg[F.checked_at], validUntil: msg[F.valid_until], signer: null };
  const digest = hashTypedData({ domain: P.layout.domain, types: P.layout.types, primaryType: P.layout.primaryType, message: msg });
  if (digest !== uid) {
    rows.push(["M7.uid", "FAIL", null, `${E.uid} ${uid} is not the EIP-712 digest ${digest} recomputed from the profile's domain and types`]);
    rows.push(["M7.signature", "NOT-EVALUATED", "prerequisite-failed:M7.uid", ""], ["M7.signer-key", "NOT-EVALUATED", "prerequisite-failed:M7.signature", ""]);
    return { rows, r };
  }
  rows.push(["M7.uid", "PASS", null, `${E.uid} ${uid} equals the EIP-712 digest recomputed from the profile's domain and types`]);
  const sig = env[E.signature];
  const sres = await (async () => {
    const rr = BigInt("0x" + sig.slice(2, 66));
    const ss = BigInt("0x" + sig.slice(66, 130));
    const v = parseInt(sig.slice(130, 132), 16);
    if (v !== 27 && v !== 28) return { problem: `${E.signature} v is ${v}, not 27 or 28` };
    const sc = attempt(() => sigScalars(rr, ss, "receipt signature"));
    if (sc.problem) return { problem: sc.problem };
    const signer = await recoverSigner(uid, rr, ss, v - 27);
    if (signer !== claimed) return { problem: `${E.signature} recovers to ${signer}, not the envelope's ${E.signer} ${claimed}` };
    return { signer, v };
  })();
  if (sres.problem) {
    rows.push(["M7.signature", "FAIL", null, sres.problem], ["M7.signer-key", "NOT-EVALUATED", "prerequisite-failed:M7.signature", ""]);
    return { rows, r };
  }
  r.signer = sres.signer;
  rows.push(["M7.signature", "PASS", null, `${E.signature} (v ${sres.v}, low s) recovers to ${sres.signer}, the envelope's ${E.signer}`]);
  const hits = P.signers.filter((x) => x.address === sres.signer);
  const at = Number(r.checkedAt) * 1000;
  if (hits.length !== 1) rows.push(["M7.signer-key", "FAIL", null, `signer ${sres.signer} is not among the profile's signers`]);
  else if (at < hits[0].from || (hits[0].until !== null && at > hits[0].until)) rows.push(["M7.signer-key", "FAIL", null, `signer ${sres.signer} is ${hits[0].keyId}, valid ${hits[0].window}, which does not hold the receipt's ${F.checked_at}`]);
  else rows.push(["M7.signer-key", "PASS", null, `signer ${sres.signer} is the profile's ${hits[0].keyId} (${hits[0].window}), valid at the receipt's ${F.checked_at}`]);
  return { rows, r };
}

// How the pins read a receipt's verdict (spec 4.2 and 4.3, "The cited
// decision"): permit, refuse, or null under an unpinned profile, a profile
// pinned without verdict values, or a value in neither list.
export function reading(pin, verdict) {
  if (!pin) return null;
  const permit = pin.permit ?? [];
  const refuse = pin.refuse ?? [];
  if (permit.includes(verdict)) return "permit";
  if (refuse.includes(verdict)) return "refuse";
  return null;
}

// A receipt's own state (spec 4.3, B-GRC; the state B-GRC would have from
// that receipt alone), from its checks, the records that carry its uid, its
// profile's pin, and the payment block's timestamp when M5.block-hash bound it
// (null otherwise: the times are then reported, not judged). Returns
// { state, reason, flags }.
built("B-GRC.receipts");
export function ownState(x, blockTs) {
  if (!x.ok) return { state: "FAIL", reason: null, flags: [] };
  if (x.records.length !== 1) return { state: "FAIL", reason: null, flags: [] };
  const after = blockTs !== null && blockTs > x.r.validUntil;
  if (!x.pin) return { state: "SUPPLIED", reason: null, flags: after ? ["after-receipt-expiry"] : [] };
  if (after) return { state: "EXCEEDS", reason: "after-receipt-expiry", flags: [] };
  if (blockTs !== null && blockTs < x.r.checkedAt) return { state: "NOT-EVALUATED", reason: "before-receipt-check", flags: [] };
  return { state: "BOUND", reason: null, flags: [] };
}
