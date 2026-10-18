// lib/check.mjs: the checks that check-h4.mjs runs on one ordering-evidence
// case for a third-party pre-trade workflow on Base: two EIP-712 receipts
// from a pre-trade check issuer, read through an issuer profile that the
// verifier pins by sha256, the hash-chained log entries that carry their
// uids, an Ed25519 checkpoint of that log witnessed by Headless Oracle, and a
// transaction in which the account the verifier names (--authorizer) signed
// bytes that carry the later (destination) entry's hash. Offline, the chain
// facts are as the case supplies them and the run never passes. README.md in
// the folder above states the case layout, the profile format, the log rules,
// the exit codes and what each mode does and does not show.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { domainSeparator, getAddress, hashTypedData, keccak256 } from "viem";
import {
  FormatError,
  SHA256_RE,
  b64urlCanonical,
  ed25519Verify,
  exactMembers,
  hexBytes,
  isPlainObject,
  isoUtc,
  jcs,
  jcsSha256,
  okpThumbprint,
  parseStrictJson,
  quantity,
  sha256Hex,
  withoutMember,
} from "./formats.mjs";
import {
  AUTHORIZATION_USED_TOPIC,
  EIP3009_ABI,
  ENTRYPOINTS,
  TRANSFER_TOPIC,
  USEROP_ABI,
  address,
  cborToText,
  decodeAbiString,
  decodeCall,
  findBytes,
  findFragment,
  headerHash,
  parseErc8021,
  recoverAuthorization,
  recoverSigner,
  selectorOf,
  shortError,
  sigScalars,
  txSerialization,
} from "./evm.mjs";
import { RPC_ENDPOINTS, getJson, rpc, witnessReceipts } from "./online.mjs";

// The checker's folder (this file is in its lib/ folder).
const FOLDER = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
export const CASE_FORMAT = "chirindo-h4-case/1";
export const PINS_FORMAT = "chirindo-h4-pins/2";
export const PROFILE_FORMAT = "chirindo-h4-issuer-profile/1";
export const HO_WITNESS_KEY_ID = "key_2026_v1";
export const HO_WITNESS_PUBLIC_HEX = "03dc27993a2c90856cdeb45e228ac065f18f69f0933c917b2336c1e75712f178";
// Base mainnet: the chain a case must be on unless the pinned profile names another.
export const BASE_MAINNET = 8453;
const CHECKPOINT_TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const WITNESS_FIELDS = ["type", "witness", "received_at", "kid", "session_id", "count", "last_entry_hash", "checkpoint_ts", "checkpoint_sha256", "fork", "public_key_id"];
const ROLES = ["source", "destination"];

class CheckFail extends Error {}
const fail = (msg) => {
  throw new CheckFail(msg);
};

class Report {
  constructor() {
    this.rows = [];
  }
  add(status, id, text) {
    this.rows.push({ status, id, text });
  }
  count(status) {
    return this.rows.filter((r) => r.status === status).length;
  }
  ids(status) {
    return this.rows.filter((r) => r.status === status).map((r) => r.id);
  }
}

// Runs one check. A returned string is a PASS; CheckFail or any other error is
// a FAIL; undefined means the check wrote its own line.
async function check(r, ok, id, deps, fn) {
  const missing = deps.filter((d) => !ok[d]);
  if (missing.length) {
    r.add("NOT CHECKED", id, `not run because ${missing.join(", ")} did not pass`);
    ok[id] = false;
    return false;
  }
  try {
    const text = await fn();
    if (typeof text === "string") r.add("PASS", id, text);
    ok[id] = true;
    return true;
  } catch (e) {
    // shortError keeps the first line of a library error, whose details can
    // repeat calldata that holds a party's address.
    r.add("FAIL", id, e instanceof CheckFail ? e.message : `error: ${shortError(e)}`);
    ok[id] = false;
    return false;
  }
}

const plain = (v) => JSON.parse(JSON.stringify(v));
const sameJson = (a, b) => jcs(plain(a)) === jcs(plain(b));
const pad32Addr = (a) => "0x" + "0".repeat(24) + a.slice(2);
const secondsIso = (s) => `${s} (${isoUtc(s)})`;

function typedValue(v, type, name, where = "data") {
  const at = `${where}.${name}`;
  if (type === "string") {
    if (typeof v !== "string") fail(`${at} is not a string`);
    return v;
  }
  if (type === "bytes32") return hexBytes(v, at, 32);
  if (type === "address") return address(v, at);
  if (type === "bool") {
    if (typeof v !== "boolean") fail(`${at} is not a boolean`);
    return v;
  }
  const m = /^uint(\d+)$/.exec(type);
  if (m) {
    if (!(typeof v === "bigint" || (typeof v === "number" && Number.isSafeInteger(v)))) fail(`${at} is not a JSON integer`);
    const b = BigInt(v);
    if (b < 0n || b >= 1n << BigInt(m[1])) fail(`${at} is outside ${type}`);
    return b;
  }
  fail(`${at} has type ${type}, which this checker does not read`);
}

// The value at a dotted path ("a.b.c") of nested objects, or undefined.
export function getPath(obj, p) {
  let v = obj;
  for (const k of p.split(".")) {
    if (!isPlainObject(v) || !Object.prototype.hasOwnProperty.call(v, k)) return undefined;
    v = v[k];
  }
  return v;
}

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

// An EIP-712 layout {domain, types, primaryType}, checked for shape.
function layoutOf(e, what) {
  if (!isPlainObject(e)) fail(`${what} is not an object`);
  exactMembers(e, ["domain", "types", "primaryType"], [], what);
  if (!isPlainObject(e.domain) || !isPlainObject(e.types) || typeof e.primaryType !== "string") fail(`${what} lacks domain, types or primaryType`);
  exactMembers(e.domain, [], ["name", "version", "chainId", "verifyingContract", "salt"], `${what}.domain`);
  if (Object.keys(e.domain).length === 0) fail(`${what}.domain is empty`);
  for (const [t, list] of Object.entries(e.types)) {
    if (!Array.isArray(list) || list.length === 0) fail(`${what}.types.${t} is not a non-empty list`);
    for (const f of list) {
      exactMembers(f, ["name", "type"], [], `${what}.types.${t} field`);
      if (typeof f.name !== "string" || typeof f.type !== "string") fail(`${what}.types.${t} has a malformed field`);
    }
  }
  const fields = e.types[e.primaryType];
  if (!Array.isArray(fields)) fail(`${what}.types has no ${e.primaryType}`);
  return { domain: plain(e.domain), types: plain(e.types), primaryType: e.primaryType, fields: plain(fields) };
}
const layoutOnly = (l) => ({ domain: l.domain, types: l.types, primaryType: l.primaryType });

// An issuer profile (README.md, "Issuer profiles"), read strictly. Everything
// about one issuer's receipts is here: the EIP-712 layout, which signed field
// holds which time and hash, the envelope's member names, the request-hash
// rule, the signer keys with their validity, and where the issuer publishes
// its keys. The verifier pins the profile's bytes by sha256.
function readProfile(buf) {
  const p = readJson(buf, "issuer/profile.json");
  exactMembers(p, ["format", "label", "test", "issuer", "receipt", "envelope", "signers"], ["sources", "request", "key_document", "chain_id", "tokens"], "issuer profile");
  if (p.format !== PROFILE_FORMAT) fail(`issuer profile format is ${JSON.stringify(p.format)}, not ${PROFILE_FORMAT}`);
  if (typeof p.label !== "string" || typeof p.issuer !== "string" || typeof p.test !== "boolean") fail("issuer profile label and issuer must be strings and test a boolean");
  if (p.chain_id !== undefined && (!Number.isSafeInteger(p.chain_id) || p.chain_id < 1)) fail("issuer profile chain_id is not a positive integer");
  const chainId = p.chain_id ?? BASE_MAINNET;
  // The EIP-3009 token contracts the verifier accepts on that chain, with their
  // EIP-712 domain name and version (verifyingContract is the address).
  const tokens = new Map();
  if (p.tokens !== undefined) {
    if (!Array.isArray(p.tokens) || p.tokens.length === 0) fail("issuer profile tokens is not a non-empty list");
    p.tokens.forEach((t, k) => {
      exactMembers(t, ["address", "name", "version"], [], `issuer profile tokens[${k}]`);
      const a = address(t.address, `tokens[${k}].address`);
      if (typeof t.name !== "string" || t.name.length === 0 || typeof t.version !== "string" || t.version.length === 0) fail(`tokens[${k}] name and version must be non-empty strings`);
      if (tokens.has(a)) fail("issuer profile tokens list an address twice");
      tokens.set(a, { name: t.name, version: t.version });
    });
  }
  if (p.sources !== undefined) {
    if (!Array.isArray(p.sources)) fail("issuer profile sources is not a list");
    p.sources.forEach((x, k) => {
      exactMembers(x, ["url", "fetched_at", "bytes", "sha256"], [], `issuer profile sources[${k}]`);
      if (typeof x.url !== "string" || typeof x.fetched_at !== "string" || !Number.isSafeInteger(x.bytes) || typeof x.sha256 !== "string" || !SHA256_HEX_RE.test(x.sha256)) fail(`issuer profile sources[${k}] is malformed`);
    });
  }
  const rc = p.receipt;
  exactMembers(rc, ["eip712", "fields", "schema_version"], [], "issuer profile receipt");
  const layout = layoutOf(rc.eip712, "receipt.eip712");
  if (layout.fields.length === 0) fail(`receipt.eip712.types.${layout.primaryType} has no fields`);
  exactMembers(rc.fields, ["checked_at", "valid_until", "request_hash", "verdict", "schema_version"], [], "receipt.fields");
  const typeOf = new Map(layout.fields.map((f) => [f.name, f.type]));
  const want = { checked_at: /^uint\d+$/, valid_until: /^uint\d+$/, request_hash: /^bytes32$/, verdict: /^string$/, schema_version: /^uint\d+$/ };
  for (const [k, re] of Object.entries(want)) {
    const name = rc.fields[k];
    if (typeof name !== "string" || !typeOf.has(name)) fail(`receipt.fields.${k} names no field of ${layout.primaryType}`);
    if (!re.test(typeOf.get(name))) fail(`receipt.fields.${k} (${name}) has type ${typeOf.get(name)}`);
  }
  if (!Number.isSafeInteger(rc.schema_version) || rc.schema_version < 0) fail("receipt.schema_version is not a non-negative integer");
  const e = p.envelope;
  exactMembers(e, ["required", "optional", "uid", "signature", "signer", "message"], ["unwrap", "schema_version", "valid_until", "valid_for_seconds", "layout", "request_layout"], "issuer profile envelope");
  for (const k of ["required", "optional"]) if (!Array.isArray(e[k]) || !e[k].every((x) => typeof x === "string" && NAME_RE.test(x))) fail(`envelope.${k} is not a list of member names`);
  if (new Set([...e.required, ...e.optional]).size !== e.required.length + e.optional.length) fail("envelope.required and envelope.optional repeat a name");
  if (e.unwrap !== undefined && (!Array.isArray(e.unwrap) || !e.unwrap.every((x) => typeof x === "string" && PATH_RE.test(x)))) fail("envelope.unwrap is not a list of member paths");
  for (const k of ["uid", "signature", "signer", "message", "schema_version", "valid_until", "valid_for_seconds", "layout"]) {
    if (e[k] === undefined) continue;
    if (typeof e[k] !== "string" || !NAME_RE.test(e[k])) fail(`envelope.${k} is not a member name`);
    if (!e.required.includes(e[k]) && !e.optional.includes(e[k])) fail(`envelope.${k} (${e[k]}) is in neither envelope.required nor envelope.optional`);
  }
  for (const k of ["uid", "signature", "signer", "message"]) if (!e.required.includes(e[k])) fail(`envelope.${k} must be a required member`);
  let request = null;
  if (p.request !== undefined) {
    exactMembers(p.request, ["eip712"], [], "issuer profile request");
    request = layoutOf(p.request.eip712, "request.eip712");
    if (request.fields.length === 0) fail(`request.eip712.types.${request.primaryType} has no fields`);
  }
  if (e.request_layout !== undefined) {
    exactMembers(e.request_layout, ["domain", "types", "primaryType"], [], "envelope.request_layout");
    if (!Object.values(e.request_layout).every((x) => typeof x === "string" && NAME_RE.test(x))) fail("envelope.request_layout names are not member names");
    if (e.layout === undefined || !request) fail("envelope.request_layout needs envelope.layout and a request");
  }
  if (!Array.isArray(p.signers) || p.signers.length === 0) fail("issuer profile signers is not a non-empty list");
  const signers = p.signers.map((x, k) => {
    exactMembers(x, ["address", "key_id", "valid_from", "valid_until"], [], `signers[${k}]`);
    const a = address(x.address, `signers[${k}].address`);
    if (typeof x.key_id !== "string") fail(`signers[${k}].key_id is not a string`);
    const from = typeof x.valid_from === "string" ? Date.parse(x.valid_from) : NaN;
    if (!Number.isFinite(from)) fail(`signers[${k}].valid_from is not a date`);
    let until = null;
    if (x.valid_until !== null) {
      until = typeof x.valid_until === "string" ? Date.parse(x.valid_until) : NaN;
      if (!Number.isFinite(until)) fail(`signers[${k}].valid_until is neither null nor a date`);
    }
    return { address: a, keyId: x.key_id, from, until, window: `${x.valid_from} to ${x.valid_until ?? "open"}` };
  });
  if (new Set(signers.map((x) => x.address)).size !== signers.length) fail("issuer profile signers list an address twice");
  let keyDoc = null;
  if (p.key_document !== undefined) {
    const k = p.key_document;
    exactMembers(k, ["url", "keys", "address"], ["key_id", "valid_from", "valid_until", "require", "role", "accepted_roles", "revoked_list", "layout"], "issuer profile key_document");
    if (typeof k.url !== "string" || !/^https:\/\/\S+$/.test(k.url)) fail("key_document.url is not an https URL");
    for (const m of ["keys", "address", "key_id", "valid_from", "valid_until", "role", "revoked_list", "layout"]) if (k[m] !== undefined && (typeof k[m] !== "string" || !PATH_RE.test(k[m]))) fail(`key_document.${m} is not a member path`);
    if (k.require !== undefined) {
      if (!isPlainObject(k.require)) fail("key_document.require is not an object");
      for (const [m, x] of Object.entries(k.require)) if (!PATH_RE.test(m) || !(x === null || ["string", "boolean"].includes(typeof x) || Number.isSafeInteger(x))) fail(`key_document.require.${m} is not a plain value`);
    }
    if (k.accepted_roles !== undefined && (!Array.isArray(k.accepted_roles) || !k.accepted_roles.every((x) => typeof x === "string"))) fail("key_document.accepted_roles is not a list of strings");
    keyDoc = plain(k);
  }
  return { label: p.label, issuer: p.issuer, test: p.test, chainId, chainIdStated: p.chain_id !== undefined, tokens, layout, fields: plain(rc.fields), schemaVersion: rc.schema_version, envelope: plain(e), request, signers, keyDoc };
}

// The signer's entry in the key document the issuer serves now, read with the
// profile's key_document map.
function keyDocStatus(doc, keys, K, signer, atSeconds) {
  const hits = keys.filter((k) => isPlainObject(k) && typeof getPath(k, K.address) === "string" && getPath(k, K.address).toLowerCase() === signer);
  if (hits.length === 0) return { ok: false, listed: false, reason: "not listed" };
  if (hits.length > 1) return { ok: false, listed: true, reason: "listed more than once" };
  const k = hits[0];
  const id = K.key_id !== undefined && typeof getPath(k, K.key_id) === "string" ? getPath(k, K.key_id) : "(no key id)";
  for (const [m, want] of Object.entries(K.require ?? {})) if (getPath(k, m) !== want) return { ok: false, listed: true, reason: `${id} has ${m} ${JSON.stringify(getPath(k, m))}, not ${JSON.stringify(want)}` };
  if (K.role !== undefined) {
    const role = getPath(k, K.role);
    if (role !== undefined && !(K.accepted_roles ?? []).includes(role)) return { ok: false, listed: true, reason: `${id} has role ${JSON.stringify(role)}, which the profile does not accept` };
  }
  if (K.revoked_list !== undefined) {
    const list = getPath(doc, K.revoked_list);
    if (Array.isArray(list) && JSON.stringify(plain(list)).toLowerCase().includes(signer)) return { ok: false, listed: true, reason: `${id} appears in ${K.revoked_list}` };
  }
  const at = Number(atSeconds) * 1000;
  if (K.valid_from !== undefined) {
    const from = Date.parse(getPath(k, K.valid_from));
    if (!Number.isFinite(from)) return { ok: false, listed: true, reason: `${id} has no readable ${K.valid_from}` };
    if (at < from) return { ok: false, listed: true, reason: `${id} is valid from ${getPath(k, K.valid_from)}, after the receipt's check time` };
  }
  if (K.valid_until !== undefined) {
    const u = getPath(k, K.valid_until);
    if (u !== null && u !== undefined) {
      const until = Date.parse(u);
      if (!Number.isFinite(until)) return { ok: false, listed: true, reason: `${id} has an unreadable ${K.valid_until}` };
      if (at > until) return { ok: false, listed: true, reason: `${id} is valid until ${u}, before the receipt's check time` };
    }
  }
  return { ok: true, keyId: id };
}

function readJson(buf, what, opts) {
  if (!buf) fail(`${what} is missing`);
  try {
    return parseStrictJson(buf, opts);
  } catch (e) {
    fail(`${what}: ${e.message}`);
  }
}

function normLog(l, k) {
  if (!isPlainObject(l)) fail(`receipt log ${k} is not an object`);
  if (!Array.isArray(l.topics)) fail(`receipt log ${k} has no topics array`);
  return {
    address: address(l.address, `log ${k} address`),
    topics: l.topics.map((t, j) => hexBytes(t, `log ${k} topic ${j}`, 32)),
    data: hexBytes(l.data, `log ${k} data`),
    logIndex: l.logIndex === undefined ? undefined : quantity(l.logIndex, `log ${k} logIndex`).toString(),
  };
}

// The 24 facts on which the online check compares the case's chain/ files,
// when the case has them, with the first endpoint's answers (CASE_FILE_FACTS
// names them for the PASS line, and README.md lists them under check f). The
// two endpoints' answers are compared with each other on every member instead.
// The checks read other members too (the signed fields that recompute the
// transaction hash, the header fields that recompute the block hash); online
// they read them from the endpoints' answers, and the case's copies of those
// members are not compared.
function chainFacts(tx, rc, blk) {
  return {
    tx: {
      hash: tx.hash,
      type: tx.type,
      chainId: tx.chainId,
      nonce: tx.nonce,
      from: typeof tx.from === "string" ? tx.from.toLowerCase() : tx.from,
      to: typeof tx.to === "string" ? tx.to.toLowerCase() : tx.to,
      value: tx.value,
      input: tx.input,
      r: tx.r,
      s: tx.s,
      blockHash: tx.blockHash,
      blockNumber: tx.blockNumber,
      transactionIndex: tx.transactionIndex,
    },
    receipt: {
      status: rc.status,
      transactionHash: rc.transactionHash,
      blockHash: rc.blockHash,
      blockNumber: rc.blockNumber,
      transactionIndex: rc.transactionIndex,
      logs: Array.isArray(rc.logs) ? rc.logs.map((l, k) => normLog(l, k)) : null,
    },
    block: {
      number: blk.number,
      hash: blk.hash,
      parentHash: blk.parentHash,
      timestamp: blk.timestamp,
      hasTx: Array.isArray(blk.transactions) && blk.transactions.some((t) => (typeof t === "string" ? t : t?.hash) === tx.hash),
    },
  };
}

function diffFacts(a, b) {
  const out = [];
  for (const part of ["tx", "receipt", "block"])
    for (const k of Object.keys(a[part])) if (JSON.stringify(a[part][k]) !== JSON.stringify(b[part][k])) out.push(`${part}.${k}`);
  return out;
}

// What chainFacts compares, as the PASS line states it: 13 transaction facts,
// 6 receipt facts and 5 block facts.
const CASE_FILE_FACTS =
  "24 facts: the transaction's hash, type, chainId, nonce, from, to, value, input, r, s, blockHash, blockNumber and transactionIndex; " +
  "the receipt's status, transactionHash, blockHash, blockNumber, transactionIndex and logs (each log's address, topics, data and logIndex); " +
  "and the block's number, hash, parentHash and timestamp, and whether its transactions list holds the transaction. The files' other members are not compared";

// The --authorizer value: 0x and 40 hex digits, all in lower case, all in upper
// case, or in mixed case that is its EIP-55 checksum. Returned in lower case.
// The messages do not repeat the value.
export function authorizerAddress(s) {
  if (typeof s !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(s)) throw new FormatError("--authorizer is not a 20-byte hex address (0x and 40 hex digits)");
  const hex = s.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return s.toLowerCase();
  const want = getAddress(s.toLowerCase()).slice(2);
  const k = [...hex].findIndex((ch, i) => ch !== want[i]);
  if (k !== -1)
    throw new FormatError(
      `--authorizer is in mixed case, so it is read as an EIP-55 checksum, and it is not a valid one: hex digit ${k + 1} of 40 should be ${want[k] === want[k].toUpperCase() ? "upper" : "lower"} case. Give the address all in lower case, all in upper case, or exactly in its EIP-55 form`,
    );
  return s.toLowerCase();
}

// The --rpc endpoints, one per host: a URL whose host an earlier URL already
// names is dropped. Two answers from one host are one source, so fewer than
// two distinct hosts is refused. Each must be an http or https URL.
export function rpcEndpoints(urls) {
  const kept = [];
  const dropped = [];
  const hosts = new Set();
  for (const u of urls) {
    let url;
    try {
      url = new URL(u);
    } catch {
      throw new FormatError(`--rpc ${JSON.stringify(u)} is not a URL`);
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new FormatError(`--rpc ${JSON.stringify(u)} is not an http or https URL`);
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (hosts.has(host)) {
      dropped.push(u);
      continue;
    }
    hosts.add(host);
    kept.push(u);
  }
  if (kept.length < 2)
    throw new FormatError(
      `--rpc names ${kept.length} distinct host(s)${dropped.length ? ` (${dropped.length} more URL(s) on a host already named)` : ""}: name endpoints on at least two different hosts, run by different operators`,
    );
  return { urls: kept, dropped };
}

// Call recognition: EIP-3009 by selector, an ERC-4337 EntryPoint by selector
// or address, otherwise the ABI the case supplies in chain/target-abi.json.
function recogniseCall(input, to, caseAbi) {
  const sel = selectorOf(input);
  if (sel === null) return { kind: "no-selector" };
  const eip = findFragment(EIP3009_ABI, sel);
  if (eip.length === 1) {
    const d = decodeCall(input, eip[0]);
    const vrs = eip[0].inputs.length === 9;
    const kind = `${eip[0].name === "transferWithAuthorization" ? "eip3009-transfer" : "eip3009-receive"}-${vrs ? "vrs" : "bytes"}`;
    return { kind, decoded: d };
  }
  if (findFragment(USEROP_ABI, sel).length || (to && ENTRYPOINTS.has(to))) return { kind: "userop" };
  if (caseAbi) {
    const frags = findFragment(caseAbi, sel);
    if (frags.length === 1) return { kind: "case-abi", decoded: decodeCall(input, frags[0]) };
    return { kind: "unknown", note: `selector ${sel} is not in chain/target-abi.json` };
  }
  return { kind: "unknown", note: `selector ${sel} is not recognised and the case supplies no chain/target-abi.json` };
}

function authorizationFields(decoded) {
  const [from, to, value, validAfter, validBefore, nonce, ...rest] = decoded.args;
  const a = { from: from.toLowerCase(), to: to.toLowerCase(), value, validAfter, validBefore, nonce: nonce.toLowerCase() };
  if (rest.length === 3) Object.assign(a, { v: rest[0], r: rest[1], s: rest[2] });
  else a.signature = rest[0];
  return a;
}

// Offset of the nonce word in either transferWithAuthorization overload:
// selector, then five static words before it.
const NONCE_OFFSET = 4 + 5 * 32;

export async function checkCase(io, opts = {}) {
  const r = new Report();
  const ok = {};
  const ctx = { receipts: {} };
  const showParties = !!opts.showParties;
  const party = (a) => (showParties ? a : `${a.slice(0, 8)}...${a.slice(-4)}`);
  const files = [];
  const readCase = (rel) => {
    const b = io.readCase(rel);
    if (b) files.push(`${rel} ${b.length} B sha256 ${sha256Hex(b)}`);
    return b;
  };
  const online = !!opts.online;
  const fetchImpl = opts.fetchImpl ?? fetch;
  // The account the trade must come from, stated by the verifier (--authorizer),
  // never by the case.
  const stated = opts.authorizer === undefined || opts.authorizer === null ? null : authorizerAddress(opts.authorizer);
  // A chain fact (a receipt, its logs, a block) PASSes only when two endpoints
  // gave byte-equal answers for it; otherwise its line is NOT VERIFIED OFFLINE.
  ctx.chainVerified = false;
  const fact = (id, deps, fn) =>
    check(r, ok, id, deps, async () => {
      const t = await fn();
      if (typeof t !== "string" || ctx.chainVerified) return t;
      r.add("NOT VERIFIED OFFLINE", id, `${t}; this rests on chain data as the case supplies it, not on two endpoints' byte-equal answers (--online)`);
      return undefined;
    });

  // Pins: the verifier's own trust anchors, never the case's.
  await check(r, ok, "pins", [], async () => {
    const p = readJson(io.readPin("pins.json"), "pins.json in the pins directory");
    exactMembers(p, ["format", "label", "test", "witness_keys", "issuer_profiles"], [], "pins.json");
    if (p.format !== PINS_FORMAT) fail(`pins.json format is ${JSON.stringify(p.format)}, not ${PINS_FORMAT}`);
    if (typeof p.label !== "string" || typeof p.test !== "boolean") fail("pins.json label must be a string and test a boolean");
    if (!Array.isArray(p.issuer_profiles)) fail("pins.json issuer_profiles is not a list");
    ctx.pinnedProfiles = p.issuer_profiles.map((x, k) => {
      exactMembers(x, ["label", "sha256"], [], `pins.json issuer_profiles[${k}]`);
      if (typeof x.label !== "string" || typeof x.sha256 !== "string" || !SHA256_HEX_RE.test(x.sha256)) fail(`pins.json issuer_profiles[${k}] must be a label and 64 lowercase hex digits`);
      return { label: x.label, sha256: x.sha256, from: "pins.json" };
    });
    for (const h of opts.profileSha256 ?? []) {
      if (typeof h !== "string" || !SHA256_HEX_RE.test(h)) fail(`--profile-sha256 ${h} is not 64 lowercase hex digits`);
      ctx.pinnedProfiles.push({ label: "named with --profile-sha256", sha256: h, from: "--profile-sha256" });
    }
    const wk = p.witness_keys;
    exactMembers(wk, ["file", "url", "fetched_at", "bytes", "sha256", "key_id", "public_key_hex"], [], "pins.json witness_keys");
    const wkBuf = io.readPin(wk.file);
    if (!wkBuf) fail(`pinned witness key response ${wk.file} is missing`);
    if (wkBuf.length !== wk.bytes || sha256Hex(wkBuf) !== wk.sha256) fail(`pinned witness key response ${wk.file} is ${wkBuf.length} B with sha256 ${sha256Hex(wkBuf)}, not ${wk.bytes} B ${wk.sha256}`);
    const keysDoc = readJson(wkBuf, `pinned ${wk.file}`);
    const hits = Array.isArray(keysDoc.keys) ? keysDoc.keys.filter((k) => isPlainObject(k) && k.key_id === wk.key_id) : [];
    if (hits.length !== 1) fail(`pinned witness key response lists ${hits.length} entries with key_id ${wk.key_id}`);
    const k = hits[0];
    if (k.algorithm !== "Ed25519" || k.format !== "hex" || typeof k.public_key !== "string" || !/^[0-9a-f]{64}$/.test(k.public_key)) fail("pinned witness key is not a 32-byte Ed25519 key in lowercase hex");
    if (k.public_key !== wk.public_key_hex) fail("pins.json public_key_hex differs from the pinned response");
    if (!p.test && (wk.key_id !== HO_WITNESS_KEY_ID || wk.public_key_hex !== HO_WITNESS_PUBLIC_HEX)) fail(`non-test pins must pin ${HO_WITNESS_KEY_ID} ${HO_WITNESS_PUBLIC_HEX}`);
    ctx.witnessKey = { id: wk.key_id, hex: wk.public_key_hex, pub: Buffer.from(wk.public_key_hex, "hex") };
    ctx.pinsTest = p.test;
    const profiles = ctx.pinnedProfiles.length ? ctx.pinnedProfiles.map((x) => `${x.sha256} (${x.label}, ${x.from})`).join("; ") : "none";
    return `${p.test ? "TEST PINS (not a real issuer's or Headless Oracle's keys): " : ""}${p.label} | issuer profiles accepted: ${profiles} | witness key ${wk.key_id} ${wk.public_key_hex} from ${wk.url} fetched ${wk.fetched_at}`;
  });

  await check(r, ok, "case", [], async () => {
    const c = readJson(readCase("case.json"), "case.json");
    if (isPlainObject(c) && Object.prototype.hasOwnProperty.call(c, "expected_authorizer")) fail("case.json names expected_authorizer, which this version does not read: the authorizer comes from the verifier (--authorizer), never from the case");
    exactMembers(c, ["format", "mode", "chain_id", "tx_hash"], ["binding"], "case.json");
    if (c.format !== CASE_FORMAT) fail(`case.json format is ${JSON.stringify(c.format)}, not ${CASE_FORMAT}`);
    if (c.mode !== "ordering" && c.mode !== "trailer-report") fail(`case.json mode must be "ordering" or "trailer-report"`);
    if (!Number.isSafeInteger(c.chain_id) || c.chain_id < 1) fail("case.json chain_id must be a positive integer");
    hexBytes(c.tx_hash, "case.json tx_hash", 32);
    if (c.mode === "ordering") {
      if (c.binding !== "calldata" && c.binding !== "eip3009-nonce") fail(`case.json binding must be "calldata" or "eip3009-nonce"`);
    } else {
      if (c.binding !== undefined) fail("a trailer-report case carries no binding");
      if (c.chain_id !== BASE_MAINNET) fail(`trailer-report mode reads Base mainnet only: case.json chain_id must be ${BASE_MAINNET}, not ${c.chain_id}`);
    }
    ctx.case = c;
    return `mode ${c.mode}, chain id ${c.chain_id}, transaction ${c.tx_hash}${c.binding ? `, binding claimed: ${c.binding}` : ""}${c.mode === "ordering" ? (stated ? `; authorizer stated by the verifier: ${party(stated)}` : "; no authorizer stated by the verifier") : stated ? "; --authorizer is not read in trailer-report mode" : ""}`;
  });
  const ordering = ok.case && ctx.case.mode === "ordering";

  if (ordering) {
    // a. The issuer profile, which the verifier pins by sha256.
    await check(r, ok, "a.profile", ["pins"], async () => {
      const buf = readCase("issuer/profile.json");
      if (!buf) fail("issuer/profile.json is missing");
      const h = sha256Hex(buf);
      const pin = ctx.pinnedProfiles.find((x) => x.sha256 === h);
      if (!pin) fail("the case's issuer/profile.json is not a profile the verifier pinned. Obtain the sha256 of this issuer's published profile from the issuer, out of band, and pin that value (pins.json issuer_profiles, or --profile-sha256); never pin a value read from the case itself");
      const P = readProfile(buf);
      ctx.profile = P;
      const toks = P.tokens.size ? `EIP-3009 tokens ${[...P.tokens].map(([a, t]) => `${a} (${JSON.stringify(t.name)} version ${JSON.stringify(t.version)})`).join(", ")}` : "no EIP-3009 token";
      return `${P.test ? "TEST PROFILE: " : ""}${P.label} | issuer ${JSON.stringify(P.issuer)} | ${buf.length} B, sha256 ${h}, pinned in ${pin.from} (${pin.label}) | chain id ${P.chainId}${P.chainIdStated ? "" : " (Base mainnet: the profile names none)"}; ${toks} | ${P.layout.primaryType} at schema version ${P.schemaVersion}, EIP-712 domain ${JSON.stringify(P.layout.domain)}, ${P.layout.fields.length} signed fields | signers: ${P.signers.map((x) => `${x.keyId} ${x.address} (${x.window})`).join("; ")}`;
    });
    await check(r, ok, "a.chain-id", ["a.profile", "case"], async () => {
      const P = ctx.profile;
      if (ctx.case.chain_id !== P.chainId) fail(`case.json chain_id ${ctx.case.chain_id} is not the chain the pinned profile names: ${P.chainId}${P.chainIdStated ? "" : " (Base mainnet, since the profile names no chain_id)"}`);
      return `chain id ${ctx.case.chain_id}, the chain the pinned profile names${P.chainIdStated ? "" : " (Base mainnet, since the profile names no chain_id)"}`;
    });

    // b. The two receipt envelopes, read through the profile.
    for (const role of ROLES) {
      const id = `b.${role}`;
      await check(r, ok, `${id}.envelope`, ["a.profile"], async () => {
        const P = ctx.profile;
        const E = P.envelope;
        const F = P.fields;
        let env = readJson(readCase(`receipts/${role}.json`), `receipts/${role}.json`);
        let unwrapped = "";
        if (isPlainObject(env) && !Object.prototype.hasOwnProperty.call(env, E.uid)) {
          for (const u of E.unwrap ?? []) {
            const inner = getPath(env, u);
            if (isPlainObject(inner) && Object.prototype.hasOwnProperty.call(inner, E.uid)) {
              env = inner;
              unwrapped = `read ${u} of the file (its other members are not checked); `;
              break;
            }
          }
        }
        exactMembers(env, E.required, E.optional, `receipts/${role}.json envelope`);
        const uid = hexBytes(env[E.uid], `envelope ${E.uid}`, 32);
        hexBytes(env[E.signature], `envelope ${E.signature}`, 65);
        const claimed = address(env[E.signer], `envelope ${E.signer}`);
        if (E.schema_version !== undefined && env[E.schema_version] !== undefined && env[E.schema_version] !== P.schemaVersion) fail(`envelope ${E.schema_version} is ${JSON.stringify(env[E.schema_version])}, not ${P.schemaVersion}`);
        exactMembers(env[E.message], P.layout.fields.map((f) => f.name), [], `envelope ${E.message}`);
        const msg = {};
        for (const f of P.layout.fields) msg[f.name] = typedValue(env[E.message][f.name], f.type, f.name, E.message);
        if (msg[F.schema_version] !== BigInt(P.schemaVersion)) fail(`${E.message}.${F.schema_version} is ${msg[F.schema_version]}, not ${P.schemaVersion}`);
        for (const k of [E.valid_until, E.valid_for_seconds]) if (k !== undefined && env[k] !== undefined && !Number.isSafeInteger(env[k])) fail(`the envelope's ${k} is not a JSON integer`);
        if (E.valid_until !== undefined && env[E.valid_until] !== undefined && BigInt(env[E.valid_until]) !== msg[F.valid_until]) fail(`the envelope's ${E.valid_until} differs from the signed ${F.valid_until}`);
        if (E.valid_for_seconds !== undefined && env[E.valid_for_seconds] !== undefined && BigInt(env[E.valid_for_seconds]) !== msg[F.valid_until] - msg[F.checked_at]) fail(`the envelope's ${E.valid_for_seconds} is not ${F.valid_until} minus ${F.checked_at}`);
        let layoutNote = "";
        if (E.layout !== undefined && env[E.layout] !== undefined) {
          const L = env[E.layout];
          const RL = E.request_layout;
          exactMembers(L, ["domain", "types", "primaryType"], RL ? [RL.domain, RL.types, RL.primaryType] : [], `envelope ${E.layout}`);
          if (!sameJson({ d: L.domain, t: L.types, p: L.primaryType }, { d: P.layout.domain, t: P.layout.types, p: P.layout.primaryType })) fail(`the envelope's ${E.layout} domain, types or primaryType differ from the profile's`);
          if (RL && [RL.domain, RL.types, RL.primaryType].some((n) => L[n] !== undefined)) {
            if (!sameJson({ d: L[RL.domain], t: L[RL.types], p: L[RL.primaryType] }, { d: P.request.domain, t: P.request.types, p: P.request.primaryType })) fail(`the envelope's request layout differs from the profile's`);
          }
          layoutNote = `; its ${E.layout} member equals the profile's layout`;
        }
        ctx.receipts[role] = { env, msg, uid, claimed, checkedAt: msg[F.checked_at], validUntil: msg[F.valid_until] };
        return `${unwrapped}${P.layout.primaryType} envelope; the ${P.layout.fields.length} signed fields are exactly the profile's layout; ${E.message}.${F.schema_version} is ${P.schemaVersion}${layoutNote}`;
      });
      await check(r, ok, `${id}.uid`, [`${id}.envelope`], async () => {
        const { uid, msg } = ctx.receipts[role];
        const L = ctx.profile.layout;
        const digest = hashTypedData({ domain: L.domain, types: L.types, primaryType: L.primaryType, message: msg });
        if (digest !== uid) fail(`${ctx.profile.envelope.uid} ${uid} is not the EIP-712 digest ${digest} recomputed from the profile's domain and types`);
        return `${ctx.profile.envelope.uid} ${uid} equals the EIP-712 digest recomputed from the profile's domain and types`;
      });
      await check(r, ok, `${id}.signature`, [`${id}.uid`], async () => {
        const { env, uid, claimed } = ctx.receipts[role];
        const E = ctx.profile.envelope;
        const sig = env[E.signature];
        const rr = BigInt("0x" + sig.slice(2, 66));
        const ss = BigInt("0x" + sig.slice(66, 130));
        const v = parseInt(sig.slice(130, 132), 16);
        if (v !== 27 && v !== 28) fail(`${E.signature} v is ${v}, not 27 or 28`);
        sigScalars(rr, ss, "receipt signature");
        const signer = await recoverSigner(uid, rr, ss, v - 27);
        if (signer !== claimed) fail(`${E.signature} recovers to ${signer}, not the envelope's ${E.signer} ${claimed}`);
        ctx.receipts[role].signer = signer;
        return `${E.signature} (v ${v}, low s) recovers to ${signer}, the envelope's ${E.signer}`;
      });
      await check(r, ok, `${id}.signer-key`, [`${id}.signature`], async () => {
        const { signer, checkedAt } = ctx.receipts[role];
        const F = ctx.profile.fields;
        const hits = ctx.profile.signers.filter((x) => x.address === signer);
        if (hits.length !== 1) fail(`signer ${signer} is not among the profile's signers`);
        const k = hits[0];
        const at = Number(checkedAt) * 1000;
        if (at < k.from) fail(`signer ${signer} is ${k.keyId}, valid ${k.window}: from after the receipt's ${F.checked_at}`);
        if (k.until !== null && at > k.until) fail(`signer ${signer} is ${k.keyId}, valid ${k.window}: until before the receipt's ${F.checked_at}`);
        return `signer ${signer} is the profile's ${k.keyId} (${k.window}), valid at the receipt's ${F.checked_at}`;
      });
      if (ok[`${id}.envelope`]) {
        const { uid, msg } = ctx.receipts[role];
        const P = ctx.profile;
        const F = P.fields;
        r.add("INFO", `${id}.fields`, `${P.envelope.uid} ${uid} | verdict (${F.verdict}) ${msg[F.verdict]} | request hash (${F.request_hash}) ${msg[F.request_hash]} | checked at (${F.checked_at}) ${secondsIso(msg[F.checked_at])} | valid until (${F.valid_until}) ${secondsIso(msg[F.valid_until])}`);
        await check(r, ok, `${id}.request-hash`, [], async () => {
            const reqBuf = readCase(`requests/${role}.json`);
            if (!reqBuf) {
              r.add("NOT CHECKED", `${id}.request-hash`, `the case carries no requests/${role}.json, so ${F.request_hash} is reported, not recomputed from the request`);
              return undefined;
            }
            const q = P.request;
            if (!q) fail("the issuer profile has no request layout, so requests/ cannot be read");
            const req = readJson(reqBuf, `requests/${role}.json`);
            exactMembers(req, q.fields.map((f) => f.name), [], `requests/${role}.json`);
            const m = {};
            for (const f of q.fields) m[f.name] = typedValue(req[f.name], f.type, f.name, `requests/${role}.json`);
            const h = hashTypedData({ domain: q.domain, types: q.types, primaryType: q.primaryType, message: m });
            if (h !== msg[F.request_hash]) fail(`the EIP-712 hash of requests/${role}.json is ${h}, not the receipt's ${F.request_hash} ${msg[F.request_hash]}`);
            return `${F.request_hash} ${h} recomputed from requests/${role}.json under the profile's request domain ${JSON.stringify(q.domain)}`;
          });
        if (P.request && P.request.fields.every((f) => f.name in msg)) {
          const q = P.request;
          try {
            const m = {};
            for (const f of q.fields) m[f.name] = msg[f.name];
            const h = hashTypedData({ domain: q.domain, types: q.types, primaryType: q.primaryType, message: m });
            r.add("INFO", `${id}.request-fields`, `${F.request_hash} ${h === msg[F.request_hash] ? "equals" : "does not equal"} the request hash of the receipt's own ${q.fields.map((f) => f.name).join(", ")}`);
          } catch (e) {
            r.add("INFO", `${id}.request-fields`, `the request hash of the receipt's own ${q.fields.map((f) => f.name).join(", ")} could not be computed under the profile's request layout: ${shortError(e)}`);
          }
        }
      }
    }

    // a, online: the key document the issuer serves now.
    if (!online) r.add("NOT CHECKED", "a.online-keys", "offline: the receipts' signers are checked against the pinned profile; --online also reads the key document the profile names");
    else
      await check(r, ok, "a.online-keys", ["a.profile"], async () => {
        const K = ctx.profile.keyDoc;
        if (!K) {
          r.add("NOT CHECKED", "a.online-keys", "the issuer profile names no key document");
          return undefined;
        }
        const { body, json } = await getJson(K.url, fetchImpl, { allowNonInteger: true });
        let layoutNote = "";
        if (K.layout !== undefined) {
          let served;
          try {
            served = layoutOf(getPath(json, K.layout), `${K.url} ${K.layout}`);
          } catch (e) {
            fail(`the key document has no EIP-712 layout at ${K.layout}: ${e.message}`);
          }
          if (!sameJson(layoutOnly(served), layoutOnly(ctx.profile.layout))) fail(`the EIP-712 layout ${K.url} serves now at ${K.layout} differs from the profile's`);
          layoutNote = `; the same EIP-712 layout at ${K.layout}`;
        }
        const keys = getPath(json, K.keys);
        if (!Array.isArray(keys)) fail(`${K.url} has no list at ${K.keys}`);
        const notes = [];
        for (const role of ROLES) {
          const x = ctx.receipts[role];
          if (!x?.signer) continue;
          const st = keyDocStatus(json, keys, K, x.signer, x.checkedAt);
          if (st.ok) notes.push(`the ${role} signer is ${st.keyId}, accepted and valid at its check time`);
          else if (!st.listed) r.add("NOT CHECKED", `a.online-keys.${role}`, `the key document served now no longer lists the ${role} signer (rotated out?); the pinned profile is what the check used`);
          else fail(`the ${role} signer in the key document served now: ${st.reason}`);
        }
        return `GET ${K.url} now: ${body.length} B, sha256 ${sha256Hex(body)}${layoutNote}${notes.length ? "; " + notes.join("; ") : ""}`;
      });

    // c. The log.
    await check(r, ok, "c.log-key", [], async () => {
      const jwk = readJson(readCase("log/public-key-jwk.json"), "log/public-key-jwk.json");
      exactMembers(jwk, ["kty", "crv", "x"], ["kid"], "log/public-key-jwk.json");
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") fail("the log key is not kty OKP, crv Ed25519");
      const pub = b64urlCanonical(jwk.x, 32, "log key x");
      const kid = okpThumbprint(jwk.x);
      if (jwk.kid !== undefined && jwk.kid !== kid) fail(`the JWK's kid ${jwk.kid} is not its RFC 7638 thumbprint ${kid}`);
      ctx.logKey = { pub, kid };
      return `Ed25519 log key x ${jwk.x}; RFC 7638 thumbprint ${kid}`;
    });
    await check(r, ok, "c.entries", [], async () => {
      const buf = readCase("log/entries.jsonl");
      if (!buf) fail("log/entries.jsonl is missing");
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buf);
      } catch {
        fail("log/entries.jsonl is not valid UTF-8");
      }
      const lines = text.split("\n");
      if (lines[lines.length - 1] === "") lines.pop();
      const entries = lines.map((line, k) => {
        const l = line.endsWith("\r") ? line.slice(0, -1) : line;
        if (l.trim() === "") fail(`log/entries.jsonl line ${k + 1} is blank`);
        let e;
        try {
          e = parseStrictJson(Buffer.from(l, "utf8"));
        } catch (err) {
          fail(`log/entries.jsonl line ${k + 1}: ${err.message}`);
        }
        if (!isPlainObject(e)) fail(`log/entries.jsonl line ${k + 1} is not a JSON object`);
        for (const m of ["v", "seq", "session_id", "prev_hash"]) if (!(m in e)) fail(`entry ${k} lacks ${m}`);
        if (typeof e.v !== "string" || e.v.length === 0) fail(`entry ${k} v is not a non-empty string`);
        if (!Number.isSafeInteger(e.seq)) fail(`entry ${k} seq is not an integer`);
        if (typeof e.session_id !== "string" || e.session_id.length < 1 || e.session_id.length > 128) fail(`entry ${k} session_id is not a string of 1 to 128 characters`);
        if (typeof e.prev_hash !== "string" || !SHA256_RE.test(e.prev_hash)) fail(`entry ${k} prev_hash is not sha256:<64 lowercase hex>`);
        if (e.receipt_uid !== undefined) hexBytes(e.receipt_uid, `entry ${k} receipt_uid`, 32);
        if (e.sig !== undefined && typeof e.sig !== "string") fail(`entry ${k} sig is not a string`);
        jcs(withoutMember(e, "sig"));
        return e;
      });
      if (entries.length === 0) fail("log/entries.jsonl holds no entries");
      ctx.entries = entries;
      return `${entries.length} entries, each one JSON object per line with no duplicate member and no number outside the safe integers`;
    });
    await check(r, ok, "c.chain", ["c.entries"], async () => {
      const es = ctx.entries;
      const v = es[0].v;
      const sid = es[0].session_id;
      const genesis = jcsSha256({ v, session_id: sid, marker: "genesis" });
      const hashes = [];
      for (let k = 0; k < es.length; k++) {
        const e = es[k];
        if (e.seq !== k) fail(`entry ${k} has seq ${e.seq}`);
        if (e.session_id !== sid) fail(`entry ${k} has session_id ${JSON.stringify(e.session_id)}, not ${JSON.stringify(sid)}`);
        if (e.v !== v) fail(`entry ${k} has v ${JSON.stringify(e.v)}, not ${JSON.stringify(v)}`);
        const prev = k === 0 ? genesis : hashes[k - 1];
        if (e.prev_hash !== prev) fail(`entry ${k} prev_hash ${e.prev_hash} is not ${k === 0 ? "the genesis value" : `the entry hash of entry ${k - 1}`} ${prev}`);
        hashes.push(jcsSha256(withoutMember(e, "sig")));
      }
      ctx.entryHashes = hashes;
      ctx.sessionId = sid;
      return `seq equals the index; one session_id ${JSON.stringify(sid)} and one v ${JSON.stringify(v)}; every prev_hash recomputed from the genesis value ${genesis}`;
    });
    await check(r, ok, "c.entry-signatures", ["c.chain", "c.log-key"], async () => {
      let signed = 0;
      for (let k = 0; k < ctx.entries.length; k++) {
        const e = ctx.entries[k];
        if (e.sig === undefined) continue;
        const sig = b64urlCanonical(e.sig, 64, `entry ${k} sig`);
        if (!ed25519Verify(ctx.logKey.pub, Buffer.from(jcs(withoutMember(e, "sig")), "utf8"), sig)) fail(`entry ${k} sig does not verify under the log key`);
        signed++;
      }
      if (signed === 0) {
        r.add("INFO", "c.entry-signatures", "no entry carries sig; the entries are bound by the hash chain, the checkpoint and the witness receipt");
        return undefined;
      }
      return `${signed} of ${ctx.entries.length} entries carry sig, and each verifies under the log key`;
    });
    await check(r, ok, "c.receipt-uids", ["c.chain", "b.source.envelope", "b.destination.envelope"], async () => {
      const at = {};
      for (const role of ROLES) {
        const uid = ctx.receipts[role].uid;
        const idx = ctx.entries.map((e, k) => (e.receipt_uid === uid ? k : -1)).filter((k) => k >= 0);
        if (idx.length !== 1) fail(`the ${role} receipt's uid appears as receipt_uid in ${idx.length} entries, not exactly one`);
        at[role] = idx[0];
      }
      if (!(at.source < at.destination)) fail(`the source receipt's entry (${at.source}) is not before the destination receipt's entry (${at.destination})`);
      ctx.srcIndex = at.source;
      ctx.dstIndex = at.destination;
      ctx.dstEntryHash = ctx.entryHashes[at.destination];
      return `source uid in entry ${at.source} (entry hash ${ctx.entryHashes[at.source]}), destination uid in entry ${at.destination} (entry hash ${ctx.dstEntryHash}); source before destination`;
    });

    // d. The checkpoint.
    await check(r, ok, "d.checkpoint-shape", [], async () => {
      const cp = readJson(readCase("log/checkpoint.json"), "log/checkpoint.json");
      exactMembers(cp, ["v", "type", "session_id", "count", "last_entry_hash", "ts", "kid", "sig"], [], "checkpoint");
      if (cp.v !== "evidence.action/1" || cp.type !== "checkpoint") fail('checkpoint v must be "evidence.action/1" and type "checkpoint"');
      if (!Number.isSafeInteger(cp.count) || cp.count < 1) fail("checkpoint count is not a safe integer of at least 1");
      if (typeof cp.last_entry_hash !== "string" || !SHA256_RE.test(cp.last_entry_hash)) fail("checkpoint last_entry_hash is not sha256:<64 lowercase hex>");
      if (typeof cp.ts !== "string" || !CHECKPOINT_TS_RE.test(cp.ts) || !Number.isFinite(Date.parse(cp.ts))) fail("checkpoint ts is not an ISO-8601 UTC time");
      if (typeof cp.session_id !== "string" || cp.session_id.length < 1 || cp.session_id.length > 128) fail("checkpoint session_id is not a string of 1 to 128 characters");
      if (typeof cp.kid !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(cp.kid)) fail("checkpoint kid is not a 43-character thumbprint");
      ctx.cpSig = b64urlCanonical(cp.sig, 64, "checkpoint sig");
      ctx.checkpoint = cp;
      return `the eight members of witness-spec/0.5 submit.checkpoint; count ${cp.count}, ts ${cp.ts}`;
    });
    await check(r, ok, "d.checkpoint-key", ["d.checkpoint-shape", "c.log-key"], async () => {
      if (ctx.checkpoint.kid !== ctx.logKey.kid) fail(`checkpoint kid ${ctx.checkpoint.kid} is not the log key's thumbprint ${ctx.logKey.kid}`);
      return `kid ${ctx.checkpoint.kid} is the RFC 7638 thumbprint of the log key`;
    });
    await check(r, ok, "d.checkpoint-signature", ["d.checkpoint-key"], async () => {
      if (!ed25519Verify(ctx.logKey.pub, Buffer.from(jcs(withoutMember(ctx.checkpoint, "sig")), "utf8"), ctx.cpSig)) fail("the checkpoint signature does not verify under the log key");
      return "Ed25519 over the JCS bytes of the checkpoint without sig verifies under the log key";
    });
    await check(r, ok, "d.checkpoint-session", ["d.checkpoint-shape", "c.chain"], async () => {
      if (ctx.checkpoint.session_id !== ctx.sessionId) fail(`checkpoint session_id ${JSON.stringify(ctx.checkpoint.session_id)} is not the log's ${JSON.stringify(ctx.sessionId)}`);
      return "checkpoint session_id equals the log's";
    });
    await check(r, ok, "d.checkpoint-covers", ["d.checkpoint-shape", "c.chain", "c.receipt-uids"], async () => {
      const cp = ctx.checkpoint;
      if (cp.count !== ctx.entries.length) fail(`checkpoint count ${cp.count} but the log holds ${ctx.entries.length} entries; the case's log runs from the first entry through the checkpoint's last entry`);
      if (cp.count < ctx.dstIndex + 1) fail(`checkpoint count ${cp.count} does not cover the destination entry ${ctx.dstIndex}`);
      if (cp.last_entry_hash !== ctx.entryHashes[cp.count - 1]) fail(`checkpoint last_entry_hash ${cp.last_entry_hash} is not the recomputed entry hash ${ctx.entryHashes[cp.count - 1]} of entry ${cp.count - 1}`);
      return `last_entry_hash equals the recomputed entry hash of entry ${cp.count - 1}; count ${cp.count} covers the destination entry ${ctx.dstIndex}`;
    });

    // e. The witness receipt.
    await check(r, ok, "e.witness-receipt", ["pins"], async () => {
      const w = readJson(readCase("witness/receipt.json"), "witness/receipt.json");
      exactMembers(w, [...WITNESS_FIELDS, "signature"], [], "witness receipt");
      for (const k of Object.keys(w)) if (typeof w[k] !== "string") fail(`witness receipt ${k} is not a string`);
      if (!/^[0-9a-f]{128}$/.test(w.signature)) fail("witness receipt signature is not 128 lowercase hex characters");
      if (w.public_key_id !== ctx.witnessKey.id) fail(`witness receipt public_key_id ${w.public_key_id} is not the pinned ${ctx.witnessKey.id}`);
      if (!ed25519Verify(ctx.witnessKey.pub, Buffer.from(jcs(withoutMember(w, "signature")), "utf8"), Buffer.from(w.signature, "hex"))) fail(`witness receipt signature does not verify under the pinned key ${ctx.witnessKey.id} ${ctx.witnessKey.hex}`);
      ctx.witness = w;
      return `signed by the pinned key ${ctx.witnessKey.id} ${ctx.witnessKey.hex}${ctx.pinsTest ? " (STUB key from the test pins)" : ""}`;
    });
    await check(r, ok, "e.witness-covers-checkpoint", ["e.witness-receipt", "d.checkpoint-shape"], async () => {
      const w = ctx.witness;
      const cp = ctx.checkpoint;
      if (w.type !== "witness.checkpoint/1") fail(`witness receipt type is ${w.type}`);
      if (w.witness !== "headlessoracle.com") fail(`witness receipt witness is ${w.witness}`);
      for (const [k, v] of [["kid", cp.kid], ["session_id", cp.session_id], ["count", String(cp.count)], ["last_entry_hash", cp.last_entry_hash]]) if (w[k] !== v) fail(`witness receipt ${k} ${JSON.stringify(w[k])} is not the checkpoint's ${JSON.stringify(v)}`);
      if (w.fork !== "false") fail(`witness receipt fork is ${JSON.stringify(w.fork)}`);
      const sha = jcsSha256(cp);
      if (w.checkpoint_sha256 === sha && w.checkpoint_ts === cp.ts) return `type, witness, kid, session_id, count ${w.count}, last_entry_hash equal the checkpoint's; checkpoint_sha256 ${sha} recomputed over the full signed checkpoint; fork "false"`;
      r.add("INFO", "e.checkpoint-sha256", `the receipt's checkpoint_sha256 ${w.checkpoint_sha256} and checkpoint_ts ${w.checkpoint_ts} are not those of the supplied checkpoint (${sha}, ${cp.ts}): the witness stored another checkpoint of the same head (kid, session_id, count, last_entry_hash), as its spec allows when one head is checkpointed twice`);
      return `type, witness, kid, session_id, count ${w.count}, last_entry_hash equal the checkpoint's; fork "false"; the receipt is for another signed checkpoint of the same head (see e.checkpoint-sha256)`;
    });
    if (!online) r.add("NOT CHECKED", "e.online-witness", "offline: the witness receipt is checked as supplied; --online compares it with the witness's own list for the log's kid and session_id");
    else
      await check(r, ok, "e.online-witness", ["e.witness-receipt", "c.chain", "c.log-key"], async () => {
        const { receipts, pages } = await witnessReceipts(ctx.logKey.kid, ctx.sessionId, fetchImpl);
        let found = false;
        const byCount = new Map();
        const beyond = [];
        for (const [k, w] of receipts.entries()) {
          exactMembers(w, [...WITNESS_FIELDS, "signature"], [], `listed receipt ${k}`);
          if (w.public_key_id !== ctx.witnessKey.id) fail(`listed receipt ${k} names key ${w.public_key_id}`);
          if (!/^[0-9a-f]{128}$/.test(w.signature) || !ed25519Verify(ctx.witnessKey.pub, Buffer.from(jcs(withoutMember(w, "signature")), "utf8"), Buffer.from(w.signature, "hex"))) fail(`listed receipt ${k} does not verify under the pinned key`);
          if (w.kid !== ctx.logKey.kid || w.session_id !== ctx.sessionId) fail(`listed receipt ${k} is for another kid or session_id`);
          if (jcs(w) === jcs(ctx.witness)) found = true;
          const c = Number(w.count);
          if (!byCount.has(c)) byCount.set(c, new Set());
          byCount.get(c).add(w.last_entry_hash);
        }
        for (const [c, set] of byCount) if (set.size > 1) fail(`the witness holds ${set.size} different last_entry_hash values at count ${c}: a fork`);
        for (const [c, set] of [...byCount].sort((a, b) => a[0] - b[0])) {
          const [h] = [...set];
          if (c > ctx.entries.length) beyond.push(c);
          else if (h !== ctx.entryHashes[c - 1]) fail(`the witness holds count ${c} with last_entry_hash ${h}, but the supplied log's entry ${c - 1} hashes to ${ctx.entryHashes[c - 1]}: the history was rewritten after that checkpoint was witnessed`);
        }
        if (!found) fail("the witness does not list a receipt equal (JCS) to witness/receipt.json for the log's kid and session_id");
        return `GET ${receipts.length} receipt(s) in ${pages} page(s) for the log's kid and session_id: the supplied receipt is listed; no fork; every listed count within the log matches its entry hash${beyond.length ? `; ${beyond.length} later checkpoint(s) (counts ${beyond.join(", ")}) go beyond the supplied log` : ""}`;
      });
  }

  // f. The transaction, its receipt and its block.
  const chainDeps = ["case"];
  await fact("f.chain-data", chainDeps, async () => {
    const tb = readCase("chain/transaction.json");
    const rb = readCase("chain/receipt.json");
    const bb = readCase("chain/block.json");
    const present = [tb, rb, bb].filter(Boolean).length;
    if (present !== 0 && present !== 3) fail("chain/ must hold all three of transaction.json, receipt.json and block.json, or none of them (none: --online fetches them)");
    if (present === 3) {
      // Each file is a JSON-RPC result object, or the whole response
      // {jsonrpc, id, result}, whose result is then read.
      const unwrapped = [];
      const result = (buf, rel) => {
        const v = readJson(buf, rel);
        if (isPlainObject(v) && Object.keys(v).length === 3 && v.jsonrpc === "2.0" && "id" in v && isPlainObject(v.result)) {
          unwrapped.push(rel);
          return v.result;
        }
        return v;
      };
      ctx.chain = { tx: result(tb, "chain/transaction.json"), rc: result(rb, "chain/receipt.json"), blk: result(bb, "chain/block.json"), source: "the case's chain/ files" };
      if (unwrapped.length) ctx.chain.source += ` (the result member of the JSON-RPC response in ${unwrapped.join(", ")})`;
    }
    if (online) {
      let urls = RPC_ENDPOINTS[ctx.case.chain_id];
      if (opts.rpcUrls?.length) {
        let named;
        try {
          named = rpcEndpoints(opts.rpcUrls);
        } catch (e) {
          fail(e.message);
        }
        if (named.dropped.length) r.add("INFO", "f.online-rpc-hosts", `--rpc URL(s) on a host that an earlier --rpc URL names, not used: ${named.dropped.join(", ")}`);
        urls = named.urls;
      }
      if (!urls) {
        r.add("NOT CHECKED", "f.online-rpc", `no public JSON-RPC endpoint is named for chain ${ctx.case.chain_id}; pass --rpc <url> for two endpoints on different hosts to compare them`);
        if (!ctx.chain) fail("no chain data: the case has no chain/ files and no endpoint is known for its chain");
        return `transaction, receipt and block read from ${ctx.chain.source}`;
      }
      const answers = [];
      const errors = [];
      for (const url of urls) {
        if (answers.length === 2) break;
        try {
          const tx = await rpc(url, "eth_getTransactionByHash", [ctx.case.tx_hash], fetchImpl);
          if (!tx) throw new Error("transaction not found");
          const rc = await rpc(url, "eth_getTransactionReceipt", [ctx.case.tx_hash], fetchImpl);
          if (!rc) throw new Error("receipt not found");
          const blk = await rpc(url, "eth_getBlockByNumber", [tx.blockNumber, false], fetchImpl);
          if (!blk) throw new Error("block not found");
          let fin = null;
          try {
            fin = await rpc(url, "eth_getBlockByNumber", ["finalized", false], fetchImpl);
          } catch (e) {
            fin = { error: e.message };
          }
          answers.push({ url, tx, rc, blk, fin });
        } catch (e) {
          errors.push(`${url}: ${e.message}`);
        }
      }
      if (answers.length < 2) fail(`fewer than two JSON-RPC endpoints answered (${errors.join("; ")})`);
      if (errors.length) r.add("INFO", "f.online-rpc-skipped", `endpoint(s) that did not answer, so the next in the list was used: ${errors.join("; ")}`);
      const [A, B] = answers;
      // Byte-equal answers: the two results, each in canonical JSON (RFC 8785),
      // must be the same bytes, member for member, not only the fields read below.
      const unequal = [];
      for (const [name, a, b] of [["transaction", A.tx, B.tx], ["receipt", A.rc, B.rc], ["block", A.blk, B.blk]]) {
        const members = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
        const differ = members.filter((k) => !(k in a) || !(k in b) || jcs(plain(a[k])) !== jcs(plain(b[k])));
        if (differ.length) unequal.push(`${name} ${differ.join(", ")}`);
      }
      if (unequal.length) fail(`${A.url} and ${B.url} do not give byte-equal answers (canonical JSON, RFC 8785): they differ on ${unequal.join("; ")}`);
      if (ctx.chain) {
        const dc = diffFacts(chainFacts(ctx.chain.tx, ctx.chain.rc, ctx.chain.blk), chainFacts(A.tx, A.rc, A.blk));
        if (dc.length) fail(`the case's chain/ files differ from ${A.url} and ${B.url} on ${dc.join(", ")}`);
      }
      ctx.chain = { tx: A.tx, rc: A.rc, blk: A.blk, source: `${A.url} and ${B.url}, byte-equal (in memory; nothing saved)` };
      ctx.chainVerified = true;
      ctx.rpcAnswers = answers;
      r.add("PASS", "f.online-rpc", `${A.url} and ${B.url} give byte-equal answers for the transaction, its receipt and its block; the checks below read those answers${present === 3 ? `; the case's chain/ files agree with them on ${CASE_FILE_FACTS}` : ""}`);
      const fins = answers.map((a) => (a.fin && a.fin.number ? BigInt(a.fin.number) : null));
      const n = BigInt(A.tx.blockNumber);
      if (fins.every((f) => f !== null && f >= n)) r.add("PASS", "f.finality", `block ${n} is at or below the finalized block on both endpoints (${fins.join(", ")})`);
      else r.add("FLAG", "f.finality", `block ${n} is not at or below the finalized block on both endpoints (${answers.map((a, k) => `${a.url}: ${fins[k] ?? a.fin?.error ?? "no answer"}`).join("; ")}): run again once it is final`);
    } else {
      r.add("NOT CHECKED", "f.online-rpc", "offline: the transaction, receipt and block are as the case supplies them; --online reads them from two public endpoints, whose answers must be byte-equal");
      if (!ctx.chain) fail("offline mode needs chain/transaction.json, chain/receipt.json and chain/block.json");
    }
    return `transaction, receipt and block read from ${ctx.chain.source}`;
  });
  await check(r, ok, "f.transaction", ["f.chain-data"], async () => {
    const tx = ctx.chain.tx;
    let ser;
    try {
      ser = txSerialization(tx);
    } catch (e) {
      fail(e.message);
    }
    if (ser.chainId === null) fail("a legacy transaction without EIP-155 carries no chain id");
    if (ser.chainId !== BigInt(ctx.case.chain_id)) fail(`transaction chain id ${ser.chainId} is not the case's chain_id ${ctx.case.chain_id}`);
    const h = keccak256(ser.signedHex);
    if (h !== tx.hash) fail(`hash ${h} recomputed from the signed fields is not the transaction's hash ${tx.hash}`);
    if (h !== ctx.case.tx_hash) fail(`transaction hash ${h} is not the case's tx_hash ${ctx.case.tx_hash}`);
    ctx.ser = ser;
    ctx.txHash = h;
    return `type ${ser.type} (${ser.typeName}), chain id ${ser.chainId}; hash ${h} recomputed from the signed fields equals the transaction's hash and the case's tx_hash`;
  });
  await check(r, ok, "f.sender", ["f.transaction"], async () => {
    const sender = await recoverSigner(keccak256(ctx.ser.payloadHex), ctx.ser.r, ctx.ser.s, ctx.ser.yParity);
    const from = address(ctx.chain.tx.from, "transaction from");
    if (sender !== from) fail(`the signature recovers to ${party(sender)}, not the transaction's from ${party(from)}`);
    ctx.sender = sender;
    return `sender ${party(sender)} recovered from the transaction signature (low s) equals the transaction's from`;
  });
  await fact("f.receipt", ["f.transaction"], async () => {
    const rc = ctx.chain.rc;
    const tx = ctx.chain.tx;
    if (!isPlainObject(rc)) fail("receipt is not a JSON object");
    if (rc.status !== "0x1") fail(`receipt status is ${JSON.stringify(rc.status)}, not "0x1"`);
    if (rc.transactionHash !== ctx.txHash) fail("receipt transactionHash differs from the transaction's");
    hexBytes(rc.blockHash, "receipt blockHash", 32);
    for (const k of ["blockHash", "blockNumber", "transactionIndex"]) if (rc[k] !== tx[k]) fail(`receipt ${k} ${rc[k]} differs from the transaction's ${tx[k]}`);
    quantity(rc.blockNumber, "receipt blockNumber");
    quantity(rc.transactionIndex, "receipt transactionIndex");
    for (const m of ["from", "to", "type", "contractAddress", "logs"]) if (!(m in rc)) fail(`receipt lacks ${m}`);
    if (address(rc.from, "receipt from") !== address(tx.from, "transaction from")) fail("receipt from differs from the transaction's");
    if ((rc.to === null ? null : address(rc.to, "receipt to")) !== (tx.to === null ? null : address(tx.to, "transaction to"))) fail("receipt to differs from the transaction's");
    if (rc.type !== tx.type) fail("receipt type differs from the transaction's");
    if (tx.to !== null && rc.contractAddress !== null) fail("receipt names a created contract for a call");
    if (!Array.isArray(rc.logs)) fail("receipt has no logs array");
    ctx.logs = rc.logs.map((l, k) => normLog(l, k));
    rc.logs.forEach((l, k) => {
      for (const m of ["blockHash", "blockNumber", "transactionHash", "transactionIndex", "logIndex", "removed"]) if (!(m in l)) fail(`receipt log ${k} lacks ${m}`);
      for (const m of ["blockHash", "blockNumber", "transactionHash", "transactionIndex"]) if (l[m] !== rc[m]) fail(`receipt log ${k} ${m} differs from the receipt's`);
      if (l.removed !== false) fail(`receipt log ${k} is not marked removed: false`);
    });
    return `status 0x1; same transaction hash, block number ${BigInt(rc.blockNumber)}, block hash ${rc.blockHash}, index ${BigInt(rc.transactionIndex)}; ${ctx.logs.length} log(s)`;
  });
  await fact("f.block", ["f.receipt"], async () => {
    const b = ctx.chain.blk;
    const tx = ctx.chain.tx;
    if (!isPlainObject(b)) fail("block is not a JSON object");
    if (b.number !== tx.blockNumber || b.hash !== tx.blockHash) fail(`block ${b.number} ${b.hash} is not the transaction's block ${tx.blockNumber} ${tx.blockHash}`);
    if (!Array.isArray(b.transactions)) fail("block has no transactions array");
    const idx = Number(quantity(tx.transactionIndex, "transactionIndex"));
    const at = b.transactions[idx];
    if ((typeof at === "string" ? at : at?.hash) !== ctx.txHash) fail(`the block's transactions[${idx}] is not the transaction`);
    ctx.blockTs = quantity(b.timestamp, "block timestamp");
    if (tx.blockTimestamp !== undefined && tx.blockTimestamp !== b.timestamp) fail("the transaction's blockTimestamp differs from the block's timestamp");
    ctx.chain.rc.logs.forEach((l, k) => {
      if (l.blockTimestamp !== undefined && l.blockTimestamp !== b.timestamp) fail(`receipt log ${k} blockTimestamp differs from the block's timestamp`);
    });
    return `block ${BigInt(b.number)} ${b.hash} lists the transaction at index ${idx}`;
  });
  await fact("f.block-hash", ["f.block"], async () => {
    const hh = headerHash(ctx.chain.blk);
    const extra = hh.unknown.length ? ` (member(s) ${hh.unknown.join(", ")} are not header fields this checker knows${hh.recomputed === ctx.chain.blk.hash ? " and are not part of the hash" : "; if they are header fields of a newer format, this checker was not built for it"})` : "";
    if (hh.recomputed !== ctx.chain.blk.hash) fail(`block hash ${ctx.chain.blk.hash} is not keccak-256 of its ${hh.fields} header fields (${hh.recomputed})${extra}`);
    return `block hash recomputed from its ${hh.fields} header fields${extra}; the header binds number, timestamp ${secondsIso(ctx.blockTs)} and the transactions and receipts roots, which are not themselves recomputed`;
  });

  // g. The binding, and h. trailers.
  let call = null;
  if (ok["f.transaction"]) {
    try {
      let caseAbi = null;
      const abiBuf = readCase("chain/target-abi.json");
      if (abiBuf) {
        const abi = readJson(abiBuf, "chain/target-abi.json");
        if (!Array.isArray(abi)) fail("chain/target-abi.json is not a JSON ABI array");
        caseAbi = plain(abi);
      }
      const to = ctx.chain.tx.to === null ? null : address(ctx.chain.tx.to, "to");
      call = recogniseCall(ctx.chain.tx.input, to, caseAbi);
      ok.call = true;
    } catch (e) {
      r.add("FAIL", "g.call", `the call could not be read: ${shortError(e)}`);
      ok.call = false;
    }
  }

  // EIP-3009: the authorization, the token's domain, the token's logs and the
  // validity window. Run for a recognised transferWithAuthorization in either
  // mode; the authorizer it derives is the payer.
  // An EIP-3009 call this version does not read: its reason, for g.binding.
  let eip3009Unread = null;
  let eip3009 = call && call.kind && call.kind.startsWith("eip3009-transfer") && call.decoded && call.decoded.canonical;
  if (call && call.kind && call.kind.startsWith("eip3009-receive")) {
    eip3009Unread = "receiveWithAuthorization is not read in this version";
    r.add("NOT SUPPORTED", "g.authorization", eip3009Unread);
  } else if (call && call.kind && call.kind.startsWith("eip3009") && call.decoded && !call.decoded.canonical) {
    eip3009Unread = `the transferWithAuthorization arguments are not read: ${call.decoded.reason}`;
    r.add("FAIL", "g.authorization", eip3009Unread);
  } else if (eip3009 && call.kind === "eip3009-transfer-bytes" && (call.decoded.args[6].length - 2) / 2 !== 65) {
    eip3009Unread = `the authorization signature is ${(call.decoded.args[6].length - 2) / 2} bytes, not 65: a contract-wallet signature (ERC-1271 or ERC-6492) is not read in this version`;
    r.add("NOT SUPPORTED", "g.authorization", eip3009Unread);
    eip3009 = false;
  }
  if (eip3009) {
    const auth = authorizationFields(call.decoded);
    ctx.auth = auth;
    await check(r, ok, "g.token-domain", ordering ? ["f.transaction", "f.block", "a.profile"] : ["f.transaction", "f.block"], async () => {
      const token = address(ctx.chain.tx.to, "to");
      let domain = null;
      let note = "";
      // Ordering mode: the token and its domain are the pinned profile's. Trailer-report
      // mode pins nothing: chain/token-domain.json, or the token itself with --online.
      const tdBuf = ordering ? null : readCase("chain/token-domain.json");
      const ignored = ordering && readCase("chain/token-domain.json") ? "; chain/token-domain.json is not read in ordering mode" : "";
      if (ordering) {
        const t = ctx.profile.tokens.get(token);
        if (!t) fail(`the transaction calls ${token}, which the pinned profile does not name among its EIP-3009 tokens (${ctx.profile.tokens.size ? [...ctx.profile.tokens.keys()].join(", ") : "it names none"})`);
        domain = { name: t.name, version: t.version, chainId: ctx.case.chain_id, verifyingContract: token };
        note = `named by the pinned profile${ignored}`;
      } else if (tdBuf) {
        const td = readJson(tdBuf, "chain/token-domain.json");
        exactMembers(td, ["name", "version", "chainId", "verifyingContract", "source"], [], "chain/token-domain.json");
        if (typeof td.name !== "string" || typeof td.version !== "string" || !Number.isSafeInteger(td.chainId)) fail("chain/token-domain.json name, version or chainId is malformed");
        if (!isPlainObject(td.source)) fail("chain/token-domain.json source is not an object");
        domain = { name: td.name, version: td.version, chainId: td.chainId, verifyingContract: address(td.verifyingContract, "verifyingContract") };
        note = `pinned in chain/token-domain.json (source: ${JSON.stringify(plain(td.source))})`;
      }
      if (online && ctx.rpcAnswers) {
        const live = [];
        const atLatest = new Set();
        for (const a of ctx.rpcAnswers) {
          const call1 = async (data) => {
            try {
              return await rpc(a.url, "eth_call", [{ to: token, data }, ctx.chain.tx.blockNumber], fetchImpl);
            } catch {
              atLatest.add(a.url);
              return await rpc(a.url, "eth_call", [{ to: token, data }, "latest"], fetchImpl);
            }
          };
          live.push({ url: a.url, raw: { name: await call1("0x06fdde03"), version: await call1("0x54fd4d50"), separator: await call1("0x3644e515") } });
        }
        if (jcs(live[0].raw) !== jcs(live[1].raw)) fail("the two endpoints do not give byte-equal answers for the token's name(), version() and DOMAIN_SEPARATOR()");
        for (const l of live) Object.assign(l, { name: decodeAbiString(l.raw.name), version: decodeAbiString(l.raw.version), separator: l.raw.separator });
        const d2 = { name: live[0].name, version: live[0].version, chainId: ctx.case.chain_id, verifyingContract: token };
        if (domainSeparator({ domain: d2 }) !== live[0].separator) fail("DOMAIN_SEPARATOR() is not the separator of the token's name(), version(), the chain id and its address");
        if (domain && !sameJson(domain, d2)) fail(`${ordering ? "the pinned profile's domain" : "chain/token-domain.json"} ${JSON.stringify(domain)} differs from the token's own ${JSON.stringify(d2)}`);
        domain = d2;
        note = `${ordering ? "named by the pinned profile and " : ""}read with eth_call (name, version, DOMAIN_SEPARATOR) from ${live.map((l) => l.url).join(" and ")} at ${atLatest.size ? `the latest block (${[...atLatest].join(", ")} would not answer at block ${BigInt(ctx.chain.tx.blockNumber)})` : `the transaction's block ${BigInt(ctx.chain.tx.blockNumber)}`}${tdBuf ? ", equal to chain/token-domain.json" : ""}${ignored}`;
      }
      if (!domain) fail("no token domain: offline trailer-report mode needs chain/token-domain.json");
      if (BigInt(domain.chainId) !== BigInt(ctx.case.chain_id)) fail(`token domain chainId ${domain.chainId} is not the case's chain id`);
      if (domain.verifyingContract !== token) fail("the token domain's verifyingContract is not the contract the transaction calls");
      ctx.tokenDomain = domain;
      return `token ${token}: EIP-712 domain {name ${JSON.stringify(domain.name)}, version ${JSON.stringify(domain.version)}, chainId ${domain.chainId}, verifyingContract ${token}}, ${note}`;
    });
    await check(r, ok, "g.authorization", ["g.token-domain"], async () => {
      const { signer } = await recoverAuthorization(auth, ctx.tokenDomain);
      if (signer !== auth.from) fail(`the authorization signature recovers to ${party(signer)}, not the authorization's from ${party(auth.from)}`);
      ctx.payer = signer;
      return `${call.decoded.signature}: the authorization signature recovers to its from ${party(signer)} (the payer); to ${party(auth.to)}, value ${auth.value}, validAfter ${secondsIso(auth.validAfter)}, validBefore ${secondsIso(auth.validBefore)}, nonce ${auth.nonce}`;
    });
    // A Transfer log counts only when it comes from the token the pinned profile
    // names, moves more than zero, comes from the authorization's signer, and is
    // tied to the authorization by its nonce (an AuthorizationUsed log).
    const tokenLogs = () => {
      const token = ctx.tokenDomain.verifyingContract;
      const used = ctx.logs.filter((l) => l.address === token && l.topics[0] === AUTHORIZATION_USED_TOPIC);
      if (used.length !== 1) fail(`the receipt holds ${used.length} AuthorizationUsed logs from the token, not one`);
      if (used[0].topics.length !== 3 || used[0].topics[1] !== pad32Addr(auth.from) || used[0].topics[2] !== auth.nonce) fail("the AuthorizationUsed log names another authorizer or nonce, so no Transfer is tied to this authorization");
      if (auth.value === 0n) fail("the authorization moves 0, and a Transfer of 0 does not count");
      const transfers = ctx.logs.filter((l) => l.address === token && l.topics[0] === TRANSFER_TOPIC && l.topics.length === 3 && l.topics[1] === pad32Addr(auth.from) && l.topics[2] === pad32Addr(auth.to) && l.data === "0x" + auth.value.toString(16).padStart(64, "0"));
      if (transfers.length !== 1) fail(`the receipt holds ${transfers.length} Transfer logs from the token with the authorization's from, to and value, not one`);
      return `one AuthorizationUsed(${party(auth.from)}, nonce) from the token ${token}${ordering ? ", the token the pinned profile names" : ""}, which ties the transfer to this authorization, and one Transfer from ${party(auth.from)} to ${party(auth.to)} of ${auth.value} (more than zero) from the same token, equal to the authorization's fields; the call is the transaction's top-level call to the token`;
    };
    if (ordering) await fact("g.token-logs", ["g.authorization", "f.receipt"], tokenLogs);
    else if (ok["g.authorization"] && ok["f.receipt"]) {
      try {
        r.add("INFO", "g.token-logs", `${tokenLogs()} (reported only: trailer-report mode pins no token, so no log is counted)`);
      } catch (e) {
        r.add("INFO", "g.token-logs", `${e instanceof CheckFail ? e.message : shortError(e)} (reported only: trailer-report mode counts no log)`);
      }
    }
    await fact("g.validity-window", ["g.authorization", "f.block"], async () => {
      if (!(ctx.blockTs > auth.validAfter && ctx.blockTs < auth.validBefore)) fail(`block timestamp ${ctx.blockTs} is outside (validAfter ${auth.validAfter}, validBefore ${auth.validBefore}), which the token itself enforces`);
      return `block timestamp ${secondsIso(ctx.blockTs)} is inside (validAfter, validBefore), as the token enforces`;
    });
  }

  if (ordering) {
    await check(r, ok, "g.binding", ["c.receipt-uids", "f.sender", "f.receipt", "call"], async () => {
      const target = "0x" + ctx.dstEntryHash.slice("sha256:".length);
      const input = ctx.chain.tx.input;
      const offsets = findBytes(input, target);
      const srcOffsets = findBytes(input, "0x" + ctx.entryHashes[ctx.srcIndex].slice(7));
      if (srcOffsets.length) r.add("INFO", "g.source-entry", `the source entry hash also appears in the calldata at byte offset(s) ${srcOffsets.join(", ")}`);
      const claimed = ctx.case.binding;
      // signer: the account recovered from the signature over the bytes that carry
      // the hash. It must be the authorizer the verifier states; the case never names it.
      const settle = (path, signer, how) => {
        if (stated !== null && signer !== stated) fail(`CARRIED-BY-OTHER: ${how}; the verifier states the authorizer ${party(stated)} (--authorizer), who did not sign those bytes, so the ordering is not shown`);
        if (path !== claimed) fail(`the case claims binding ${claimed}, but ${how}: set binding to ${path}`);
        if (stated === null) {
          r.add("FLAG", "g.binding", `authorizer not stated by the verifier: ${how}; the account recovered from that signature is ${party(signer)}. Run with --authorizer <address> to require the account the trade must come from; without it no run passes`);
          return undefined;
        }
        return `BOUND: ${how}; this is the authorizer the verifier stated (--authorizer)`;
      };
      if (call.kind === "userop") {
        r.add("NOT SUPPORTED", "g.userop", "the transaction calls an ERC-4337 EntryPoint; a hash inside a UserOperation's callData is not read in this version");
        fail("no binding established: the UserOperation path is not supported in this version");
      }
      const position = (o) => {
        if (!call.decoded) return `${o} (position relative to the arguments not determined: ${call.note ?? call.kind})`;
        if (!call.decoded.canonical) return `${o} (position relative to the arguments not determined: ${call.decoded.reason})`;
        return o >= call.decoded.argsEnd ? `${o} (after the ABI-encoded arguments of ${call.decoded.signature}, which end at byte ${call.decoded.argsEnd})` : `${o} (inside the ABI-encoded arguments of ${call.decoded.signature})`;
      };
      if (eip3009Unread) fail(`no binding established: ${eip3009Unread}`);
      if (offsets.length === 0) fail(`ABSENT: the destination entry hash ${target} is not in the transaction's calldata${eip3009 ? `; the authorization nonce is ${ctx.auth.nonce}` : ""}`);
      if (eip3009) {
        // The payer signed the authorization's six words (bytes 4 to 196); the
        // transaction sender signed the whole calldata.
        for (const k of ["g.authorization", "g.token-logs", "g.validity-window"]) if (!ok[k]) fail(`${k} did not pass, so the payment's authorizer is not established`);
        if (offsets.includes(NONCE_OFFSET)) return settle("eip3009-nonce", ctx.payer, `the destination entry hash is the EIP-3009 nonce (calldata byte offset ${NONCE_OFFSET}), in the authorization signed by ${party(ctx.payer)} (recovered from the authorization signature)`);
        const inAuth = offsets.filter((o) => o >= 4 && o + 32 <= NONCE_OFFSET);
        if (inAuth.length) {
          r.add("NOT SUPPORTED", "g.authorization-word", `the hash is at byte offset ${inAuth.join(", ")}, an authorization word other than the nonce; only the nonce is read as a carrier in this version`);
          fail("no binding established: the hash sits in an authorization word other than the nonce");
        }
        // The value moves from the authorization's from, so the account that signed
        // the calldata must be that account too.
        if (ctx.sender !== ctx.payer) fail(`CARRIED-BY-OTHER: the destination entry hash is at byte offset ${offsets.map(position).join(", ")}, in bytes only the transaction signature covers, signed by its sender ${party(ctx.sender)}; the payment moves value from ${party(ctx.payer)}, who signed the authorization and did not sign those bytes, so no one account both signed the bytes that carry the hash and moved the value, and the ordering is not shown`);
        return settle("calldata", ctx.sender, `the destination entry hash is in the calldata at byte offset ${offsets.map(position).join(", ")}, in bytes only the transaction signature covers, signed by its sender ${party(ctx.sender)}, who also signed the authorization from which the value moves`);
      }
      // Any other call: the calldata is signed by the transaction's sender alone. A
      // trade whose authorizing signature is over an intent another account submits
      // is not read in this version; that account is the signer here.
      return settle("calldata", ctx.sender, `the destination entry hash is in the calldata at byte offset ${offsets.map(position).join(", ")}, signed by the transaction's sender ${party(ctx.sender)} (recovered from the transaction signature)`);
    });
  } else if (ok.case) {
    r.add("INFO", "g.binding", "trailer-report mode: no entry hash is supplied and none is claimed; bytes after the arguments are reported in h, not read as an entry hash");
  }

  if (call) {
    const t = (() => {
      if (call.kind === "userop") return "the call is an ERC-4337 EntryPoint batch; trailers inside UserOperations are not read";
      if (call.kind === "no-selector") return "the calldata is shorter than a selector";
      const tailSuffix = () => {
        try {
          const s = parseErc8021(ctx.chain.tx.input);
          return s ? `an ERC-8021 suffix ends the calldata (${describe8021(s)})` : "no ERC-8021 suffix ends the calldata";
        } catch (e) {
          return `the calldata ends with the ERC-8021 marker but the suffix does not parse: ${e.message}`;
        }
      };
      if (!call.decoded) return `the call is not recognised (${call.note}); the end of its arguments is not known; ${tailSuffix()}`;
      if (!call.decoded.canonical) return `${call.decoded.signature}: ${call.decoded.reason}; the end of its arguments is not determined; ${tailSuffix()}`;
      const tr = call.decoded.trailerHex;
      const len = (tr.length - 2) / 2;
      if (len === 0) return `${call.decoded.signature}: no bytes after the ABI-encoded arguments (which end at byte ${call.decoded.argsEnd})`;
      let s = null;
      let err = null;
      try {
        s = parseErc8021(tr);
      } catch (e) {
        err = e.message;
      }
      const parts = [`${call.decoded.signature}: ${len} byte(s) after the ABI-encoded arguments (from byte ${call.decoded.argsEnd}), signed by the transaction sender only`];
      if (s && s.unknown) parts.push(`it ends with the ERC-8021 marker and schema id ${s.schemaId}, which this checker does not decode`);
      else if (s && s.length <= len) {
        parts.push(`the last ${s.length} byte(s) are an ERC-8021 suffix: ${describe8021(s)}`);
        if (s.length < len) parts.push(`${len - s.length} byte(s) before it are not part of the suffix`);
      } else if (s) parts.push(`it ends with the ERC-8021 marker, but the suffix it describes (${s.length} bytes) is longer than the bytes after the arguments`);
      else if (err) parts.push(`it ends with the ERC-8021 marker but does not parse: ${err}`);
      else parts.push("it is not an ERC-8021 suffix");
      if (ordering && ok["c.receipt-uids"]) {
        const inTrailer = findBytes(tr, "0x" + ctx.dstEntryHash.slice(7));
        parts.push(inTrailer.length ? `the destination entry hash is in it at trailer offset(s) ${inTrailer.join(", ")} (whether that binds is g.binding's finding)` : "it does not hold the destination entry hash");
      } else parts.push("no entry hash is read from it");
      return parts.join("; ");
    })();
    r.add("INFO", "h.trailer", t);
  }

  // i. Times: reported, not judged.
  if (ordering) {
    for (const role of ROLES) {
      const x = ctx.receipts[role];
      if (x?.msg) r.add("INFO", `i.${role}`, `checked at ${isoUtc(x.checkedAt)}, valid until ${isoUtc(x.validUntil)} (the issuer's clock, signed in the receipt)`);
    }
    if (ctx.entries) {
      const ts = ctx.entries.map((e, k) => (typeof e.ts === "string" ? `entry ${k} ${e.ts}` : null)).filter(Boolean);
      r.add("INFO", "i.entries", ts.length ? `${ts.join("; ")} (the log operator's clock)` : "the entries carry no ts");
    }
    if (ctx.checkpoint) r.add("INFO", "i.checkpoint", `checkpoint ts ${ctx.checkpoint.ts} (the log operator's clock)${ctx.witness && ctx.witness.checkpoint_ts !== ctx.checkpoint.ts ? `; the witness's checkpoint_ts ${ctx.witness.checkpoint_ts}` : ""}`);
    if (ctx.witness) r.add("INFO", "i.received_at", `${ctx.witness.received_at} (Headless Oracle's clock${ctx.pinsTest ? "; here a stub" : ""})`);
  }
  if (ctx.blockTs !== undefined) r.add("INFO", "i.block", `block timestamp ${isoUtc(ctx.blockTs)} (Base's clock, set by the block producer)`);
  if (ordering && ctx.blockTs !== undefined) {
    for (const role of ROLES) {
      const x = ctx.receipts[role];
      if (!x?.msg) continue;
      if (ctx.blockTs > x.validUntil) r.add("FLAG", `i.${role}-valid-until`, `the block's timestamp is ${ctx.blockTs - x.validUntil} s after the ${role} receipt's valid-until time (reported, not judged)`);
      if (ctx.blockTs < x.checkedAt) r.add("FLAG", `i.${role}-checked-at`, `the block's timestamp is ${x.checkedAt - ctx.blockTs} s before the ${role} receipt's check time (reported, not judged)`);
    }
    if (ctx.witness) {
      const rec = Date.parse(ctx.witness.received_at);
      if (Number.isFinite(rec)) {
        const diff = Number(ctx.blockTs) * 1000 - rec;
        r.add("INFO", "i.received_at-vs-block", `witness received_at is ${Math.abs(diff) / 1000} s ${diff >= 0 ? "before" : "after"} the block timestamp (two clocks; the ordering rests on g.binding, not on this)`);
      }
    }
  }

  for (const f of files) r.add("INFO", "files", f);

  const fails = r.count("FAIL");
  const passes = r.count("PASS");
  const flags = r.ids("FLAG");
  const nvo = r.ids("NOT VERIFIED OFFLINE");
  const nc = r.ids("NOT CHECKED");
  const ns = r.ids("NOT SUPPORTED");
  const total = (ids) => (ids.length ? `${ids.length}: ${ids.join(", ")}` : "0");
  r.add("SUMMARY", "flag", total(flags));
  r.add("SUMMARY", "not-verified-offline", total(nvo));
  r.add("SUMMARY", "not-checked", total(nc));
  r.add("SUMMARY", "not-supported", total(ns));
  const tag = ctx.pinsTest ? " [TEST PINS: a test issuer profile and a stub witness key, not evidence]" : ctx.profile?.test ? " [TEST PROFILE: not evidence]" : "";
  const counts = `${passes} PASS, ${fails} FAIL, ${flags.length} FLAG, ${nvo.length} NOT VERIFIED OFFLINE, ${nc.length} NOT CHECKED, ${ns.length} NOT SUPPORTED`;
  let result;
  let exitCode;
  if (fails) {
    result = `FAIL (${counts})${tag}`;
    exitCode = 1;
  } else if (!ordering) {
    result = `TRAILER REPORT: the transaction was read and reported; no ordering is claimed (${counts})${tag}`;
    exitCode = 3;
  } else if (nvo.length) {
    result = `NOT VERIFIED OFFLINE: no check failed, but the chain data (the transaction's receipt, its logs and its block) is as the case supplies it, not two endpoints' byte-equal answers; this is not a pass (${counts})${tag}`;
    exitCode = 4;
  } else if (flags.length) {
    result = `FLAG: no check failed, but ${flags.length} FLAG line(s) stand against a pass: ${flags.join(", ")} (${counts})${tag}`;
    exitCode = 5;
  } else {
    result = `PASS: every check that applies passed, online, with the authorizer the verifier stated (${counts})${tag}`;
    exitCode = 0;
  }
  r.add("RESULT", "", result);
  return { rows: r.rows, exitCode, result };
}

function describe8021(s) {
  const base = `schema ${s.schemaId}`;
  if (s.unknown) return `${base}, unknown to this checker, not decoded`;
  if (s.codes) return `${base}, codes ${JSON.stringify(s.codes)}${s.codeRegistryAddress ? `, code registry ${s.codeRegistryAddress} on chain ${s.codeRegistryChainId}` : ", the chain's canonical code registry"}, ${s.length} bytes`;
  return `${base}, CBOR ${cborToText(s.cbor)}, ${s.length} bytes`;
}

export function formatRows(rows) {
  const SUMMARY = { flag: "FLAG", "not-verified-offline": "NOT VERIFIED OFFLINE", "not-checked": "NOT CHECKED", "not-supported": "NOT SUPPORTED" };
  return rows.map((x) => (x.status === "RESULT" ? `RESULT: ${x.text}` : x.status === "SUMMARY" ? `${SUMMARY[x.id]} total: ${x.text}` : `${x.status} ${x.id}: ${x.text}`)).join("\n");
}

export function diskIo(caseDir, pinsDir) {
  const read = (base) => (rel) => {
    const p = path.resolve(base, rel);
    if (!p.startsWith(path.resolve(base) + path.sep)) return null;
    try {
      return readFileSync(p);
    } catch (e) {
      if (e.code === "ENOENT") return null;
      throw e;
    }
  };
  return { readCase: read(caseDir), readPin: read(pinsDir) };
}

export async function main(argv = process.argv.slice(2)) {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: { online: { type: "boolean" }, "show-parties": { type: "boolean" }, pins: { type: "string" }, "profile-sha256": { type: "string", multiple: true }, authorizer: { type: "string", multiple: true }, rpc: { type: "string", multiple: true }, help: { type: "boolean" } },
    });
  } catch (e) {
    console.error(`usage error: ${e.message}`);
    process.exit(2);
  }
  if (args.values.help || args.positionals.length !== 1) {
    console.error("usage: node check-h4.mjs <case-dir> [--authorizer <address>] [--online] [--show-parties] [--pins <dir>] [--profile-sha256 <hex>]... [--rpc <url>]...");
    process.exit(args.values.help ? 0 : 2);
  }
  for (const h of args.values["profile-sha256"] ?? []) {
    if (!/^[0-9a-f]{64}$/.test(h)) {
      console.error(`usage error: --profile-sha256 ${h} is not 64 lowercase hex digits`);
      process.exit(2);
    }
  }
  // One --authorizer: a second one (a wrapper that appends a default, say) is
  // refused rather than read in place of the first.
  const given = args.values.authorizer ?? [];
  if (given.length > 1) {
    console.error(`usage error: --authorizer is given ${given.length} times; give it once`);
    process.exit(2);
  }
  let authorizer;
  try {
    if (given.length === 1) authorizer = authorizerAddress(given[0]);
    if (args.values.rpc !== undefined) rpcEndpoints(args.values.rpc);
  } catch (e) {
    console.error(`usage error: ${e.message}`);
    process.exit(2);
  }
  const caseDir = path.resolve(args.positionals[0]);
  const pinsDir = path.resolve(args.values.pins ?? path.join(FOLDER, "pins"));
  let out;
  try {
    out = await checkCase(diskIo(caseDir, pinsDir), { online: args.values.online, showParties: args.values["show-parties"], profileSha256: args.values["profile-sha256"], authorizer, rpcUrls: args.values.rpc });
  } catch (e) {
    // Every input is read inside a check; this is a last guard, so a RESULT line
    // and exit 1 are printed however the run ends.
    console.log(`FAIL checker: the run stopped on an input it does not handle: ${shortError(e)}`);
    console.log("RESULT: FAIL (the run stopped; see the line above)");
    process.exitCode = 1;
    return;
  }
  console.log(formatRows(out.rows));
  process.exitCode = out.exitCode;
}
