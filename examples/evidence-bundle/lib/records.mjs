// Gate logs (spec M2), checkpoints (M3), witness receipts (M4), action
// arguments (M8) and keys (M9), read from the members' decoded bytes.

import canonicalize from "canonicalize";
import { createHash } from "node:crypto";
import {
  b64urlCanonical,
  ed25519Verify,
  isPlainObject,
  jcs,
  jcsSha256,
  okpThumbprint,
  parseStrictJson,
  SHA256_RE,
  withoutMember,
} from "../../ordering-evidence-h4/lib/formats.mjs";
import { LEGACY_KID_RE, THUMBPRINT_RE, TIME_RE, UID_RE } from "./table.mjs";

const utf8 = (bytes) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
const isStr = (v) => typeof v === "string";
const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");

// A chirindo session file, read as chirindo's strict reader reads it
// (src/vendor/recorder/io.ts: each line trimmed, blank lines skipped, a line
// whose type is "checkpoint" an in-file checkpoint that must come last).
export function parseChirindoLog(bytes) {
  const lines = utf8(bytes).split(/\r?\n/);
  const records = [];
  let checkpoint = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.length === 0) continue;
    const obj = parseStrictJson(Buffer.from(t, "utf8"));
    if (!isPlainObject(obj)) throw new Error(`line ${i + 1} is not a JSON object`);
    if (obj.type === "checkpoint") {
      if (checkpoint) throw new Error("more than one in-file checkpoint");
      checkpoint = obj;
    } else {
      if (checkpoint) throw new Error("a record follows the in-file checkpoint");
      records.push(obj);
    }
  }
  return { records, checkpoint };
}

// A witness sidecar (chirindo-witness-sidecar/1): one line per checkpoint, each
// an object with exactly checkpoint, witness_receipt and witness_error. Line
// terminators and blank lines are not read (spec table 4-8).
export function parseSidecar(bytes) {
  const out = [];
  const lines = utf8(bytes).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.length === 0) continue;
    const obj = parseStrictJson(Buffer.from(t, "utf8"));
    const names = isPlainObject(obj) ? Object.keys(obj) : [];
    if (names.length !== 3 || !["checkpoint", "witness_receipt", "witness_error"].every((k) => names.includes(k))) throw new Error(`line ${i + 1} is not an object with exactly checkpoint, witness_receipt and witness_error`);
    if (!(obj.witness_error === null || isStr(obj.witness_error))) throw new Error(`line ${i + 1}: witness_error is neither a string nor null`);
    if (!(obj.witness_receipt === null || isPlainObject(obj.witness_receipt))) throw new Error(`line ${i + 1}: witness_receipt is neither an object nor null`);
    out.push({ line: i + 1, checkpoint: obj.checkpoint, receipt: obj.witness_receipt, error: obj.witness_error });
  }
  return out;
}

export const entryHash = (rec) => jcsSha256(withoutMember(rec, "sig"));
export const genesisHash = (v, sessionId) => jcsSha256({ v, session_id: sessionId, marker: "genesis" });

// chirindo's request commitment (src/vendor/recorder/request.ts): the JCS
// SHA-256 of the closed descriptor of the event's type.
export function requestCommitment(event) {
  if (!isPlainObject(event)) throw new Error("event is not an object");
  let d;
  if (event.type === "shell") d = { class: "shell", argv: event.argv, cwd: event.cwd };
  else if (event.type === "file_edit") d = { class: "file_edit", path: event.path, content_hash: event.content_hash };
  else if (event.type === "file_read") d = { class: "file_read", path: event.path };
  else if (event.type === "tool_call") d = { class: "tool_call", tool: event.tool_name, args_hash: event.args_hash };
  else if (event.type === "mcp_call") d = { class: "mcp_call", server: event.server, tool: event.tool_name, args_hash: event.args_hash };
  else throw new Error(`event.type ${JSON.stringify(event.type)} is not one chirindo writes`);
  return "sha256:" + sha256Hex(Buffer.from(canonicalize(d), "utf8"));
}

// The Ed25519 public keys the carried operator-key members hold, by RFC 7638
// thumbprint (spec M2: kid is the thumbprint of a carried operator key).
export function operatorKeysByThumbprint(opMembers) {
  const out = new Map();
  for (const { value, profile } of opMembers) {
    const list = profile === "jwks" ? (isPlainObject(value) && Array.isArray(value.keys) ? value.keys : []) : [value];
    for (const k of list) {
      if (!isPlainObject(k) || k.kty !== "OKP" || k.crv !== "Ed25519") continue;
      let pub;
      try {
        pub = b64urlCanonical(k.x, 32, "x");
      } catch {
        continue;
      }
      const t = okpThumbprint(k.x);
      if (!out.has(t)) out.set(t, pub);
    }
  }
  return out;
}

export const tsMs = (s) => (isStr(s) && TIME_RE.test(s) && Number.isFinite(Date.parse(s)) ? Date.parse(s) : null);

// M2 for one chirindo-evidence.action/1 log (spec 4.2). Returns
// { status, reason, detail, flags[], entryHashes[] }.
export function m2ChirindoLog(log, opKeys) {
  const flags = [];
  const fail = (detail) => ({ status: "FAIL", reason: null, detail, flags, entryHashes: [] });
  const recs = log.records;
  if (recs.length === 0) return fail("the log holds no record");
  const r0 = recs[0];
  const v = r0.v;
  if (!["evidence.action/1", "evidence.action/0"].includes(v)) return fail("record 0: v is not evidence.action/1 or evidence.action/0");
  if (!isStr(r0.session_id) || r0.session_id.length === 0) return fail("record 0: session_id is not a non-empty string");
  if (!isStr(r0.kid)) return fail("record 0: kid is not a string");
  const kid = r0.kid;
  const legacy = LEGACY_KID_RE.test(kid);
  if (!legacy && !THUMBPRINT_RE.test(kid)) return fail("kid is neither an RFC 7638 thumbprint nor a legacy kid");
  const hashes = [];
  let prev = genesisHash(v, r0.session_id);
  let jwksUri;
  let lastTs = null;
  let legacyFieldsAbsent = false;
  for (let i = 0; i < recs.length; i++) {
    const r = recs[i];
    const at = `record ${i}`;
    if (r.seq !== i) return fail(`${at}: seq is not ${i}`);
    if (r.v !== v || r.session_id !== r0.session_id || r.kid !== kid) return fail(`${at}: v, session_id or kid differs from record 0`);
    if (r.prev_hash !== prev) return fail(`${at}: prev_hash is not ${i === 0 ? "the genesis hash" : "the entry hash of the record before it"}`);
    let h;
    try {
      h = entryHash(r);
    } catch (e) {
      return fail(`${at}: no RFC 8785 form (${e.message})`);
    }
    hashes.push(h);
    prev = h;
    const names = Object.keys(r);
    if (names.includes("receipt_uid") && !(isStr(r.receipt_uid) && UID_RE.test(r.receipt_uid))) return fail(`${at}: receipt_uid is not 0x and 64 lowercase hex digits`);
    if (!isStr(r.sig)) return fail(`${at}: sig is not a string`);
    let rc;
    try {
      rc = requestCommitment(r.event);
    } catch (e) {
      return fail(`${at}: ${e.message}`);
    }
    if (r.request_commitment !== rc) return fail(`${at}: request_commitment does not recompute`);
    const g = r["gate"];
    if (!isPlainObject(g) || g.request_commitment !== rc) return fail(`${at}: the gate member's request_commitment is not the record's request commitment`);
    if (v === "evidence.action/1") {
      if (r.key_thumbprint !== kid) return fail(`${at}: key_thumbprint is not kid`);
      const hasUri = names.includes("jwks_uri");
      if (i === 0) jwksUri = hasUri ? r.jwks_uri : undefined;
      if ((jwksUri === undefined) === hasUri || (hasUri && r.jwks_uri !== jwksUri)) return fail(`${at}: jwks_uri is not the same in every record`);
      if (hasUri) {
        let u;
        try {
          u = new URL(r.jwks_uri);
        } catch {
          return fail(`${at}: jwks_uri is not a URL`);
        }
        if (u.protocol !== "https:") return fail(`${at}: jwks_uri is not https`);
        if (r.iss !== u.origin) return fail(`${at}: iss is not the origin of jwks_uri`);
      } else if (r.iss !== `urn:chirindo:key:${kid}`) return fail(`${at}: iss is not urn:chirindo:key:<kid>`);
    } else if (!names.includes("iss") || !names.includes("key_thumbprint")) legacyFieldsAbsent = true;
    const t = tsMs(r.ts);
    if (t === null) return fail(`${at}: ts is not a time`);
    if (lastTs !== null && t < lastTs) {
      if (lastTs - t > 5000) return fail(`${at}: ts is ${lastTs - t} ms earlier than the record before it (more than 5,000 ms)`);
      flags.push({ code: "ts-decreases", detail: `${log.member} ${at}: ts is ${lastTs - t} ms earlier than the record before it` });
    }
    lastTs = Math.max(lastTs ?? t, t);
  }
  if (legacyFieldsAbsent) flags.push({ code: "legacy-fields-absent", detail: `${log.member}: its evidence.action/0 records have no iss and no key_thumbprint, members that format does not define` });
  if (legacy) return { status: "NOT-EVALUATED", reason: "legacy-kid", detail: `kid ${kid} is a legacy kid, a form this version does not read; the key binding and the signatures are not evaluated, and every other rule holds`, flags, entryHashes: hashes };
  const pub = opKeys.get(kid);
  if (!pub) return fail("kid is the thumbprint of no carried operator key");
  for (let i = 0; i < recs.length; i++) {
    let sig;
    try {
      sig = b64urlCanonical(recs[i].sig, 64, `record ${i} sig`);
    } catch (e) {
      return fail(e.message);
    }
    if (!ed25519Verify(pub, Buffer.from(jcs(withoutMember(recs[i], "sig")), "utf8"), sig)) return fail(`record ${i}: sig does not verify under the operator key`);
  }
  return { status: "PASS", reason: null, detail: `${recs.length} records, hash chain from genesis, every sig verifies under the key whose thumbprint is kid`, flags, entryHashes: hashes };
}

// M3.checkpoint: the eight members of the served submit.checkpoint and their
// field rules (spec 4.2).
export function m3Shape(c) {
  if (!isPlainObject(c)) return "the checkpoint is not a JSON object";
  const want = ["v", "type", "session_id", "count", "last_entry_hash", "ts", "kid", "sig"];
  const names = Object.keys(c);
  if (names.length !== 8 || !want.every((k) => names.includes(k))) return "the checkpoint does not have exactly its eight members";
  if (c.v !== "evidence.action/1") return "v is not evidence.action/1";
  if (c.type !== "checkpoint") return "type is not checkpoint";
  if (typeof c.count !== "number" || !Number.isSafeInteger(c.count) || c.count < 1) return "count is not a safe integer of at least 1";
  if (!isStr(c.session_id) || c.session_id.length < 1 || c.session_id.length > 128) return "session_id is not 1 to 128 characters";
  if (!isStr(c.last_entry_hash) || !SHA256_RE.test(c.last_entry_hash)) return "last_entry_hash is not sha256: and 64 lowercase hex digits";
  if (tsMs(c.ts) === null) return "ts is not a time";
  if (!isStr(c.kid) || !THUMBPRINT_RE.test(c.kid)) return "kid is not an RFC 7638 thumbprint";
  try {
    b64urlCanonical(c.sig, 64, "sig");
  } catch (e) {
    return e.message;
  }
  return null;
}

export const checkpointSigOk = (c, pub) => ed25519Verify(pub, Buffer.from(jcs(withoutMember(c, "sig")), "utf8"), Buffer.from(c.sig, "base64url"));

const RECEIPT_FIELDS = ["type", "witness", "received_at", "kid", "session_id", "count", "last_entry_hash", "checkpoint_ts", "checkpoint_sha256", "fork", "public_key_id", "signature"];

// M4's shape rules (spec 4.2): exactly twelve members, all strings, and the
// field values the served spec fixes.
export function m4Shape(r) {
  if (!isPlainObject(r)) return "the witness receipt is not a JSON object";
  const names = Object.keys(r);
  if (names.length !== 12 || !RECEIPT_FIELDS.every((k) => names.includes(k))) return "the witness receipt does not have exactly its twelve members";
  for (const k of names) if (!isStr(r[k])) return `${k} is not a string`;
  if (r.type !== "witness.checkpoint/1") return "type is not witness.checkpoint/1";
  if (r.witness !== "headlessoracle.com") return "witness is not headlessoracle.com";
  if (r.fork !== "false") return 'fork is not "false"';
  if (!/^[1-9][0-9]*$/.test(r.count) || !Number.isSafeInteger(Number(r.count))) return "count is not the decimal string of a safe integer of at least 1";
  if (!SHA256_RE.test(r.last_entry_hash) || !SHA256_RE.test(r.checkpoint_sha256)) return "last_entry_hash or checkpoint_sha256 is not sha256: and 64 lowercase hex digits";
  if (tsMs(r.received_at) === null || tsMs(r.checkpoint_ts) === null) return "received_at or checkpoint_ts is not a time";
  if (!/^[0-9a-f]{128}$/.test(r.signature)) return "signature is not 128 lowercase hex digits";
  return null;
}

export const receiptSigOk = (r, pubHex) => ed25519Verify(Buffer.from(pubHex, "hex"), Buffer.from(jcs(withoutMember(r, "signature")), "utf8"), Buffer.from(r.signature, "hex"));

// A key's validity window: valid_from inclusive, valid_until exclusive, null open.
export function inWindow(timeIso, k) {
  const t = Date.parse(timeIso);
  if (!(Date.parse(k.valid_from) <= t)) return false;
  if (k.valid_until === null) return true;
  return t < Date.parse(k.valid_until);
}

// The entries of an ho-v5-keys member, by key id.
export function witnessKeyEntries(value) {
  if (!isPlainObject(value) || !Array.isArray(value.keys)) throw new Error("the member has no keys list");
  const m = new Map();
  for (const e of value.keys) {
    if (!isPlainObject(e) || !isStr(e.key_id)) throw new Error("a keys[] entry has no key_id");
    if (m.has(e.key_id)) throw new Error(`key_id ${e.key_id} is listed twice`);
    m.set(e.key_id, e);
  }
  return m;
}

// Spec M9.witness-key: algorithm Ed25519, format hex, a 32-byte public key.
export function witnessEntryShape(e) {
  if (e.algorithm !== "Ed25519" || e.format !== "hex" || !isStr(e.public_key) || !/^[0-9a-f]{64}$/.test(e.public_key)) return "the entry is not an Ed25519 key in hex of 32 bytes";
  if (!isStr(e.valid_from) || tsMs(e.valid_from) === null || !(e.valid_until === null || tsMs(e.valid_until) !== null)) return "the entry's validity window is not valid_from and valid_until times";
  return null;
}

// M9.operator-key (spec 4.2). `logKids` are the thumbprint kids of the carried
// logs. Returns null when it passes, or the failure.
export function m9OperatorKey(profile, value, logKids) {
  const jwkProblem = (k) => {
    if (!isPlainObject(k)) return "the JWK is not a JSON object";
    if (k.kty !== "OKP" || k.crv !== "Ed25519") return "the JWK is not kty OKP, crv Ed25519";
    try {
      b64urlCanonical(k.x, 32, "x");
    } catch (e) {
      return e.message;
    }
    if (Object.keys(k).includes("kid") && k.kid !== okpThumbprint(k.x)) return "the JWK's kid is not its RFC 7638 thumbprint";
    return null;
  };
  if (profile === "jwk-okp-ed25519") return jwkProblem(value);
  if (!isPlainObject(value) || !Array.isArray(value.keys)) return "the JWKS has no keys list";
  let held = 0;
  for (const kid of logKids) {
    const matches = value.keys.filter((k) => isPlainObject(k) && k.kty === "OKP" && k.crv === "Ed25519" && isStr(k.x) && /^[A-Za-z0-9_-]{43}$/.test(k.x) && okpThumbprint(k.x) === kid);
    if (matches.length > 1) return `the JWKS holds more than one entry for kid ${kid}`;
    if (matches.length === 1) {
      const p = jwkProblem(matches[0]);
      if (p) return p;
      held++;
    }
  }
  if (held === 0) return "the JWKS holds the key of no carried log's kid";
  return null;
}
