// The bundle document (spec section 3, M0) and its manifest (M1).

import canonicalize from "canonicalize";
import { createHash } from "node:crypto";
import { isPlainObject, parseStrictJson } from "../../ordering-evidence-h4/lib/formats.mjs";
import { built } from "./built.mjs";
import { BUNDLE_TYPE, BUNDLE_TYPES, PROFILES_OF } from "./table.mjs";

export const EXPECTED_AUTHORIZER_TEXT = "the account the payment must come from is stated by the person running the verifier, never by the bundle";

const isStr = (v) => typeof v === "string";
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");

function exactly(obj, required, optional, what) {
  if (!isPlainObject(obj)) return `${what} is not a JSON object`;
  const keys = Object.keys(obj);
  for (const k of required) if (!keys.includes(k)) return `${what} lacks member ${k}`;
  for (const k of keys) if (!required.includes(k) && !optional.includes(k)) return `${what} has a member this format does not name: ${JSON.stringify(k)}`;
  return null;
}

const MEMBER_FIELDS = ["id", "role", "profile", "media_type", "sha256", "bytes_b64", "source", "fetched_at", "capture"];

// M0 (spec 4.2): strict JSON; the type; exactly the members of section 3; the
// subject well formed for its kind; never an expected_authorizer. Returns
// { doc } or { fail }.
built("M0.bundle");
export function m0(bytes) {
  let doc;
  try {
    doc = parseStrictJson(bytes);
  } catch (e) {
    return { fail: `the bundle is not strict JSON: ${e.message}` };
  }
  let err = exactly(doc, ["type", "created_at", "assembled_by", "subject", "members"], [], "the bundle");
  if (err) return { fail: err };
  if (!BUNDLE_TYPES.includes(doc.type)) return { fail: `type is not ${BUNDLE_TYPES.join(" or ")}` };
  if (!isStr(doc.created_at) || !isStr(doc.assembled_by)) return { fail: "created_at and assembled_by must be strings" };
  const s = doc.subject;
  if (isPlainObject(s) && Object.keys(s).includes("expected_authorizer")) return { fail: EXPECTED_AUTHORIZER_TEXT, expectedAuthorizer: true };
  if (!isPlainObject(s)) return { fail: "subject is not a JSON object" };
  if (s.kind === "evm-payment") {
    err = exactly(s, ["kind", "chain_id", "tx_hash", "cites", "carried_as"], [], "subject");
    if (err) return { fail: err };
    if (!isStr(s.chain_id) || !/^eip155:[1-9][0-9]*$/.test(s.chain_id)) return { fail: "subject.chain_id is not eip155:<decimal chain id>" };
    if (!isStr(s.tx_hash) || !/^0x[0-9a-f]{64}$/.test(s.tx_hash)) return { fail: "subject.tx_hash is not 0x and 64 lowercase hex digits" };
    if (!["eip3009-nonce", "calldata", "none"].includes(s.carried_as)) return { fail: "subject.carried_as is not eip3009-nonce, calldata or none" };
  } else if (s.kind === "card-payment") {
    err = exactly(s, ["kind", "reference", "cites"], [], "subject");
    if (err) return { fail: err };
    if (!isStr(s.reference)) return { fail: "subject.reference is not a string" };
  } else return { fail: "subject.kind is not evm-payment or card-payment" };
  err = exactly(s.cites, ["log", "seq"], [], "subject.cites");
  if (err) return { fail: err };
  if (!isStr(s.cites.log) || typeof s.cites.seq !== "number" || !Number.isInteger(s.cites.seq)) return { fail: "subject.cites must hold a string log and an integer seq" };
  if (!Array.isArray(doc.members)) return { fail: "members is not an array" };
  for (let i = 0; i < doc.members.length; i++) {
    const m = doc.members[i];
    err = exactly(m, MEMBER_FIELDS, ["issuer_profile"], `members[${i}]`);
    if (err) return { fail: err };
    for (const k of Object.keys(m)) if (!isStr(m[k])) return { fail: `members[${i}].${k} is not a string` };
  }
  return { doc };
}

// Canonical RFC 4648 section 4 base64 with padding: decodes and re-encodes to
// the same string (spec 4.1).
export function decodeB64(s) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  const buf = Buffer.from(s, "base64");
  return buf.toString("base64") === s ? buf : null;
}

// The JCS SHA-256 of a jcs-json member, read as spec 4.1 and D.1 say: the
// bytes checked strictly (duplicate names, UTF-8, lone surrogates), the value
// taken from JSON.parse and serialised by RFC 8785 (npm canonicalize 2.1.0).
export function jcsJsonDigest(bytes) {
  parseStrictJson(bytes, { allowNonInteger: true });
  const value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  return { value, digest: "sha256:" + sha256Hex(Buffer.from(canonicalize(value), "utf8")) };
}

// M1 (spec 4.2). `peekFactory(decoded)` gives, for the count rules of table 3-1 that need a
// member's contents, what can be read of them: the kids of the carried logs,
// the key ids of the carried witness receipts, the digests of jcs-json members.
// A member that cannot be read here is left to its own check (M2 to M9).
built("M1.member", "M1.manifest");
export function m1(doc, peekFactory) {
  const rows = [];
  const decoded = new Map();
  const ids = doc.members.map((m) => m.id);
  const byRole = (role) => doc.members.filter((m) => m.role === role);
  for (const m of doc.members) {
    const fail = (detail) => rows.push({ id: "M1.member", member: m.id, status: "FAIL", reason: null, detail });
    const bytes = decodeB64(m.bytes_b64);
    if (!bytes) {
      fail("bytes_b64 is not canonical base64 with padding");
      continue;
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(m.sha256) || m.sha256 !== "sha256:" + sha256Hex(bytes)) {
      fail("the decoded bytes do not hash to the member's sha256");
      continue;
    }
    if (!PROFILES_OF.has(m.role) || !PROFILES_OF.get(m.role).includes(m.profile)) {
      fail(`(${m.role}, ${m.profile}) is not a role and profile of table 3-1`);
      continue;
    }
    // Table 3-1 allows profile 0.3 only in an evidence-bundle/0.10 bundle (spec M0).
    if (m.role === "instruction" && m.profile === "signed-instruction-ed25519/0.3" && doc.type !== BUNDLE_TYPE) {
      fail(`a signed-instruction-ed25519/0.3 member is allowed only in an ${BUNDLE_TYPE} bundle (table 3-1)`);
      continue;
    }
    const hasIp = Object.keys(m).includes("issuer_profile");
    if (m.role === "gate-receipt" && !hasIp) {
      fail("a gate-receipt member must name its issuer_profile");
      continue;
    }
    if (m.role !== "gate-receipt" && hasIp) {
      fail("only a gate-receipt member names an issuer_profile");
      continue;
    }
    if (hasIp && !doc.members.some((x) => x.id === m.issuer_profile && x.role === "issuer-profile")) {
      fail("issuer_profile names no issuer-profile member");
      continue;
    }
    decoded.set(m.id, bytes);
    rows.push({ id: "M1.member", member: m.id, status: "PASS", reason: null, detail: `${bytes.length} bytes, digest and (role, profile) as declared` });
  }
  const peek = peekFactory(decoded);
  const manifestFail = (() => {
    if (new Set(ids).size !== ids.length || ids.some((i) => i.length === 0)) return "member ids are not unique and non-empty";
    const s = doc.subject;
    if (!byRole("gate-log").some((m) => m.id === s.cites.log)) return "subject.cites.log names no gate-log member";
    if (!Number.isSafeInteger(s.cites.seq) || s.cites.seq < 0) return "subject.cites.seq is not a safe integer of at least 0";
    if (byRole("gate-log").length < 1) return "no gate-log member";
    const receipts = byRole("gate-receipt");
    const profiles = byRole("issuer-profile");
    if (receipts.length === 0 && profiles.length > 0) return "an issuer-profile member is carried without a gate receipt";
    for (const p of profiles) if (!receipts.some((r) => r.issuer_profile === p.id)) return `issuer-profile ${p.id} is named by no gate receipt`;
    for (const role of ["action-arguments", "action-result"]) {
      const ds = byRole(role).map((m) => peek.jcsDigest(m.id)).filter((d) => d !== null);
      if (new Set(ds).size !== ds.length) return `two ${role} members have the same JCS digest`;
    }
    if (byRole("witness-key").length !== peek.receiptKeyIds().size) return "witness-key members are not one per distinct public_key_id among the carried receipts";
    if (byRole("operator-key").length !== peek.logKids().size) return "operator-key members are not one per distinct kid among the carried logs";
    const evm = s.kind === "evm-payment";
    for (const role of ["payment-transaction", "payment-receipt", "payment-block"]) {
      const n = byRole(role).length;
      if (!evm && n !== 0) return `a ${role} member is carried for a card subject`;
      // Offline, the three payment members are required (table 3-1: 0 only online).
      if (evm && n !== 1) return `an evm-payment bundle carries ${n} ${role} members offline, not 1`;
    }
    for (const role of ["payment-parent-block", "payment-block-transactions"]) {
      const n = byRole(role).length;
      if (n > (evm ? 1 : 0)) return `too many ${role} members`;
    }
    if (!evm && byRole("account-proof").length) return "an account-proof member is carried for a card subject";
    const proofs = byRole("account-proof").map((m) => peek.proofKey(m.id)).filter((k) => k !== null);
    if (new Set(proofs).size !== proofs.length) return "two account proofs for one account and block";
    return null;
  })();
  rows.unshift({ id: "M1.manifest", member: null, status: manifestFail ? "FAIL" : "PASS", reason: null, detail: manifestFail ?? `${doc.members.length} members; ids, counts and references as table 3-1 requires` });
  return { rows, decoded };
}

