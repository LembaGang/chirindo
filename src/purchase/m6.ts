// The instruction side of the purchase check (B-432): strict JSON, RFC 8785
// and M6 for spec v0.10 Annex A.3, `signed-instruction-ed25519/0.3`, with
// card limits only (design §2).
//
// Ports, not imports (the package never imports examples/):
//   parseStrictJson, jcs, b64urlCanonical, okpThumbprint
//       examples/ordering-evidence-h4/lib/formats.mjs
//   m6Check (with checkCard)
//       examples/evidence-bundle/lib/instructions.mjs, m6Instruction
// test/purchase-parity.test.ts holds each to its original.
//
// The vendored strictJsonParse is not used for instructions. It accepts lone
// surrogates, fractions and exponents that M6 refuses, so an instruction it
// read could be allowed here and failed by the verifier (B-432 T0, HOLD-2).

import { createHash, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { pointer } from "../trial/rules.js";
import { TIME_RE, dateOk, tsMs } from "./time.js";

export const ANNEX_A3 = "signed-instruction-ed25519/0.3";
// Annex A.3's card member, in its order (also the order of card_limits).
export const CARD_LIMITS = [
  "currency",
  "max_total_minor",
  "max_unit_price_minor",
  "merchants",
  "items",
  "categories",
  "refundable_only",
  "service_window",
  "locations",
] as const;
export type CardLimit = (typeof CARD_LIMITS)[number];
// Constraint members outside v0.1's scope (design §2). An instruction naming
// one is denied unsupported-limit:<member>, so none of them is validated.
export const UNSUPPORTED_LIMITS = ["chain_id", "asset", "max_amount", "payees", "budget"] as const;
export const MAX_INSTRUCTION_BYTES = 65_536;
export const THUMBPRINT_RE = /^[A-Za-z0-9_-]{43}$/;
const MAX_DEPTH = 64;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

type Obj = Record<string, unknown>;
const isStr = (v: unknown): v is string => typeof v === "string";
export const isPlainObject = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

// ---- strict JSON -----------------------------------------------------------

export type ParseProblem =
  | "not-utf8"
  | "bom"
  | "lone-surrogate"
  | "duplicate-member"
  | "non-integer-number"
  | "nesting-too-deep"
  | "syntax";

export type Parsed = { ok: true; value: unknown } | { ok: false; problem: ParseProblem };

class ParseFail extends Error {
  constructor(readonly problem: ParseProblem) {
    super(problem);
  }
}

// Well-formed UTF-16: no lone surrogate.
export function isWellFormed(s: string): boolean {
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(k + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      k++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

// Strict JSON (RFC 8259) from a string, by the examples' rules: a member name
// once per object; an integer literal a Number when safe and a BigInt
// otherwise, so none is rounded; no fraction and no exponent; no lone
// surrogate, raw or escaped; no byte order mark; depth at most 64; objects
// without a prototype. A raw lone surrogate is this reader's form of the
// examples' invalid UTF-8: a JS string holding one has no UTF-8 encoding.
export function parseStrictJson(text: string): Parsed {
  if (!isWellFormed(text)) return { ok: false, problem: "lone-surrogate" };
  try {
    return { ok: true, value: parse(text) };
  } catch (e) {
    if (e instanceof ParseFail) return { ok: false, problem: e.problem };
    throw e;
  }
}

// The same from bytes, read as the examples read them: fatal UTF-8, and a
// byte order mark kept (then refused as "bom").
export function parseStrictJsonBytes(bytes: Uint8Array): Parsed {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { ok: false, problem: "not-utf8" };
  }
  return parseStrictJson(text);
}

function parse(text: string): unknown {
  let i = 0;
  const n = text.length;
  const fail = (p: ParseProblem): never => {
    throw new ParseFail(p);
  };
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH) fail("nesting-too-deep");
    ws();
    const c = text[i];
    if (c === "{") return object(depth);
    if (c === "[") return array(depth);
    if (c === '"') return string();
    if (c === "t") return literal("true", true);
    if (c === "f") return literal("false", false);
    if (c === "n") return literal("null", null);
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return number();
    if (i === 0 && c === "﻿") fail("bom");
    return fail("syntax");
  };
  const literal = (word: string, v: unknown): unknown => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return v;
    }
    return fail("syntax");
  };
  const number = (): unknown => {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 400));
    if (!m) return fail("syntax");
    const lit = m[0];
    i += lit.length;
    if (m[2] !== undefined || m[3] !== undefined) return fail("non-integer-number");
    const big = BigInt(lit);
    if (big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(big);
    return big;
  };
  const SIMPLE: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
  const string = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= n) fail("syntax");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        break;
      }
      if (c < 0x20) fail("syntax");
      if (c === 0x5c) {
        const e = text[i + 1] ?? "";
        const simple = Object.prototype.hasOwnProperty.call(SIMPLE, e) ? SIMPLE[e] : undefined;
        if (simple !== undefined) {
          out += simple;
          i += 2;
          continue;
        }
        if (e === "u") {
          const h = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("syntax");
          out += String.fromCharCode(parseInt(h, 16));
          i += 6;
          continue;
        }
        fail("syntax");
      }
      out += text[i];
      i++;
    }
    if (!isWellFormed(out)) fail("lone-surrogate");
    return out;
  };
  const object = (depth: number): Obj => {
    i++;
    const obj = Object.create(null) as Obj;
    ws();
    if (text[i] === "}") {
      i++;
      return obj;
    }
    for (;;) {
      ws();
      if (text[i] !== '"') fail("syntax");
      const key = string();
      if (Object.prototype.hasOwnProperty.call(obj, key)) fail("duplicate-member");
      ws();
      if (text[i] !== ":") fail("syntax");
      i++;
      obj[key] = value(depth + 1);
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        return obj;
      }
      fail("syntax");
    }
  };
  const array = (depth: number): unknown[] => {
    i++;
    const arr: unknown[] = [];
    ws();
    if (text[i] === "]") {
      i++;
      return arr;
    }
    for (;;) {
      arr.push(value(depth + 1));
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        return arr;
      }
      fail("syntax");
    }
  };
  const v = value(0);
  ws();
  if (i !== n) fail("syntax");
  return v;
}

// ---- RFC 8785, keys and signatures ----------------------------------------

export class JcsError extends Error {}

// RFC 8785 for the values an instruction may hold: objects, arrays, strings,
// booleans, null and safe integers. Keys sort by UTF-16 code units, and
// strings serialize as JSON.stringify does (RFC 8785 section 3.2.2.2).
export function jcs(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") {
    if (!isWellFormed(v)) throw new JcsError("lone surrogate");
    return JSON.stringify(v);
  }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new JcsError("JCS here takes safe integers only");
    return String(v);
  }
  if (typeof v === "bigint") throw new JcsError("integer outside the safe range");
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Obj;
    const keys = Object.keys(o).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(o[k])).join(",") + "}";
  }
  throw new JcsError(`no JCS form for ${typeof v}`);
}

// "sha256:" + lowercase hex of SHA-256 over the UTF-8 JCS bytes.
export function jcsSha256(v: unknown): string {
  return "sha256:" + createHash("sha256").update(jcs(v), "utf8").digest("hex");
}

// base64url without padding, decoded to exactly nBytes and re-encoded to the
// same string (so the unused low bits of the last character are zero); null
// when it is not.
export function b64urlCanonical(s: unknown, nBytes: number): Buffer | null {
  if (!isStr(s) || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const buf = Buffer.from(s, "base64url");
  if (buf.length !== nBytes || buf.toString("base64url") !== s) return null;
  return buf;
}

// RFC 7638 thumbprint of an Ed25519 OKP key. x is checked as base64url
// before this is called, so it needs no escaping.
export function okpThumbprint(x: string): string {
  return createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`, "utf8").digest("base64url");
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verify(publicKey32: Buffer, message: Buffer, signature64: Buffer): boolean {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey32]), format: "der", type: "spki" });
    return verify(null, message, key, signature64);
  } catch {
    // A key Node will not load verifies nothing.
    return false;
  }
}

function withoutMember(obj: Obj, name: string): Obj {
  const out = Object.create(null) as Obj;
  for (const k of Object.keys(obj)) if (k !== name) out[k] = obj[k];
  return out;
}

// The signed instruction: `body` (every member but sig) with sig, the
// base64url Ed25519 signature over body's JCS bytes, under the principal's key.
export function signInstruction(body: Obj, privateKey: KeyObject): Obj {
  if (!isPlainObject(body) || Object.keys(body).includes("sig")) {
    throw new TypeError("signInstruction: body must be a JSON object without sig");
  }
  if (privateKey?.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("signInstruction: privateKey must be an Ed25519 private KeyObject");
  }
  const sig = sign(null, Buffer.from(jcs(body), "utf8"), privateKey).toString("base64url");
  return { ...body, sig };
}

// ---- reading and M6 ----------------------------------------------------------

function containsBigInt(v: unknown): boolean {
  if (typeof v === "bigint") return true;
  if (Array.isArray(v)) return v.some(containsBigInt);
  if (isPlainObject(v)) return Object.keys(v).some((k) => containsBigInt(v[k]));
  return false;
}

// Design §4.2 step 1 for the instruction: a string of at most 64 KB that reads
// as strict JSON. An integer outside the safe range is refused here too: every
// member M6 knows refuses one anyway, and a value holding one has no JCS form
// for denied_instruction_sha256. `problem` is a code of
// instruction-invalid:<problem>.
export function readInstruction(text: unknown): { ok: true; value: unknown } | { ok: false; problem: string } {
  if (!isStr(text)) return { ok: false, problem: "not-a-string" };
  if (Buffer.byteLength(text, "utf8") > MAX_INSTRUCTION_BYTES) return { ok: false, problem: "too-large" };
  const r = parseStrictJson(text);
  if (!r.ok) return r;
  if (containsBigInt(r.value)) return { ok: false, problem: "unsafe-integer" };
  return r;
}

export type M6Result =
  | { ok: true; digest: string; unsupported: string[] }
  | { ok: false; problem: string };

class Bad extends Error {}
function bad(code: string): never {
  throw new Bad(code);
}
type Path = (string | number)[];
const at = (p: Path) => (p.length === 0 ? "" : `:${pointer(p)}`);

function exactly(obj: unknown, required: readonly string[], optional: readonly string[], path: Path): asserts obj is Obj {
  if (!isPlainObject(obj)) bad(`not-an-object${at(path)}`);
  const keys = Object.keys(obj);
  for (const k of required) if (!keys.includes(k)) bad(`missing-member${at([...path, k])}`);
  for (const k of keys) if (!required.includes(k) && !optional.includes(k)) bad(`extra-member${at([...path, k])}`);
}

// Annex A.3's card member: currency and at least one other member that
// limits something (refundable_only false limits nothing, so it does not count).
function checkCard(card: unknown): void {
  const path = ["constraints", "card"];
  exactly(card, ["currency"], CARD_LIMITS.slice(1), path);
  const has = (k: string) => Object.keys(card).includes(k);
  if (!isStr(card["currency"]) || !/^[A-Z]{3}$/.test(card["currency"])) bad("bad-value:/constraints/card/currency");
  for (const k of ["max_total_minor", "max_unit_price_minor"]) {
    if (has(k) && !(isStr(card[k]) && DECIMAL.test(card[k]))) bad(`bad-value:/constraints/card/${k}`);
  }
  for (const k of ["merchants", "items", "categories", "locations"]) {
    const v = card[k];
    if (has(k) && !(Array.isArray(v) && v.length > 0 && v.every((x) => isStr(x) && x.length >= 1 && x.length <= 256))) {
      bad(`bad-value:/constraints/card/${k}`);
    }
  }
  if (has("refundable_only") && typeof card["refundable_only"] !== "boolean") bad("bad-value:/constraints/card/refundable_only");
  if (has("service_window")) {
    const sw = card["service_window"];
    exactly(sw, ["from", "until"], [], [...path, "service_window"]);
    if (!dateOk(sw["from"]) || !dateOk(sw["until"]) || (sw["from"] as string) > (sw["until"] as string)) {
      bad("bad-value:/constraints/card/service_window");
    }
  }
  if (!Object.keys(card).some((k) => k !== "currency" && !(k === "refundable_only" && card[k] === false))) bad("card-limits-empty");
}

// M6 for profile 0.3, card only, in the verifier's order: exactly the
// profile's members with their types; v; principal.kid the thumbprint of its
// key; the card member; valid_from not after valid_until; sig over the JCS
// bytes without sig. The returned digest is what an action cites: the JCS
// SHA-256 of the whole object, sig included.
//
// Where it differs from the verifier's M6, it refuses more, never less: a
// missing card is card-missing (the verifier asks for the payment members
// instead); a time that is not a TIME_RE time is time-not-z, and one that is
// but Date.parse cannot read is time-not-calendar (the verifier says "not a
// time" for both). The members of UNSUPPORTED_LIMITS are allowed through
// unvalidated and returned, for step 2 to deny.
export function m6Check(ins: unknown): M6Result {
  try {
    exactly(ins, ["v", "principal", "agent_kid", "text", "constraints", "iat", "sig"], [], []);
    if (ins["v"] !== ANNEX_A3) bad("wrong-profile");
    const principal = ins["principal"];
    exactly(principal, ["kid", "public_key_jwk"], [], ["principal"]);
    const jwk = principal["public_key_jwk"];
    exactly(jwk, ["kty", "crv", "x"], [], ["principal", "public_key_jwk"]);
    if (jwk["kty"] !== "OKP" || jwk["crv"] !== "Ed25519") bad("bad-value:/principal/public_key_jwk");
    const pub = b64urlCanonical(jwk["x"], 32);
    if (pub === null) bad("bad-value:/principal/public_key_jwk/x");
    if (principal["kid"] !== okpThumbprint(jwk["x"] as string)) bad("kid-not-thumbprint");
    const ak = ins["agent_kid"];
    if (!Array.isArray(ak) || ak.length === 0 || !ak.every((k) => isStr(k) && THUMBPRINT_RE.test(k))) bad("bad-value:/agent_kid");
    if (!isStr(ins["text"])) bad("bad-value:/text");
    const c = ins["constraints"];
    exactly(c, ["valid_from", "valid_until"], ["max_uses", "card", ...UNSUPPORTED_LIMITS], ["constraints"]);
    if (!Object.keys(c).includes("card")) bad("card-missing");
    if (Object.keys(c).includes("max_uses") && !(Number.isSafeInteger(c["max_uses"]) && (c["max_uses"] as number) >= 1)) {
      bad("bad-value:/constraints/max_uses");
    }
    checkCard(c["card"]);
    const zTime = (t: unknown) => isStr(t) && TIME_RE.test(t);
    const vf = tsMs(c["valid_from"]);
    const vu = tsMs(c["valid_until"]);
    if (!zTime(c["valid_from"]) || !zTime(c["valid_until"])) bad("time-not-z");
    if (vf === null || vu === null) bad("time-not-calendar");
    if (vf > vu) bad("window-reversed");
    if (!zTime(ins["iat"])) bad("time-not-z");
    if (tsMs(ins["iat"]) === null) bad("time-not-calendar");
    const sig = b64urlCanonical(ins["sig"], 64);
    if (sig === null) bad("bad-value:/sig");
    if (!ed25519Verify(pub, Buffer.from(jcs(withoutMember(ins, "sig")), "utf8"), sig)) bad("bad-signature");
    return { ok: true, digest: jcsSha256(ins), unsupported: UNSUPPORTED_LIMITS.filter((k) => Object.keys(c).includes(k)) };
  } catch (e) {
    if (e instanceof Bad) return { ok: false, problem: e.message };
    if (e instanceof JcsError) return { ok: false, problem: "not-canonical" };
    throw e;
  }
}
