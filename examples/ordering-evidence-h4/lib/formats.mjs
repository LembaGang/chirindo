// Byte-level formats used by check-h4.mjs: strict JSON, RFC 8785 (JCS) for the
// values a hash-chained log carries, base64url, Ed25519 and RFC 7638
// thumbprints, and the hex forms of Ethereum JSON-RPC.
//
// Every reader here refuses rather than repairs: a duplicate member name, an
// integer JSON.parse would round, a non-canonical base64url string or an
// upper-case hex digit is an error, because each of them lets two different
// byte strings read as one value.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export class FormatError extends Error {}

const MAX_DEPTH = 64;

// Strict JSON (RFC 8259) from bytes.
// - The bytes must be valid UTF-8 with no byte order mark.
// - A member name may appear only once in an object.
// - An integer literal is returned as a Number when it is a safe integer and
//   as a BigInt otherwise, so no integer is ever rounded.
// - A number with a fraction or an exponent is refused unless
//   allowNonInteger is set (only the issuer documents use it).
// - Strings must be well-formed UTF-16 (no lone surrogate from a \u escape).
// - Objects are created without a prototype, so "__proto__" is an ordinary
//   member name.
export function parseStrictJson(bytes, { allowNonInteger = false } = {}) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new FormatError("not valid UTF-8");
  }
  let i = 0;
  const n = text.length;
  const fail = (msg) => {
    throw new FormatError(`${msg} at character ${i}`);
  };
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const value = (depth) => {
    if (depth > MAX_DEPTH) fail("nesting too deep");
    ws();
    const c = text[i];
    if (c === "{") return object(depth);
    if (c === "[") return array(depth);
    if (c === '"') return string();
    if (c === "t") return literal("true", true);
    if (c === "f") return literal("false", false);
    if (c === "n") return literal("null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    return fail("unexpected character");
  };
  const literal = (word, v) => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return v;
    }
    return fail("bad literal");
  };
  const number = () => {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 400));
    if (!m) fail("bad number");
    const lit = m[0];
    i += lit.length;
    if (m[2] === undefined && m[3] === undefined) {
      const big = BigInt(lit);
      if (big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(big);
      return big;
    }
    if (!allowNonInteger) fail(`number with a fraction or exponent (${lit})`);
    return Number(lit);
  };
  const string = () => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        break;
      }
      if (c < 0x20) fail("control character in string");
      if (c === 0x5c) {
        const e = text[i + 1];
        const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
        if (simple !== undefined) {
          out += simple;
          i += 2;
          continue;
        }
        if (e === "u") {
          const h = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad \\u escape");
          out += String.fromCharCode(parseInt(h, 16));
          i += 6;
          continue;
        }
        fail("bad escape");
      }
      out += text[i];
      i++;
    }
    if (!isWellFormed(out)) fail("lone surrogate in string");
    return out;
  };
  const object = (depth) => {
    i++;
    const obj = Object.create(null);
    ws();
    if (text[i] === "}") {
      i++;
      return obj;
    }
    for (;;) {
      ws();
      if (text[i] !== '"') fail("expected a member name");
      const key = string();
      if (Object.prototype.hasOwnProperty.call(obj, key)) fail(`duplicate member name ${JSON.stringify(key)}`);
      ws();
      if (text[i] !== ":") fail("expected ':'");
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
      fail("expected ',' or '}'");
    }
  };
  const array = (depth) => {
    i++;
    const arr = [];
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
      fail("expected ',' or ']'");
    }
  };
  const v = value(0);
  ws();
  if (i !== n) fail("trailing characters after the JSON value");
  return v;
}

export function isWellFormed(s) {
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

export function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Members of an object must be exactly `required` plus any of `optional`.
export function exactMembers(obj, required, optional = [], what = "object") {
  if (!isPlainObject(obj)) throw new FormatError(`${what} is not a JSON object`);
  const keys = Object.keys(obj);
  for (const k of required) if (!keys.includes(k)) throw new FormatError(`${what} lacks member ${k}`);
  for (const k of keys)
    if (!required.includes(k) && !optional.includes(k)) throw new FormatError(`${what} has an unexpected member ${JSON.stringify(k)}`);
}

// RFC 8785 for the values a log entry, checkpoint or witness receipt may hold:
// objects, arrays, strings, booleans, null and safe integers. Keys sort by
// UTF-16 code units (the default sort), and strings serialize as
// JSON.stringify does, which RFC 8785 section 3.2.2.2 adopts.
export function jcs(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") {
    if (!isWellFormed(v)) throw new FormatError("lone surrogate");
    return JSON.stringify(v);
  }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new FormatError("JCS here takes safe integers only");
    return String(v);
  }
  if (typeof v === "bigint") throw new FormatError("integer outside the safe range");
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  throw new FormatError(`no JCS form for ${typeof v}`);
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function withoutMember(obj, name) {
  const out = Object.create(null);
  for (const k of Object.keys(obj)) if (k !== name) out[k] = obj[k];
  return out;
}

// "sha256:" + lowercase hex of SHA-256 over the UTF-8 JCS bytes.
export function jcsSha256(v) {
  return "sha256:" + sha256Hex(Buffer.from(jcs(v), "utf8"));
}

export const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

// base64url without padding, decoded to exactly nBytes, and re-encoded to the
// same string (so the unused low bits of the last character are zero).
export function b64urlCanonical(s, nBytes, what) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) throw new FormatError(`${what} is not base64url without padding`);
  const buf = Buffer.from(s, "base64url");
  if (buf.length !== nBytes) throw new FormatError(`${what} decodes to ${buf.length} bytes, not ${nBytes}`);
  if (buf.toString("base64url") !== s) throw new FormatError(`${what} is not the canonical base64url form of its bytes`);
  return buf;
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function ed25519Verify(publicKey32, message, signature64) {
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey32]), format: "der", type: "spki" });
  return cryptoVerify(null, message, key, signature64);
}

// RFC 7638 thumbprint of an Ed25519 OKP key: base64url-nopad(SHA-256(UTF-8 of
// {"crv":"Ed25519","kty":"OKP","x":"<x>"})). x is checked as base64url first,
// so it needs no escaping.
export function okpThumbprint(x) {
  return createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`, "utf8").digest("base64url");
}

// Lowercase 0x-prefixed hex of whole bytes; nBytes optional.
export function hexBytes(s, what, nBytes) {
  if (typeof s !== "string" || !/^0x([0-9a-f]{2})*$/.test(s)) throw new FormatError(`${what} is not lowercase 0x-prefixed hex of whole bytes`);
  if (nBytes !== undefined && s.length !== 2 + 2 * nBytes) throw new FormatError(`${what} is not ${nBytes} bytes`);
  return s;
}

// JSON-RPC quantity: 0x0 or 0x followed by lowercase hex with no leading zero.
export function quantity(s, what) {
  if (typeof s !== "string" || !/^0x(0|[1-9a-f][0-9a-f]*)$/.test(s)) throw new FormatError(`${what} is not a JSON-RPC quantity (0x, lowercase, no leading zero)`);
  return BigInt(s);
}

// Seconds since 1970 as an ISO-8601 time, or a note when the value is outside
// the range a date can hold (an authorization may use 2^256 - 1 for "never").
export function isoUtc(seconds) {
  const ms = Number(seconds) * 1000;
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return "beyond the range of dates";
  return new Date(ms).toISOString();
}
