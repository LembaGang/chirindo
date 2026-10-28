// What record() accepts: JSON values within 256 KB, an allow-list of members,
// screening of the free-text fields, formats, and the committed order of spec
// v0.10 section 4.3. Checked in that order; the first failure decides.
//
// The order rules reimplement orderProblem in
// examples/evidence-bundle/lib/card.mjs (the package never imports examples/;
// test/trial-order-parity.test.ts holds the two to the same verdict), with
// one addition: an item name is capped at 256 characters.

import type { RecordRefusal } from "./types.js";

export const MAX_INPUT_BYTES = 262_144;
const MAX_DEPTH = 32;
const MAX_PATHS = 20;
const MAX_POINTER = 128;

type Obj = Record<string, unknown>;

export type Checked =
  | { ok: true; orderRef: string; callSeq: number | null; args: Obj }
  | { ok: false; reason: RecordRefusal; paths: string[] };

const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const has = (o: Obj, k: string) => Object.keys(o).includes(k);

// RFC 6901, over keys of [A-Za-z0-9_-]{1,64} only, so a pointer never carries
// a caller's free text; any other key is written ~invalid-key.
export function pointer(segments: (string | number)[]): string {
  const p = segments.map((s) => (typeof s === "number" || /^[A-Za-z0-9_-]{1,64}$/.test(s) ? String(s) : "~invalid-key")).join("/");
  return ("/" + p).slice(0, MAX_POINTER);
}

// Plain objects, dense arrays, strings, booleans, null, finite numbers, and
// integers only within the safe range (the strict ingest rule, so that the
// arguments hash is recomputable by any JSON reader).
function isJsonValue(v: unknown, depth: number): boolean {
  if (v === null) return true;
  switch (typeof v) {
    case "string":
    case "boolean":
      return true;
    case "number":
      return Number.isFinite(v) && (!Number.isInteger(v) || Number.isSafeInteger(v));
    case "object": {
      if (depth >= MAX_DEPTH) return false;
      if (Array.isArray(v)) {
        if (Object.getPrototypeOf(v) !== Array.prototype || Object.keys(v).length !== v.length) return false;
        for (let i = 0; i < v.length; i++) if (!(i in v) || !isJsonValue(v[i], depth + 1)) return false;
        return true;
      }
      const proto = Object.getPrototypeOf(v);
      if ((proto !== Object.prototype && proto !== null) || Object.getOwnPropertySymbols(v).length > 0) return false;
      for (const k of Object.keys(v)) if (!isJsonValue((v as Obj)[k], depth + 1)) return false;
      return true;
    }
    default:
      return false;
  }
}

const TOP_MEMBERS = ["order_ref", "order", "agent_context", "call_seq"];
// agent_context members; a list names the members of that nested object.
const CONTEXT_MEMBERS: Record<string, string[] | null> = {
  channel: null,
  platform_signature: ["header_name", "value", "key_id", "alg"],
  payment_token_limits: ["currency", "max_amount_minor", "expires_at"],
  agent_name: null,
  mandate: ["format", "value"],
};
const ORDER_MEMBERS = ["merchant_id", "merchant_order_id", "checkout_ref", "currency", "total_minor", "items"];
const ITEM_MEMBERS = ["sku", "quantity", "unit_price_minor", "name", "category", "refundable", "service_from", "service_until", "location"];

// Members outside the allow-list, wherever an object of the schema holds them.
function refusedFields(input: Obj): string[] {
  const out: string[] = [];
  for (const k of Object.keys(input)) if (!TOP_MEMBERS.includes(k)) out.push(pointer([k]));
  const ac = input["agent_context"];
  if (isObj(ac)) {
    for (const k of Object.keys(ac)) {
      if (!Object.prototype.hasOwnProperty.call(CONTEXT_MEMBERS, k)) {
        out.push(pointer(["agent_context", k]));
        continue;
      }
      const allowed = CONTEXT_MEMBERS[k];
      const inner = ac[k];
      if (allowed && isObj(inner)) {
        for (const kk of Object.keys(inner)) if (!allowed.includes(kk)) out.push(pointer(["agent_context", k, kk]));
      }
    }
  }
  const order = input["order"];
  if (isObj(order)) {
    for (const k of Object.keys(order)) if (!ORDER_MEMBERS.includes(k)) out.push(pointer(["order", k]));
    const items = order["items"];
    if (Array.isArray(items)) {
      items.forEach((it, i) => {
        if (isObj(it)) for (const k of Object.keys(it)) if (!ITEM_MEMBERS.includes(k)) out.push(pointer(["order", "items", i, k]));
      });
    }
  }
  return out;
}

function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

const isAlnum = (c: string | undefined) => c !== undefined && /[\p{L}\p{N}]/u.test(c);

// A card-number-like token: 13 to 19 contiguous digits, or digit groups of 3
// to 6 digits joined by one separator kind throughout (single spaces, or
// single hyphens), 13 to 19 digits in all; first digit 2 to 6; Luhn-valid;
// standalone (not touching a letter or digit). Dates such as
// "2026-11-10 2026-11-12" mix separators and have 2-digit groups, so they
// are not tokens.
export function hasCardToken(s: string): boolean {
  for (const m of s.matchAll(/[0-9]+(?:[ -][0-9]+)*/g)) {
    const run = m[0];
    const start = m.index ?? 0;
    const groups = run.split(/[ -]/);
    const seps = run.match(/[ -]/g) ?? [];
    const starts: number[] = [];
    let pos = start;
    for (const g of groups) {
      starts.push(pos);
      pos += g.length + 1;
    }
    for (let i = 0; i < groups.length; i++) {
      if (i === 0 && isAlnum(s[start - 1])) continue;
      let digits = "";
      for (let j = i; j < groups.length; j++) {
        if (j > i) {
          if (seps[j - 1] !== seps[i]) break;
          const g = groups.slice(i, j + 1);
          if (!g.every((x) => x.length >= 3 && x.length <= 6)) break;
        }
        digits += groups[j]!;
        if (digits.length > 19) break;
        const after = starts[j]! + groups[j]!.length;
        const standaloneRight = j < groups.length - 1 || !isAlnum(s[after]);
        if (digits.length >= 13 && standaloneRight && /^[2-6]/.test(digits) && luhn(digits)) return true;
      }
    }
  }
  return false;
}

const EMAIL = /(?<![\p{L}\p{N}._%+@-])[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,63}(?![\p{L}\p{N}])/u;

export function hasEmailToken(s: string): boolean {
  return EMAIL.test(s);
}

// Screening covers only the free-text fields: item name, location and
// category (card and e-mail), and agent_context.agent_name (card only).
// Identifiers, references, SKUs, amounts and dates are the merchant's own
// values and are never screened.
function refusedValues(input: Obj): string[] {
  const out: string[] = [];
  const order = input["order"];
  if (isObj(order) && Array.isArray(order["items"])) {
    (order["items"] as unknown[]).forEach((it, i) => {
      if (!isObj(it)) return;
      for (const k of ["name", "location", "category"]) {
        const v = it[k];
        if (isStr(v) && (hasCardToken(v) || hasEmailToken(v))) out.push(pointer(["order", "items", i, k]));
      }
    });
  }
  const ac = input["agent_context"];
  if (isObj(ac) && isStr(ac["agent_name"]) && hasCardToken(ac["agent_name"])) out.push(pointer(["agent_context", "agent_name"]));
  return out;
}

export const PRINTABLE_256 = /^[\x20-\x7e]{1,256}$/;
const AMOUNT = /^(0|[1-9][0-9]*)$/;
const CURRENCY = /^[A-Z]{3}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const CHANNELS = ["acp", "ucp", "ap2", "mcp", "stripe-approval-hook", "other"];
const MANDATE_FORMATS = ["ap2", "vi", "other"];
const strMax = (v: unknown, max: number, min = 0) => isStr(v) && v.length >= min && v.length <= max;

export const isCallSeq = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

// An RFC 3339 UTC time that names a real instant, by the same round trip as
// dateOk: 2026-02-30T00:00:00Z and 2026-01-01T24:00:00Z are refused.
function timeOk(s: unknown): boolean {
  if (!isStr(s) || !RFC3339_UTC.test(s)) return false;
  const d = new Date(s);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 19) === s.slice(0, 19);
}

// Formats outside the order: the first failing pointer, or null.
function formatFailure(input: Obj): string | null {
  if (!(isStr(input["order_ref"]) && PRINTABLE_256.test(input["order_ref"]))) return "/order_ref";
  if (has(input, "call_seq") && !isCallSeq(input["call_seq"])) return "/call_seq";
  if (!has(input, "agent_context")) return null;
  const ac = input["agent_context"];
  if (!isObj(ac)) return "/agent_context";
  const at = (...p: string[]) => pointer(["agent_context", ...p]);
  if (has(ac, "channel") && !CHANNELS.includes(ac["channel"] as string)) return at("channel");
  if (has(ac, "platform_signature")) {
    const ps = ac["platform_signature"];
    if (!isObj(ps)) return at("platform_signature");
    for (const k of ["header_name", "value"]) if (!strMax(ps[k], 4096)) return at("platform_signature", k);
    for (const k of ["key_id", "alg"]) if (has(ps, k) && !strMax(ps[k], 4096)) return at("platform_signature", k);
  }
  if (has(ac, "payment_token_limits")) {
    const pl = ac["payment_token_limits"];
    if (!isObj(pl)) return at("payment_token_limits");
    if (!(isStr(pl["currency"]) && CURRENCY.test(pl["currency"]))) return at("payment_token_limits", "currency");
    if (!(isStr(pl["max_amount_minor"]) && AMOUNT.test(pl["max_amount_minor"]))) return at("payment_token_limits", "max_amount_minor");
    if (has(pl, "expires_at")) {
      const e = pl["expires_at"];
      if (!timeOk(e)) return at("payment_token_limits", "expires_at");
    }
  }
  if (has(ac, "agent_name") && !strMax(ac["agent_name"], 256, 1)) return at("agent_name");
  if (has(ac, "mandate")) {
    const md = ac["mandate"];
    if (!isObj(md)) return at("mandate");
    if (!MANDATE_FORMATS.includes(md["format"] as string)) return at("mandate", "format");
    if (!strMax(md["value"], 65_536)) return at("mandate", "value");
  }
  return null;
}

const len256 = (v: unknown) => strMax(v, 256, 1);

function dateOk(s: unknown): boolean {
  if (!isStr(s) || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

// orderProblem's checks, in its order, answering with the failing pointer.
export function orderFailure(o: unknown): string | null {
  if (!isObj(o)) return "/order";
  for (const k of Object.keys(o)) if (!ORDER_MEMBERS.includes(k)) return pointer(["order", k]);
  if (!len256(o["merchant_id"])) return "/order/merchant_id";
  if (!has(o, "merchant_order_id") && !has(o, "checkout_ref")) return "/order";
  for (const k of ["merchant_order_id", "checkout_ref"]) {
    if (has(o, k) && !(isStr(o[k]) && PRINTABLE_256.test(o[k]))) return `/order/${k}`;
  }
  if (!(isStr(o["currency"]) && CURRENCY.test(o["currency"]))) return "/order/currency";
  if (!(isStr(o["total_minor"]) && AMOUNT.test(o["total_minor"]))) return "/order/total_minor";
  const items = o["items"];
  if (!Array.isArray(items) || items.length === 0) return "/order/items";
  for (let i = 0; i < items.length; i++) {
    const it: unknown = items[i];
    const at = (k?: string) => pointer(k === undefined ? ["order", "items", i] : ["order", "items", i, k]);
    if (!isObj(it)) return at();
    for (const k of Object.keys(it)) if (!ITEM_MEMBERS.includes(k)) return at(k);
    for (const k of ["sku", "quantity", "unit_price_minor"]) if (!has(it, k)) return at(k);
    if (!len256(it["sku"])) return at("sku");
    const q = it["quantity"];
    if (!(typeof q === "number" && Number.isSafeInteger(q) && q >= 1)) return at("quantity");
    if (!(isStr(it["unit_price_minor"]) && AMOUNT.test(it["unit_price_minor"]))) return at("unit_price_minor");
    // The one rule orderProblem does not have: the cap.
    if (has(it, "name") && !strMax(it["name"], 256)) return at("name");
    for (const k of ["category", "location"]) if (has(it, k) && !len256(it[k])) return at(k);
    if (has(it, "refundable") && typeof it["refundable"] !== "boolean") return at("refundable");
    for (const k of ["service_from", "service_until"]) if (has(it, k) && !dateOk(it[k])) return at(k);
    if (has(it, "service_from") && has(it, "service_until") && (it["service_from"] as string) > (it["service_until"] as string)) {
      return at("service_from");
    }
  }
  return null;
}

// The length caps of the screened free-text fields, checked before they are
// screened (so an oversized string is never scanned): an item's name,
// location and category (order rules), and agent_context.agent_name.
function capFailure(input: Obj): Checked | null {
  const order = input["order"];
  if (isObj(order) && Array.isArray(order["items"])) {
    const items = order["items"] as unknown[];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (!isObj(it)) continue;
      for (const k of ["name", "location", "category"]) {
        const v = it[k];
        if (isStr(v) && v.length > 256) return { ok: false, reason: "invalid-order", paths: [pointer(["order", "items", i, k])] };
      }
    }
  }
  const ac = input["agent_context"];
  if (isObj(ac) && isStr(ac["agent_name"]) && ac["agent_name"].length > 256) {
    return { ok: false, reason: "invalid-input", paths: ["/agent_context/agent_name"] };
  }
  return null;
}

export function checkRecordInput(raw: unknown): Checked {
  if (!isObj(raw) || !isJsonValue(raw, 0)) return { ok: false, reason: "invalid-input", paths: [] };
  const text = JSON.stringify(raw);
  if (Buffer.byteLength(text, "utf8") > MAX_INPUT_BYTES) return { ok: false, reason: "invalid-input", paths: [] };
  // One snapshot for every later check and for the write: a getter or a
  // caller's later change cannot make the checked and the written differ.
  const input = JSON.parse(text) as Obj;
  const fields = refusedFields(input);
  if (fields.length > 0) return { ok: false, reason: "refused-field", paths: fields.slice(0, MAX_PATHS) };
  const cap = capFailure(input);
  if (cap !== null) return cap;
  const values = refusedValues(input);
  if (values.length > 0) return { ok: false, reason: "refused-value", paths: values.slice(0, MAX_PATHS) };
  const format = formatFailure(input);
  if (format !== null) return { ok: false, reason: "invalid-input", paths: [format] };
  const order = orderFailure(input["order"]);
  if (order !== null) return { ok: false, reason: "invalid-order", paths: [order] };
  const args: Obj = { order: input["order"] };
  if (has(input, "agent_context")) args["agent_context"] = input["agent_context"];
  return { ok: true, orderRef: input["order_ref"] as string, callSeq: isCallSeq(input["call_seq"]) ? input["call_seq"] : null, args };
}

export type GapChecked =
  | { ok: true; orderRef: string; callSeq: number | null; reason: "caller-timeout" | "unreachable" | "other" }
  | { ok: false };

export function checkGapInput(input: unknown): GapChecked {
  if (!isObj(input) || !isJsonValue(input, 0)) return { ok: false };
  if (Object.keys(input).some((k) => !["order_ref", "call_seq", "reason"].includes(k))) return { ok: false };
  const ref = input["order_ref"];
  const reason = input["reason"];
  if (!(isStr(ref) && PRINTABLE_256.test(ref))) return { ok: false };
  if (has(input, "call_seq") && !isCallSeq(input["call_seq"])) return { ok: false };
  if (reason !== "caller-timeout" && reason !== "unreachable" && reason !== "other") return { ok: false };
  return { ok: true, orderRef: ref, callSeq: isCallSeq(input["call_seq"]) ? input["call_seq"] : null, reason };
}

// order_ref and call_seq for a gap line, read without running any getter (an
// input that failed the checks may be anything).
export function gapFieldsOf(input: unknown): { orderRef: string | null; callSeq: number | null } {
  if (typeof input !== "object" || input === null) return { orderRef: null, callSeq: null };
  try {
    const ref = Object.getOwnPropertyDescriptor(input, "order_ref")?.value;
    const seq = Object.getOwnPropertyDescriptor(input, "call_seq")?.value;
    return { orderRef: isStr(ref) ? ref : null, callSeq: isCallSeq(seq) ? seq : null };
  } catch {
    return { orderRef: null, callSeq: null };
  }
}
