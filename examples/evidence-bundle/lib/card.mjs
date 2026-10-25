// Card subjects (spec v0.10): the committed order of 4.3 ("The committed
// order", M8.order), its summary for the output's `card` member, B-CARD's
// match and time (rules 2 and 3), and the card forms of D.1.

import { isPlainObject } from "../../ordering-evidence-h4/lib/formats.mjs";
import { TIME_RE } from "./table.mjs";

const isStr = (v) => typeof v === "string";
const PRINTABLE = /^[\x20-\x7e]{1,256}$/;
const AMOUNT = /^(0|[1-9][0-9]*)$/;
const CURRENCY = /^[A-Z]{3}$/;
const len256 = (s) => isStr(s) && s.length >= 1 && s.length <= 256;

// A date YYYY-MM-DD that names a calendar day.
export function dateOk(s) {
  if (!isStr(s) || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

const ORDER_MEMBERS = ["merchant_id", "merchant_order_id", "checkout_ref", "currency", "total_minor", "items"];
const ITEM_MEMBERS = ["sku", "quantity", "unit_price_minor", "name", "category", "refundable", "service_from", "service_until", "location"];

// M8.order: the order has exactly the shape of spec 4.3, "The committed
// order". Returns null when it does, or the first problem.
export function orderProblem(o) {
  if (!isPlainObject(o)) return "order is not a JSON object";
  for (const k of Object.keys(o)) if (!ORDER_MEMBERS.includes(k)) return `order has a member the committed order does not have: ${JSON.stringify(k)}`;
  if (!len256(o.merchant_id)) return "order.merchant_id is not a string of 1 to 256 characters";
  const has = (k) => Object.keys(o).includes(k);
  if (!has("merchant_order_id") && !has("checkout_ref")) return "order commits to neither merchant_order_id nor checkout_ref";
  for (const k of ["merchant_order_id", "checkout_ref"]) if (has(k) && !(isStr(o[k]) && PRINTABLE.test(o[k]))) return `order.${k} is not 1 to 256 printable ASCII characters`;
  if (!isStr(o.currency) || !CURRENCY.test(o.currency)) return "order.currency is not three upper-case letters";
  if (!isStr(o.total_minor) || !AMOUNT.test(o.total_minor)) return "order.total_minor is not a decimal string with no sign and no leading zero";
  if (!Array.isArray(o.items) || o.items.length === 0) return "order.items is not a non-empty list";
  for (let i = 0; i < o.items.length; i++) {
    const it = o.items[i];
    const at = `order.items[${i}]`;
    if (!isPlainObject(it)) return `${at} is not a JSON object`;
    for (const k of Object.keys(it)) if (!ITEM_MEMBERS.includes(k)) return `${at} has a member an item does not have: ${JSON.stringify(k)}`;
    const ih = (k) => Object.keys(it).includes(k);
    for (const k of ["sku", "quantity", "unit_price_minor"]) if (!ih(k)) return `${at} lacks ${k}`;
    if (!len256(it.sku)) return `${at}.sku is not a string of 1 to 256 characters`;
    if (!Number.isSafeInteger(it.quantity) || it.quantity < 1) return `${at}.quantity is not an integer of at least 1`;
    if (!isStr(it.unit_price_minor) || !AMOUNT.test(it.unit_price_minor)) return `${at}.unit_price_minor is not a decimal string with no sign and no leading zero`;
    if (ih("name") && !isStr(it.name)) return `${at}.name is not a string`;
    for (const k of ["category", "location"]) if (ih(k) && !len256(it[k])) return `${at}.${k} is not a string of 1 to 256 characters`;
    if (ih("refundable") && typeof it.refundable !== "boolean") return `${at}.refundable is not a boolean`;
    for (const k of ["service_from", "service_until"]) if (ih(k) && !dateOk(it[k])) return `${at}.${k} is not a date YYYY-MM-DD`;
    if (ih("service_from") && ih("service_until") && it.service_from > it.service_until) return `${at}.service_from is after service_until`;
  }
  return null;
}

// The output's card.order (spec 4.7): the items' sum beside the total, for
// the reader to compare; it changes no check's state.
export function orderSummary(o) {
  const sum = o.items.reduce((s, it) => s + BigInt(it.quantity) * BigInt(it.unit_price_minor), 0n);
  return { merchant_id: o.merchant_id, merchant_order_id: o.merchant_order_id ?? null, checkout_ref: o.checkout_ref ?? null, currency: o.currency, total_minor: o.total_minor, items_sum_minor: sum.toString(), item_count: o.items.length };
}

// Spec D.1: two times compared as instants, a time with a fraction against
// one without at the precision both carry, the shorter read with zeros.
// Returns -1, 0 or 1.
export function compareInstants(a, b) {
  if (!TIME_RE.test(a) || !TIME_RE.test(b)) throw new Error("not a time");
  const split = (t) => {
    const [whole, frac = ""] = t.slice(0, -1).split(".");
    return [whole, frac];
  };
  const [wa, fa] = split(a);
  const [wb, fb] = split(b);
  if (wa !== wb) return wa < wb ? -1 : 1;
  const n = Math.max(fa.length, fb.length);
  const [pa, pb] = [fa.padEnd(n, "0"), fb.padEnd(n, "0")];
  return pa === pb ? 0 : pa < pb ? -1 : 1;
}

// B-CARD rule 2, the match: each field compared, true or false, or null when
// not compared (a reference the order or the stated charge does not carry).
export function cardMatches(order, charge) {
  const ref = (k, ck) => (order[k] !== undefined && charge[ck] !== null ? order[k] === charge[ck] : null);
  return { amount: BigInt(order.total_minor) === BigInt(charge.amount_minor), currency: order.currency === charge.currency, merchant_order_id: ref("merchant_order_id", "merchant_order_id"), checkout_ref: ref("checkout_ref", "checkout_ref") };
}
