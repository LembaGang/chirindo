// Mappers (B-432, design rev 3 §7): a provider's own approval object becomes
// the body of an Annex A.3 card-only instruction, which the provider signs
// with its own key as principal (signInstruction). None of the three
// providers publishes a user-signed limit object, so the instruction states
// what the provider says its customer approved (limit 2).
//
// Field names and units are as each provider's documentation gave them when
// read on 2026-10-30 (cited in test/purchase-mappers.test.ts). Every amount
// there is a major-unit decimal string ("150.00").
//
// Every refusal throws a MapperError with a stable code. The mappers never
// widen what was approved: a precision finer than the minor unit is floored,
// a validity window is the earlier of two, and a "listed" Prava scope with
// no merchant refuses.

import { createPublicKey, type KeyObject } from "node:crypto";
import { ANNEX_A3, THUMBPRINT_RE, okpThumbprint } from "./m6.js";
import { compareInstants } from "./time.js";

export type MapperErrorCode =
  | "bad-option"
  | "bad-amount"
  | "unknown-currency"
  | "bad-url"
  | "unsupported-scheme"
  | "userinfo-url"
  | "bad-time"
  | "bad-field"
  | "prava-custom-entries"
  | "prava-scope"
  | "max-uses-over-max-charges";

export class MapperError extends Error {
  constructor(
    readonly code: MapperErrorCode,
    detail: string,
  ) {
    super(`${code}: ${detail}`);
    this.name = "MapperError";
  }
}

const refuse = (code: MapperErrorCode, detail: string): never => {
  throw new MapperError(code, detail);
};

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";

// ISO 4217 exponents (minor-unit digits) for the currencies v0.1 maps. Any
// other currency refuses rather than guess.
export const CURRENCY_EXPONENTS: Readonly<Record<string, 0 | 2>> = Object.freeze({
  USD: 2,
  EUR: 2,
  GBP: 2,
  CAD: 2,
  AUD: 2,
  SGD: 2,
  HKD: 2,
  CHF: 2,
  INR: 2,
  ZAR: 2,
  JPY: 0,
  KRW: 0,
});

// A major-unit decimal string ("150.00") as minor units ("15000"), by the
// currency's exponent. Digits past the minor unit are floored, so the cap is
// never above what was approved: "150.0050" USD is "15000".
export function toMinorUnits(value: unknown, currency: unknown): string {
  if (!isStr(currency) || !Object.prototype.hasOwnProperty.call(CURRENCY_EXPONENTS, currency)) {
    refuse("unknown-currency", `${JSON.stringify(currency)} is not in the currency table`);
  }
  const exp = CURRENCY_EXPONENTS[currency as string]!;
  if (!isStr(value) || !/^\d+(\.\d+)?$/.test(value)) refuse("bad-amount", "the amount is not a decimal string in major units");
  const [whole, frac = ""] = (value as string).split(".");
  const minor = BigInt(whole!) * 10n ** BigInt(exp) + (exp === 0 ? 0n : BigInt(frac.padEnd(exp, "0").slice(0, exp)));
  return minor.toString();
}

// The merchant id the purchase check compares: the origin of the merchant's
// URL (WHATWG URL), http or https only, and never a URL with userinfo. The
// provider builds order.merchant_id with this same function.
export function merchantIdOf(url: unknown): string {
  if (!isStr(url)) refuse("bad-url", "the merchant URL is not a string");
  let u: URL;
  try {
    u = new URL(url as string);
  } catch {
    return refuse("bad-url", "the merchant URL does not parse");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") refuse("unsupported-scheme", `scheme ${u.protocol} is not https or http`);
  if (u.username !== "" || u.password !== "") refuse("userinfo-url", "the merchant URL carries userinfo");
  return u.origin;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|([+-])(\d{2}):(\d{2}))$/;

// An RFC 3339 time as a Z instant, its fractional digits kept. A time that
// does not parse, or names no calendar instant (30 February, hour 24, second
// 60, an offset beyond 23:59), refuses.
export function toZ(time: unknown): string {
  const m = isStr(time) ? RFC3339.exec(time) : null;
  if (m === null) return refuse("bad-time", `${JSON.stringify(time)} is not an RFC 3339 time`);
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const fields = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  const ok =
    fields.getUTCFullYear() === y && fields.getUTCMonth() === mo - 1 && fields.getUTCDate() === d && fields.getUTCHours() === h && fields.getUTCMinutes() === mi && fields.getUTCSeconds() === s;
  if (!ok || y < 100) refuse("bad-time", `${time as string} names no calendar instant`);
  let offsetMin = 0;
  if (m[9] !== undefined) {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) refuse("bad-time", `${time as string} has an offset beyond 23:59`);
    offsetMin = (m[9] === "+" ? 1 : -1) * (oh * 60 + om);
  }
  const instant = new Date(fields.getTime() - offsetMin * 60_000);
  const iso = instant.toISOString();
  if (!/^\d{4}-/.test(iso)) refuse("bad-time", `${time as string} is outside the years 0000 to 9999 once in UTC`);
  return `${iso.slice(0, 19)}${m[7] ?? ""}Z`;
}

export interface MapOptions {
  // The provider's key, as principal: the instruction is signed with it.
  principalKey: KeyObject;
  // The gate kids allowed to act on the instruction (at least one).
  agentKids: string[];
  // How many purchases the instruction allows. Required: absent would mean one.
  maxUses: number;
  // The customer's approval time (else the instruction's issue time): valid_from.
  approvedAt: string;
  // The instruction's issue time; defaults to approvedAt.
  iat?: string;
}

interface Card {
  currency: string;
  max_total_minor: string;
  merchants?: string[];
}

function body(o: MapOptions, text: unknown, validUntil: string, card: Card): Obj {
  if (!isObj(o)) refuse("bad-option", "options must be an object");
  let x: string;
  try {
    const pub = o.principalKey.type === "private" ? createPublicKey(o.principalKey) : o.principalKey;
    if (pub.asymmetricKeyType !== "ed25519") throw new Error("not ed25519");
    x = (pub.export({ format: "jwk" }) as { x: string }).x;
  } catch {
    return refuse("bad-option", "principalKey must be an Ed25519 KeyObject");
  }
  if (!Array.isArray(o.agentKids) || o.agentKids.length === 0 || !o.agentKids.every((k) => isStr(k) && THUMBPRINT_RE.test(k))) {
    refuse("bad-option", "agentKids must be a non-empty list of RFC 7638 thumbprints");
  }
  if (!Number.isSafeInteger(o.maxUses) || o.maxUses < 1) refuse("bad-option", "maxUses must be an integer of at least 1");
  if (!isStr(text)) refuse("bad-field", "the description is not a string");
  const validFrom = toZ(o.approvedAt);
  return {
    v: ANNEX_A3,
    principal: { kid: okpThumbprint(x), public_key_jwk: { kty: "OKP", crv: "Ed25519", x } },
    agent_kid: [...o.agentKids],
    // Carried and signed over, not checked (limit 3).
    text,
    constraints: { valid_from: validFrom, valid_until: validUntil, max_uses: o.maxUses, card },
    iat: o.iat === undefined ? validFrom : toZ(o.iat),
  };
}

// amount {value, currency} and an optional merchant {url} into the card member.
function cardOf(amount: unknown, merchant: unknown): Card {
  if (!isObj(amount)) refuse("bad-field", "amount is not an object");
  const a = amount as Obj;
  const card: Card = { currency: a["currency"] as string, max_total_minor: toMinorUnits(a["value"], a["currency"]) };
  if (merchant !== undefined && merchant !== null) {
    if (!isObj(merchant)) refuse("bad-field", "merchant is not an object");
    card.merchants = [merchantIdOf((merchant as Obj)["url"])];
  }
  return card;
}

// A Crossmint order intent: amount {value, currency}, optional merchant {url},
// expiresAt, description. The amount is the intent's total; each purchase is
// checked against it and uses are counted (limit 4).
export function mapCrossmintOrderIntent(intent: unknown, o: MapOptions): Obj {
  if (!isObj(intent)) refuse("bad-field", "the order intent is not an object");
  const i = intent as Obj;
  return body(o, i["description"], toZ(i["expiresAt"]), cardOf(i["amount"], i["merchant"]));
}

// A Basis Theory allowance: amount {value, currency}, optional merchant {url},
// expires_at, description. As Crossmint's, the amount is a total (limit 4).
export function mapBasisTheoryAllowance(allowance: unknown, o: MapOptions): Obj {
  if (!isObj(allowance)) refuse("bad-field", "the allowance is not an object");
  const a = allowance as Obj;
  return body(o, a["description"], toZ(a["expires_at"]), cardOf(a["amount"], a["merchant"]));
}

const PRAVA_DEFAULT_MINUTES = 15;

// A Prava mandate (as GET returns it) with the session request that set it
// up. approvedAmount is the per-charge cap. The merchant is the session's one
// custom entry when the scope is "listed". valid_until is the earlier of
// mandate.validUntil and approvedAt + effective_until_minutes (default 15):
// Prava's docs do not reconcile the two, and the earlier is never beyond what
// was approved. maxUses may not exceed mandate_setup.max_charges.
export function mapPravaMandate(input: { mandate: unknown; session: unknown }, o: MapOptions): Obj {
  if (!isObj(input) || !isObj(input.mandate) || !isObj(input.session)) refuse("bad-field", "mandate and session must be objects");
  const mandate = input.mandate as Obj;
  const session = input.session as Obj;
  const pc = session["purchase_context"];
  const custom = isObj(pc) ? (pc as Obj)["custom"] : undefined;
  const entries = custom === undefined ? [] : custom;
  if (!Array.isArray(entries)) return refuse("bad-field", "purchase_context.custom is not a list");
  if (entries.length > 1) refuse("prava-custom-entries", `purchase_context.custom has ${entries.length} entries; the mapper takes one`);
  const entry = entries[0] as unknown;
  if (entry !== undefined && !isObj(entry)) refuse("bad-field", "purchase_context.custom[0] is not an object");

  const setup = isObj(session["mandate_setup"]) ? (session["mandate_setup"] as Obj) : undefined;
  const scope = mandate["merchantScope"] ?? setup?.["merchant_scope"];
  if (scope !== "listed" && scope !== "any") refuse("prava-scope", "the merchant scope is neither listed nor any");
  const card: Card = { currency: mandate["currency"] as string, max_total_minor: toMinorUnits(mandate["approvedAmount"], mandate["currency"]) };
  if (scope === "listed") {
    const md = entry === undefined ? undefined : (entry as Obj)["merchant_details"];
    if (!isObj(md)) refuse("prava-scope", 'the scope is "listed" and no custom entry names a merchant');
    card.merchants = [merchantIdOf((md as Obj)["url"])];
  }

  const minutes = entry === undefined ? undefined : (entry as Obj)["effective_until_minutes"];
  const mins = minutes === undefined ? PRAVA_DEFAULT_MINUTES : minutes;
  if (!Number.isSafeInteger(mins) || (mins as number) < 1) refuse("bad-field", "effective_until_minutes is not a positive integer");
  const from = toZ(o.approvedAt);
  // Date milliseconds drop sub-millisecond digits of approvedAt: that floors
  // the end, never extends it.
  const byMinutes = new Date(Date.parse(from) + (mins as number) * 60_000).toISOString();
  const vu = mandate["validUntil"];
  let validUntil = byMinutes;
  if (vu !== undefined && vu !== null) {
    const z = toZ(vu);
    if (compareInstants(z, byMinutes) < 0) validUntil = z;
  }

  const maxCharges = setup?.["max_charges"];
  if (maxCharges !== undefined) {
    if (!Number.isSafeInteger(maxCharges) || (maxCharges as number) < 1) refuse("bad-field", "mandate_setup.max_charges is not a positive integer");
    if (Number.isSafeInteger(o.maxUses) && o.maxUses > (maxCharges as number)) {
      refuse("max-uses-over-max-charges", `maxUses ${o.maxUses} is more than mandate_setup.max_charges ${maxCharges as number}`);
    }
  }
  // The session's own top-level description when it carries one (T3 ruling
  // 1); otherwise the product lines' descriptions, joined.
  const products = entry === undefined ? undefined : (entry as Obj)["product_details"];
  const text = isStr(session["description"])
    ? session["description"]
    : Array.isArray(products)
      ? products.map((p) => (isObj(p) && isStr(p["description"]) ? p["description"] : "")).join("; ")
      : "";
  return body(o, text, validUntil, card);
}
