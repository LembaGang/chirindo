// B-432 test 8, the mappers and the currency table (design rev 3 §7, §8.8).
//
// The provider examples are those of each provider's documentation, read on
// 2026-10-30 (values as the pages show them; members a page's example omits
// are noted):
//   Crossmint, create card permissions (order intent request; expiresAt from
//     the response example): docs.crossmint.com/agents/payment-methods/cards/create-card-permissions
//   Basis Theory, allowances (create request): developers.basistheory.com/docs/api/agentic-commerce/allowances
//   Prava, Get a Mandate (200 example) and Create Session (mandate setup):
//     docs.prava.space/api-reference/mandate-get.md, docs.prava.space/api-reference/create-session.md
//
// instructions.mjs imports evm.mjs, which needs viem (not installed in CI); a
// lowercase-only `address` stands in, and no card-only instruction reaches it.

import { describe, expect, it, vi } from "vitest";
import { evaluatePurchase } from "../src/purchase/limits.js";
import { m6Check, parseStrictJson, signInstruction } from "../src/purchase/m6.js";
import {
  CURRENCY_EXPONENTS,
  MapperError,
  mapBasisTheoryAllowance,
  mapCrossmintOrderIntent,
  mapPravaMandate,
  mapNeverminedCardDelegation,
  mapReapMandate,
  mapSkyfirePayToken,
  mapStripeSharedPaymentIssuedToken,
  merchantIdOf,
  toMinorUnits,
  toZ,
  type MapOptions,
} from "../src/purchase/mappers.js";
import { GATE, PRINCIPAL, expectVocabulary, type Obj } from "./purchase-helpers.js";
// @ts-expect-error -- plain .mjs without declarations; the reference verifier
import { ANNEX_A3, m6Instruction } from "../examples/evidence-bundle/lib/instructions.mjs";

vi.mock("../examples/ordering-evidence-h4/lib/evm.mjs", () => ({
  address: (s: unknown, what: string) => {
    if (typeof s !== "string" || !/^0x[0-9a-f]{40}$/.test(s)) throw new Error(`${what} is not a lowercase 20-byte hex address`);
    return s;
  },
}));

const CROSSMINT_INTENT = {
  paymentMethodId: "pm_123",
  amount: { value: "150.00", currency: "USD" },
  merchant: { name: "Acme Store", url: "https://acme.example.com", countryCode: "US" },
  description: "Weekly grocery purchases",
  expiresAt: "2099-01-01T00:00:00.000Z",
};
const BASIS_THEORY_ALLOWANCE = {
  payment_method_id: "pm_h2Kd91mAqLwX",
  amount: { value: "100.00", currency: "USD" },
  merchant: { name: "Acme Store", url: "https://acme.example.com", country_code: "US", category_code: "5732", acquirer_bin: "545301" },
  description: "Buy approved office supplies from Acme Store",
  expires_at: "2030-07-08T00:00:00.000Z",
};
// The 200 example omits validUntil (nullable) and merchantScope; the scope
// comes from the session's mandate_setup.merchant_scope.
const PRAVA_MANDATE = {
  id: "mdt_123",
  status: "active",
  approvedAmount: "40.00",
  currency: "USD",
  spent: "40.00",
  chargeCount: 1,
  charges: [{ transactionId: "txn_9", amount: "40.00", currency: "USD", status: "completed", reference: "invoice_2026_07", createdAt: "2026-07-26T00:00:00Z" }],
};
const PRAVA_SESSION = {
  user_id: "user_123",
  user_email: "jane@example.com",
  total_amount: "40.00",
  currency: "USD",
  purchase_context: {
    custom: [
      {
        merchant_details: { name: "Acme Store", url: "https://acme.example.com", country_code_iso2: "US" },
        product_details: [{ description: "Monthly plan", unit_price: "40.00", quantity: 1 }],
      },
    ],
  },
  mandate_setup: { intent: "mandate_setup", recurring_frequency: "monthly", merchant_scope: "listed", max_charges: 12, valid_until: "2028-07-26T12:00:00Z" },
};

const opts = (over: Partial<MapOptions> = {}): MapOptions => ({ principalKey: PRINCIPAL.priv, agentKids: [GATE.kid], maxUses: 2, approvedAt: "2026-07-26T00:00:00Z", ...over });
const sign = (b: Obj) => JSON.stringify(signInstruction(b, PRINCIPAL.priv));
const constraints = (b: Obj) => b["constraints"] as Obj;
const card = (b: Obj) => constraints(b)["card"] as Obj;
const code = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    if (e instanceof MapperError) return e.code;
    throw e;
  }
  return "no refusal";
};

describe("test 8: each provider's documented example passes M6", () => {
  const cases: [string, Obj, { total: string; at: string }][] = [
    ["Crossmint order intent", mapCrossmintOrderIntent(CROSSMINT_INTENT, opts()), { total: "12000", at: "2026-08-01T00:00:00.000Z" }],
    ["Basis Theory allowance", mapBasisTheoryAllowance(BASIS_THEORY_ALLOWANCE, opts()), { total: "9000", at: "2026-08-01T00:00:00.000Z" }],
    ["Prava mandate", mapPravaMandate({ mandate: PRAVA_MANDATE, session: PRAVA_SESSION }, opts()), { total: "4000", at: "2026-07-26T00:10:00.000Z" }],
  ];
  for (const [name, b, use] of cases) {
    it(name, () => {
      const text = sign(b);
      const parsed = parseStrictJson(text) as { ok: true; value: unknown };
      expect(m6Check(parsed.value)).toMatchObject({ ok: true, unsupported: [] });
      const ref = m6Instruction(Buffer.from(text, "utf8"), ANNEX_A3);
      expect(ref.problem).toBeUndefined();
      // And a purchase inside it, at the merchant it names, is allowed.
      const order = { merchant_id: "https://acme.example.com", merchant_order_id: "A-1", currency: "USD", total_minor: use.total, items: [{ sku: "X", quantity: 1, unit_price_minor: use.total }] };
      const e = evaluatePurchase(text, order, { kid: GATE.kid, at: use.at, usesSoFar: 0 });
      expectVocabulary(e.reasons);
      expect(e.reasons).toEqual([]);
    });
  }

  it("the mapped members, as §7's table gives them", () => {
    const c = mapCrossmintOrderIntent(CROSSMINT_INTENT, opts());
    expect(card(c)).toEqual({ currency: "USD", max_total_minor: "15000", merchants: ["https://acme.example.com"] });
    expect(constraints(c)).toMatchObject({ valid_from: "2026-07-26T00:00:00Z", valid_until: "2099-01-01T00:00:00.000Z", max_uses: 2 });
    expect([c["text"], c["iat"], c["agent_kid"]]).toEqual(["Weekly grocery purchases", "2026-07-26T00:00:00Z", [GATE.kid]]);
    expect((c["principal"] as Obj)["kid"]).toBe(PRINCIPAL.kid);
    const bt = mapBasisTheoryAllowance(BASIS_THEORY_ALLOWANCE, opts());
    expect(card(bt)).toEqual({ currency: "USD", max_total_minor: "10000", merchants: ["https://acme.example.com"] });
    expect(constraints(bt)["valid_until"]).toBe("2030-07-08T00:00:00.000Z");
    const p = mapPravaMandate({ mandate: PRAVA_MANDATE, session: PRAVA_SESSION }, opts());
    expect(card(p)).toEqual({ currency: "USD", max_total_minor: "4000", merchants: ["https://acme.example.com"] });
    // validUntil is absent (null): the minutes rule alone, 15 by default.
    expect(constraints(p)["valid_until"]).toBe("2026-07-26T00:15:00.000Z");
    expect(p["text"]).toBe("Monthly plan");
  });

  it("Prava text: the session's top-level description when it has one, else the product descriptions joined", () => {
    const described = { ...PRAVA_SESSION, description: "Monthly plan at Acme Store, up to USD 40.00 a charge" };
    expect(mapPravaMandate({ mandate: PRAVA_MANDATE, session: described }, opts())["text"]).toBe("Monthly plan at Acme Store, up to USD 40.00 a charge");
    const twoLines = { ...PRAVA_SESSION, purchase_context: { custom: [{ ...PRAVA_SESSION.purchase_context.custom[0], product_details: [{ description: "Plan" }, { description: "Add-on" }] }] } };
    expect(mapPravaMandate({ mandate: PRAVA_MANDATE, session: twoLines }, opts())["text"]).toBe("Plan; Add-on");
  });

  it("an open intent or allowance (no merchant) sets no merchants limit; Prava scope any sets none", () => {
    const { merchant: _m, ...open } = CROSSMINT_INTENT;
    expect(card(mapCrossmintOrderIntent(open, opts()))).toEqual({ currency: "USD", max_total_minor: "15000" });
    const any = { ...PRAVA_SESSION, mandate_setup: { ...PRAVA_SESSION.mandate_setup, merchant_scope: "any" } };
    expect(card(mapPravaMandate({ mandate: PRAVA_MANDATE, session: any }, opts()))).toEqual({ currency: "USD", max_total_minor: "4000" });
  });
});

describe("test 8: refusals", () => {
  it("an unknown currency", () => {
    expect(code(() => mapCrossmintOrderIntent({ ...CROSSMINT_INTENT, amount: { value: "1.000", currency: "KWD" } }, opts()))).toBe("unknown-currency");
    expect(code(() => toMinorUnits("1.00", "usd"))).toBe("unknown-currency");
    expect(code(() => toMinorUnits("1.00", undefined))).toBe("unknown-currency");
  });
  it("a URL with userinfo", () => {
    expect(code(() => merchantIdOf("https://user:pw@acme.example.com/"))).toBe("userinfo-url");
    expect(code(() => mapBasisTheoryAllowance({ ...BASIS_THEORY_ALLOWANCE, merchant: { url: "https://user@acme.example.com" } }, opts()))).toBe("userinfo-url");
  });
  it("an ftp scheme, and URLs that do not parse", () => {
    expect(code(() => merchantIdOf("ftp://acme.example.com"))).toBe("unsupported-scheme");
    expect(code(() => merchantIdOf("javascript:alert(1)"))).toBe("unsupported-scheme");
    expect(code(() => merchantIdOf("acme.example.com"))).toBe("bad-url");
  });
  it("an unparseable time, or one that names no calendar instant", () => {
    for (const t of ["next tuesday", "2026-07-26", "2026-07-26 00:00:00Z", "2026-02-30T00:00:00Z", "2026-07-26T24:00:00Z", "2026-07-26T00:00:60Z", "2026-07-26T00:00:00+24:00", 1_700_000_000]) {
      expect([t, code(() => toZ(t))]).toEqual([t, "bad-time"]);
    }
    expect(code(() => mapCrossmintOrderIntent({ ...CROSSMINT_INTENT, expiresAt: "tomorrow" }, opts()))).toBe("bad-time");
    expect(code(() => mapCrossmintOrderIntent(CROSSMINT_INTENT, opts({ approvedAt: "yesterday" })))).toBe("bad-time");
  });
  it("Prava custom with two entries", () => {
    const two = { ...PRAVA_SESSION, purchase_context: { custom: [PRAVA_SESSION.purchase_context.custom[0], PRAVA_SESSION.purchase_context.custom[0]] } };
    expect(code(() => mapPravaMandate({ mandate: PRAVA_MANDATE, session: two }, opts()))).toBe("prava-custom-entries");
  });
  it("Prava: a listed scope with no merchant, an unknown scope, maxUses over max_charges", () => {
    const none = { ...PRAVA_SESSION, purchase_context: { custom: [] } };
    expect(code(() => mapPravaMandate({ mandate: PRAVA_MANDATE, session: none }, opts()))).toBe("prava-scope");
    const { mandate_setup: _s, ...noScope } = PRAVA_SESSION;
    expect(code(() => mapPravaMandate({ mandate: PRAVA_MANDATE, session: noScope }, opts()))).toBe("prava-scope");
    expect(code(() => mapPravaMandate({ mandate: PRAVA_MANDATE, session: PRAVA_SESSION }, opts({ maxUses: 13 })))).toBe("max-uses-over-max-charges");
  });
  it("bad options", () => {
    expect(code(() => mapCrossmintOrderIntent(CROSSMINT_INTENT, opts({ agentKids: [] })))).toBe("bad-option");
    expect(code(() => mapCrossmintOrderIntent(CROSSMINT_INTENT, opts({ maxUses: 0 })))).toBe("bad-option");
    expect(code(() => mapCrossmintOrderIntent(CROSSMINT_INTENT, opts({ principalKey: "k" as never })))).toBe("bad-option");
    expect(code(() => mapCrossmintOrderIntent({ ...CROSSMINT_INTENT, amount: { value: "-1", currency: "USD" } }, opts()))).toBe("bad-amount");
  });
});

describe("test 8: conversions", () => {
  it("an offset time to Z, with its fractional digits kept", () => {
    expect(toZ("2026-11-01T02:30:00+02:00")).toBe("2026-11-01T00:30:00Z");
    expect(toZ("2026-10-31T19:30:00.123456-05:00")).toBe("2026-11-01T00:30:00.123456Z");
    expect(toZ("2026-11-01t00:30:00z")).toBe("2026-11-01T00:30:00Z");
    expect(toZ("2026-01-01T00:30:00+01:00")).toBe("2025-12-31T23:30:00Z");
  });
  it('"150.0050" to 15000 minor units, and the table\'s exponents', () => {
    expect(toMinorUnits("150.0050", "USD")).toBe("15000");
    expect(toMinorUnits("150.009", "EUR")).toBe("15000");
    expect(toMinorUnits("150", "GBP")).toBe("15000");
    expect(toMinorUnits("0.5", "USD")).toBe("50");
    expect(toMinorUnits("1500", "JPY")).toBe("1500");
    expect(toMinorUnits("1500.9", "KRW")).toBe("1500");
    expect(Object.keys(CURRENCY_EXPONENTS).sort()).toEqual(["AUD", "CAD", "CHF", "EUR", "GBP", "HKD", "INR", "JPY", "KRW", "SGD", "USD", "ZAR"]);
  });
  it("an https URL with a path to its origin", () => {
    expect(merchantIdOf("https://Acme.Example.com:443/checkout/cart?id=1#x")).toBe("https://acme.example.com");
    expect(merchantIdOf("http://shop.example:8080/a")).toBe("http://shop.example:8080");
  });
  it("Prava validUntil null to the minutes rule; the earlier of the two windows otherwise", () => {
    const at = "2026-07-26T00:00:00Z";
    const vu = (mandate: Obj, session: Obj = PRAVA_SESSION) => constraints(mapPravaMandate({ mandate, session }, opts({ approvedAt: at })))["valid_until"];
    expect(vu({ ...PRAVA_MANDATE, validUntil: null })).toBe("2026-07-26T00:15:00.000Z");
    const thirty = { ...PRAVA_SESSION, purchase_context: { custom: [{ ...PRAVA_SESSION.purchase_context.custom[0], effective_until_minutes: 30 }] } };
    expect(vu({ ...PRAVA_MANDATE, validUntil: null }, thirty)).toBe("2026-07-26T00:30:00.000Z");
    expect(vu({ ...PRAVA_MANDATE, validUntil: "2026-07-26T00:05:00Z" })).toBe("2026-07-26T00:05:00Z");
    expect(vu({ ...PRAVA_MANDATE, validUntil: "2028-07-26T12:00:00Z" })).toBe("2026-07-26T00:15:00.000Z");
  });
});

// B-459 (2026-11-04). Reap, the "Response" example of "What the mandate
// controls" on docs.reap.global/agentic-payments/recurring-purchases.md (read
// 2026-11-04T17:03:11Z; the page marks mandates as not yet released; the
// <...> values are the page's placeholders). Skyfire, the payload of
// docs.skyfire.xyz/docs/example-pay-token.md (read 2026-11-04T17:03:19Z; the
// page's // comments dropped, its sti card values not used by the mapper).
const REAP_MANDATE = {
  id: "<mandate-id>",
  status: "ACTIVE",
  enrollmentId: "<enrollment-id>",
  frequency: "MONTHLY",
  maxCharges: 12,
  merchantScope: "LISTED",
  merchant: { name: "<merchant-name>", url: "https://example.com", country: "US" },
  amount: { amount: 150, currency: "USD" },
};
const SKYFIRE_PAY = {
  iss: "https://example.net/pay_token_issuer",
  iat: 1742245254,
  exp: 1773867654,
  jti: "b9821893-7699-4d24-af06-803a6a16476b",
  sub: "8b810549-7443-494f-b4ad-5bc65871e32b",
  aud: "37888095-2721-48d9-a2df-bfe4075f223a",
  env: "sandbox",
  ssi: "274efc47-024e-466f-b278-152d2ee73955",
  btg: "16c135ce-a99a-453d-a7b5-4958fd91de5f",
  spr: "0.01",
  sps: "pay_per_use",
  amt: "15",
  cur: "USD",
  val: "15000000",
  mnr: 1600,
  stp: "card",
};
const REAP_UNTIL = "2027-07-26T00:00:00Z";

describe("B-459: Reap mandate and Skyfire PAY token", () => {
  it("each documented example passes M6, and an order inside it is allowed", () => {
    const cases: [string, Obj, { merchant: string; total: string; at: string }][] = [
      ["Reap mandate", mapReapMandate(REAP_MANDATE, { ...opts(), validUntil: REAP_UNTIL }), { merchant: "https://example.com", total: "14000", at: "2026-08-01T00:00:00.000Z" }],
      ["Skyfire PAY token", mapSkyfirePayToken(SKYFIRE_PAY, opts({ approvedAt: "2025-03-17T21:00:54Z" })), { merchant: SKYFIRE_PAY.aud, total: "1000", at: "2025-04-01T00:00:00.000Z" }],
    ];
    for (const [name, b, use] of cases) {
      const text = sign(b);
      const parsed = parseStrictJson(text) as { ok: true; value: unknown };
      expect([name, m6Check(parsed.value)]).toMatchObject([name, { ok: true, unsupported: [] }]);
      expect(m6Instruction(Buffer.from(text, "utf8"), ANNEX_A3).problem).toBeUndefined();
      const order = { merchant_id: use.merchant, merchant_order_id: "A-1", currency: "USD", total_minor: use.total, items: [{ sku: "X", quantity: 1, unit_price_minor: use.total }] };
      const e = evaluatePurchase(text, order, { kid: GATE.kid, at: use.at, usesSoFar: 0 });
      expectVocabulary(e.reasons);
      expect([name, e.reasons]).toEqual([name, []]);
    }
  });

  it("the mapped members", () => {
    const r = mapReapMandate(REAP_MANDATE, { ...opts(), validUntil: REAP_UNTIL });
    expect(card(r)).toEqual({ currency: "USD", max_total_minor: "15000", merchants: ["https://example.com"] });
    expect(constraints(r)).toMatchObject({ valid_from: "2026-07-26T00:00:00Z", valid_until: REAP_UNTIL, max_uses: 2 });
    expect(r["text"]).toBe("<merchant-name>");
    const s = mapSkyfirePayToken(SKYFIRE_PAY, opts({ approvedAt: "2025-03-17T21:00:54Z" }));
    expect(card(s)).toEqual({ currency: "USD", max_total_minor: "1500", merchants: [SKYFIRE_PAY.aud] });
    expect(constraints(s)).toMatchObject({ valid_from: "2025-03-17T21:00:54Z", valid_until: "2026-03-18T21:00:54Z", max_uses: 2 });
    expect(s["text"]).toBe(SKYFIRE_PAY.ssi);
  });

  it("Reap: scope ANY sets no merchants; a fractional JSON number amount converts", () => {
    const any = { ...REAP_MANDATE, merchantScope: "ANY", merchant: null };
    expect(card(mapReapMandate(any, { ...opts(), validUntil: REAP_UNTIL }))).toEqual({ currency: "USD", max_total_minor: "15000" });
    const frac = { ...REAP_MANDATE, amount: { amount: 49.99, currency: "USD" } };
    expect(card(mapReapMandate(frac, { ...opts(), validUntil: REAP_UNTIL }))["max_total_minor"]).toBe("4999");
  });

  it("Reap refusals", () => {
    const o = { ...opts(), validUntil: REAP_UNTIL };
    for (const status of ["REQUIRES_ACTION", "PAUSED", "CONSUMED", "EXPIRED", "FAILED", "CANCELLED", "REVOKED", undefined]) {
      expect([status, code(() => mapReapMandate({ ...REAP_MANDATE, status }, o))]).toEqual([status, "reap-status"]);
    }
    expect(code(() => mapReapMandate(REAP_MANDATE, opts() as never))).toBe("bad-option");
    expect(code(() => mapReapMandate({ ...REAP_MANDATE, merchant: null }, o))).toBe("reap-scope");
    expect(code(() => mapReapMandate({ ...REAP_MANDATE, merchantScope: "listed" }, o))).toBe("reap-scope");
    expect(code(() => mapReapMandate(REAP_MANDATE, { ...o, maxUses: 13 }))).toBe("max-uses-over-max-charges");
    for (const amount of [-1, Number.NaN, Infinity, 1e21, "150"]) {
      expect([amount, code(() => mapReapMandate({ ...REAP_MANDATE, amount: { amount, currency: "USD" } }, o))]).toEqual([amount, "bad-amount"]);
    }
    expect(code(() => mapReapMandate({ ...REAP_MANDATE, amount: { amount: 150, currency: "XYZ" } }, o))).toBe("unknown-currency");
    expect(code(() => mapReapMandate({ ...REAP_MANDATE, merchant: { url: "ftp://example.com" } }, o))).toBe("unsupported-scheme");
  });

  it("Skyfire refusals", () => {
    const o = opts({ approvedAt: "2025-03-17T21:00:54Z" });
    expect(code(() => mapSkyfirePayToken(SKYFIRE_PAY, opts({ approvedAt: "2025-03-17T21:00:54Z", maxUses: 1601 })))).toBe("max-uses-over-max-requests");
    for (const exp of ["1773867654", 1.5, -1, 1e20, undefined]) {
      expect([exp, code(() => mapSkyfirePayToken({ ...SKYFIRE_PAY, exp }, o))]).toEqual([exp, "bad-time"]);
    }
    for (const aud of ["", 7, undefined]) {
      expect([aud, code(() => mapSkyfirePayToken({ ...SKYFIRE_PAY, aud }, o))]).toEqual([aud, "bad-field"]);
    }
    expect(code(() => mapSkyfirePayToken({ ...SKYFIRE_PAY, amt: 15 }, o))).toBe("bad-amount");
    expect(code(() => mapSkyfirePayToken({ ...SKYFIRE_PAY, cur: "USDC" }, o))).toBe("unknown-currency");
    // mnr counts only when the scheme is pay_per_use.
    const sub = { ...SKYFIRE_PAY, sps: "subscription" };
    expect(constraints(mapSkyfirePayToken(sub, opts({ approvedAt: "2025-03-17T21:00:54Z", maxUses: 5000 })))["max_uses"]).toBe(5000);
  });
});

// B-441 day 5 (2026-11-09). Stripe, the example object of "The Shared Payment
// Issued Token object", docs.stripe.com/api/shared-payment/issued-token/object.md
// (read 2026-11-09T08:47:23Z; usage_limits.max_amount is an integer in the
// currency's minor unit, docs.stripe.com/currencies.md line 41, read
// 08:48:13Z). Nevermined, the "Stripe Delegation" create request of
// nevermined.ai/docs/products/payments/mandates.md (read 2026-11-09T08:47:31Z;
// spendingLimitCents is the lifetime cap in cents; durationSecs runs from the
// delegation's createdAt; the object names no merchant).
const STRIPE_ISSUED = {
  id: "spt_1RgaZcFPC5QUO6ZCDVZuVA8q",
  object: "shared_payment.issued_token",
  livemode: false,
  created: 1751500820,
  deactivated_at: null,
  deactivated_reason: null,
  payment_method: "pm_1RgaZbFPC5QUO6ZCe2ekOCNX",
  seller_details: { external_id: null, network_business_profile: "profile_test_61TU90nIeGjU7NNVXA6TU90m7ISQWsBxpcx9lASWWXTk" },
  setup_future_usage: null,
  shared_metadata: {},
  status: "active",
  usage_details: { amount_captured: { value: 0, currency: "usd" } },
  usage_limits: { currency: "usd", expires_at: 1751587220, max_amount: 1000 },
};
const NEVERMINED_STRIPE = {
  provider: "stripe",
  providerPaymentMethodId: "pm_1Abc2Def3Ghi4Jkl",
  spendingLimitCents: 10000,
  durationSecs: 604800,
  maxTransactions: 100,
  currency: "usd",
  apiKeyId: "sk-abc123",
};
const STRIPE_AT = "2025-07-03T00:00:20Z";
const NVM_CREATED = "2026-11-09T00:00:00Z";
const nvmOpts = (over: Partial<MapOptions & { createdAt: string }> = {}) => ({ ...opts(), approvedAt: NVM_CREATED, createdAt: NVM_CREATED, ...over });

describe("B-441: Stripe Shared Payment Issued Token and Nevermined card delegation", () => {
  it("each documented example passes M6, and an order inside it is allowed", () => {
    const cases: [string, Obj, { merchant: string; total: string; at: string }][] = [
      ["Stripe issued token", mapStripeSharedPaymentIssuedToken(STRIPE_ISSUED, opts({ approvedAt: STRIPE_AT })), { merchant: STRIPE_ISSUED.seller_details.network_business_profile, total: "900", at: "2025-07-03T12:00:00.000Z" }],
      ["Nevermined delegation", mapNeverminedCardDelegation(NEVERMINED_STRIPE, nvmOpts()), { merchant: "https://any.example", total: "9000", at: "2026-11-10T00:00:00.000Z" }],
    ];
    for (const [name, b, use] of cases) {
      const text = sign(b);
      const parsed = parseStrictJson(text) as { ok: true; value: unknown };
      expect([name, m6Check(parsed.value)]).toMatchObject([name, { ok: true, unsupported: [] }]);
      expect(m6Instruction(Buffer.from(text, "utf8"), ANNEX_A3).problem).toBeUndefined();
      const order = { merchant_id: use.merchant, merchant_order_id: "A-1", currency: "USD", total_minor: use.total, items: [{ sku: "X", quantity: 1, unit_price_minor: use.total }] };
      const e = evaluatePurchase(text, order, { kid: GATE.kid, at: use.at, usesSoFar: 0 });
      expectVocabulary(e.reasons);
      expect([name, e.reasons]).toEqual([name, []]);
    }
  });

  it("the mapped members", () => {
    const s = mapStripeSharedPaymentIssuedToken(STRIPE_ISSUED, opts({ approvedAt: STRIPE_AT }));
    expect(card(s)).toEqual({ currency: "USD", max_total_minor: "1000", merchants: [STRIPE_ISSUED.seller_details.network_business_profile] });
    expect(constraints(s)).toMatchObject({ valid_from: STRIPE_AT, valid_until: "2025-07-04T00:00:20Z", max_uses: 2 });
    expect(s["text"]).toBe(STRIPE_ISSUED.id);
    const n = mapNeverminedCardDelegation(NEVERMINED_STRIPE, nvmOpts());
    // No merchants member: the delegation names no merchant.
    expect(card(n)).toEqual({ currency: "USD", max_total_minor: "10000" });
    expect(constraints(n)).toMatchObject({ valid_from: NVM_CREATED, valid_until: "2026-11-16T00:00:00Z", max_uses: 2 });
  });

  it("Stripe: what was already captured comes off the cap; JPY is zero-decimal", () => {
    const used = { ...STRIPE_ISSUED, usage_details: { amount_captured: { value: 400, currency: "usd" } } };
    expect(card(mapStripeSharedPaymentIssuedToken(used, opts({ approvedAt: STRIPE_AT })))["max_total_minor"]).toBe("600");
    const jpy = { ...STRIPE_ISSUED, usage_details: { amount_captured: { value: 0, currency: "jpy" } }, usage_limits: { currency: "jpy", expires_at: 1751587220, max_amount: 500 } };
    expect(card(mapStripeSharedPaymentIssuedToken(jpy, opts({ approvedAt: STRIPE_AT })))).toMatchObject({ currency: "JPY", max_total_minor: "500" });
  });

  it("Stripe refusals", () => {
    const o = opts({ approvedAt: STRIPE_AT });
    const ul = STRIPE_ISSUED.usage_limits;
    expect(code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, object: "shared_payment.granted_token" }, o))).toBe("stripe-object");
    for (const status of ["deactivated", "requires_action", null, undefined]) {
      expect([status, code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, status }, o))]).toEqual([status, "stripe-status"]);
    }
    expect(code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, deactivated_at: 1751500900 }, o))).toBe("stripe-status");
    for (const max_amount of [-1, 10.5, "1000", 2 ** 60, undefined]) {
      expect([max_amount, code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, usage_limits: { ...ul, max_amount } }, o))]).toEqual([max_amount, "bad-amount"]);
    }
    // KRW: Stripe's zero-decimal list is not in the page as served, so its
    // unit is unknown and the mapper refuses rather than risk a cap 100 times
    // too high. Capital letters are not Stripe's spelling of a currency.
    for (const currency of ["krw", "USD", "xyz", 840]) {
      expect([currency, code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, usage_limits: { ...ul, currency } }, o))]).toEqual([currency, "unknown-currency"]);
    }
    expect(code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, usage_limits: null }, o))).toBe("bad-field");
    for (const expires_at of ["1751587220", 1.5, -1, undefined]) {
      expect([expires_at, code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, usage_limits: { ...ul, expires_at } }, o))]).toEqual([expires_at, "bad-time"]);
    }
    for (const seller_details of [null, {}, { external_id: null, network_business_profile: "" }]) {
      expect(code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, seller_details }, o))).toBe("bad-field");
    }
    // An unknown amount already captured is not taken as zero.
    for (const usage_details of [null, {}, { amount_captured: { value: 0, currency: "eur" } }, { amount_captured: { value: -1, currency: "usd" } }]) {
      expect(code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, usage_details }, o))).toBe("stripe-usage");
    }
    expect(code(() => mapStripeSharedPaymentIssuedToken({ ...STRIPE_ISSUED, usage_details: { amount_captured: { value: 1001, currency: "usd" } } }, o))).toBe("stripe-usage");
  });

  it("Nevermined refusals; maxTransactions omitted allows any maxUses", () => {
    expect(code(() => mapNeverminedCardDelegation({ ...NEVERMINED_STRIPE, provider: "erc4337" }, nvmOpts()))).toBe("nevermined-provider");
    expect(code(() => mapNeverminedCardDelegation(NEVERMINED_STRIPE, nvmOpts({ maxUses: 101 })))).toBe("max-uses-over-max-transactions");
    const { maxTransactions: _omitted, ...unlimited } = NEVERMINED_STRIPE;
    expect(constraints(mapNeverminedCardDelegation(unlimited, nvmOpts({ maxUses: 5000 })))["max_uses"]).toBe(5000);
    for (const maxTransactions of [0, 1.5, "100", null]) {
      expect([maxTransactions, code(() => mapNeverminedCardDelegation({ ...NEVERMINED_STRIPE, maxTransactions }, nvmOpts()))]).toEqual([maxTransactions, "bad-field"]);
    }
    for (const spendingLimitCents of [-1, 99.5, "10000", 2 ** 60, undefined]) {
      expect([spendingLimitCents, code(() => mapNeverminedCardDelegation({ ...NEVERMINED_STRIPE, spendingLimitCents }, nvmOpts()))]).toEqual([spendingLimitCents, "bad-amount"]);
    }
    // "In cents" names a two-decimal unit: a zero-decimal currency refuses.
    for (const currency of ["jpy", "krw", "USD", "xyz"]) {
      expect([currency, code(() => mapNeverminedCardDelegation({ ...NEVERMINED_STRIPE, currency }, nvmOpts()))]).toEqual([currency, "unknown-currency"]);
    }
    for (const durationSecs of [0, -1, 1.5, "604800", undefined]) {
      expect([durationSecs, code(() => mapNeverminedCardDelegation({ ...NEVERMINED_STRIPE, durationSecs }, nvmOpts()))]).toEqual([durationSecs, "bad-field"]);
    }
    expect(code(() => mapNeverminedCardDelegation(NEVERMINED_STRIPE, opts() as never))).toBe("bad-option");
    expect(code(() => mapNeverminedCardDelegation(NEVERMINED_STRIPE, nvmOpts({ createdAt: "yesterday" })))).toBe("bad-time");
  });
});
