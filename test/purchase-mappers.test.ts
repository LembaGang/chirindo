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
