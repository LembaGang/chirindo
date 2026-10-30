// B-432 test 2, reasons (design §4.2 and §8.2): a fixed set of vectors, each
// with its exact `reasons` array in order, through evaluatePurchase. Step 1
// reasons stand alone; step 2 reasons stand alone; step 3 lists every failure
// in the order not-yet-valid, expired, agent-not-named, uses-exhausted, then
// the nine card limits in CARD_LIMITS order.

import { describe, expect, it } from "vitest";
import { evaluatePurchase, judgePurchase } from "../src/purchase/limits.js";
import { AT, GATE, STRANGER, cardOf, constraintsOf, itemOf, order, signedText, type Obj } from "./purchase-helpers.js";

const run = (text: unknown, ord: unknown, at = AT, usesSoFar = 0) => evaluatePurchase(text, ord, { kid: GATE.kid, at, usesSoFar });
const tampered = () => {
  const o = JSON.parse(signedText()) as Obj;
  o["text"] = "anything";
  return JSON.stringify(o);
};

interface Case {
  name: string;
  text: unknown;
  order: unknown;
  at?: string;
  uses?: number;
  reasons: string[];
  exceeded?: string[];
}

const cases: Case[] = [
  { name: "allow", text: signedText(), order: order(), reasons: [], exceeded: [] },
  // Step 1: the instruction and the order are both read; each failure is a reason.
  { name: "a parsed object, and no order", text: { v: "x" }, order: undefined, reasons: ["instruction-invalid:not-a-string", "order-invalid:/order"] },
  { name: "not JSON", text: "{", order: order(), reasons: ["instruction-invalid:syntax"] },
  { name: "over 64 KB", text: signedText((b) => (b["text"] = "x".repeat(70_000))), order: order(), reasons: ["instruction-invalid:too-large"] },
  { name: "an order item quantity of 0", text: signedText(), order: order((o) => (itemOf(o)["quantity"] = 0)), reasons: ["order-invalid:/order/items/0/quantity"] },
  { name: "a fractional quantity", text: signedText(), order: order((o) => (itemOf(o)["quantity"] = 1.5)), reasons: ["order-invalid:/order/items/0/quantity"] },
  { name: "an order member the committed order lacks", text: signedText(), order: order((o) => (o["tip"] = "1")), reasons: ["order-invalid:/order/tip"] },
  {
    name: "two screened fields",
    text: signedText(),
    order: order((o) => ((itemOf(o)["name"] = "4111-1111-1111-1111"), (itemOf(o)["location"] = "a@b.example"))),
    reasons: ["order-invalid:/order/items/0/name", "order-invalid:/order/items/0/location"],
  },
  {
    name: "two lone surrogates in the order, and a broken instruction",
    text: "[",
    order: order((o) => ((o["merchant_order_id"] = "H\uD800"), (itemOf(o)["name"] = "\uDC00"))),
    reasons: ["instruction-invalid:syntax", "order-invalid:/order/merchant_order_id", "order-invalid:/order/items/0/name"],
  },
  { name: "a getter in the order", text: signedText(), order: order((o) => Object.defineProperty(o, "currency", { get: () => "EUR", enumerable: true })), reasons: ["order-invalid:/order/currency"] },
  // A step 1 failure hides step 2 and step 3.
  { name: "an invalid order and a bad signature", text: tampered(), order: order((o) => delete o["currency"]), reasons: ["order-invalid:/order/currency"] },
  // Step 2: the profile.
  { name: "bad signature", text: tampered(), order: order(), reasons: ["instruction-invalid:bad-signature"] },
  { name: "not an object", text: '"text"', order: order(), reasons: ["instruction-invalid:not-an-object"] },
  { name: "a card with nothing but currency", text: signedText((b) => (constraintsOf(b)["card"] = { currency: "EUR" })), order: order(), reasons: ["instruction-invalid:card-limits-empty"] },
  { name: "max_uses 0", text: signedText((b) => (constraintsOf(b)["max_uses"] = 0)), order: order(), reasons: ["instruction-invalid:bad-value:/constraints/max_uses"] },
  {
    name: "valid_from after valid_until",
    text: signedText((b) => Object.assign(constraintsOf(b), { valid_from: "2026-11-30T00:00:00Z", valid_until: "2026-11-01T00:00:00Z" })),
    order: order(),
    reasons: ["instruction-invalid:window-reversed"],
  },
  { name: "a time with an offset", text: signedText((b) => (b["iat"] = "2026-10-30T00:00:00+02:00")), order: order(), reasons: ["instruction-invalid:time-not-z"] },
  { name: "a missing constraints member", text: signedText((b) => delete constraintsOf(b)["valid_until"]), order: order(), reasons: ["instruction-invalid:missing-member:/constraints/valid_until"] },
  {
    name: "every unsupported limit, and a non-calendar time",
    text: signedText((b) => {
      Object.assign(constraintsOf(b), { chain_id: "eip155:8453", asset: "native", max_amount: "1", payees: ["0x" + "22".repeat(20)], budget: "1" });
      b["iat"] = "2026-10-30T24:00:00Z";
    }),
    order: order(),
    reasons: [
      "unsupported-limit:chain_id",
      "unsupported-limit:asset",
      "unsupported-limit:max_amount",
      "unsupported-limit:payees",
      "unsupported-limit:budget",
      "instruction-invalid:time-not-calendar",
    ],
  },
  // Step 3: every failure, in order.
  {
    name: "before the window, agent not named, uses exhausted, over the cap, a location missing",
    text: signedText((b) => (b["agent_kid"] = [STRANGER.kid])),
    order: order((o) => ((o["total_minor"] = "30001"), delete itemOf(o)["location"])),
    at: "2026-10-31T00:00:00.000Z",
    uses: 1,
    reasons: ["not-yet-valid", "agent-not-named", "uses-exhausted", "limit-exceeded:max_total_minor", "order-field-missing:locations"],
    exceeded: ["valid_from", "agent_kid", "max_uses", "max_total_minor"],
  },
  {
    name: "after the window, every card limit outside",
    text: signedText(),
    order: order((o) => {
      Object.assign(o, { merchant_id: "x.example", currency: "USD", total_minor: "90000" });
      Object.assign(itemOf(o), { sku: "X", unit_price_minor: "90000", category: "x", refundable: false, service_until: "2026-12-31", location: "x" });
    }),
    at: "2026-12-01T00:00:00.000Z",
    reasons: [
      "expired",
      "limit-exceeded:currency",
      "limit-exceeded:max_total_minor",
      "limit-exceeded:max_unit_price_minor",
      "limit-exceeded:merchants",
      "limit-exceeded:items",
      "limit-exceeded:categories",
      "limit-exceeded:refundable_only",
      "limit-exceeded:service_window",
      "limit-exceeded:locations",
    ],
    exceeded: ["valid_until", "currency", "max_total_minor", "max_unit_price_minor", "merchants", "items", "categories", "refundable_only", "service_window", "locations"],
  },
  {
    name: "a limit outside beside a field missing",
    text: signedText(),
    order: order((o) => ((itemOf(o)["sku"] = "SUITE"), delete itemOf(o)["category"])),
    reasons: ["limit-exceeded:items", "order-field-missing:categories"],
    exceeded: ["items"],
  },
  {
    name: "refundable_only false limits nothing",
    text: signedText((b) => (cardOf(b)["refundable_only"] = false)),
    order: order((o) => (itemOf(o)["refundable"] = false)),
    reasons: [],
    exceeded: [],
  },
];

describe("reasons: exact arrays, in order", () => {
  for (const c of cases) {
    it(c.name, () => {
      const e = run(c.text, c.order, c.at, c.uses);
      expect(e.reasons).toEqual(c.reasons);
      expect(e.decision).toBe(c.reasons.length === 0 ? "allow" : "deny");
      if (c.exceeded !== undefined) expect(e.exceeded).toEqual(c.exceeded);
    });
  }
});

describe("the judge's steps and digests", () => {
  it("step 1 carries no digest; step 2 the JCS digest of the parsed text; step 3 the M6 digest", () => {
    const s1 = judgePurchase("{", order(), { kid: GATE.kid, at: AT, usesSoFar: 0 });
    expect([s1.step, s1.instruction_sha256, s1.card_limits]).toEqual([1, null, []]);
    const s2 = judgePurchase(tampered(), order(), { kid: GATE.kid, at: AT, usesSoFar: 0 });
    expect(s2.step).toBe(2);
    expect(s2.instruction_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    const s3 = judgePurchase(signedText(), order(), { kid: GATE.kid, at: AT, usesSoFar: 0 });
    expect(s3.step).toBe(3);
    expect(s3.instruction_sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(s3.instruction_sha256).not.toBe(s2.instruction_sha256);
  });

  it("the order judged is a copy: a later change to the caller's object does not reach it", () => {
    const ord = order();
    const j = judgePurchase(signedText(), ord, { kid: GATE.kid, at: AT, usesSoFar: 0 });
    itemOf(ord)["sku"] = "CHANGED";
    expect(itemOf(j.order!)["sku"]).toBe("ROOM");
  });

  it("invalid options throw; nothing else does", () => {
    const ok = { kid: GATE.kid, at: AT, usesSoFar: 0 };
    for (const bad of [{ ...ok, kid: "" }, { ...ok, at: "2026-11-05T12:00:00+00:00" }, { ...ok, at: "2026-02-30T00:00:00Z" }, { ...ok, at: "2026-11-05T12:00:00.0000000001Z" }, { ...ok, usesSoFar: -1 }, { ...ok, usesSoFar: 0.5 }]) {
      expect(() => evaluatePurchase(signedText(), order(), bad)).toThrow(TypeError);
    }
    for (const junk of [null, 42, [], new Map(), Symbol("x")]) {
      expect(evaluatePurchase(junk, junk, ok).decision).toBe("deny");
    }
  });
});
