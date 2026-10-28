// D3(g): the recorder's order rules (TypeScript) agree with orderProblem in
// examples/evidence-bundle/lib/card.mjs at the verdict, accept or refuse, on
// the four page orders and on malformed orders for every refusal branch and
// every member of each of its loops. The package never imports examples/; only
// this test does, and card.mjs needs nothing outside node: (formats.mjs,
// table.mjs).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { createTrialRecorder } from "../src/trial/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { newDataDir, ROOT } from "./trial-helpers.js";
// @ts-expect-error -- plain .mjs without declarations; it is the reference being compared against
import { orderProblem } from "../examples/evidence-bundle/lib/card.mjs";

type Obj = Record<string, unknown>;
const problem = orderProblem as (o: unknown) => string | null;

const { dir } = newDataDir();
const rec = createTrialRecorder({ dir, serverLabel: "parity", logger: () => {} });
afterAll(async () => {
  await rec.close(500);
  cleanupTmpDir(dir);
});
let n = 0;
const recorderAccepts = (order: unknown) => {
  const r = rec.record({ order_ref: `P-${n++}`, order } as never);
  return { ok: r.ok, reason: r.ok ? null : r.reason };
};

function pageOrders(): { page: string; order: Obj }[] {
  return ["we-4-1", "we-4-2", "we-5-1", "we-5-2"].map((page) => {
    const b = JSON.parse(readFileSync(join(ROOT, "examples", "evidence-bundle", "pages", `${page}.bundle.json`), "utf8")) as { members: Obj[] };
    const m = b.members.find((x) => x["id"] === "args-d")!;
    const args = JSON.parse(Buffer.from(String(m["bytes_b64"]), "base64").toString("utf8")) as Obj;
    return { page, order: args["order"] as Obj };
  });
}

const base = (): Obj => ({
  merchant_id: "hotel.example",
  merchant_order_id: "H-1",
  checkout_ref: "CK-1",
  currency: "EUR",
  total_minor: "28000",
  items: [{ sku: "ROOM", quantity: 2, unit_price_minor: "14000", name: "Room", category: "lodging", refundable: true, service_from: "2026-11-10", service_until: "2026-11-12", location: "Lisbon" }],
});
const withOrder = (patch: Obj): Obj => ({ ...base(), ...patch });
const without = (k: string): Obj => {
  const o = base();
  delete o[k];
  return o;
};
const withItem = (patch: Obj): Obj => ({ ...base(), items: [{ ...((base()["items"] as Obj[])[0]!), ...patch }] });
const withoutItem = (k: string): Obj => {
  const it = { ...((base()["items"] as Obj[])[0]!) };
  delete it[k];
  return { ...base(), items: [it] };
};

const ORDER_MEMBERS = ["merchant_id", "merchant_order_id", "checkout_ref", "currency", "total_minor", "items"];
const ITEM_MEMBERS = ["sku", "quantity", "unit_price_minor", "name", "category", "refundable", "service_from", "service_until", "location"];
const long = "x".repeat(257);

// Malformed orders, by orderProblem's refusal branch (in its source order).
const BRANCHES: { branch: number; name: string; order: unknown }[] = [
  { branch: 1, name: "not an object: string", order: "order" },
  { branch: 1, name: "not an object: array", order: [] },
  { branch: 1, name: "not an object: null", order: null },
  { branch: 2, name: "unknown order member", order: withOrder({ note: "x" }) },
  { branch: 3, name: "merchant_id missing", order: without("merchant_id") },
  { branch: 3, name: "merchant_id empty", order: withOrder({ merchant_id: "" }) },
  { branch: 3, name: "merchant_id 257", order: withOrder({ merchant_id: long }) },
  { branch: 4, name: "neither reference", order: (() => { const o = without("merchant_order_id"); delete o["checkout_ref"]; return o; })() },
  { branch: 5, name: "merchant_order_id not printable", order: withOrder({ merchant_order_id: "Hé" }) },
  { branch: 5, name: "checkout_ref not printable", order: withOrder({ checkout_ref: "C\tK" }) },
  { branch: 5, name: "merchant_order_id empty", order: withOrder({ merchant_order_id: "" }) },
  { branch: 5, name: "checkout_ref 257", order: withOrder({ checkout_ref: long }) },
  { branch: 6, name: "currency lower case", order: withOrder({ currency: "eur" }) },
  { branch: 7, name: "total_minor leading zero", order: withOrder({ total_minor: "028000" }) },
  { branch: 7, name: "total_minor number", order: withOrder({ total_minor: 28000 }) },
  { branch: 8, name: "items empty", order: withOrder({ items: [] }) },
  { branch: 8, name: "items not a list", order: withOrder({ items: "ROOM" }) },
  { branch: 9, name: "item not an object", order: withOrder({ items: ["ROOM"] }) },
  { branch: 10, name: "unknown item member", order: withItem({ colour: "red" }) },
  { branch: 11, name: "item lacks sku", order: withoutItem("sku") },
  { branch: 11, name: "item lacks quantity", order: withoutItem("quantity") },
  { branch: 11, name: "item lacks unit_price_minor", order: withoutItem("unit_price_minor") },
  { branch: 12, name: "sku empty", order: withItem({ sku: "" }) },
  { branch: 13, name: "quantity 0", order: withItem({ quantity: 0 }) },
  { branch: 13, name: "quantity 1.5", order: withItem({ quantity: 1.5 }) },
  { branch: 13, name: "quantity string", order: withItem({ quantity: "2" }) },
  { branch: 14, name: "unit_price_minor signed", order: withItem({ unit_price_minor: "-1" }) },
  { branch: 15, name: "name not a string", order: withItem({ name: 5 }) },
  { branch: 16, name: "category empty", order: withItem({ category: "" }) },
  { branch: 16, name: "location 257", order: withItem({ location: long }) },
  { branch: 17, name: "refundable not boolean", order: withItem({ refundable: "yes" }) },
  { branch: 18, name: "service_from not a day", order: withItem({ service_from: "2026-02-30" }) },
  { branch: 18, name: "service_until not a date", order: withItem({ service_until: "12/11/2026" }) },
  { branch: 19, name: "service_from after service_until", order: withItem({ service_from: "2026-11-13" }) },
];
// Each member of each loop, given a value of the wrong type (an object).
const LOOP_CASES: { name: string; order: unknown }[] = [
  ...ORDER_MEMBERS.map((k) => ({ name: `order.${k} an object`, order: withOrder({ [k]: { v: 1 } }) })),
  ...ITEM_MEMBERS.map((k) => ({ name: `item.${k} an object`, order: withItem({ [k]: { v: 1 } }) })),
];
const MORE_ACCEPTED: { name: string; order: unknown }[] = [
  { name: "base", order: base() },
  { name: "checkout_ref only", order: without("merchant_order_id") },
  { name: "same-day service", order: withItem({ service_until: "2026-11-10" }) },
  { name: "empty name", order: withItem({ name: "" }) },
  { name: "name of 256", order: withItem({ name: "n".repeat(256) }) },
  { name: "minimal item", order: withOrder({ items: [{ sku: "A", quantity: 1, unit_price_minor: "0" }] }) },
];

describe("trial recorder: order rules equal orderProblem at the verdict", () => {
  it("(g) the four page orders are accepted by both", () => {
    const pages = pageOrders();
    expect(pages).toHaveLength(4);
    for (const { page, order } of pages) {
      expect(problem(order), page).toBeNull();
      expect(recorderAccepts(order), page).toEqual({ ok: true, reason: null });
    }
  });

  it("(g) at least one malformed order per refusal branch, and each member of each loop, is refused by both", () => {
    const covered = new Set(BRANCHES.map((b) => b.branch));
    console.log(`D3(g) orderProblem refusal branches covered: ${covered.size}; malformed cases: ${BRANCHES.length + LOOP_CASES.length}`);
    expect([...covered].sort((a, b) => a - b)).toEqual(Array.from({ length: 19 }, (_, i) => i + 1));
    for (const c of [...BRANCHES, ...LOOP_CASES]) {
      expect(problem(c.order), c.name).not.toBeNull();
      const r = recorderAccepts(c.order);
      expect(r.ok, c.name).toBe(false);
      expect(["invalid-order", "refused-field"], c.name).toContain(r.reason);
    }
  });

  it("(g) further well-formed orders are accepted by both", () => {
    for (const c of MORE_ACCEPTED) {
      expect(problem(c.order), c.name).toBeNull();
      expect(recorderAccepts(c.order), c.name).toEqual({ ok: true, reason: null });
    }
  });

  it("an item name over 256 characters is refused by the recorder only (its cap; orderProblem has none)", () => {
    const order = withItem({ name: "n".repeat(257) });
    expect(problem(order)).toBeNull();
    expect(recorderAccepts(order)).toEqual({ ok: false, reason: "invalid-order" });
  });
});
