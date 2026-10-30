// B-432 T4: the README's purchase-check section, held by machine (design §8
// rule 5). It must have the claim of design rev 3 §9 word for word, limits 1,
// 2, 4, 5 and 6 directly beside it and only those, the full list 1 to 10, the
// mapper disclaimer, and none of B-419's words. B-331: it names no network.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ROOT } from "./trial-helpers.js";

const CLAIM =
  "Before you charge, Chirindo checks each purchase against the instruction you signed for your customer, refuses one outside it, and keeps a signed, chained record of each decision it makes and its reason.";
const LIMITS: Record<number, string> = {
  1: "1. It checks only purchases the provider sends through it. A purchase made around it is not checked, and a deny binds only if the provider obeys it. A repeat allow is not a second purchase.",
  2: "2. The instruction is signed by the provider, stating what its customer approved. Chirindo does not see or verify the customer's approval. The provider also holds the gate key. The record is the provider's own signed, chained record, with checkpoints sent to Headless Oracle's witness.",
  3: "3. The description is carried and signed over, not checked. The v0.1 mappers set no item or category limits.",
  4: "4. Spend is not summed across purchases. Each purchase is checked against the cap and uses are counted, so an instruction allows up to max_uses purchases, each up to the cap. Counts are shared only within one directory and one process.",
  5: "5. The order is what the caller states. The cap is judged on its stated total, and Chirindo does not see the charge. Only an after-the-fact comparison with the charge shows a mismatch (L24).",
  6: "6. These leave no receipt: input refused at step 1, record-failed, and a repeat (it returns the earlier receipt). `evaluatePurchase` is a dry run, not a record.",
  7: "7. Today's evidence-bundle verifier does not read `check`. In a bundle a deny shows only as a record that cites no instruction; its reason is read from the receipt itself. A verifier update is noted for B-420.",
  8: "8. The witness is Headless Oracle's own, not independent (L3).",
  9: "9. The MCP gate does not check purchases (v0.2).",
  10: "10. A later evidence bundle judges the instruction's time window at the charge's authorization time, as the processor states it, not at the time of the check. A charge authorized after valid_until shows as outside the instruction, even when the check allowed it in time.",
};
const MAPPER_DISCLAIMER = "The mappers follow each provider's public documentation as read on 30 Oct 2026; no provider has reviewed or endorsed them.";

const readme = readFileSync(join(ROOT, "README.md"), "utf8").replace(/\r\n/g, "\n");
const section = readme.slice(readme.indexOf("## Purchase check (before you charge)"), readme.indexOf("## Getting started"));

describe("README: Purchase check (before you charge)", () => {
  it("exists, before Getting started", () => {
    expect(readme.indexOf("## Purchase check (before you charge)")).toBeGreaterThan(0);
    expect(section.length).toBeGreaterThan(1000);
  });

  it("has the claim word for word, with limits 1, 2, 4, 5 and 6 directly beside it and no other", () => {
    expect(section).toContain(`> ${CLAIM}`);
    const beside = section.slice(section.indexOf(`> ${CLAIM}`), section.indexOf("The full list"));
    for (const n of [1, 2, 4, 5, 6]) expect([n, beside.includes(LIMITS[n]!)]).toEqual([n, true]);
    for (const n of [3, 7, 8, 9, 10]) expect([n, beside.includes(LIMITS[n]!)]).toEqual([n, false]);
  });

  it("has the full list, limits 1 to 10, after the claim", () => {
    const full = section.slice(section.indexOf("The full list"));
    for (let n = 1; n <= 10; n++) expect([n, full.includes(LIMITS[n]!)]).toEqual([n, true]);
  });

  it("has the stale-lock instruction, the vocabulary pointer and the mapper disclaimer", () => {
    expect(section).toContain("purchase-chains/.lock");
    expect(section).toContain("then remove that file");
    expect(section).toContain("docs/purchase-check-reasons.md");
    expect(section).toContain(MAPPER_DISCLAIMER);
  });

  it("uses none of B-419's words and names no network (B-331)", () => {
    for (const w of [/guarantee/i, /proves the purchase/i, /independent witness/i, /compliant/i, /certified/i, /\bvisa\b/i, /mastercard/i, /google/i]) {
      expect([String(w), w.test(section)]).toEqual([String(w), false]);
    }
  });
});
