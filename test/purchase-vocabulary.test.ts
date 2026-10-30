// B-432 T1 ruling 3: the frozen reason vocabulary. The patterns are disjoint,
// docs/purchase-check-reasons.md publishes exactly them, and a corpus run
// through createPurchaseCheck produces every pattern at least once, each
// reason matching exactly one. (Every reason that tests 1 to 7 and the fuzz
// pass see is also held to exactly one pattern, where they see it, by
// expectVocabulary in test/purchase-helpers.ts.)

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { CARD_LIMITS, UNSUPPORTED_LIMITS } from "../src/purchase/m6.js";
import { PURCHASE_CHECK_VERSION } from "../src/purchase/member.js";
import { INSTRUCTION_PROBLEMS, PURCHASE_REASON_PATTERNS, reasonPatterns, type ReasonPattern } from "../src/purchase/reasons.js";
import { cleanupTmpDir } from "./helpers.js";
import { STRANGER, checkDir, checked, clockAt, constraintsOf, itemOf, openCheck, order, signedText, type Obj } from "./purchase-helpers.js";
import { ROOT } from "./trial-helpers.js";

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));

describe("the vocabulary of purchase-check/0.1", () => {
  it("has fifteen patterns with distinct prefixes, and the version is purchase-check/0.1", () => {
    expect(PURCHASE_CHECK_VERSION).toBe("purchase-check/0.1");
    expect(PURCHASE_REASON_PATTERNS).toHaveLength(15);
    expect(new Set(PURCHASE_REASON_PATTERNS.map((p) => p.prefix)).size).toBe(15);
    expect(PURCHASE_REASON_PATTERNS.find((p) => p.prefix === "unsupported-limit:")!.words).toEqual(UNSUPPORTED_LIMITS);
    for (const p of PURCHASE_REASON_PATTERNS.filter((x) => x.suffix === "card-limit")) expect(p.words).toEqual(CARD_LIMITS);
  });

  it("docs/purchase-check-reasons.md lists the version, every prefix with its suffix, and every word", () => {
    const doc = readFileSync(join(ROOT, "docs", "purchase-check-reasons.md"), "utf8");
    expect(doc).toContain("`purchase-check/0.1`");
    const rows = doc.split("\n").filter((l) => l.startsWith("| `"));
    for (const p of PURCHASE_REASON_PATTERNS) {
      const row = rows.find((l) => l.startsWith(`| \`${p.prefix}\` |`));
      expect([p.prefix, row !== undefined]).toEqual([p.prefix, true]);
      expect(row!.split("|")[2]!.trim().startsWith(p.suffix)).toBe(true);
      if (p.suffix === "word") for (const w of p.words) expect(row).toContain(`\`${w}\``);
    }
    for (const w of INSTRUCTION_PROBLEMS) expect(doc).toContain(`| \`${w}\` |`);
    // No row names a prefix the code does not have.
    const prefixes = rows.map((l) => l.split("`")[1]!).filter((x) => !INSTRUCTION_PROBLEMS.includes(x as never));
    expect(new Set(prefixes)).toEqual(new Set(PURCHASE_REASON_PATTERNS.map((p) => p.prefix)));
  });

  it("near misses match no pattern", () => {
    for (const s of [
      "",
      "expired:",
      "record-failed ",
      "Expired",
      "limit-exceeded:budget",
      "order-field-missing:",
      "unsupported-limit:currency",
      "instruction-invalid:",
      "instruction-invalid:not-utf8",
      "instruction-invalid:bad-value:",
      "instruction-invalid:bad-value:constraints",
      "order-invalid:",
      "order-invalid:/order/items/0/na me",
      "order-invalid:/" + "a".repeat(128),
    ]) {
      expect([s, reasonPatterns(s)]).toEqual([s, []]);
    }
  });

  it("a corpus through createPurchaseCheck produces every pattern, each reason matching exactly one", async () => {
    const dir = checkDir();
    dirs.push(dir);
    const clock = clockAt();
    let clockFails = false;
    const pc = openCheck(dir, {
      now: () => {
        if (clockFails) throw new Error("clock");
        return clock.t;
      },
    });
    const produced: string[] = [];
    const run = (ins: unknown, ord: unknown) => produced.push(...checked(pc, ins, ord).reasons);
    const ref = (id: string) => order((o) => (o["merchant_order_id"] = id));

    // First, as the clock may not run backwards more than 5 s.
    clock.t = "2026-10-31T00:00:00.000Z";
    run(signedText(), ref("V-6")); // not-yet-valid
    clock.t = "2026-11-05T12:00:00.000Z";
    run("{", order());
    run(signedText((b) => (b["principal"] = "x")), order());
    run(signedText((b) => delete constraintsOf(b)["valid_until"]), order());
    run(signedText((b) => (b["note"] = 1)), order());
    run(signedText((b) => (constraintsOf(b)["max_uses"] = 0)), order());
    run(signedText(), order((o) => (itemOf(o)["quantity"] = 0)));
    run(signedText((b) => (constraintsOf(b)["budget"] = "1")), order());
    run(signedText((b) => (b["agent_kid"] = [STRANGER.kid])), ref("V-1"));
    run(signedText(), order((o) => ((o["total_minor"] = "30001"), (o["merchant_order_id"] = "V-2"))));
    run(signedText(), order((o) => (delete itemOf(o)["category"], (o["merchant_order_id"] = "V-3"))));
    run(signedText(), ref("V-4")); // allow: spends max_uses 1
    run(signedText(), order((o) => ((o["merchant_order_id"] = "V-4"), (o["total_minor"] = "27000")))); // order-ref-reused
    run(signedText(), ref("V-5")); // uses-exhausted
    clock.t = "2026-12-01T00:00:00.000Z";
    run(signedText(), ref("V-7")); // expired
    clockFails = true;
    run(signedText(), ref("V-8")); // record-failed
    await pc.close();

    const hit = new Set<ReasonPattern>();
    for (const reason of produced) {
      const ps = reasonPatterns(reason);
      expect([reason, ps.length]).toEqual([reason, 1]);
      hit.add(ps[0]!);
    }
    const missing = PURCHASE_REASON_PATTERNS.filter((p) => !hit.has(p)).map((p) => p.prefix);
    expect(missing).toEqual([]);
    expect((produced as unknown as Obj[]).length).toBeGreaterThanOrEqual(15);
  });
});
