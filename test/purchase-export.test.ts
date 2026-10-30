// B-432 T4: the `./purchase-check` package export, imported from the built
// dist. The test builds dist/ (tsconfig.build.json, as `npm run build` does),
// then a separate Node process imports `@headlessoracle/chirindo/purchase-check`
// by package name, through the exports map, and runs evaluatePurchase from it.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { GATE, order, signedText } from "./purchase-helpers.js";
import { ROOT } from "./trial-helpers.js";

describe("the ./purchase-check export", () => {
  it("resolves from the built dist and works", () => {
    const build = spawnSync(process.execPath, [join(ROOT, "node_modules", "typescript", "bin", "tsc"), "-p", "tsconfig.build.json"], { cwd: ROOT, encoding: "utf8", timeout: 180_000 });
    expect(build.status, build.stdout + build.stderr).toBe(0);
    expect(existsSync(join(ROOT, "dist", "purchase", "index.js"))).toBe(true);
    expect(existsSync(join(ROOT, "dist", "purchase", "index.d.ts"))).toBe(true);

    const program = `
      const m = await import("@headlessoracle/chirindo/purchase-check");
      const [text, order, kid] = JSON.parse(process.argv[1]);
      const e = m.evaluatePurchase(text, order, { kid, at: "2026-11-05T12:00:00.000Z", usesSoFar: 0 });
      console.log(JSON.stringify({
        names: Object.keys(m).sort(),
        version: m.PURCHASE_CHECK_VERSION,
        origin: m.merchantIdOf("https://shop.example/cart"),
        decision: e.decision,
        resolved: import.meta.resolve("@headlessoracle/chirindo/purchase-check"),
      }));`;
    const run = spawnSync(process.execPath, ["--input-type=module", "-e", program, JSON.stringify([signedText(), order(), GATE.kid])], { cwd: ROOT, encoding: "utf8", timeout: 60_000 });
    expect(run.status, run.stderr).toBe(0);
    const out = JSON.parse(run.stdout.trim()) as { names: string[]; version: string; origin: string; decision: string; resolved: string };
    expect(out.resolved.replace(/\\/g, "/")).toMatch(/\/dist\/purchase\/index\.js$/);
    expect(out.version).toBe("purchase-check/0.1");
    expect(out.origin).toBe("https://shop.example");
    expect(out.decision).toBe("allow");
    expect(out.names).toEqual(
      [
        "CURRENCY_EXPONENTS",
        "MapperError",
        "PURCHASE_CHECK_VERSION",
        "PURCHASE_REASON_PATTERNS",
        "createPurchaseCheck",
        "createPurchaseServer",
        "evaluatePurchase",
        "mapBasisTheoryAllowance",
        "mapCrossmintOrderIntent",
        "mapPravaMandate",
        "merchantIdOf",
        "reasonPatterns",
        "signInstruction",
        "toMinorUnits",
        "toZ",
      ].sort(),
    );
  }, 240_000);
});
