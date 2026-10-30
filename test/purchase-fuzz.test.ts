// B-432 T1 ruling 2: check() never throws (design §4). A seeded fuzz pass
// feeds it values of every JavaScript kind (getters and proxies that throw,
// cycles, symbols, BigInt, lone surrogates, huge strings) as the input, the
// instruction and the order, and mutations of a valid instruction and order.
// Every answer must be well formed, with reasons in the frozen vocabulary, and
// the chain it wrote must verify.

import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { IDENTITY_FILENAME, runVerify } from "../src/vendor/recorder/index.js";
import { cleanupTmpDir } from "./helpers.js";
import { baseOrder, chainPathOf, checkDir, clockAt, expectVocabulary, openCheck, signedText, type Obj } from "./purchase-helpers.js";

const SEED = 0xb432;
const RUNS = 3_000;

// mulberry32: a small seeded PRNG, so a failure reproduces.
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const dirs: string[] = [];
afterAll(() => dirs.forEach(cleanupTmpDir));

describe("fuzz: check() never throws", () => {
  it(`${RUNS} seeded inputs (seed ${SEED.toString(16)}) give well-formed answers and a chain that verifies`, async () => {
    const r = rng(SEED);
    const int = (n: number) => Math.floor(r() * n);
    const pick = <T,>(xs: readonly T[]): T => xs[int(xs.length)]!;
    const text = signedText();
    const throwing = () => {
      throw new Error("boom");
    };

    const str = (): string => {
      const kinds = [
        () => "",
        () => "\uD800",
        () => "a\uDC00b",
        () => "x".repeat(int(5) === 0 ? 300_000 : int(300)),
        () => String.fromCharCode(...Array.from({ length: int(40) }, () => int(0x10000))),
        () => "4111 1111 1111 1111",
        () => "guest@example.com",
        () => "﻿{}",
        () => text,
        () => text.slice(0, int(text.length)),
      ];
      return pick(kinds)();
    };
    const value = (depth: number): unknown => {
      const kinds: (() => unknown)[] = [
        () => undefined,
        () => null,
        () => r() < 0.5,
        () => pick([0, -0, 1.5, NaN, Infinity, -Infinity, 2 ** 60, -1, Number.MAX_SAFE_INTEGER + 2]),
        () => BigInt(int(1e9)) * 10n ** 20n,
        () => Symbol("s"),
        () => () => 1,
        () => str(),
        () => new Date(0),
        () => new Map([[1, 2]]),
        () => new Uint8Array(3),
        () => Object.create({ inherited: 1 }),
        () => {
          const o: Obj = { a: 1 };
          o["self"] = o;
          return o;
        },
        () => Object.defineProperty({}, "merchant_id", { get: throwing, enumerable: true }),
        () => new Proxy({}, { get: throwing, ownKeys: throwing, getOwnPropertyDescriptor: throwing, getPrototypeOf: throwing, has: throwing }),
        () => new Proxy([], { get: throwing, ownKeys: throwing, getPrototypeOf: throwing }),
        () => ({ [Symbol("k")]: 1, toJSON: throwing }),
        () => (depth > 3 ? null : Array.from({ length: int(4) }, () => value(depth + 1))),
        () => {
          const a: unknown[] = [];
          a[3] = 1;
          return a;
        },
        () => (depth > 3 ? null : Object.fromEntries(Array.from({ length: int(4) }, () => [str().slice(0, 20), value(depth + 1)]))),
      ];
      return pick(kinds)();
    };
    // A valid order with one member deleted or replaced by a random value.
    const mutatedOrder = (): unknown => {
      const o = baseOrder();
      const it = (o["items"] as Obj[])[0]!;
      const target = r() < 0.5 ? o : it;
      const keys = Object.keys(target);
      const k = r() < 0.2 ? str().slice(0, 10) : pick(keys);
      if (r() < 0.3) delete target[k];
      else target[k] = value(1);
      return o;
    };
    // A valid instruction text with bytes changed, cut or doubled.
    const mutatedText = (): unknown => {
      const t = text;
      const i = int(t.length);
      return pick([
        () => t.slice(0, i) + String.fromCharCode(int(0x10000)) + t.slice(i + 1),
        () => t.slice(0, i),
        () => t.slice(0, i) + t.slice(i, i + 20) + t.slice(i),
        () => t.replace(/"max_uses":1/, `"max_uses":${pick(["0", "1.0", "1e1", "-1", "9007199254740993", "true", "null"])}`),
        () => t.replace(/"currency":"EUR"/, `"currency":${pick(['"eur"', "1", '"EUR","currency":"USD"'])}`),
        () => t,
      ])();
    };
    const input = (): unknown =>
      pick([
        () => value(0),
        () => ({ instruction: value(0), order: value(0) }),
        () => ({ instruction: mutatedText(), order: mutatedOrder() }),
        () => ({ instruction: text, order: mutatedOrder() }),
        () => ({ instruction: mutatedText(), order: baseOrder() }),
        () => Object.defineProperty({ order: baseOrder() }, "instruction", { get: throwing, enumerable: true }),
        () => new Proxy({ instruction: text, order: baseOrder() }, { getOwnPropertyDescriptor: throwing }),
      ])();

    const dir = checkDir();
    dirs.push(dir);
    const pc = openCheck(dir, clockAt());
    const seen = { allow: 0, deny: 0, receipts: 0 };
    for (let n = 0; n < RUNS; n++) {
      const x = input();
      let res;
      try {
        res = pc.check(x as never);
      } catch (e) {
        throw new Error(`run ${n}: check threw ${(e as Error).message}`);
      }
      expect(["allow", "deny"]).toContain(res.decision);
      expect(Array.isArray(res.reasons) && res.reasons.every((s) => typeof s === "string")).toBe(true);
      expectVocabulary(res.reasons);
      expect(res.decision === "allow").toBe(res.reasons.length === 0);
      if (res.decision === "allow") expect(res.receipt).not.toBeNull();
      expect(typeof res.repeat).toBe("boolean");
      seen[res.decision]++;
      if (res.receipt !== null && !res.repeat) seen.receipts++;
    }
    await pc.close();
    // The pass reached the record path, both answers, and not only step 1.
    expect(seen.allow).toBeGreaterThan(0);
    expect(seen.deny).toBeGreaterThan(0);
    expect(seen.receipts).toBeGreaterThan(10);
    expect(runVerify({ chainPath: chainPathOf(dir, pc.session_id), identityPath: join(dir, IDENTITY_FILENAME) })).toMatchObject({ kind: "valid", count: seen.receipts });
  }, 120_000);
});
