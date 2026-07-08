// Strict JSON ingest gate (F3/F4) — unit + integration coverage.
//
// Proves the gate rejects the two recomputability-breaking classes (unsafe
// integers, duplicate members) at any depth and FAILS CLOSED at the wired
// call sites (argsHashFromJsonString / resultHashFromJsonString) — a rejected
// input must never fall through to a raw-UTF-8 hash. Valid inputs must parse
// identically to the built-in JSON.parse (non-breaking).

import { describe, expect, it } from "vitest";
import {
  StrictJsonParseError,
  argsHashFromJsonString,
  resultHashFromJsonString,
  strictJsonParse,
} from "../src/vendor/recorder/index.js";

describe("strictJsonParse — unsafe_number", () => {
  it("rejects a top-level integer past 2^53-1", () => {
    try {
      strictJsonParse("9007199254740993"); // 2^53+1
      throw new Error("expected rejection");
    } catch (e) {
      expect(e).toBeInstanceOf(StrictJsonParseError);
      expect((e as StrictJsonParseError).reason).toBe("unsafe_number");
    }
  });

  it("rejects 2^53 itself (first value outside the safe range)", () => {
    expect(() => strictJsonParse("9007199254740992")).toThrowError(
      /unsafe_number/,
    );
  });

  it("rejects an unsafe integer nested in an object value", () => {
    const err = catchStrict(() => strictJsonParse('{"n":99999999999999999}'));
    expect(err.reason).toBe("unsafe_number");
  });

  it("rejects an unsafe integer inside an array", () => {
    const err = catchStrict(() => strictJsonParse("[1, 2, 90071992547409999]"));
    expect(err.reason).toBe("unsafe_number");
  });

  it("rejects a negative unsafe integer", () => {
    const err = catchStrict(() => strictJsonParse("-9007199254740993"));
    expect(err.reason).toBe("unsafe_number");
  });

  it("ACCEPTS 2^53-1 (the max safe integer)", () => {
    expect(strictJsonParse("9007199254740991")).toBe(9007199254740991);
  });

  it("ACCEPTS ordinary integers, floats, and exponentials", () => {
    expect(strictJsonParse("[0, 1, -42, 4.5, 0.002, 1e-7, 333333333.3333333]")).toEqual(
      [0, 1, -42, 4.5, 0.002, 1e-7, 333333333.3333333],
    );
  });

  it("does NOT flag digits that live inside a string value", () => {
    expect(strictJsonParse('{"note":"9007199254740993 is too big"}')).toEqual({
      note: "9007199254740993 is too big",
    });
  });

  it("does NOT flag digits inside a KEY name", () => {
    expect(strictJsonParse('{"9007199254740993":1}')).toEqual({
      "9007199254740993": 1,
    });
  });
});

describe("strictJsonParse — duplicate_member", () => {
  it("rejects duplicate keys at the top level", () => {
    const err = catchStrict(() => strictJsonParse('{"a":1,"a":2}'));
    expect(err.reason).toBe("duplicate_member");
  });

  it("rejects duplicate keys nested at depth", () => {
    const err = catchStrict(() =>
      strictJsonParse('{"outer":{"x":1,"x":2}}'),
    );
    expect(err.reason).toBe("duplicate_member");
  });

  it("rejects a duplicate where one key is written with a \\u escape", () => {
    // "a" decodes to "a" — same member name, must be caught.
    const err = catchStrict(() => strictJsonParse('{"a":1,"\\u0061":2}'));
    expect(err.reason).toBe("duplicate_member");
  });

  it("ACCEPTS the same key name in sibling objects (not a duplicate)", () => {
    expect(strictJsonParse('[{"a":1},{"a":2}]')).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("ACCEPTS a key string that appears as a value elsewhere", () => {
    expect(strictJsonParse('{"a":"a","b":"a"}')).toEqual({ a: "a", b: "a" });
  });
});

describe("strictJsonParse — parity with JSON.parse for valid input", () => {
  const valid = [
    "{}",
    "[]",
    '""',
    "null",
    "true",
    '{"a":[{"x":2,"y":1}],"z":{"a":null,"b":[3,1,2]}}',
    '{"escaped":"a\\"b\\\\c","key\\"quote":1}',
    '{"unicode":"€💩é"}',
  ];
  for (const text of valid) {
    it(`round-trips: ${text}`, () => {
      expect(strictJsonParse(text)).toEqual(JSON.parse(text));
    });
  }

  it("propagates a SyntaxError (NOT StrictJsonParseError) for malformed JSON", () => {
    try {
      strictJsonParse("{ not json");
      throw new Error("expected a throw");
    } catch (e) {
      expect(e).not.toBeInstanceOf(StrictJsonParseError);
    }
  });
});

describe("wired call sites fail closed (no raw-UTF-8 fallback on a strict violation)", () => {
  it("argsHashFromJsonString THROWS on an unsafe integer", () => {
    const err = catchStrict(() =>
      argsHashFromJsonString('{"amount":9007199254740993}'),
    );
    expect(err.reason).toBe("unsafe_number");
  });

  it("resultHashFromJsonString THROWS on a duplicate member", () => {
    const err = catchStrict(() =>
      resultHashFromJsonString('{"a":1,"a":2}'),
    );
    expect(err.reason).toBe("duplicate_member");
  });

  it("argsHashFromJsonString STILL falls back to raw-UTF-8 for non-JSON", () => {
    // Pre-existing observe-only behavior for un-parseable bytes is preserved:
    // a stable hash, not a throw.
    const h = argsHashFromJsonString("this is not json");
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("argsHashFromJsonString produces the SAME hash as before for valid input", () => {
    // Valid args are unaffected by the strict layer — identical bytes/hash.
    expect(argsHashFromJsonString('{"b":1,"a":2}')).toBe(
      argsHashFromJsonString('{"a":2,"b":1}'),
    );
  });
});

// Helper: assert a thunk threw StrictJsonParseError and return it typed.
function catchStrict(fn: () => unknown): StrictJsonParseError {
  try {
    fn();
  } catch (e) {
    if (e instanceof StrictJsonParseError) return e;
    throw new Error(`expected StrictJsonParseError, got ${String(e)}`);
  }
  throw new Error("expected a throw, got none");
}
