// B-432 test 1, parity, card only (design §3 and §8.1). The purchase check's
// ports (src/purchase/) and the verifier they port
// (examples/evidence-bundle/lib/instructions.mjs and its readers) are run on
// the same vectors and must give the same per-limit results and the same
// exceeded list. The named differences D1, D4, D5, D7 and D9 each have a test
// showing the check denying where the verifier does not; D3 is reclassified (a
// more specific reason for what M6 refuses too); D6 and D8 need the record
// path and are tested with createPurchaseCheck (T2).
//
// The package never imports examples/; only tests do. instructions.mjs
// imports evm.mjs for `address`, and evm.mjs needs viem, which only
// examples/ordering-evidence-h4 installs (CI installs the root alone). It is
// replaced by a lowercase-only `address`. That is faithful for these vectors,
// whose addresses are all lowercase, so the EIP-55 branch is never reached.

import { describe, expect, it, vi } from "vitest";
import { judgePurchase, type Judgement } from "../src/purchase/limits.js";
import { parseStrictJson, parseStrictJsonBytes, type Parsed } from "../src/purchase/m6.js";
import { TIME_RE, compareInstants, tsMs } from "../src/purchase/time.js";
import { AT, GATE, PRINCIPAL, STRANGER, cardOf, constraintsOf, itemOf, order, signedText, type Obj } from "./purchase-helpers.js";
// @ts-expect-error -- plain .mjs without declarations; it is the reference being compared against
import { ANNEX_A3 as REF_A3, cardLimitsOf as refCardLimitsOf, m6Instruction } from "../examples/evidence-bundle/lib/instructions.mjs";
// @ts-expect-error -- as above
import { parseStrictJson as refParse } from "../examples/ordering-evidence-h4/lib/formats.mjs";
// @ts-expect-error -- as above
import { compareInstants as refCompare, orderProblem } from "../examples/evidence-bundle/lib/card.mjs";
// @ts-expect-error -- as above
import { TIME_RE as REF_TIME_RE } from "../examples/evidence-bundle/lib/table.mjs";
// @ts-expect-error -- as above
import { tsMs as refTsMs } from "../examples/evidence-bundle/lib/records.mjs";

vi.mock("../examples/ordering-evidence-h4/lib/evm.mjs", () => ({
  address: (s: unknown, what: string) => {
    if (typeof s !== "string" || !/^0x[0-9a-f]{40}$/.test(s)) throw new Error(`${what} is not a lowercase 20-byte hex address`);
    return s;
  },
}));

interface RefLimits {
  card_limits: unknown[];
  exceeded: string[];
  missing: boolean;
}

// The verifier on the same inputs: M6, then B-INS's card step with the same
// kid, time and use count (this purchase included).
function ref(text: string, ord: Obj, at = AT, usesSoFar = 0): { problem: string } | RefLimits {
  const m = m6Instruction(Buffer.from(text, "utf8"), REF_A3) as { problem?: string; value?: unknown };
  if (m.problem !== undefined) return { problem: m.problem };
  return refCardLimitsOf(m.value, ord, { kid: GATE.kid, authorizedAt: at }, usesSoFar + 1) as RefLimits;
}
const check = (text: string, ord: unknown, at = AT, usesSoFar = 0): Judgement => judgePurchase(text, ord, { kid: GATE.kid, at, usesSoFar });
const evaluated = (r: ReturnType<typeof ref>): RefLimits => {
  expect("problem" in r ? r.problem : null).toBeNull();
  return r as RefLimits;
};

// ---- the vectors both implementations evaluate -----------------------------

interface Vec {
  name: string;
  text: string;
  order: Obj;
  at?: string;
  uses?: number;
  exceeded: string[];
  allow: boolean;
}
const vectors: Vec[] = [];
const vec = (name: string, edit: { body?: (b: Obj) => void; order?: (o: Obj) => void; at?: string; uses?: number }, exceeded: string[], allow = exceeded.length === 0) =>
  vectors.push({ name, text: signedText(edit.body), order: order(edit.order), exceeded, allow, ...(edit.at !== undefined ? { at: edit.at } : {}), ...(edit.uses !== undefined ? { uses: edit.uses } : {}) });

vec("all nine limits inside", {}, []);
// Each of the nine limits outside.
vec("currency outside", { order: (o) => (o["currency"] = "USD") }, ["currency"]);
vec("max_total_minor outside", { order: (o) => (o["total_minor"] = "30001") }, ["max_total_minor"]);
vec("max_total_minor at the cap", { order: (o) => (o["total_minor"] = "30000") }, []);
vec("max_unit_price_minor outside", { order: (o) => (itemOf(o)["unit_price_minor"] = "15001") }, ["max_unit_price_minor"]);
vec("merchants outside", { order: (o) => (o["merchant_id"] = "other.example") }, ["merchants"]);
vec("items outside", { order: (o) => (itemOf(o)["sku"] = "SUITE") }, ["items"]);
vec("categories outside", { order: (o) => (itemOf(o)["category"] = "dining") }, ["categories"]);
vec("refundable_only outside", { order: (o) => (itemOf(o)["refundable"] = false) }, ["refundable_only"]);
vec("service_window outside", { order: (o) => (itemOf(o)["service_until"] = "2026-12-01") }, ["service_window"]);
vec("locations outside", { order: (o) => (itemOf(o)["location"] = "Porto") }, ["locations"]);
vec("refundable_only false limits nothing", { body: (b) => (cardOf(b)["refundable_only"] = false), order: (o) => (itemOf(o)["refundable"] = false) }, []);
// Field missing: orderFailure makes the other five fields always present.
vec("categories field missing", { order: (o) => delete itemOf(o)["category"] }, [], false);
vec("refundable_only field missing", { order: (o) => delete itemOf(o)["refundable"] }, [], false);
vec("service_window field missing", { order: (o) => delete itemOf(o)["service_from"] }, [], false);
vec("locations field missing", { order: (o) => delete itemOf(o)["location"] }, [], false);
// valid_from and valid_until at the exact instant and +-1 ms, with 0, 3 and 9
// fractional digits; and one sub-millisecond case each, which Date
// milliseconds cannot tell apart.
const window: [string, string, [string, string[]][]][] = [
  ["valid_from", "2026-11-01T00:00:00Z", [["2026-11-01T00:00:00.000Z", []], ["2026-10-31T23:59:59.999Z", ["valid_from"]], ["2026-11-01T00:00:00.001Z", []]]],
  ["valid_from", "2026-11-01T00:00:00.500Z", [["2026-11-01T00:00:00.500Z", []], ["2026-11-01T00:00:00.499Z", ["valid_from"]], ["2026-11-01T00:00:00.501Z", []]]],
  ["valid_from", "2026-11-01T00:00:00.500000000Z", [["2026-11-01T00:00:00.500000000Z", []], ["2026-11-01T00:00:00.499000000Z", ["valid_from"]], ["2026-11-01T00:00:00.501000000Z", []]]],
  ["valid_from", "2026-11-01T00:00:00.500000001Z", [["2026-11-01T00:00:00.500Z", ["valid_from"]], ["2026-11-01T00:00:00.500000001Z", []]]],
  ["valid_until", "2026-11-30T00:00:00Z", [["2026-11-30T00:00:00.000Z", []], ["2026-11-30T00:00:00.001Z", ["valid_until"]], ["2026-11-29T23:59:59.999Z", []]]],
  ["valid_until", "2026-11-30T00:00:00.500Z", [["2026-11-30T00:00:00.500Z", []], ["2026-11-30T00:00:00.501Z", ["valid_until"]], ["2026-11-30T00:00:00.499Z", []]]],
  ["valid_until", "2026-11-30T00:00:00.500000000Z", [["2026-11-30T00:00:00.500000000Z", []], ["2026-11-30T00:00:00.501000000Z", ["valid_until"]], ["2026-11-30T00:00:00.499000000Z", []]]],
  ["valid_until", "2026-11-30T00:00:00.500000001Z", [["2026-11-30T00:00:00.500000002Z", ["valid_until"]], ["2026-11-30T00:00:00.500000001Z", []]]],
];
for (const [member, bound, cases] of window) {
  for (const [at, exceeded] of cases) vec(`${member} ${bound} at ${at}`, { body: (b) => (constraintsOf(b)[member] = bound), at }, exceeded);
}
vec("agent_kid names the gate", { body: (b) => (b["agent_kid"] = [STRANGER.kid, GATE.kid]) }, []);
vec("agent_kid does not name the gate", { body: (b) => (b["agent_kid"] = [STRANGER.kid]) }, ["agent_kid"]);
vec("max_uses 1, first use", { uses: 0 }, []);
vec("max_uses 1, second use", { uses: 1 }, ["max_uses"]);
vec("max_uses 3, third use", { body: (b) => (constraintsOf(b)["max_uses"] = 3), uses: 2 }, []);
vec("max_uses 3, fourth use", { body: (b) => (constraintsOf(b)["max_uses"] = 3), uses: 3 }, ["max_uses"]);
vec("max_uses absent (1), first use", { body: (b) => delete constraintsOf(b)["max_uses"], uses: 0 }, []);
vec("max_uses absent (1), second use", { body: (b) => delete constraintsOf(b)["max_uses"], uses: 1 }, ["max_uses"]);
vec("a paired surrogate in text", { body: (b) => (b["text"] = "Room \u{1F600}") }, []);
vec("two limits outside at once", { order: (o) => ((o["merchant_id"] = "other.example"), (o["total_minor"] = "99999")) }, ["max_total_minor", "merchants"]);

describe("parity: the check's ports and the verifier give the same per-limit results and exceeded list", () => {
  for (const v of vectors) {
    it(v.name, () => {
      const r = evaluated(ref(v.text, v.order, v.at, v.uses));
      const j = check(v.text, v.order, v.at, v.uses);
      expect(j.step).toBe(3);
      expect(j.card_limits).toEqual(r.card_limits);
      expect(j.exceeded).toEqual(r.exceeded);
      expect(j.exceeded).toEqual(v.exceeded);
      expect(j.reasons.length === 0).toBe(v.allow);
      // The rule (design §3): whenever the check allows, the verifier reports no exceeded limit.
      if (j.reasons.length === 0) expect(r.exceeded).toEqual([]);
    });
  }
});

describe("parity: M6 failures are refused by both", () => {
  const tampered = () => {
    const o = JSON.parse(signedText()) as Obj;
    o["text"] = "A suite in Lisbon, any price";
    return JSON.stringify(o);
  };
  const cases: [string, string, string][] = [
    ["bad sig", tampered(), "instruction-invalid:bad-signature"],
    ["extra member", signedText((b) => (b["note"] = "x")), "instruction-invalid:extra-member:/note"],
    ["kid not the thumbprint", signedText((b) => ((b["principal"] as Obj)["kid"] = GATE.kid)), "instruction-invalid:kid-not-thumbprint"],
    ["profile 0.2", signedText((b) => (b["v"] = "signed-instruction-ed25519/0.2")), "instruction-invalid:wrong-profile"],
    ["0.3 without card", signedText((b) => delete constraintsOf(b)["card"]), "instruction-invalid:card-missing"],
    ["signed by another key", signedText(() => {}, STRANGER.priv), "instruction-invalid:bad-signature"],
  ];
  for (const [name, text, reason] of cases) {
    it(name, () => {
      const r = ref(text, order());
      expect("problem" in r && typeof r.problem === "string").toBe(true);
      const j = check(text, order());
      expect(j.step).toBe(2);
      expect(j.reasons).toEqual([reason]);
    });
  }
});

// ---- strict JSON: one vector per row of HOLD-2's parser table ------------------

const show = (v: unknown) => JSON.stringify(v, (_k, x: unknown) => (typeof x === "bigint" ? `${x}n` : x));
const refRead = (bytes: Uint8Array): { ok: true; value: string } | { ok: false } => {
  try {
    return { ok: true, value: show(refParse(bytes)) };
  } catch {
    return { ok: false };
  }
};
const S = signedText();
const maxUses = (tok: string) => S.replace('"max_uses":1', `"max_uses":${tok}`);
const textValue = (raw: string) => S.replace(/"text":"[^"]*"/, `"text":${raw}`);

interface Row {
  name: string;
  // The port on the input; the reference on its bytes.
  port: () => Parsed;
  bytes: Uint8Array;
  // "ok", or the port's parse problem.
  want: string;
  // The row inside an instruction, and the check's reason for it.
  embedded?: [string, string];
}
const utf8 = (s: string) => Buffer.from(s, "utf8");
const fromText = (s: string) => () => parseStrictJson(s);
const fromBytes = (b: Uint8Array) => () => parseStrictJsonBytes(b);
const LONE_HI_BYTES = Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xed, 0xa0, 0x80, 0x22, 0x7d]); // {"a":"<WTF-8 D800>"}
const BAD_UTF8 = Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]); // {"a":"\xff"}
const BOM_BYTES = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), utf8('{"a":1}')]);
const rows: Row[] = [
  { name: "duplicate, top level", port: fromText('{"a":1,"a":2}'), bytes: utf8('{"a":1,"a":2}'), want: "duplicate-member", embedded: [S.replace('"text":', '"text":"x","text":'), "instruction-invalid:duplicate-member"] },
  { name: "duplicate, nested", port: fromText('{"x":{"a":1,"a":2}}'), bytes: utf8('{"x":{"a":1,"a":2}}'), want: "duplicate-member", embedded: [S.replace('"card":{', '"card":{"currency":"EUR",'), "instruction-invalid:duplicate-member"] },
  { name: "duplicate via \\u0061", port: fromText('{"a":1,"\\u0061":2}'), bytes: utf8('{"a":1,"\\u0061":2}'), want: "duplicate-member", embedded: [S.replace('"text":', '"\\u0074ext":"x","text":'), "instruction-invalid:duplicate-member"] },
  { name: "lone high surrogate escape", port: fromText('{"a":"\\ud800"}'), bytes: utf8('{"a":"\\ud800"}'), want: "lone-surrogate", embedded: [textValue('"\\ud800"'), "instruction-invalid:lone-surrogate"] },
  { name: "lone low surrogate escape", port: fromText('{"a":"\\udc00"}'), bytes: utf8('{"a":"\\udc00"}'), want: "lone-surrogate", embedded: [textValue('"\\udc00"'), "instruction-invalid:lone-surrogate"] },
  { name: "raw lone surrogate (string) / its WTF-8 bytes", port: fromText('{"a":"\uD800"}'), bytes: LONE_HI_BYTES, want: "lone-surrogate", embedded: [textValue('"\uD800"'), "instruction-invalid:lone-surrogate"] },
  { name: "raw lone surrogate bytes through the byte reader", port: fromBytes(LONE_HI_BYTES), bytes: LONE_HI_BYTES, want: "not-utf8" },
  { name: "paired surrogate", port: fromText('{"a":"\\ud83d\\ude00"}'), bytes: utf8('{"a":"\\ud83d\\ude00"}'), want: "ok" },
  { name: "2^53-1", port: fromText('{"n":9007199254740991}'), bytes: utf8('{"n":9007199254740991}'), want: "ok" },
  { name: "2^53+1", port: fromText('{"n":9007199254740993}'), bytes: utf8('{"n":9007199254740993}'), want: "ok", embedded: [maxUses("9007199254740993"), "instruction-invalid:unsafe-integer"] },
  { name: "-(2^53+1)", port: fromText('{"n":-9007199254740993}'), bytes: utf8('{"n":-9007199254740993}'), want: "ok", embedded: [maxUses("-9007199254740993"), "instruction-invalid:unsafe-integer"] },
  { name: "fraction 1.0", port: fromText('{"n":1.0}'), bytes: utf8('{"n":1.0}'), want: "non-integer-number", embedded: [maxUses("1.0"), "instruction-invalid:non-integer-number"] },
  { name: "fraction 1.5", port: fromText('{"n":1.5}'), bytes: utf8('{"n":1.5}'), want: "non-integer-number", embedded: [maxUses("1.5"), "instruction-invalid:non-integer-number"] },
  { name: "exponent 1e2", port: fromText('{"n":1e2}'), bytes: utf8('{"n":1e2}'), want: "non-integer-number", embedded: [maxUses("1e2"), "instruction-invalid:non-integer-number"] },
  { name: "exponent 1e400", port: fromText('{"n":1e400}'), bytes: utf8('{"n":1e400}'), want: "non-integer-number", embedded: [maxUses("1e400"), "instruction-invalid:non-integer-number"] },
  { name: "-0", port: fromText('{"n":-0}'), bytes: utf8('{"n":-0}'), want: "ok" },
  { name: "leading zero 01", port: fromText('{"n":01}'), bytes: utf8('{"n":01}'), want: "syntax", embedded: [maxUses("01"), "instruction-invalid:syntax"] },
  { name: "BOM as U+FEFF in a string", port: fromText('﻿{"a":1}'), bytes: utf8('﻿{"a":1}'), want: "bom", embedded: ["﻿" + S, "instruction-invalid:bom"] },
  { name: "BOM as EF BB BF bytes", port: fromBytes(BOM_BYTES), bytes: BOM_BYTES, want: "bom" },
  { name: "invalid UTF-8 bytes", port: fromBytes(BAD_UTF8), bytes: BAD_UTF8, want: "not-utf8" },
  { name: "depth 65", port: fromText("[".repeat(65) + "]".repeat(65)), bytes: utf8("[".repeat(65) + "]".repeat(65)), want: "ok" },
  { name: "depth 66", port: fromText("[".repeat(66) + "]".repeat(66)), bytes: utf8("[".repeat(66) + "]".repeat(66)), want: "nesting-too-deep", embedded: [textValue("[".repeat(66) + "]".repeat(66)), "instruction-invalid:nesting-too-deep"] },
  { name: "__proto__ member", port: fromText('{"__proto__":{"x":1}}'), bytes: utf8('{"__proto__":{"x":1}}'), want: "ok" },
];

describe("strict JSON: the port reads as the examples' parseStrictJson does", () => {
  for (const row of rows) {
    it(row.name, () => {
      const p = row.port();
      const r = refRead(row.bytes);
      if (row.want === "ok") {
        expect(p).toMatchObject({ ok: true });
        expect(r.ok).toBe(true);
        expect(show((p as { value: unknown }).value)).toBe((r as { value: string }).value);
      } else {
        expect(p).toEqual({ ok: false, problem: row.want });
        expect(r.ok).toBe(false);
      }
      if (row.embedded) {
        const [text, reason] = row.embedded;
        const j = check(text, order());
        expect(j.step).toBe(1);
        expect(j.reasons).toEqual([reason]);
        expect("problem" in ref(text, order())).toBe(true);
      }
    });
  }
  it("__proto__ is an own member, not a prototype", () => {
    const p = parseStrictJson('{"__proto__":{"x":1}}') as { ok: true; value: Obj };
    expect(Object.keys(p.value)).toEqual(["__proto__"]);
    expect(Object.getPrototypeOf(p.value)).toBeNull();
  });
});

// ---- times -------------------------------------------------------------------

describe("time: the ports equal TIME_RE, tsMs and compareInstants", () => {
  const times = [
    "2026-10-30T10:00:00Z",
    "2026-10-30T10:00:00.1Z",
    "2026-10-30T10:00:00.123Z",
    "2026-10-30T10:00:00.123456789Z",
    "2026-10-30T10:00:00.1234567891Z",
    "2026-10-30T10:00:00.1239Z",
    "2026-10-30T10:00:00+00:00",
    "2026-10-30T10:00:00z",
    "2026-10-30 10:00:00Z",
    "2026-02-30T10:00:00Z",
    "2026-10-30T24:00:00Z",
    "2026-10-30T10:00:60Z",
    "+002026-10-30T10:00:00Z",
  ];
  it("TIME_RE is the same expression", () => expect(TIME_RE.source).toBe((REF_TIME_RE as RegExp).source));
  it("tsMs gives the same reading for each time", () => {
    for (const t of times) expect([t, tsMs(t)]).toEqual([t, refTsMs(t)]);
  });
  it("compareInstants gives the same order for each pair, or both throw", () => {
    for (const a of times)
      for (const b of times) {
        let mine: unknown;
        let theirs: unknown;
        try {
          mine = compareInstants(a, b);
        } catch {
          mine = "throws";
        }
        try {
          theirs = refCompare(a, b);
        } catch {
          theirs = "throws";
        }
        expect([a, b, mine]).toEqual([a, b, theirs]);
      }
  });
});

// ---- the named differences ------------------------------------------------------

describe("the named differences: the check denies where the verifier does not", () => {
  it("D1 order-field-missing", () => {
    for (const [field, limit] of [["category", "categories"], ["refundable", "refundable_only"], ["service_until", "service_window"], ["location", "locations"]] as const) {
      const ord = order((o) => delete itemOf(o)[field]);
      const r = evaluated(ref(signedText(), ord));
      expect(r.exceeded).toEqual([]);
      expect(check(signedText(), ord).reasons).toEqual([`order-field-missing:${limit}`]);
    }
  });

  // D3 is not a deny-only difference: the verifier's M6 reads times through
  // tsMs, which needs TIME_RE, so it refuses these too ("not a time"). The
  // check names the cause. Reclassified by the Lead on 30 Oct (B-432 T1).
  it("D3 (reclassified) a time that is not a Z instant: the check says time-not-z, and the verifier refuses it at M6", () => {
    for (const edit of [
      (b: Obj) => (constraintsOf(b)["valid_until"] = "2026-11-30T00:00:00+00:00"),
      (b: Obj) => (constraintsOf(b)["valid_from"] = "2026-11-01T00:00:00z"),
      (b: Obj) => (b["iat"] = "2026-10-30 00:00:00Z"),
    ]) {
      const text = signedText(edit);
      expect(check(text, order()).reasons).toEqual(["instruction-invalid:time-not-z"]);
      const r = ref(text, order());
      expect("problem" in r ? r.problem : null).toMatch(/is not a time$/);
    }
  });

  it("D4 the order screen: a name over 256 characters, card-like or e-mail-like text, a lone surrogate", () => {
    const cases: [string, string][] = [
      ["n".repeat(257), "order-invalid:/order/items/0/name"],
      ["Room, card 4111 1111 1111 1111", "order-invalid:/order/items/0/name"],
      ["Room for guest@example.com", "order-invalid:/order/items/0/name"],
      ["Room \uD800", "order-invalid:/order/items/0/name"],
    ];
    for (const [name, reason] of cases) {
      const ord = order((o) => (itemOf(o)["name"] = name));
      expect(orderProblem(ord)).toBeNull();
      expect(evaluated(ref(signedText(), ord)).exceeded).toEqual([]);
      const j = check(signedText(), ord);
      expect(j.step).toBe(1);
      expect(j.reasons).toEqual([reason]);
    }
  });

  it("D5 an instruction over 64 KB", () => {
    const text = signedText((b) => (b["text"] = "x".repeat(70_000)));
    expect(Buffer.byteLength(text)).toBeGreaterThan(65_536);
    expect(evaluated(ref(text, order())).exceeded).toEqual([]);
    expect(check(text, order()).reasons).toEqual(["instruction-invalid:too-large"]);
  });

  it("D7 unsupported-limit", () => {
    const budget = signedText((b) => (constraintsOf(b)["budget"] = "100000"));
    expect(evaluated(ref(budget, order())).exceeded).toEqual([]);
    expect(check(budget, order()).reasons).toEqual(["unsupported-limit:budget"]);
    const payment = signedText((b) =>
      Object.assign(constraintsOf(b), { chain_id: "eip155:8453", asset: "native", max_amount: "1000", payees: ["0x" + "11".repeat(20)] }),
    );
    expect(evaluated(ref(payment, order())).exceeded).toEqual([]);
    expect(check(payment, order()).reasons).toEqual([
      "unsupported-limit:chain_id",
      "unsupported-limit:asset",
      "unsupported-limit:max_amount",
      "unsupported-limit:payees",
    ]);
  });

  it("D9 an instruction time that is not a calendar instant (Feb 30, hour 24)", () => {
    const feb30 = signedText((b) => {
      Object.assign(constraintsOf(b), { valid_from: "2026-02-01T00:00:00Z", valid_until: "2026-02-30T00:00:00Z" });
      b["iat"] = "2026-01-30T00:00:00Z";
    });
    const at = "2026-02-15T00:00:00.000Z";
    expect(evaluated(ref(feb30, order(), at)).exceeded).toEqual([]);
    expect(check(feb30, order(), at).reasons).toEqual(["instruction-invalid:time-not-calendar"]);
    const hour24 = signedText((b) => (b["iat"] = "2026-10-30T24:00:00Z"));
    expect(evaluated(ref(hour24, order())).exceeded).toEqual([]);
    expect(check(hour24, order()).reasons).toEqual(["instruction-invalid:time-not-calendar"]);
  });

  it("D9 second 60: the check denies time-not-calendar, and here the verifier refuses too (Date.parse cannot read it)", () => {
    const sec60 = signedText((b) => (constraintsOf(b)["valid_until"] = "2026-11-30T00:00:60Z"));
    expect("problem" in ref(sec60, order())).toBe(true);
    expect(check(sec60, order()).reasons).toEqual(["instruction-invalid:time-not-calendar"]);
  });
});

it("fixtures: the principal and gate keys are distinct thumbprint kids", () => {
  expect(new Set([PRINCIPAL.kid, GATE.kid, STRANGER.kid]).size).toBe(3);
});
