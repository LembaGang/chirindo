// The frozen reason vocabulary of purchase-check/0.1 (B-432, T1 ruling 3).
// Every reason the check gives matches exactly one of these patterns. A change
// to a pattern, or to a word list, is a change of check.v (PURCHASE_CHECK_VERSION).
// docs/purchase-check-reasons.md publishes the same list.

import { CARD_LIMITS, UNSUPPORTED_LIMITS } from "./m6.js";
import { PURCHASE_CHECK_VERSION } from "./member.js";

export type ReasonSuffix = "none" | "word" | "card-limit" | "json-pointer";

export interface ReasonPattern {
  // The reason itself when suffix is "none"; otherwise what precedes the suffix.
  prefix: string;
  suffix: ReasonSuffix;
  // The allowed suffixes when suffix is "word" or "card-limit".
  words: readonly string[];
  // The step of design §4.2 that gives it.
  step: 1 | 2 | "2b" | 3 | 5;
}

// instruction-invalid:<word>: the instruction problems with no pointer.
export const INSTRUCTION_PROBLEMS = [
  "not-a-string",
  "too-large",
  "syntax",
  "bom",
  "lone-surrogate",
  "duplicate-member",
  "non-integer-number",
  "nesting-too-deep",
  "unsafe-integer",
  "not-an-object",
  "wrong-profile",
  "kid-not-thumbprint",
  "card-missing",
  "card-limits-empty",
  "window-reversed",
  "time-not-z",
  "time-not-calendar",
  "bad-signature",
  "not-canonical",
] as const;

// A JSON Pointer as src/trial/rules.ts `pointer` writes one: "/" and segments
// that are member names of [A-Za-z0-9_-]{1,64}, array indexes, or
// "~invalid-key" for any other member name (so a pointer never carries the
// caller's text), cut at 128 characters.
export const POINTER_RE_SOURCE = "/[A-Za-z0-9_~/-]{0,127}";

const p = (prefix: string, suffix: ReasonSuffix, step: ReasonPattern["step"], words: readonly string[] = []): ReasonPattern => ({ prefix, suffix, words, step });

export const PURCHASE_REASON_PATTERNS: readonly ReasonPattern[] = [
  p("instruction-invalid:", "word", 1, INSTRUCTION_PROBLEMS),
  p("instruction-invalid:not-an-object:", "json-pointer", 2),
  p("instruction-invalid:missing-member:", "json-pointer", 2),
  p("instruction-invalid:extra-member:", "json-pointer", 2),
  p("instruction-invalid:bad-value:", "json-pointer", 2),
  p("order-invalid:", "json-pointer", 1),
  p("unsupported-limit:", "word", 2, UNSUPPORTED_LIMITS),
  p("order-ref-reused", "none", "2b"),
  p("not-yet-valid", "none", 3),
  p("expired", "none", 3),
  p("agent-not-named", "none", 3),
  p("uses-exhausted", "none", 3),
  p("limit-exceeded:", "card-limit", 3, CARD_LIMITS),
  p("order-field-missing:", "card-limit", 3, CARD_LIMITS),
  p("record-failed", "none", 5),
];

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

export function patternRegExp(pt: ReasonPattern): RegExp {
  const tail =
    pt.suffix === "none" ? "" : pt.suffix === "json-pointer" ? POINTER_RE_SOURCE : `(?:${pt.words.map(escape).join("|")})`;
  return new RegExp(`^${escape(pt.prefix)}${tail}$`);
}

const COMPILED = PURCHASE_REASON_PATTERNS.map((pt) => ({ pt, re: patternRegExp(pt) }));

// The patterns a reason matches: exactly one for every reason the check gives.
export function reasonPatterns(reason: string): ReasonPattern[] {
  return COMPILED.filter((c) => c.re.test(reason)).map((c) => c.pt);
}

export { PURCHASE_CHECK_VERSION };
