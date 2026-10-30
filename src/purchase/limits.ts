// The order side of the purchase check (B-432) and the pure judge: design
// §4.2 steps 1 to 4. There is no repeat lookup and no record here; those are
// createPurchaseCheck's.
//
// cardLimitsOf ports examples/evidence-bundle/lib/instructions.mjs (the
// package never imports examples/; test/purchase-parity.test.ts holds the two
// to the same per-limit results and the same exceeded list). The order rules
// and the screen are the trial recorder's (src/trial/rules.ts), which
// test/trial-order-parity.test.ts already holds to orderProblem.

import { hasCardToken, hasEmailToken, orderFailure, pointer } from "../trial/rules.js";
import { CARD_LIMITS, isWellFormed, jcsSha256, m6Check, readInstruction, type CardLimit } from "./m6.js";
import { ISO_UTC, compareInstants, isCalendarInstant } from "./time.js";

type Obj = Record<string, unknown>;

export type LimitResult = "not-declared" | "inside" | "outside" | "not-evaluated";
export interface CardLimitRow {
  limit: CardLimit;
  result: LimitResult;
  reason: "order-field-missing" | null;
}

// The verifier's exceeded vocabulary and order (EXCEEDED_ORDER), restricted
// to what a card-only instruction can exceed.
const EXCEEDED_ORDER: readonly string[] = ["valid_from", "valid_until", "agent_kid", "max_uses", ...CARD_LIMITS];
const MAX_DEPTH = 32;
const MAX_POINTERS = 20;

// ---- the order -----------------------------------------------------------------

// One copy of the caller's order, read without running a getter or a toJSON,
// so the order checked is the order recorded. Plain objects, dense arrays,
// well-formed strings, booleans, null and finite numbers (integers within the
// safe range) only. A failure names its pointer under /order.
export function snapshotOrder(order: unknown): { ok: true; order: unknown } | { ok: false; pointers: string[] } {
  const bad: string[] = [];
  const walk = (v: unknown, path: (string | number)[], depth: number): unknown => {
    if (v === null || typeof v === "boolean") return v;
    if (typeof v === "string") {
      if (!isWellFormed(v)) bad.push(pointer(path));
      return v;
    }
    if (typeof v === "number") {
      if (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v))) bad.push(pointer(path));
      return v;
    }
    if (typeof v !== "object" || depth >= MAX_DEPTH) {
      bad.push(pointer(path));
      return null;
    }
    const isArr = Array.isArray(v);
    const proto = Object.getPrototypeOf(v);
    if ((isArr ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) || Object.getOwnPropertySymbols(v).length > 0) {
      bad.push(pointer(path));
      return null;
    }
    const keys = Object.keys(v);
    if (isArr && keys.length !== (v as unknown[]).length) {
      bad.push(pointer(path));
      return null;
    }
    const out: Obj | unknown[] = isArr ? [] : {};
    for (const k of keys) {
      const seg: string | number = isArr ? Number(k) : k;
      const d = Object.getOwnPropertyDescriptor(v, k);
      if (d === undefined || !("value" in d)) {
        bad.push(pointer([...path, seg]));
        continue;
      }
      if (!isArr && !isWellFormed(k)) bad.push(pointer([...path, k]));
      // defineProperty, so a member named __proto__ stays a member.
      Object.defineProperty(out, k, { value: walk(d.value, [...path, seg], depth + 1), enumerable: true, writable: true, configurable: true });
    }
    return out;
  };
  try {
    const copy = walk(order, ["order"], 0);
    return bad.length === 0 ? { ok: true, order: copy } : { ok: false, pointers: [...new Set(bad)].slice(0, MAX_POINTERS) };
  } catch {
    // A proxy whose traps throw.
    return { ok: false, pointers: ["/order"] };
  }
}

// D4, the screen: card-number-like or e-mail-like text in an item's name,
// location or category, the free-text fields (the trial recorder's rule).
// Read after orderFailure has passed, so no string is over 256 characters.
function screenFailures(order: Obj): string[] {
  const out: string[] = [];
  (order["items"] as Obj[]).forEach((it, i) => {
    for (const k of ["name", "location", "category"]) {
      const v = it[k];
      if (typeof v === "string" && (hasCardToken(v) || hasEmailToken(v))) out.push(pointer(["order", "items", i, k]));
    }
  });
  return out;
}

// ---- the limits ----------------------------------------------------------------

// Spec 4.3, "B-INS for a card subject", step 5: the card limits against the
// committed order, each with its result, and the instruction's own members
// against the kid, the use count (this purchase included) and the time.
export function cardLimitsOf(
  ins: Obj,
  order: Obj,
  { kid, authorizedAt }: { kid: string; authorizedAt: string },
  uses: number,
): { card_limits: CardLimitRow[]; exceeded: string[]; missing: boolean } {
  const c = ins["constraints"] as Obj;
  const card = c["card"] as Obj;
  const items = order["items"] as Obj[];
  const has = (o: Obj, k: string) => Object.keys(o).includes(k);
  const list = (k: string) => card[k] as string[];
  // Each item read for one limit: true inside, false outside, null its field missing.
  const everyItem = (fields: string[], ok: (it: Obj) => boolean): LimitResult => {
    const r = items.map((it) => (fields.every((f) => has(it, f)) ? ok(it) : null));
    return r.includes(false) ? "outside" : r.includes(null) ? "not-evaluated" : "inside";
  };
  const sw = card["service_window"] as { from: string; until: string } | undefined;
  const judge: Record<CardLimit, () => LimitResult> = {
    currency: () => (order["currency"] === card["currency"] ? "inside" : "outside"),
    max_total_minor: () => (BigInt(order["total_minor"] as string) <= BigInt(card["max_total_minor"] as string) ? "inside" : "outside"),
    max_unit_price_minor: () =>
      everyItem(["unit_price_minor"], (it) => BigInt(it["unit_price_minor"] as string) <= BigInt(card["max_unit_price_minor"] as string)),
    merchants: () => (list("merchants").includes(order["merchant_id"] as string) ? "inside" : "outside"),
    items: () => everyItem(["sku"], (it) => list("items").includes(it["sku"] as string)),
    categories: () => everyItem(["category"], (it) => list("categories").includes(it["category"] as string)),
    refundable_only: () => everyItem(["refundable"], (it) => it["refundable"] === true),
    service_window: () =>
      everyItem(["service_from", "service_until"], (it) => (it["service_from"] as string) >= sw!.from && (it["service_until"] as string) <= sw!.until),
    locations: () => everyItem(["location"], (it) => list("locations").includes(it["location"] as string)),
  };
  // A limit the card does not set, and refundable_only false, limit nothing.
  const card_limits: CardLimitRow[] = CARD_LIMITS.map((k) => {
    const result: LimitResult = !has(card, k) || (k === "refundable_only" && card[k] === false) ? "not-declared" : judge[k]();
    return { limit: k, result, reason: result === "not-evaluated" ? "order-field-missing" : null };
  });
  const out = new Set<string>(card_limits.filter((l) => l.result === "outside").map((l) => l.limit));
  if (compareInstants(authorizedAt, c["valid_from"] as string) < 0) out.add("valid_from");
  if (compareInstants(authorizedAt, c["valid_until"] as string) > 0) out.add("valid_until");
  if (!(ins["agent_kid"] as string[]).includes(kid)) out.add("agent_kid");
  if (uses > ((c["max_uses"] as number | undefined) ?? 1)) out.add("max_uses");
  return { card_limits, exceeded: EXCEEDED_ORDER.filter((x) => out.has(x)), missing: card_limits.some((l) => l.result === "not-evaluated") };
}

// ---- the judge -----------------------------------------------------------------

export interface PurchaseOptions {
  // The gate's kid, which the instruction's agent_kid must name.
  kid: string;
  // The time of the decision: an ISO_UTC calendar instant.
  at: string;
  // ALLOW decisions already made on this instruction.
  usesSoFar: number;
}

export interface Judgement {
  // The last step that ran: 1 refuses the input (no receipt), 2 the
  // instruction's profile (a deny receipt), 3 the limits.
  step: 1 | 2 | 3;
  reasons: string[];
  // The verifier's names for what the order exceeds (step 3 only).
  exceeded: string[];
  card_limits: CardLimitRow[];
  // The JCS SHA-256 of the strict-parsed instruction: its M6 digest at step 3,
  // denied_instruction_sha256 at step 2; null at step 1.
  instruction_sha256: string | null;
  // The strict-parsed instruction and the copied order, from step 2 on.
  instruction: unknown;
  order: Obj | null;
}

function checkOptions(o: PurchaseOptions): void {
  if (typeof o !== "object" || o === null) throw new TypeError("purchase options must be an object");
  if (typeof o.kid !== "string" || o.kid === "") throw new TypeError("kid must be a non-empty string");
  if (typeof o.at !== "string" || !ISO_UTC.test(o.at) || !isCalendarInstant(o.at)) {
    throw new TypeError("at must be an ISO 8601 UTC calendar instant with at most nine fractional digits");
  }
  if (!Number.isSafeInteger(o.usesSoFar) || o.usesSoFar < 0) throw new TypeError("usesSoFar must be a non-negative safe integer");
}

// Design §4.2 steps 1 to 4. Throws only on invalid options.
export function judgePurchase(instructionText: unknown, order: unknown, opts: PurchaseOptions): Judgement {
  checkOptions(opts);
  const deny = (step: 1 | 2, reasons: string[], fields: Partial<Judgement> = {}): Judgement => ({
    step,
    reasons,
    exceeded: [],
    card_limits: [],
    instruction_sha256: null,
    instruction: null,
    order: null,
    ...fields,
  });

  // Step 1: the input. Every failure is a reason.
  const step1: string[] = [];
  const read = readInstruction(instructionText);
  if (!read.ok) step1.push(`instruction-invalid:${read.problem}`);
  const snap = snapshotOrder(order);
  let o: Obj | null = null;
  if (!snap.ok) step1.push(...snap.pointers.map((p) => `order-invalid:${p}`));
  else {
    const f = orderFailure(snap.order);
    if (f !== null) step1.push(`order-invalid:${f}`);
    else {
      o = snap.order as Obj;
      step1.push(...screenFailures(o).map((p) => `order-invalid:${p}`));
    }
  }
  if (step1.length > 0 || !read.ok || o === null) return deny(1, step1);

  // Step 2: the profile.
  const ins = read.value;
  const digest = jcsSha256(ins);
  const m6 = m6Check(ins);
  if (!m6.ok) return deny(2, [`instruction-invalid:${m6.problem}`], { instruction_sha256: digest, instruction: ins, order: o });
  const value = ins as Obj;
  const c = value["constraints"] as Obj;
  const step2 = m6.unsupported.map((k) => `unsupported-limit:${k}`);
  if (![c["valid_from"], c["valid_until"], value["iat"]].every(isCalendarInstant)) step2.push("instruction-invalid:time-not-calendar");
  if (step2.length > 0) return deny(2, step2, { instruction_sha256: digest, instruction: ins, order: o });

  // Step 3: the limits, every failure listed in the order of design §4.2.
  const { card_limits, exceeded } = cardLimitsOf(value, o, { kid: opts.kid, authorizedAt: opts.at }, opts.usesSoFar + 1);
  const reasons: string[] = [];
  if (compareInstants(opts.at, c["valid_from"] as string) < 0) reasons.push("not-yet-valid");
  if (compareInstants(opts.at, c["valid_until"] as string) > 0) reasons.push("expired");
  if (!(value["agent_kid"] as string[]).includes(opts.kid)) reasons.push("agent-not-named");
  if (opts.usesSoFar + 1 > ((c["max_uses"] as number | undefined) ?? 1)) reasons.push("uses-exhausted");
  for (const l of card_limits) {
    if (l.result === "outside") reasons.push(`limit-exceeded:${l.limit}`);
    else if (l.result === "not-evaluated") reasons.push(`order-field-missing:${l.limit}`);
  }
  // Step 4: allow if and only if no reason.
  return { step: 3, reasons, exceeded, card_limits, instruction_sha256: m6.digest, instruction: ins, order: o };
}

export interface Evaluation {
  decision: "allow" | "deny";
  reasons: string[];
  exceeded: string[];
  card_limits: CardLimitRow[];
}

// The pure judge, as a dry run: it writes nothing, consumes no use, and takes
// the caller's kid, time and use count. Its answer is neither a decision nor
// a record, and a provider must not charge on it (design §4, limit 6).
export function evaluatePurchase(instructionText: unknown, order: unknown, opts: PurchaseOptions): Evaluation {
  const j = judgePurchase(instructionText, order, opts);
  return { decision: j.reasons.length === 0 ? "allow" : "deny", reasons: j.reasons, exceeded: j.exceeded, card_limits: j.card_limits };
}
