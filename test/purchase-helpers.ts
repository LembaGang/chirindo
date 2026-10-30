// Fixtures for the purchase-check tests (B-432): fixed Ed25519 keys, a
// card-only A.3 instruction that limits all nine card members, and an order
// inside every one of them.

import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";
import { openPurchaseCheck, type PurchaseCheck, type ResolvedPurchaseOptions } from "../src/purchase/check.js";
import { ANNEX_A3, signInstruction } from "../src/purchase/m6.js";
import { reasonPatterns } from "../src/purchase/reasons.js";
import { readChainFile, rfc7638Thumbprint, writeIdentity, type SignedRecord } from "../src/vendor/recorder/index.js";
import { makeTmpDir } from "./helpers.js";

export type Obj = Record<string, unknown>;

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface Key {
  priv: KeyObject;
  x: string;
  kid: string;
}

// A key from a fixed 32-byte seed, so vectors are the same on every run. The
// kid is the vendored RFC 7638 thumbprint, not the port under test.
export function keyFromSeed(byte: number): Key {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.alloc(32, byte)]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  return { priv, x: (pub.export({ format: "jwk" }) as { x: string }).x, kid: rfc7638Thumbprint(pub) };
}

export const PRINCIPAL = keyFromSeed(1);
export const GATE = keyFromSeed(2);
export const STRANGER = keyFromSeed(3);

// Inside the window, for every vector that does not test the window.
export const AT = "2026-11-05T12:00:00.000Z";

export function baseBody(): Obj {
  return {
    v: ANNEX_A3,
    principal: { kid: PRINCIPAL.kid, public_key_jwk: { kty: "OKP", crv: "Ed25519", x: PRINCIPAL.x } },
    agent_kid: [GATE.kid],
    text: "A room in Lisbon in November, up to EUR 300.00",
    constraints: {
      valid_from: "2026-11-01T00:00:00Z",
      valid_until: "2026-11-30T00:00:00Z",
      max_uses: 1,
      card: {
        currency: "EUR",
        max_total_minor: "30000",
        max_unit_price_minor: "15000",
        merchants: ["hotel.example"],
        items: ["ROOM"],
        categories: ["lodging"],
        refundable_only: true,
        service_window: { from: "2026-11-01", until: "2026-11-30" },
        locations: ["Lisbon"],
      },
    },
    iat: "2026-10-30T00:00:00Z",
  };
}

export function baseOrder(): Obj {
  return {
    merchant_id: "hotel.example",
    merchant_order_id: "H-1",
    currency: "EUR",
    total_minor: "28000",
    items: [
      {
        sku: "ROOM",
        quantity: 2,
        unit_price_minor: "14000",
        name: "Room",
        category: "lodging",
        refundable: true,
        service_from: "2026-11-10",
        service_until: "2026-11-12",
        location: "Lisbon",
      },
    ],
  };
}

export const constraintsOf = (b: Obj) => b["constraints"] as Obj;
export const cardOf = (b: Obj) => constraintsOf(b)["card"] as Obj;
export const itemOf = (o: Obj) => (o["items"] as Obj[])[0]!;

// The instruction text, signed by the principal after `edit` changes the body.
export function signedText(edit: (b: Obj) => void = () => {}, key: KeyObject = PRINCIPAL.priv): string {
  const b = baseBody();
  edit(b);
  return JSON.stringify(signInstruction(b, key));
}

export function order(edit: (o: Obj) => void = () => {}): Obj {
  const o = baseOrder();
  edit(o);
  return o;
}

// T1 ruling 3: every reason a test sees matches exactly one pattern of the
// frozen vocabulary. Called on every result the purchase tests examine.
export function expectVocabulary(reasons: readonly string[]): void {
  for (const r of reasons) expect([r, reasonPatterns(r).map((p) => p.prefix)]).toEqual([r, [expect.any(String)]]);
}

// ---- createPurchaseCheck -------------------------------------------------------

// A data directory whose identity is GATE, so the base instruction's agent_kid names it.
export function checkDir(prefix = "chirindo-purchase-"): string {
  const dir = makeTmpDir(prefix);
  writeIdentity(dir, GATE.priv, createPublicKey(GATE.priv));
  return dir;
}

// A settable gate clock.
export function clockAt(t: string = AT): { t: string; now: () => string } {
  const c = { t, now: () => c.t };
  return c;
}

export function openCheck(dir: string, clock: { now: () => string }, extra: Partial<ResolvedPurchaseOptions> = {}): PurchaseCheck & { logs: string[] } {
  const logs: string[] = [];
  const pc = openPurchaseCheck({ dir, serverLabel: "purchase-check", now: clock.now, log: (l) => logs.push(l), ...extra });
  return Object.assign(pc, { logs });
}

// check(), with the vocabulary held on its answer.
export function checked(pc: PurchaseCheck, instruction: unknown, ord: unknown) {
  const r = pc.check({ instruction, order: ord } as never);
  expectVocabulary(r.reasons);
  return r;
}

export const chainsDirOf = (dir: string) => join(dir, "purchase-chains");
export const chainPathOf = (dir: string, sessionId: string) => join(dir, "purchase-chains", `${sessionId}.jsonl`);
export const recordsOf = (dir: string, sessionId: string): SignedRecord[] => readChainFile(chainPathOf(dir, sessionId)).records;
export const checkOf = (r: SignedRecord) => (r as unknown as { check: Obj }).check;

// Every retained-arguments file under dir/purchase-args, by its path relative to it.
export function argsFiles(dir: string): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  const root = join(dir, "purchase-args");
  let sessions: string[] = [];
  try {
    sessions = readdirSync(root);
  } catch {
    return out;
  }
  for (const s of sessions) for (const f of readdirSync(join(root, s))) out.set(`${s}/${f}`, readFileSync(join(root, s, f)));
  return out;
}
