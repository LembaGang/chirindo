// Fixtures for the purchase-check tests (B-432): fixed Ed25519 keys, a
// card-only A.3 instruction that limits all nine card members, and an order
// inside every one of them.

import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { ANNEX_A3, signInstruction } from "../src/purchase/m6.js";
import { rfc7638Thumbprint } from "../src/vendor/recorder/index.js";

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
