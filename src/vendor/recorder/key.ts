import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { base64UrlNoPad } from "./sign.js";

// PKCS#8 prefix for Ed25519 private keys. Followed by the 32-byte seed.
//   30 2e                  SEQUENCE (46 bytes)
//     02 01 00             INTEGER version=0
//     30 05                SEQUENCE (5 bytes) AlgorithmIdentifier
//       06 03 2b 65 70     OID 1.3.101.112 (id-Ed25519)
//     04 22                OCTET STRING (34 bytes)
//       04 20              OCTET STRING (32 bytes) — CurvePrivateKey
//       <32-byte seed>
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

// Build a deterministic Ed25519 private KeyObject from a fixed 32-byte seed.
// Used by the golden vector and by any callers that need reproducible keys
// (tests, fixtures). NOT for production key generation — use `generateKeyPair`.
export function ed25519PrivateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.length !== 32) {
    throw new Error(
      `Ed25519 seed must be 32 bytes, got ${seed.length}`,
    );
  }
  const der = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function publicKeyFromPrivate(privateKey: KeyObject): KeyObject {
  return createPublicKey(privateKey);
}

// Raw 32-byte Ed25519 public key bytes (the `x` coordinate).
export function rawPublicKeyBytes(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new Error("public key JWK has no x coordinate");
  const pad = (4 - (jwk.x.length % 4)) % 4;
  const b64 =
    jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64");
}

export function publicKeyBase64Url(publicKey: KeyObject): string {
  return base64UrlNoPad(rawPublicKeyBytes(publicKey));
}

export function generateKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}
