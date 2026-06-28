// Identity files written by `recorder init` and consumed by `recorder verify`.
//
// On-disk layout (under `.<PRODUCT_NAME>/` by default):
//   identity.json   — public material + kid (safe to share / commit)
//   private-key.pem — PKCS#8 PEM of the Ed25519 private key (chmod 0600)
//
// kid format: "ed25519/<12-char base64url of SHA-256(raw public key)>".
// Deterministic from the key, so re-initializing the same key yields the
// same kid; collisions across keys are infeasible at 72 bits.

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import {
  publicKeyBase64Url,
  rawPublicKeyBytes,
} from "./key.js";
import { base64UrlNoPad } from "./sign.js";
import { sha256Hex } from "./hash.js";

export interface IdentityFile {
  kid: string;
  alg: "ed25519";
  public_key_b64url: string;
  public_key_pem: string;
}

export interface LoadedIdentity {
  kid: string;
  publicKey: KeyObject;
  identityPath: string;
}

export interface LoadedFullIdentity extends LoadedIdentity {
  privateKey: KeyObject;
  privateKeyPath: string;
}

export const IDENTITY_FILENAME = "identity.json";
export const PRIVATE_KEY_FILENAME = "private-key.pem";

// Stable, short fingerprint of the public key. base64url so it's filename-
// and URL-safe; 12 chars = 72 bits of collision resistance, ample for a
// human-readable handle on a local key.
export function makeKid(publicKey: KeyObject): string {
  const raw = rawPublicKeyBytes(publicKey);
  const digest = Buffer.from(sha256Hex(raw), "hex");
  return "ed25519/" + base64UrlNoPad(digest).slice(0, 12);
}

export function buildIdentityFile(publicKey: KeyObject): IdentityFile {
  const pem = publicKey.export({ format: "pem", type: "spki" }).toString();
  return {
    kid: makeKid(publicKey),
    alg: "ed25519",
    public_key_b64url: publicKeyBase64Url(publicKey),
    public_key_pem: pem,
  };
}

export interface WriteIdentityResult {
  dir: string;
  identityPath: string;
  privateKeyPath: string;
  identity: IdentityFile;
}

export function writeIdentity(
  dir: string,
  privateKey: KeyObject,
  publicKey: KeyObject,
): WriteIdentityResult {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  const identity = buildIdentityFile(publicKey);
  const identityPath = join(dir, IDENTITY_FILENAME);
  const privateKeyPath = join(dir, PRIVATE_KEY_FILENAME);

  writeFileSync(identityPath, JSON.stringify(identity, null, 2) + "\n", "utf8");

  const pkcs8 = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  writeFileSync(privateKeyPath, pkcs8, "utf8");
  // Best-effort restriction; on Windows this is largely ignored.
  try {
    chmodSync(privateKeyPath, 0o600);
  } catch {
    /* non-fatal */
  }

  return { dir, identityPath, privateKeyPath, identity };
}

export function readIdentityFile(identityPath: string): IdentityFile {
  const text = readFileSync(identityPath, "utf8");
  const parsed = JSON.parse(text) as IdentityFile;
  if (parsed.alg !== "ed25519") {
    throw new Error(
      `unsupported identity alg: ${parsed.alg} (expected "ed25519")`,
    );
  }
  if (!parsed.kid || !parsed.public_key_pem) {
    throw new Error("identity file missing kid or public_key_pem");
  }
  return parsed;
}

export function loadIdentity(identityPath: string): LoadedIdentity {
  const file = readIdentityFile(identityPath);
  const publicKey = createPublicKey({
    key: file.public_key_pem,
    format: "pem",
  });
  return { kid: file.kid, publicKey, identityPath };
}

export function loadFullIdentity(
  identityPath: string,
  privateKeyPath?: string,
): LoadedFullIdentity {
  const base = loadIdentity(identityPath);
  const pkPath =
    privateKeyPath ??
    join(identityPath.replace(/[\\/][^\\/]*$/, ""), PRIVATE_KEY_FILENAME);
  const pem = readFileSync(pkPath, "utf8");
  const privateKey = createPrivateKey({ key: pem, format: "pem" });
  return { ...base, privateKey, privateKeyPath: pkPath };
}
