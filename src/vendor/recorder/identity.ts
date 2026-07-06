// Identity files written by `recorder init` and consumed by `recorder verify`.
//
// On-disk layout (under `.<PRODUCT_NAME>/` by default):
//   identity.json   — public material + kid (safe to share / commit)
//   private-key.pem — PKCS#8 PEM of the Ed25519 private key (chmod 0600)
//
// kid format (current): the bare RFC 7638 JWK thumbprint of the public key
// (spec G). A consumer holding a receipt can recompute the thumbprint from the
// JWK and cross-check it against `kid` by construction — closing F2.
// Legacy format: "ed25519/<12-char base64url of SHA-256(raw public key)>",
// still accepted read-only by the verifier (see kidMatchesKey). Both are
// deterministic from the key.

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";
import { jcsBytes } from "./canonicalize.js";
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

// Legacy kid scheme (pre-thumbprint): "ed25519/<12-char b64url of
// SHA-256(raw pubkey)>". Retained ONLY so the verifier can still match
// receipts and identities minted under the old scheme. NOT used for new
// identities — see makeKid.
export function legacyKid(publicKey: KeyObject): string {
  const raw = rawPublicKeyBytes(publicKey);
  const digest = Buffer.from(sha256Hex(raw), "hex");
  return "ed25519/" + base64UrlNoPad(digest).slice(0, 12);
}

// kid for NEW identities (spec G): the bare RFC 7638 JWK thumbprint. Making
// kid == thumbprint means an external verifier can cross-check kid against the
// JWK by construction, and for a v1 receipt kid == key_thumbprint == the
// binding value — one identity, three places, all reconcilable.
export function makeKid(publicKey: KeyObject): string {
  return rfc7638Thumbprint(publicKey);
}

// True if `kid` names `publicKey` under EITHER the current (thumbprint) or the
// legacy scheme. A verifier matches on this instead of raw string equality so
// that a legacy chain, a new chain, and a chain that SPANS the migration (same
// key, kid representation changes partway) all still verify.
export function kidMatchesKey(publicKey: KeyObject, kid: string): boolean {
  return kid === rfc7638Thumbprint(publicKey) || kid === legacyKid(publicKey);
}

// RFC 7638 JWK thumbprint of an Ed25519 (OKP) public key.
//
// Per RFC 7638 the thumbprint is computed over a JSON object containing ONLY
// the JWK's required members, in lexicographic order, with no whitespace —
// i.e. exactly what JCS (RFC 8785) produces for `{crv, kty, x}`. For OKP the
// required members are `crv`, `kty`, `x` (which sort in that order). The
// thumbprint is `base64url-nopad(sha256(that canonical input))`.
//
// This is the value stamped into a v1 receipt's `key_thumbprint` and the value
// a verifier recomputes for the key it resolves. We reuse the SAME JCS routine
// used for record signing — one canonicalization path, no second impl that
// could drift. Cross-checked against the conformance corpus
// (conformance/vectors-v1.json key_binding.rfc7638_thumbprint).
export function rfc7638Thumbprint(publicKey: KeyObject): string {
  const x = publicKeyBase64Url(publicKey);
  const canonicalInput = jcsBytes({ crv: "Ed25519", kty: "OKP", x });
  const digest = createHash("sha256").update(canonicalInput).digest();
  return base64UrlNoPad(digest);
}

// Default issuer identifier for a v1 receipt. When the operator publishes a
// `jwks_uri`, the issuer is that URL's origin — the operator's own domain, so
// Headless Oracle is NOT named as the issuer of an adopter's receipts (the
// neutral / operator-out-of-trust-path property). Absent a jwks_uri there is
// no published issuer location, so we fall back to a key-scoped URN that is
// still globally unambiguous and agent-parseable.
export function defaultIssuer(thumbprint: string, jwksUri?: string): string {
  if (jwksUri !== undefined) {
    try {
      return new URL(jwksUri).origin;
    } catch {
      /* malformed URL — fall through to the URN form */
    }
  }
  return `urn:chirindo:key:${thumbprint}`;
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
