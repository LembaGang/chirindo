// JWKS resolution + generation for cross-machine receipt verification.
//
// Why this exists
// ---------------
// Receipts carry a `kid` (`ed25519/<fp>`) but the verifier historically only
// knew the local identity. That means a stranger holding only the receipt
// bytes had no way to learn the public key for `kid` — so they could not
// verify. This module closes that gap: given a receipt and a JWKS URL, a
// third party can fetch the JWK by `kid`, materialize an Ed25519 public key,
// and run the existing JCS+sig verify logic unchanged. Receipt schema is
// untouched (Path A — no `iss` field).
//
// Trust model (Path A)
// --------------------
// The trust root is the canonical JWKS URL + TLS. The verifier ONLY fetches
// HTTPS, and ONLY from a URL the verifier itself chose (constant, env var,
// or --jwks flag). The receipt does NOT name its issuer URL. This is
// deliberate: a Path B design where the receipt self-describes its issuer
// URL is deferred precisely to avoid SSRF from untrusted receipt content.
// If/when Path B lands, it will add `iss` allowlist checks before fetch.
//
// Failure handling
// ----------------
// HTTPS-only (non-TLS rejected). Fetch is bounded (timeout + max bytes).
// On any failure — fetch error, malformed JSON, no JWK with matching kid,
// malformed JWK — verification returns a distinct UNRESOLVED outcome (not
// VALID, not TAMPERED). Silence is never an option for a verification tool.

import { createPublicKey, type KeyObject } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { URL } from "node:url";
import { base64UrlDecode } from "./sign.js";

// Default JWKS publication location. Overridable by env var + CLI flag at
// the call site; baked here so the verifier has a sensible cross-machine
// default and consumers can verify with zero config.
export const DEFAULT_JWKS_URL =
  "https://headlessoracle.com/.well-known/jwks.json";

// Env var name the CLI honors when no --jwks flag is passed.
export const JWKS_URL_ENV_VAR = "RECORDER_JWKS_URL";

// Hard bounds on the fetch — a verifier MUST NOT be a DoS amplifier.
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const JWKS_MAX_BYTES = 256 * 1024; // 256 KiB is generous for a JWKS

// In-process cache: a single verify run that touches multiple chains under
// the same kid hits the network once. Process exit clears it; we never
// persist trust to disk.
const jwksCache = new Map<string, Jwks>();

export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  use?: string;
  alg?: string;
}

export interface Jwks {
  keys: Jwk[];
}

export type JwksResolveError =
  | { kind: "non_https"; url: string }
  | { kind: "fetch_failed"; url: string; message: string }
  | { kind: "malformed_jwks"; url: string; message: string }
  | { kind: "kid_not_found"; url: string; kid: string }
  | { kind: "malformed_jwk"; url: string; kid: string; message: string };

export type JwksResolveResult =
  | { ok: true; publicKey: KeyObject; jwk: Jwk }
  | { ok: false; error: JwksResolveError };

// Build the JWK that represents an Ed25519 public key under a given kid.
// Spec-correct: OKP / crv:Ed25519 / x = base64url(raw public key bytes).
// `use` and `alg` are advisory but emitted so JWKS consumers can filter.
export function buildJwk(opts: {
  kid: string;
  publicKeyBase64Url: string;
}): Jwk {
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: opts.publicKeyBase64Url,
    kid: opts.kid,
    use: "sig",
    alg: "EdDSA",
  };
}

export function buildJwks(jwks: Jwk[]): Jwks {
  return { keys: jwks };
}

// Convert a JWK (OKP/Ed25519) to a Node KeyObject usable with verifyEd25519.
// Throws on shape mismatch — callers map this to a JwksResolveError.
//
// `alg` and `use` are OPTIONAL in RFC 7517 — absent is fine. But if the
// publisher set them, we hold them to their declaration: a JWK explicitly
// marked `use:enc` or `alg:RS256` MUST NOT be used to verify a signature,
// even if its key material happens to be an Ed25519 public key. Lax
// acceptance here would let a rotated-out encryption key resurrect as a
// signing key.
export function ed25519PublicKeyFromJwk(jwk: Jwk): KeyObject {
  if (jwk.kty !== "OKP") {
    throw new Error(`expected JWK kty=OKP, got ${jwk.kty}`);
  }
  if (jwk.crv !== "Ed25519") {
    throw new Error(`expected JWK crv=Ed25519, got ${jwk.crv ?? "<none>"}`);
  }
  if (jwk.use !== undefined && jwk.use !== "sig") {
    throw new Error(
      `JWK use must be "sig" for signature verification, got "${jwk.use}"`,
    );
  }
  if (jwk.alg !== undefined && jwk.alg !== "EdDSA") {
    throw new Error(`expected JWK alg=EdDSA, got "${jwk.alg}"`);
  }
  if (typeof jwk.x !== "string" || jwk.x.length === 0) {
    throw new Error("JWK is missing the x coordinate");
  }
  const raw = base64UrlDecode(jwk.x);
  if (raw.length !== 32) {
    throw new Error(
      `Ed25519 raw public key must be 32 bytes, got ${raw.length}`,
    );
  }
  // Node accepts a raw Ed25519 public key via JWK only; build the JWK
  // directly rather than reconstructing SPKI by hand. The `as never` cast
  // works around a stale @types/node where JsonWebKeyInput["key"] is typed
  // as JsonWebKey (no index signature) — at runtime Node is happy with the
  // OKP shape.
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: jwk.x },
    format: "jwk",
  } as Parameters<typeof createPublicKey>[0]);
}

// HTTPS GET with a hard timeout + max-bytes cap. The verifier is a trust
// boundary; we refuse to follow redirects or accept non-TLS schemes.
export async function fetchJwks(url: string): Promise<Jwks> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") {
    throw new Error(`JWKS URL must be https:// (got ${parsed.protocol}//...)`);
  }
  return await new Promise<Jwks>((resolveP, rejectP) => {
    const req = httpsRequest(
      {
        method: "GET",
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || 443,
        path: parsed.pathname + parsed.search,
        headers: { accept: "application/json" },
        timeout: JWKS_FETCH_TIMEOUT_MS,
      },
      (res) => {
        if (res.statusCode === undefined || res.statusCode >= 300) {
          // Treat redirects as failure too — we don't follow them, and a 3xx
          // here means the operator misconfigured the URL.
          res.resume();
          rejectP(new Error(`HTTP ${res.statusCode ?? "?"} fetching JWKS`));
          return;
        }
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > JWKS_MAX_BYTES) {
            res.destroy(
              new Error(`JWKS response exceeded ${JWKS_MAX_BYTES} bytes`),
            );
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          let parsedBody: unknown;
          try {
            parsedBody = JSON.parse(body);
          } catch (e) {
            rejectP(
              new Error(`JWKS body is not valid JSON: ${(e as Error).message}`),
            );
            return;
          }
          if (
            typeof parsedBody !== "object" ||
            parsedBody === null ||
            !Array.isArray((parsedBody as { keys?: unknown }).keys)
          ) {
            rejectP(new Error("JWKS body has no `keys` array"));
            return;
          }
          resolveP(parsedBody as Jwks);
        });
        res.on("error", rejectP);
      },
    );
    req.on("error", rejectP);
    req.on("timeout", () => {
      req.destroy(new Error(`JWKS fetch timed out after ${JWKS_FETCH_TIMEOUT_MS}ms`));
    });
    req.end();
  });
}

// Find the JWK in a JWKS document whose kid matches. JWKS spec is silent on
// duplicates; we take the first match — strict equality, no normalization.
export function findJwkByKid(jwks: Jwks, kid: string): Jwk | undefined {
  return jwks.keys.find((k) => k.kid === kid);
}

// One-shot resolve: fetch (with cache), pick by kid, materialize KeyObject.
// All failure modes resolve to a structured error so the verifier can
// report UNRESOLVED with a precise reason.
export async function resolveKeyFromJwks(opts: {
  url: string;
  kid: string;
}): Promise<JwksResolveResult> {
  let parsed: URL;
  try {
    parsed = new URL(opts.url);
  } catch {
    return {
      ok: false,
      error: { kind: "fetch_failed", url: opts.url, message: "invalid URL" },
    };
  }
  if (parsed.protocol !== "https:") {
    return { ok: false, error: { kind: "non_https", url: opts.url } };
  }

  let jwks = jwksCache.get(opts.url);
  if (jwks === undefined) {
    try {
      jwks = await fetchJwks(opts.url);
    } catch (e) {
      return {
        ok: false,
        error: {
          kind: "fetch_failed",
          url: opts.url,
          message: (e as Error).message,
        },
      };
    }
    jwksCache.set(opts.url, jwks);
  }

  const jwk = findJwkByKid(jwks, opts.kid);
  if (jwk === undefined) {
    return {
      ok: false,
      error: { kind: "kid_not_found", url: opts.url, kid: opts.kid },
    };
  }

  let publicKey: KeyObject;
  try {
    publicKey = ed25519PublicKeyFromJwk(jwk);
  } catch (e) {
    return {
      ok: false,
      error: {
        kind: "malformed_jwk",
        url: opts.url,
        kid: opts.kid,
        message: (e as Error).message,
      },
    };
  }

  return { ok: true, publicKey, jwk };
}

// Test-only: drop the in-process cache so a single test process can exercise
// multiple URLs / retries without bleed-through.
export function _clearJwksCache(): void {
  jwksCache.clear();
}

// Test-only: pre-seed the in-process cache for a URL so `resolveKeyFromJwks`
// returns this JWKS without performing a network fetch. Production never
// calls this — it exists so tests can exercise the jwks_uri-driven
// resolution path without standing up an HTTPS server. Underscore prefix
// + `_setJwksCacheEntry` name signal "internal test seam, not API."
export function _setJwksCacheEntry(url: string, jwks: Jwks): void {
  jwksCache.set(url, jwks);
}
