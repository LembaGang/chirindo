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
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { URL } from "node:url";
import { base64UrlDecode } from "./sign.js";

// Default JWKS publication location. Overridable by env var + CLI flag at
// the call site; baked here so the verifier has a sensible cross-machine
// default and consumers can verify with zero config.
export const DEFAULT_JWKS_URL =
  "https://headlessoracle.com/.well-known/jwks.json";

// Env var name the CLI honors when no --jwks flag is passed.
export const JWKS_URL_ENV_VAR = "RECORDER_JWKS_URL";

// Hardened fetch profile (spec D). A verifier that follows a URL out of an
// untrusted receipt is an SSRF primitive unless every one of these holds. All
// are fail-closed: a violation aborts the fetch, it never degrades to a weaker
// check.
const JWKS_FETCH_TIMEOUT_MS = 5_000; // 5 s
const JWKS_MAX_BYTES = 64 * 1024; // 64 KiB body cap
const JWKS_MAX_REDIRECTS = 1; // at most one redirect, same-origin only
const JWKS_ALLOWED_PORT = "443"; // https default only
// A JWKS document must be served as JSON. Parameters (charset=...) are ignored.
const JWKS_ALLOWED_CONTENT_TYPES = [
  "application/jwk-set+json",
  "application/json",
];

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
  | { kind: "forbidden_port"; url: string; port: string }
  | { kind: "ip_literal_host"; url: string; host: string }
  | { kind: "private_address"; url: string; host: string; address: string }
  | { kind: "too_many_redirects"; url: string }
  | { kind: "cross_origin_redirect"; url: string; location: string }
  | { kind: "bad_content_type"; url: string; contentType: string }
  | { kind: "fetch_failed"; url: string; message: string }
  | { kind: "malformed_jwks"; url: string; message: string }
  | { kind: "kid_not_found"; url: string; kid: string }
  | { kind: "duplicate_kid"; url: string; kid: string }
  | { kind: "malformed_jwk"; url: string; kid: string; message: string };

// Internal typed error so the socket-level guards (which fire deep inside the
// https/net machinery, e.g. the DNS lookup hook) can carry a precise
// JwksResolveError back out to resolveKeyFromJwks instead of collapsing to a
// generic connection failure.
class JwksFetchError extends Error {
  constructor(readonly detail: JwksResolveError) {
    super(detail.kind);
    this.name = "JwksFetchError";
  }
}

// True if `ip` is loopback / link-local / private / otherwise not a public
// routable address. Conservative and fail-closed: anything we cannot positively
// classify as public is treated as unsafe. This is the check that stops a
// jwks_uri whose DNS resolves inward (169.254.169.254, 127.0.0.1, 10.x, ...).
export function isPrivateAddress(ip: string): boolean {
  const type = isIP(ip);
  if (type === 4) return isPrivateV4(ip);
  if (type === 6) return isPrivateV6(ip);
  return true; // not a valid IP literal — refuse
}

function isPrivateV4(ip: string): boolean {
  const parts = ip.split(".").map((o) => Number.parseInt(o, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
  return false;
}

function isPrivateV6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === "::" || s === "::1") return true; // unspecified / loopback
  // IPv4-mapped (::ffff:a.b.c.d) — classify by the embedded v4 address.
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateV4(mapped[1]!);
  if (s.startsWith("fe8") || s.startsWith("fe9") || s.startsWith("fea") || s.startsWith("feb")) {
    return true; // fe80::/10 link-local
  }
  if (s.startsWith("fc") || s.startsWith("fd")) return true; // fc00::/7 ULA
  if (s.startsWith("ff")) return true; // ff00::/8 multicast
  return false;
}

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

// Validate the STATIC properties of a fetch target — those knowable from the
// URL alone, before any DNS or socket work: https scheme, port 443, and a
// hostname that is NOT an IP literal (IP-literal targets bypass the DNS guard
// and are a classic SSRF shape). Returns a typed error, or null if the target
// clears the static checks. The DNS/private-address check happens later, at
// connection time, because it depends on resolution.
function validateFetchTarget(originalUrl: string, parsed: URL): JwksResolveError | null {
  if (parsed.protocol !== "https:") {
    return { kind: "non_https", url: originalUrl };
  }
  if (parsed.port !== "" && parsed.port !== JWKS_ALLOWED_PORT) {
    return { kind: "forbidden_port", url: originalUrl, port: parsed.port };
  }
  // URL.hostname keeps the brackets around an IPv6 literal ("[::1]"); strip
  // them before the IP test or isIP would miss every IPv6 literal.
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host) !== 0) {
    return { kind: "ip_literal_host", url: originalUrl, host };
  }
  return null;
}

// A DNS lookup hook for https.request that resolves the hostname and REFUSES
// to hand back any private/loopback/link-local address. Because the socket
// connects to exactly the address this hook returns, the public-IP decision
// and the connection target are the same resolution — no TOCTOU / DNS-rebind
// window between "checked" and "connected." Honors the `all` option so it is
// correct under Happy-Eyeballs (Node's autoSelectFamily calls with all:true).
function guardedLookup(originalUrl: string): LookupFunction {
  return (hostname, options, callback) => {
    // Resolve ALL addresses (verbatim: no reordering) so we can reject if ANY
    // of them is non-public — a hostname that returns one public and one
    // loopback address must not be reachable via the loopback entry.
    dnsLookup(hostname, { ...options, all: true, verbatim: true }, (err, addresses) => {
      if (err) {
        callback(err, "", 0);
        return;
      }
      const list = addresses as unknown as LookupAddress[];
      for (const a of list) {
        if (isPrivateAddress(a.address)) {
          callback(
            new JwksFetchError({
              kind: "private_address",
              url: originalUrl,
              host: hostname,
              address: a.address,
            }),
            "",
            0,
          );
          return;
        }
      }
      const first = list[0];
      if (first === undefined) {
        callback(new Error(`no DNS records for ${hostname}`), "", 0);
        return;
      }
      // Answer in the shape net requested: the address list when it asked for
      // all (Happy Eyeballs), otherwise a single validated address.
      if (options.all) {
        callback(null, list);
      } else {
        callback(null, first.address, first.family);
      }
    });
  };
}

// HTTPS GET a JWKS document under the full hardened profile (spec D): https +
// port 443 only, no IP-literal host, no DNS resolution to a private range,
// at most one same-origin redirect, a 64 KiB body cap, a 5 s timeout, and a
// JSON content-type. Any violation rejects with a typed JwksFetchError.
export async function fetchJwks(url: string): Promise<Jwks> {
  return await fetchJwksFollowing(url, url, JWKS_MAX_REDIRECTS);
}

// `originalUrl` is the receipt-declared URL (used for error attribution and the
// same-origin comparison); `currentUrl` is the URL of THIS hop.
async function fetchJwksFollowing(
  originalUrl: string,
  currentUrl: string,
  redirectsLeft: number,
): Promise<Jwks> {
  const parsed = new URL(currentUrl);
  const targetError = validateFetchTarget(originalUrl, parsed);
  if (targetError !== null) {
    throw new JwksFetchError(targetError);
  }

  return await new Promise<Jwks>((resolveP, rejectP) => {
    const req = httpsRequest(
      {
        method: "GET",
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: JWKS_ALLOWED_PORT,
        path: parsed.pathname + parsed.search,
        headers: { accept: JWKS_ALLOWED_CONTENT_TYPES.join(", ") },
        timeout: JWKS_FETCH_TIMEOUT_MS,
        lookup: guardedLookup(originalUrl),
      },
      (res) => {
        const status = res.statusCode ?? 0;

        // Redirects: follow at most one, and only same-origin. Anything else
        // is a fail-closed refusal — a cross-origin redirect out of an
        // untrusted URL is the SSRF pivot this profile exists to stop.
        if (status >= 300 && status < 400) {
          res.resume(); // drain
          const location = res.headers.location;
          if (redirectsLeft <= 0 || location === undefined) {
            rejectP(new JwksFetchError({ kind: "too_many_redirects", url: originalUrl }));
            return;
          }
          let target: URL;
          try {
            target = new URL(location, parsed);
          } catch {
            rejectP(new JwksFetchError({ kind: "cross_origin_redirect", url: originalUrl, location }));
            return;
          }
          if (target.protocol !== parsed.protocol || target.host !== parsed.host) {
            rejectP(new JwksFetchError({ kind: "cross_origin_redirect", url: originalUrl, location }));
            return;
          }
          fetchJwksFollowing(originalUrl, target.href, redirectsLeft - 1).then(resolveP, rejectP);
          return;
        }

        if (status !== 200) {
          res.resume();
          rejectP(new JwksFetchError({ kind: "fetch_failed", url: originalUrl, message: `HTTP ${status}` }));
          return;
        }

        const contentType = (res.headers["content-type"] ?? "")
          .split(";")[0]!
          .trim()
          .toLowerCase();
        if (!JWKS_ALLOWED_CONTENT_TYPES.includes(contentType)) {
          res.resume();
          rejectP(
            new JwksFetchError({ kind: "bad_content_type", url: originalUrl, contentType }),
          );
          return;
        }

        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > JWKS_MAX_BYTES) {
            res.destroy(
              new JwksFetchError({
                kind: "fetch_failed",
                url: originalUrl,
                message: `body exceeded ${JWKS_MAX_BYTES} bytes`,
              }),
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
              new JwksFetchError({
                kind: "malformed_jwks",
                url: originalUrl,
                message: `not valid JSON: ${(e as Error).message}`,
              }),
            );
            return;
          }
          if (
            typeof parsedBody !== "object" ||
            parsedBody === null ||
            !Array.isArray((parsedBody as { keys?: unknown }).keys)
          ) {
            rejectP(
              new JwksFetchError({
                kind: "malformed_jwks",
                url: originalUrl,
                message: "body has no `keys` array",
              }),
            );
            return;
          }
          resolveP(parsedBody as Jwks);
        });
        res.on("error", (e) =>
          rejectP(
            e instanceof JwksFetchError
              ? e
              : new JwksFetchError({ kind: "fetch_failed", url: originalUrl, message: (e as Error).message }),
          ),
        );
      },
    );
    req.on("error", (e) =>
      rejectP(
        e instanceof JwksFetchError
          ? e
          : new JwksFetchError({ kind: "fetch_failed", url: originalUrl, message: (e as Error).message }),
      ),
    );
    req.on("timeout", () => {
      req.destroy(
        new JwksFetchError({
          kind: "fetch_failed",
          url: originalUrl,
          message: `timed out after ${JWKS_FETCH_TIMEOUT_MS}ms`,
        }),
      );
    });
    req.end();
  });
}

// All JWKs in the document whose kid matches — strict equality, no
// normalization. Returns every match so the caller can fail closed on
// ambiguity rather than silently picking the first (spec H).
export function findJwksByKid(jwks: Jwks, kid: string): Jwk[] {
  return jwks.keys.filter((k) => k.kid === kid);
}

// Back-compat convenience: the first match, or undefined.
export function findJwkByKid(jwks: Jwks, kid: string): Jwk | undefined {
  return findJwksByKid(jwks, kid)[0];
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
  // Static target validation (scheme / port / IP-literal) up front so an
  // obviously-unsafe URL fails without a network round-trip. The remaining
  // guards (DNS→private, redirects, content-type, size, timeout) fire inside
  // fetchJwks and arrive here as typed JwksFetchError.detail.
  const targetError = validateFetchTarget(opts.url, parsed);
  if (targetError !== null) {
    return { ok: false, error: targetError };
  }

  let jwks = jwksCache.get(opts.url);
  if (jwks === undefined) {
    try {
      jwks = await fetchJwks(opts.url);
    } catch (e) {
      if (e instanceof JwksFetchError) {
        return { ok: false, error: e.detail };
      }
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

  // Duplicate-kid ambiguity is fail-closed (spec H): a JWKS that serves two
  // keys under the same kid gives an attacker a pick-first foothold (publish a
  // rogue key alongside the real one). We refuse to guess which is meant.
  const matches = findJwksByKid(jwks, opts.kid);
  if (matches.length > 1) {
    return {
      ok: false,
      error: { kind: "duplicate_kid", url: opts.url, kid: opts.kid },
    };
  }
  const jwk = matches[0];
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
