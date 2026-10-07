// In-process STUB witness implementing WITNESS_SPEC v0.5 sections 2 to 4, for
// the unit tests and examples/e015-4-kit. This is NOT Headless Oracle's
// witness. Deviations from the spec, both deliberate:
//
//   1. Every receipt says "witness":"stub.invalid" (by default), not
//      "headlessoracle.com", so a stub receipt can never be mistaken for one
//      issued by the real service. Verifiers must pass --witness-name.
//   2. Signature verification (POST check 6) uses node:crypto, which accepts
//      small-order Ed25519 public keys. The real witness rejects them (strict
//      RFC 8032). The client side is unaffected: it only ever submits its own
//      key.
//
// v0.5 accounts are modelled when `accounts` is given: an Authorization header
// is checked after check 1 and before checks 2 to 6, exactly as the worker
// orders it (401 invalid_key for a malformed or unknown key, never answered
// from the anonymous pool; 402 payment_required; 403 witness_plan_required;
// 503 witness_unavailable when `keyStoreDown`). Only a POST that stores a new
// row counts: per account against its plan's quota (429 quota_exceeded with
// `upgrade` and Retry-After to 00:00 UTC), anonymously against `anonymousCap`
// (503 witness_unavailable with `upgrade`). Every 4xx carries `docs`.
//
// Defaults keep the v0.4 behaviour: no cap, no quota hit, no rate limit, and
// (with no accounts configured) any Authorization header is 401 invalid_key.
// Not modelled: real rate limiting (`rateLimited` forces 429 RATE_LIMITED) and
// 503 storage failure. Storage is an in-memory list with the spec's unique key
// (kid, session_id, count, last_entry_hash) and INSERT OR IGNORE semantics.

import { createHash, sign as cryptoSign, verify as cryptoVerify, createPublicKey, type KeyObject } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  base64UrlDecode,
  base64UrlNoPad,
  ed25519PrivateKeyFromSeed,
  jcsBytes,
  publicKeyFromPrivate,
  rawPublicKeyBytes,
} from "../src/vendor/recorder/index.js";

export const STUB_WITNESS_NAME = "stub.invalid";
export const STUB_WITNESS_SEED = Buffer.alloc(32, 0x02);
// received_at comes from a fixed test clock: this instant plus 1 s per receipt
// already stored, so a rerun produces identical receipts.
export const STUB_CLOCK_BASE_MS = Date.parse("2026-10-03T00:00:00.000Z");

export function fixedClock(stored: number): string {
  return new Date(STUB_CLOCK_BASE_MS + stored * 1000).toISOString();
}

export const STUB_PRICING_URL = "https://stub.invalid/v5/pricing";
export const STUB_CHECKOUT_URL = "https://stub.invalid/v5/checkout";
export const STUB_EVIDENCE_QUOTA: Record<string, number> = { evidence_starter: 1000, evidence: 3000 };
const EVIDENCE_PLANS = new Set(Object.keys(STUB_EVIDENCE_QUOTA));
const ACCOUNT_KEY_HEADER = /^Bearer ho_live_[0-9a-f]{64}$/;

// A key the stub knows. `quota` overrides the plan's daily quota (tests use 1).
export interface StubAccount {
  status: "active" | "inactive";
  plan: string; // "evidence_starter" | "evidence" are Evidence plans; anything else is not
  quota?: number;
}

// The worker's `upgrade` object, with stub values (not Headless Oracle's prices).
export function stubUpgrade(): Record<string, unknown> {
  const plan = (p: string, name: string, quota: number) => ({
    plan: p,
    name,
    amount_usd: "0.00",
    currency: "USD",
    billing: "monthly",
    checkpoints_per_utc_day: quota,
  });
  return {
    plans: [
      plan("custody_90d", "Stub Evidence Starter", STUB_EVIDENCE_QUOTA["evidence_starter"]!),
      plan("custody_1y", "Stub Evidence", STUB_EVIDENCE_QUOTA["evidence"]!),
    ],
    checkout: {
      method: "POST",
      url: STUB_CHECKOUT_URL,
      headers: { "Content-Type": "application/json" },
      body: { plan: "custody_90d" },
      then: "stub: nothing is sold here",
    },
    pricing: STUB_PRICING_URL,
  };
}

export interface StubWitnessOptions {
  seed?: Buffer;
  name?: string;
  keyId?: string;
  clock?: (stored: number) => string;
  pageSize?: number;
  // Fault injection for tests.
  delayMs?: number; // delay every POST response
  hangPosts?: boolean; // never answer a POST
  corruptSignature?: boolean; // flip a byte of the signature in POST replies
  // v0.5 accounts (see the header comment).
  accounts?: Record<string, StubAccount>; // full key -> account
  anonymousCap?: number; // new anonymous rows allowed before 503 + upgrade
  keyStoreDown?: boolean; // any Authorization header -> 503 witness_unavailable
  rateLimited?: boolean; // every POST -> 429 RATE_LIMITED, Retry-After 60
  upgrade?: unknown; // replaces the `upgrade` object the stub sends
}

export interface StubWitness {
  url: string;
  publicKeyHex: string;
  keyId: string;
  rows: Record<string, string>[];
  // rowPools[i] is the pool rows[i] was stored under: "anon" or "acct:<id>".
  rowPools: string[];
  // The Authorization header of every request, null when absent, by route.
  postAuth: (string | null)[];
  getAuth: (string | null)[];
  keysAuth: (string | null)[];
  // Every POST response, for status/header assertions.
  postReplies: { status: number; headers: Record<string, string>; body: unknown }[];
  posts: number;
  gets: number;
  close: () => Promise<void>;
}

// Sign a receipt as the worker does: Ed25519 over sorted-keys JSON of every
// member except `signature` (for an all-string object, identical to JCS), hex.
export function signWitnessReceipt(
  fields: Record<string, string>,
  privateKey: KeyObject,
): Record<string, string> {
  const { signature: _drop, ...unsigned } = fields;
  const sig = cryptoSign(null, jcsBytes(unsigned), privateKey).toString("hex");
  return { ...unsigned, signature: sig };
}

const CP_MEMBERS = "count,kid,last_entry_hash,session_id,sig,ts,type,v";
const JWK_MEMBERS = "crv,kty,x";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function members(o: object): string {
  return Object.getOwnPropertyNames(o).sort().join(",");
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Section 2 check 1. Returns the error code or the parsed body.
function checkEnvelope(contentType: string | undefined, raw: Buffer): { error: string } | { body: Record<string, unknown> } {
  if (!(contentType ?? "").startsWith("application/json") || raw.length > 4096) return { error: "bad_request" };
  let body: unknown;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch {
    return { error: "bad_request" };
  }
  if (!isObj(body) || members(body) !== "checkpoint,public_key_jwk") return { error: "bad_request" };
  return { body };
}

// Section 2 checks 2 to 6, in order. Returns the error code or the checkpoint.
function checkSubmission(body: Record<string, unknown>): { error: string } | { cp: Record<string, unknown> } {
  const cp = body["checkpoint"];
  if (!isObj(cp) || members(cp) !== CP_MEMBERS) return { error: "bad_checkpoint_shape" };
  const { v, type, count, last_entry_hash, ts, session_id, kid, sig } = cp;
  if (
    v !== "evidence.action/1" ||
    type !== "checkpoint" ||
    typeof count !== "number" ||
    !Number.isSafeInteger(count) ||
    count < 1 ||
    typeof last_entry_hash !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(last_entry_hash) ||
    typeof ts !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(ts) ||
    !Number.isFinite(Date.parse(ts)) ||
    typeof session_id !== "string" ||
    session_id.length < 1 ||
    session_id.length > 128 ||
    typeof kid !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(kid) ||
    typeof sig !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(sig)
  ) {
    return { error: "bad_checkpoint_field" };
  }
  const jwk = body["public_key_jwk"];
  if (!isObj(jwk) || members(jwk) !== JWK_MEMBERS || jwk["kty"] !== "OKP" || jwk["crv"] !== "Ed25519") {
    return { error: "bad_jwk" };
  }
  const x = jwk["x"];
  if (typeof x !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(x)) return { error: "bad_jwk" };
  const rawX = base64UrlDecode(x);
  if (rawX.length !== 32 || base64UrlNoPad(rawX) !== x) return { error: "bad_jwk" };
  const tp = base64UrlNoPad(
    createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`, "utf8").digest(),
  );
  if (tp !== kid) return { error: "kid_mismatch" };
  const { sig: _s, ...unsigned } = cp;
  let ok = false;
  try {
    const pubObj = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawX]), format: "der", type: "spki" });
    ok = cryptoVerify(null, jcsBytes(unsigned), pubObj, base64UrlDecode(sig));
  } catch {
    ok = false;
  }
  if (!ok) return { error: "bad_signature" };
  return { cp };
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", "access-control-allow-origin": "*", ...headers });
  res.end(JSON.stringify(body));
}

function secondsToUtcMidnight(nowMs: number): number {
  const t = new Date(nowMs);
  const next = Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate() + 1);
  return Math.min(86_400, Math.max(1, Math.ceil((next - nowMs) / 1000)));
}

export async function startStubWitness(opts: StubWitnessOptions = {}): Promise<StubWitness> {
  const signer = ed25519PrivateKeyFromSeed(opts.seed ?? STUB_WITNESS_SEED);
  const publicKeyHex = rawPublicKeyBytes(publicKeyFromPrivate(signer)).toString("hex");
  const name = opts.name ?? STUB_WITNESS_NAME;
  const keyId = opts.keyId ?? "key_2026_v1";
  const clock = opts.clock ?? fixedClock;
  const pageSize = opts.pageSize ?? 500;
  const rows: Record<string, string>[] = [];
  const rowPools: string[] = [];
  const postAuth: (string | null)[] = [];
  const getAuth: (string | null)[] = [];
  const keysAuth: (string | null)[] = [];
  const postReplies: StubWitness["postReplies"] = [];
  const accounts = opts.accounts ?? {};
  const stub = { posts: 0, gets: 0, url: "" };
  const authOf = (req: IncomingMessage): string | null => {
    const h = req.headers["authorization"];
    return typeof h === "string" ? h : null;
  };

  // The account check (spec section 2, check 1.5). null = no header (anonymous).
  const checkAccount = (
    auth: string | null,
  ): { pool: string; quota: number } | { status: number; error: string } | null => {
    if (auth === null) return null;
    if (!ACCOUNT_KEY_HEADER.test(auth)) return { status: 401, error: "invalid_key" };
    if (opts.keyStoreDown) return { status: 503, error: "witness_unavailable" };
    const key = auth.slice("Bearer ".length);
    const acct = Object.prototype.hasOwnProperty.call(accounts, key) ? accounts[key]! : undefined;
    if (acct === undefined) return { status: 401, error: "invalid_key" };
    if (acct.status !== "active") return { status: 402, error: "payment_required" };
    if (!EVIDENCE_PLANS.has(acct.plan)) return { status: 403, error: "witness_plan_required" };
    return {
      pool: "acct:" + createHash("sha256").update(key, "utf8").digest("hex").slice(0, 32),
      quota: acct.quota ?? STUB_EVIDENCE_QUOTA[acct.plan]!,
    };
  };

  const handlePost = (req: IncomingMessage, res: ServerResponse, raw: Buffer): void => {
    stub.posts++;
    postAuth.push(authOf(req));
    if (opts.hangPosts) return;
    let status: number;
    let body: unknown;
    let headers: Record<string, string> = {};
    const upgrade = () => (opts.upgrade !== undefined ? opts.upgrade : stubUpgrade());
    const envelope = opts.rateLimited ? null : checkEnvelope(req.headers["content-type"], raw);
    const account = envelope !== null && "body" in envelope ? checkAccount(authOf(req)) : null;
    const checked =
      envelope !== null && "body" in envelope && (account === null || "pool" in account)
        ? checkSubmission(envelope.body)
        : null;
    if (envelope === null) {
      status = 429;
      body = { error: "RATE_LIMITED", retry_after_seconds: 60 };
      headers = { "retry-after": "60" };
    } else if ("error" in envelope) {
      status = 400;
      body = { error: envelope.error };
    } else if (account !== null && "error" in account) {
      status = account.status;
      body = { error: account.error };
    } else if (checked === null || "error" in checked) {
      status = 400;
      body = { error: checked === null ? "bad_request" : checked.error };
    } else {
      const cp = checked.cp;
      const pool = account === null ? "anon" : account.pool;
      const count = String(cp["count"]);
      const existing = rows.find(
        (r) =>
          r["kid"] === cp["kid"] &&
          r["session_id"] === cp["session_id"] &&
          r["count"] === count &&
          r["last_entry_hash"] === cp["last_entry_hash"],
      );
      const storedInPool = rowPools.filter((p) => p === pool).length;
      if (existing !== undefined) {
        status = 200;
        body = existing;
      } else if (account !== null && storedInPool >= account.quota) {
        const retryAfter = secondsToUtcMidnight(Date.now());
        status = 429;
        body = { error: "quota_exceeded", retry_after_seconds: retryAfter, upgrade: upgrade() };
        headers = { "retry-after": String(retryAfter) };
      } else if (account === null && opts.anonymousCap !== undefined && storedInPool >= opts.anonymousCap) {
        status = 503;
        body = { error: "witness_unavailable", upgrade: upgrade() };
      } else {
        const fork = rows.some(
          (r) =>
            r["kid"] === cp["kid"] &&
            r["session_id"] === cp["session_id"] &&
            r["count"] === count &&
            r["last_entry_hash"] !== cp["last_entry_hash"],
        );
        const receipt = signWitnessReceipt(
          {
            type: "witness.checkpoint/1",
            witness: name,
            received_at: clock(rows.length),
            kid: String(cp["kid"]),
            session_id: String(cp["session_id"]),
            count,
            last_entry_hash: String(cp["last_entry_hash"]),
            checkpoint_ts: String(cp["ts"]),
            checkpoint_sha256: "sha256:" + createHash("sha256").update(jcsBytes(cp)).digest("hex"),
            fork: fork ? "true" : "false",
            public_key_id: keyId,
          },
          signer,
        );
        rows.push(receipt);
        rowPools.push(pool);
        status = 201;
        body = receipt;
      }
    }
    if (status >= 400 && status < 500 && isObj(body)) body = { ...body, docs: `${stub.url}/v1/witness/spec` };
    if (opts.corruptSignature && isObj(body) && typeof body["signature"] === "string") {
      const s = body["signature"];
      body = { ...body, signature: (s[0] === "0" ? "1" : "0") + s.slice(1) };
    }
    postReplies.push({ status, headers, body });
    if (opts.delayMs) setTimeout(() => send(res, status, body, headers), opts.delayMs);
    else send(res, status, body, headers);
  };

  const handleGet = (u: URL, res: ServerResponse): void => {
    stub.gets++;
    const kid = u.searchParams.get("kid");
    const sid = u.searchParams.get("session_id");
    const after = u.searchParams.get("after");
    if (
      kid === null ||
      sid === null ||
      !/^[A-Za-z0-9_-]{43}$/.test(kid) ||
      sid.length < 1 ||
      sid.length > 128 ||
      (after !== null && !/^\d+:sha256:[0-9a-f]{64}$/.test(after))
    ) {
      send(res, 400, { error: "bad_request" });
      return;
    }
    let afterCount = -1;
    let afterHash = "";
    if (after !== null) {
      const i = after.indexOf(":");
      afterCount = Number(after.slice(0, i));
      afterHash = after.slice(i + 1);
    }
    const matching = rows
      .filter((r) => r["kid"] === kid && r["session_id"] === sid)
      .map((r) => ({ r, c: Number(r["count"]), h: r["last_entry_hash"]! }))
      .filter((x) => x.c > afterCount || (x.c === afterCount && x.h > afterHash))
      .sort((a, b) => a.c - b.c || (a.h < b.h ? -1 : a.h > b.h ? 1 : 0));
    const page = matching.slice(0, pageSize);
    const out: Record<string, unknown> = { kid, session_id: sid, receipts: page.map((x) => x.r) };
    if (matching.length > pageSize) {
      const lastRow = page[page.length - 1]!;
      out["next_after"] = `${lastRow.c}:${lastRow.h}`;
    }
    send(res, 200, out);
  };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const u = new URL(req.url ?? "/", "http://stub");
      if (req.method === "POST" && u.pathname === "/v1/witness/checkpoints") {
        handlePost(req, res, Buffer.concat(chunks));
      } else if (req.method === "GET" && u.pathname === "/v1/witness/checkpoints") {
        getAuth.push(authOf(req));
        handleGet(u, res);
      } else if (req.method === "GET" && u.pathname === "/v5/keys") {
        keysAuth.push(authOf(req));
        send(res, 200, { keys: [{ key_id: keyId, public_key: publicKeyHex }] });
      } else {
        send(res, 404, { error: "not_found", docs: `${stub.url}/v1/witness/spec` });
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  stub.url = `http://127.0.0.1:${port}`;

  return {
    url: stub.url,
    publicKeyHex,
    keyId,
    rows,
    rowPools,
    postAuth,
    getAuth,
    keysAuth,
    postReplies,
    get posts() {
      return stub.posts;
    },
    get gets() {
      return stub.gets;
    },
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}
